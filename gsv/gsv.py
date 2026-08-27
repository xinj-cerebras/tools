#!/usr/bin/env python3
"""gsv - query a GSV debug-ui backend.

Set the URL once (paste the debug-ui URL straight from the browser):

    export GSV_URL='http://<host>:<port>/debug-ui/fabric_view/?artifact_directory=...&chief_directory=...'

GSV_URL is the only variable you need to set. The scheme is honored, http or https;
the debug-viz hosts serve self-signed certs, so TLS certificate verification is
always skipped.

Timeouts: reads give up after 120s (GSV_TIMEOUT=<seconds>), connects after 4s per
resolved address (GSV_CONNECT_TIMEOUT=<seconds>).

Then:

Four commands:

  rd    READ values off a PE          --reg / --sram / --sym
  dp    DISPLAY everything else       compile, routes, summary, any endpoint
  cmp   COMPARE a PE with its neighbours and report the odd one out
  path  the artifact directories behind GSV_URL

`rd` and `cmp` take the PE location first, then what to look at - the same three
sources, so `--reg` means registers to both:

    gsv rd 381,624 --reg                      every register on that PE
    gsv rd 381,624 --reg ce_psr ce_pcr        just these two
    gsv rd 380,624,11,1 --reg fab_switch_cfg  over a rect (x,y,w,h)
    gsv rd 714,194 --sram 0x1540 --words 2    raw data memory
    gsv rd 714,194 --sym rxbcast_wdsd         one symbol's words

    gsv cmp 381,624                 symbols + registers, over the 3x3 around the PE
    gsv cmp 380,620,5,5 --reg       registers only, over an explicit rect
    gsv cmp 381,624 --sram          raw data memory, diffed per address

A bare 'x,y' is ONE PE to `rd` and the 3x3 around it to `cmp` - reading wants the
PE you named, comparing wants its neighbours.

`dp` covers everything that is not a per-PE value read, any endpoint by name:

    gsv dp compile 714,194          params, symbol table, colors, disassembly
    gsv dp compile 714,194 --at 0x41e   what is at an address: symbol + instruction
    gsv dp routes                   which colors route, and their ramp PEs
    gsv dp summary                  the stall summary
    gsv dp <endpoint> key=value     anything else, incl. endpoints added later

Endpoints: summary setting fabric_options routes kernel_tree kernel_annotation
           logical_view symbolmap annotation dfd pe_compile_info

To run ws_debug against the same artifacts instead of going through the API,
`gsv path` unpacks the directories out of GSV_URL:

    gsv path                                  all of them, labeled
    gsv path dfd                              one bare path, to substitute

    ws_debug read --dfd "$(gsv path dfd)" --rect 381,624,1,1 -r ce_psr

Those paths are on the debug-ui host. If it is not this machine, copy the files
over first - `gsv path` marks what is not readable here.
"""

import json
import os
import re
import sys
import threading
from urllib.parse import parse_qs, urlparse

import requests
import urllib3

# endpoint -> (api path, directory field name)
# The directory field is NOT the same across endpoints. That inconsistency is the
# main reason this script exists; getting it wrong returns a Python traceback.
EP = {
    "summary":           ("gsv/summary/view",          "workDirectory"),
    "setting":           ("gsv/ufv/setting",           "chiefDirectory"),
    "fabric_options":    ("gsv/ufv/fabric_options",    "chiefDirectory"),
    "routes":            ("gsv/ufv/routes",            "chiefDirectory"),
    "kernel_tree":       ("gsv/ufv/kernel_tree",       "chiefDirectory"),
    "kernel_annotation": ("gsv/ufv/kernel_annotation", "chiefDirectory"),
    "logical_view":      ("gsv/ufv/logical_view",      "chiefDirectory"),
    "symbolmap":         ("gsv/ufv/symbolmap",         "chiefDirectory"),
    "annotation":        ("gsv/ufv/annotation",        "chiefDirectory"),
    "dfd":               ("gsv/ufv/dfd",               "chiefDirectory"),
    "pe_compile_info":   ("gsv/ufv/pe_compile_info",   "chiefDirectory"),
}

# Files inside the chief directory, for tools that read the artifacts directly
# rather than over the API. The names are fixed by the service, which opens the
# same files: dataless_ckpt.pb is what the dfd endpoint reads, so
# `ws_debug read --dfd` and `gsv reg` see identical register state.
CHIEF_FILES = {
    "dfd":      "dataless_ckpt.pb",
    "routes":   "stall_viz/routes.json.zst",
    "settings": "stall_viz/ufv_settings.pb",
}


_local = threading.local()


def session():
    """One session per thread, reused across calls.

    Reused so a multi-register read does not redo the TCP+TLS handshake each time;
    per-thread because requests.Session is not guaranteed thread-safe and `reg`
    fans out concurrently. No retries, so failures surface on the first attempt.
    """
    s = getattr(_local, "session", None)
    if s is None:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=0)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        _local.session = s
    return s


def gsv_url():
    """(parsed URL, query dict) from GSV_URL. Empty query values are dropped so
    a `&chief_directory=` left behind by the UI counts as absent."""
    url = os.environ.get("GSV_URL")
    if not url:
        sys.exit("gsv: set GSV_URL to the debug-ui URL (see: gsv --help)")
    u = urlparse(url)
    return u, {k: v[0] for k, v in parse_qs(u.query).items() if v and v[0]}


def call(endpoint, directory=None, /, **params):
    # directory is positional-only: **params holds user-supplied query keys, and
    # a future endpoint field literally named "directory" must not land here.
    u, q = gsv_url()
    artifact = q.get("artifact_directory", "")
    chief = q.get("chief_directory", "")

    path, field = EP.get(endpoint, (endpoint, "chiefDirectory"))
    params[field] = directory or (artifact if field != "chiefDirectory" else chief)
    if not params[field]:
        sys.exit(f"gsv: {endpoint} needs {field}, which is not in GSV_URL")

    # Keep the scheme from GSV_URL: the cloud debug-viz hosts are HTTPS-only and
    # silently hang on port 80.
    scheme = u.scheme or "http"
    # Certificate verification is off, unconditionally. Every debug-viz host serves
    # a self-signed cert, so verification never succeeds here - making it an opt-out
    # only meant the tool broke whenever a shell was missing the env var.
    verify = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # Split connect from read: an unreachable host should fail in seconds, not sit
    # there. Only the read side needs to be generous, since a wide rect or an
    # "all" register dump genuinely takes a while.
    # The connect budget is PER RESOLVED ADDRESS - urllib3 walks every getaddrinfo
    # result within one attempt, and debug-viz has 3 A records - so the worst-case
    # wait is roughly 3x this. Keep it small.
    connect_timeout = float(os.environ.get("GSV_CONNECT_TIMEOUT", "4"))
    read_timeout = float(os.environ.get("GSV_TIMEOUT", "120"))
    r = session().get(f"{scheme}://{u.netloc}/api/{path}", params=params,
                      timeout=(connect_timeout, read_timeout), verify=verify)
    try:
        body = r.json()
    except ValueError:
        sys.exit(f"gsv: HTTP {r.status_code}, non-JSON body:\n{r.text[:300]}")

    # Errors come back as a Python traceback in JSON; keep only the useful lines.
    if r.status_code >= 400 or (isinstance(body, dict) and "traceback" in body):
        tb = body.get("traceback", "") if isinstance(body, dict) else ""
        hints = re.findall(r'has no field named "[^"]+"|Available Fields\(.*', tb)
        if not hints:
            lines = [ln.strip() for ln in tb.splitlines() if ln.strip()]
            hints = lines[-1:] or [json.dumps(body)[:300]]
        sys.exit("gsv: " + "\n     ".join(dict.fromkeys(hints)))
    return body


def paths():
    """The artifact locations behind GSV_URL, keyed the way `gsv path` names them."""
    u, q = gsv_url()
    artifact = q.get("artifact_directory", "")
    chief = q.get("chief_directory", "")
    if artifact and not chief:
        # The UI leaves chief_directory out until a dump is picked in the
        # selector; fabric_options is what fills that selector, and its first
        # option is Chief. This is the one path lookup that needs the network.
        body = call("fabric_options", directory=artifact)
        opts = body.get("options", []) if isinstance(body, dict) else []
        chief = opts[0].get("value", "") if opts else ""
    out = {"artifact": artifact, "chief": chief}
    out.update({k: f"{chief}/{v}" if chief else "" for k, v in CHIEF_FILES.items()})
    return u, out


def show_paths(keys):
    u, p = paths()
    if keys:
        # One bare path per line, nothing else, so it can be substituted:
        #   ws_debug read --dfd "$(gsv path dfd)" ...
        for key in keys:
            if key not in p:
                sys.exit(f"gsv: no such path {key!r}; try: {' '.join(p)}")
            if not p[key]:
                sys.exit(f"gsv: {key} is unknown - GSV_URL has no "
                         f"{'artifact_directory' if key == 'artifact' else 'chief directory'}")
            print(p[key])
        return

    print(f"{'host':9} {u.netloc}")
    for key, value in p.items():
        if not value:
            continue
        # These paths belong to the debug-ui host, whose /cb is its own local
        # storage - a lab box mounts a different filesystem at the same path.
        # So say whether the file is here, rather than implying it is.
        here = "" if os.path.exists(value) else "   (not on this host)"
        print(f"{key:9} {value}{here}")


def main(argv):
    # Asked-for help goes to stdout and exits 0, like the argparse subcommands, so
    # `gsv --help | less` works; a bare `gsv` is a usage error, so it goes to stderr
    # and exits 2. `sys.exit(__doc__)` did neither.
    if not argv:                        # checked FIRST: argv[:1] is [] here too
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    if argv[0] in ("-h", "--help"):
        print(__doc__)
        return
    cmd, rest = argv[0], argv[1:]

    if cmd == "path":
        show_paths(rest)
        return

    if cmd in ("rd", "dp", "cmp"):
        # The three live in sibling modules rather than in this file: together they
        # are several times the size of everything else here, and only these
        # subcommands need them, so they are imported only on this path.
        #
        # realpath, not abspath: what runs is never this file directly. bin/gsv is a
        # symlink to it (that is the entry point the installers pick up), and PATH
        # holds either another symlink to that or a generated venv wrapper. Only
        # realpath gets from any of those back to the directory the modules are in.
        sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
        # ONE module, not all three: importing a sibling you are not about to run
        # means inheriting its import-time setup. `gsv cmp` raises the read timeout
        # for its heavy dumps, and loading it alongside `dp` silently gave every
        # `dp` request that budget too - a dead endpoint then sat for 300s.
        import importlib
        mod = importlib.import_module({"rd": "gsvrd", "dp": "gsvdp",
                                       "cmp": "gsvcmp"}[cmd])
        # `call` is handed over rather than re-implemented, so everything shares one
        # GSV_URL, one endpoint table and one per-thread session.
        mod.main(rest, call)
        return

    # Everything the backend serves is now behind rd / dp / cmp, so a bare endpoint
    # name is a leftover habit rather than a command. Name where it went instead of
    # just refusing - these were the documented spellings until recently.
    moved = {"reg": ("gsv rd <pe> --reg [name ...]", "rd"),
             "pe_compile_info": ("gsv dp compile <pe>", "dp")}
    if cmd in moved:
        where, sub = moved[cmd]
        sys.exit(f"gsv: `gsv {cmd}` is now `{where}`  (see: gsv {sub} --help)")
    if cmd in EP:
        sys.exit(f"gsv: `gsv {cmd}` is now `gsv dp {cmd}`  (see: gsv dp --help)")
    sys.exit(f"gsv: no such command {cmd!r}. Commands: rd (read a PE), "
             f"dp (display everything else), cmp (compare a PE with its neighbours), "
             f"path (artifact paths).\n     See: gsv --help")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except requests.exceptions.SSLError as exc:
        # Should not happen now that verification is off; if TLS still fails it is
        # a real handshake problem, so show it rather than swallowing it.
        sys.exit(f"gsv: TLS error: {exc}")
    except requests.exceptions.ConnectTimeout:
        sys.exit("gsv: timed out connecting. Check VPN, and that GSV_URL has the "
                 "right scheme - https for the cloud debug-viz hosts")
    except requests.exceptions.ConnectionError:
        sys.exit("gsv: could not connect. Check VPN, and that the host and port "
                 "in GSV_URL are right")
    except requests.exceptions.ReadTimeout:
        sys.exit("gsv: the server did not answer in time. Raise the limit with "
                 "GSV_TIMEOUT=<seconds>")
    except requests.exceptions.RequestException as exc:
        sys.exit(f"gsv: {exc}")
    except KeyboardInterrupt:
        sys.exit(130)
