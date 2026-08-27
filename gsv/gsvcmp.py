"""gsv cmp - compare one PE against its neighbours and report the odd one out.

PEs running the same kernel should hold the same static state, so the PE that differs
from all of its neighbours is the suspect. Pick what to compare:

  --sym    every SYMBOL (dfd symbol_read), diffed per WORD. The PE's code and constant
           tables, which MUST match across same-kernel PEs - an outlier is a defect.
  --reg    every REGISTER (dfd register_read), diffed per FIELD. Runtime state, which
           legitimately varies - an outlier is a lead rather than a fault.
  --sram   raw data memory (dfd memory_read), diffed per ADDRESS. The widest net, and
           the most expensive: 32k addresses per PE. Sees words no symbol covers.

Default is `--sym --reg`. They combine freely and each gets its own section, named for
the dfd command behind it - which is also what you would re-run by hand to check a
value.

Every section is reported the same way: group the PEs by shared value, show only the
entries where one PE stands apart. What you HUNT is a LONE outlier - one PE differing
from all the rest. A whole-column or whole-row split is per-position config, i.e. by
design, and is hidden by default (--all-splits shows it). Caveat in the other
direction: same-kernel PEs legitimately hold different per-PE DATA - each PE's own
partial sum, index, state - so a difference on a compute buffer is a lead, not a fault.

Imported by `gsv`, which passes in its `call()` so both share one URL, one session and
one endpoint table. Nothing here talks to the network directly.
"""

import argparse
import hashlib
import os
import re
import sys
import time
from collections import namedtuple
from urllib.parse import parse_qs, urlsplit

from gsvlib import c, emit, note, parse_rect

# ========================================================== the diff, rendered

def fmt_pe_group(pes):
    """Compact label for a set of (x,y): a COLUMN 'x577 y=847,848' (shared x), a ROW
    'y100 x=1,2' (shared y), else a scatter '(x,y) (x,y)'."""
    ps = sorted(pes)
    if not ps:
        return "(none)"
    if len({p[0] for p in ps}) == 1:
        return f"x{ps[0][0]} y=" + ",".join(str(p[1]) for p in ps)
    if len({p[1] for p in ps}) == 1:
        return f"y{ps[0][1]} x=" + ",".join(str(p[0]) for p in ps)
    return " ".join(f"({p[0]},{p[1]})" for p in ps)


def grouped_diff(entries, render=str, absent_label="(absent)", max_distinct=2,
                 singleton_only=True):
    """Lines for ONE diffed key. `entries` is {pe: value_or_None}. Groups PEs by
    identical rendered value, largest group first.

    Returns [] - i.e. shows nothing - when there is no interesting difference:
      * every PE present with the same value (not a diff at all);
      * more than `max_distinct` distinct values (all-different is per-PE data, not
        an anomaly; 2 is the sweet spot - a shared value plus one outlier group);
      * `singleton_only` and no value group holds exactly ONE PE (a multi-PE split
        is per-position, by-design config; the lone outlier is the corruption
        signature).
    """
    present = [(pe, v) for pe, v in sorted(entries.items()) if v is not None]
    absent = [pe for pe, v in sorted(entries.items()) if v is None]
    if not present:
        return []                       # nothing readable here - no information
    rendered = {}
    for pe, v in present:
        rendered.setdefault(render(v), []).append(pe)
    if len(rendered) <= 1 and not absent:
        return []
    if max_distinct is not None and len(rendered) > max_distinct:
        return []
    if singleton_only:
        sizes = [len(g) for g in rendered.values()] + ([len(absent)] if absent else [])
        if 1 not in sizes:
            return []
    lines = [f"      {fmt_pe_group(g)}:  {val}"
             for val, g in sorted(rendered.items(), key=lambda kv: -len(kv[1]))]
    if absent:
        lines.append(f"      {fmt_pe_group(absent)}:  {absent_label}")
    return lines


# ====================================================== dump-line parsing

PE_LINE = re.compile(r"^\((\d+),\s*(\d+)\)\s+(.*)$")
MEM_LINE = re.compile(r"^\((\d+),\s*(\d+)\)\s*@\s*(0x[0-9a-fA-F]+)\s*\[\d+\]\s+(.*)$")
# Trailing '<==rd_ptr:0x3' marks which ce_oq_mem slot a queue's read pointer sits on -
# pointer position, not a data difference - so strip it before comparing.
ANNOT = re.compile(r"\s*<==\S+")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
NOT_READ = "----"       # the gateway's placeholder for a word it did not return

DumpEntry = namedtuple("DumpEntry", "pe token addr size items")


def normalize_line(line):
    return ANNOT.sub("", line).rstrip()


def parse_dump_line(line):
    """One dfd dump line -> DumpEntry(pe, token, addr, size, items), or None.

    All three sources share the same format, so one reader serves them:

        (x, y) @ 0xADDR [N]      TOKEN  field:val ...  w0 w1 ...

    Every part after the TOKEN becomes ONE diffable item:
      * `field:val`  -> a NAMED item ('length_reload', or a symbol's 'ctx')
      * a bare word  -> a POSITIONAL item, labelled '+0x<offset>'
    That is the whole reason a register ends up diffed per FIELD and a symbol per
    WORD without either needing its own code path - it falls out of what the line
    holds. `----`, the gateway's "not read" placeholder, becomes None so it groups
    as absent rather than comparing equal to another PE's unread word.
    """
    m = PE_LINE.match(line)
    if not m:
        return None                     # a non-PE line ("data src is missing ...")
    parts = m.group(3).split()
    if len(parts) < 4 or parts[0] != "@":
        return None
    try:
        addr = int(parts[1], 16)
        size = int(parts[2].strip("[]"))
    except ValueError:
        return None
    items, k = [], 0
    for part in parts[4:]:
        if ":" in part:
            name, _, val = part.partition(":")
            items.append((name, val or None))
        else:
            items.append((f"+0x{k:x}", None if part == NOT_READ else part))
            k += 1
    return DumpEntry((int(m.group(1)), int(m.group(2))), parts[3], addr, size, items)


def render_value(v):
    """Dump values are hex text ('0568', '3d'); render them as '0x568' so every
    section reads alike. A non-hex value is shown as-is."""
    return f"0x{int(v, 16):x}" if _HEX.match(v) else v


def name_filter(match, exclude):
    """keep(name) from an include and an exclude regex; exclude wins.

    `exclude` is for dropping a family you have already judged to be per-PE BY DESIGN
    once you have seen it - e.g. `ce_oq_mem`, the output-queue FIFO slots, whose
    per-slot `ctrl` bit marks where each PE's queue pointer happens to sit. Nothing is
    excluded by default: which families are noise depends on the workload, and hiding
    them silently is how a real defect gets missed."""
    rx = re.compile(match) if match else None
    ex = re.compile(exclude) if exclude else None
    return lambda n: bool((not rx or rx.search(n)) and not (ex and ex.search(n)))


def label_display(label, addr):
    """A positional item also gets its absolute address: '+0x1' in a symbol based at
    0x124 prints as '+0x1 (0x125)'."""
    if label.startswith("+0x"):
        return f"{label} (0x{addr + int(label[3:], 16):x})"
    return label


# ==================================================================== dfd reads

MAX_PES_PER_BAND = 1000     # PEs per dfd request; the response is buffered whole
MAX_PER_SYMBOL = 800        # cap on the one-symbol-at-a-time fallback for a PE
RETRIES = 4


class FetchError(Exception):
    """A dfd read that failed or came back short - retry, or split and retry."""


def dfd(call, x, y, w, h, command_type, locations="all", size=1, min_coverage=0.5):
    """ONE dfd request for the rect -> its lines. Raises FetchError on anything that
    means "the server pushed back": an HTTP error (gsv's `call` turns those into
    SystemExit, so it is caught here and made retryable), a transport failure, or a
    response covering fewer than `min_coverage` of the rect's PEs - a recovering
    worker returns a short band rather than an error. Pass min_coverage=0 for a read
    where a PE legitimately has nothing to return (a single named symbol)."""
    try:
        body = call("dfd", commandType=command_type, memoryLocations=locations,
                    rect=f"{x},{y},{w},{h}", size=size)
    except SystemExit as exc:            # call() exits on HTTP/API errors
        raise FetchError(str(exc)) from None
    except Exception as exc:
        raise FetchError(f"{type(exc).__name__}: {exc}") from None
    lines = body.get("dfd_read", []) if isinstance(body, dict) else []
    seen = {ln.split(")")[0] for ln in lines if ln.startswith("(")}
    if len(seen) < w * h * min_coverage:
        raise FetchError(f"only {len(seen)}/{w * h} PEs in the response")
    return lines


def _symbol_names(call, x, y):
    """One PE's symbol NAMES, from the cheap pe_compile_info endpoint. Works even on
    a PE whose aggregate all-symbols read 502s, and is per-PE exact. [] on failure."""
    try:
        body = call("pe_compile_info", peX=x, peY=y)
    except (SystemExit, Exception):
        return []
    syms = (body or {}).get("symbols") or {}
    names = syms.keys() if isinstance(syms, dict) else [
        s.get("name") if isinstance(s, dict) else s for s in syms]
    return sorted(n for n in names if isinstance(n, str))


def _dump_pe_per_symbol(call, x, y, why):
    """Reconstruct ONE PE's symbol dump by asking for each symbol name on its own.

    The workaround for a known server bug: for some PEs the aggregate all-symbols
    read fails deterministically - even for a 1x1 rect - while a single-symbol read
    on the same PE succeeds. Costs one request per symbol, so it is only reached
    after the banded path has isolated this PE as the culprit."""
    names = _symbol_names(call, x, y)
    if not names:
        note(f"    PE ({x},{y}): no symbol names either (pe_compile_info empty); skipped",
             "red")
        return []
    if len(names) > MAX_PER_SYMBOL:
        note(f"    PE ({x},{y}): {len(names)} symbols is past the {MAX_PER_SYMBOL} "
             f"per-symbol cap; skipped", "red")
        return []
    note(f"    PE ({x},{y}) [{why}]: fetching {len(names)} symbols individually", "yellow")
    lines = []
    for name in names:
        try:
            lines += dfd(call, x, y, 1, 1, "symbol_read", locations=name, min_coverage=0)
        except FetchError:
            pass                        # a symbol this PE lacks, or a one-off failure
    return lines


def dump(call, x, y, w, h, command_type, max_pes=MAX_PES_PER_BAND):
    """Dump the whole rect for one command type -> lines, banded by rows.

    A band that keeps failing is SPLIT (rows, then columns) to isolate the culprit PE
    rather than losing the whole band; a single PE whose symbol read still fails falls
    back to the per-symbol path above."""
    is_sym = command_type == "symbol_read"
    kind = {"symbol_read": "symbols", "register_read": "registers"}[command_type]
    lines, done = [], 0

    def progress(n):
        nonlocal done
        done += n
        note(f"  dump {kind}: {done}/{w * h} PEs")

    def band(bx, by, bw, bh):
        for attempt in range(RETRIES):
            try:
                got = dfd(call, bx, by, bw, bh, command_type)
                lines.extend(got)
                progress(bw * bh)
                return
            except FetchError as exc:
                if attempt < RETRIES - 1:
                    backoff = min(60, 5 * 2 ** attempt)
                    note(f"    band {bw}x{bh}@({bx},{by}): {exc}; "
                         f"retry {attempt + 2}/{RETRIES} in {backoff}s", "yellow")
                    time.sleep(backoff)
                    continue
                if bh > 1:              # split the taller axis first
                    note(f"    band {bw}x{bh}@({bx},{by}) still failing; splitting rows",
                         "yellow")
                    band(bx, by, bw, bh // 2)
                    band(bx, by + bh // 2, bw, bh - bh // 2)
                    return
                if bw > 1:
                    note(f"    row {bw}x1@({bx},{by}) still failing; splitting columns",
                         "yellow")
                    band(bx, by, bw // 2, bh)
                    band(bx + bw // 2, by, bw - bw // 2, bh)
                    return
                if is_sym:
                    per_pe = _dump_pe_per_symbol(call, bx, by, str(exc)[:60])
                    if per_pe:
                        lines.extend(per_pe)
                        progress(1)
                        return
                note(f"    PE ({bx},{by}) {kind}: {exc}; skipped", "red")
                progress(1)

    rows = max(1, max_pes // w)
    yy = y
    while yy < y + h:
        bh = min(rows, y + h - yy)
        band(x, yy, w, bh)
        yy += bh
    return lines


def dump_memory(call, x, y, w, h, start, end, max_pes=16):
    """Dump data memory [start, end] for the rect, EXPLODED to one line per address:
    '(x, y) @ 0xADDR [1]  mem[0xADDR] WORD'. One address per line is what makes memory
    diff per ADDRESS through the same reader as everything else."""
    count = end - start + 1
    rows = max(1, max_pes // w)
    lines, done = [], 0
    yy = y
    while yy < y + h:
        bh = min(rows, y + h - yy)
        got = None
        for attempt in range(RETRIES):
            try:
                got = dfd(call, x, yy, w, bh, "memory_read",
                          locations=hex(start), size=count)
                break
            except FetchError as exc:
                if attempt == RETRIES - 1:
                    sys.exit(f"gsv cmp: memory read {w}x{bh}@({x},{yy}) failed: {exc}")
                time.sleep(min(30, 3 * 2 ** attempt))
        for line in got:
            m = MEM_LINE.match(line)
            if not m:
                continue
            pe = f"({m.group(1)}, {m.group(2)})"
            # Key off the address the line itself reports, not the request start, so a
            # response the server chose to split into several lines per PE still lands
            # at the right addresses.
            first = int(m.group(3), 16)
            for i, wd in enumerate(m.group(4).split()):
                a = first + i
                lines.append(f"{pe} @ 0x{a:04x} [1]      mem[0x{a:x}] {wd}")
        done += w * bh
        note(f"  dump mem: {done}/{w * h} PEs")
        yy += bh
    return lines


# ========================================================== DSR canonicalization

# The five ce_<dst|s0|s1>_*_dsr views are ONE physical register reinterpreted. Which
# view is live is decided by ce_<p>_dsr's `dsr_type_or_xdsr_id`: 'e'->fab, 'f'->1d,
# anything else is an xdsr id -> ce_xdsr[id].mode ('4d' / 'cb'). Keeping only the
# active view stops one corrupted DSR from being reported five times, and stops stale
# views from being compared at all.
_DSR_RE = re.compile(r"^(ce_(?:dst|s0|s1))_(dsr|fab_dsr|1d_dsr|4d_dsr|circ_buf_dsr)\[(\d+)\]$")
_XDSR_RE = re.compile(r"^ce_xdsr\[(\d+)\]$")


def canonicalize_dsr(lines):
    """Keep only the ACTIVE view of each DSR, per PE."""
    base_type, xdsr_mode = {}, {}
    for line in lines:                                  # pass 1: the selectors
        e = parse_dump_line(normalize_line(line))
        if e is None:
            continue
        fields = dict(e.items)
        m = _DSR_RE.match(e.token)
        if m and m.group(2) == "dsr":
            base_type[(e.pe, m.group(1), m.group(3))] = (
                fields.get("dsr_type_or_xdsr_id") or "").lower()
            continue
        xm = _XDSR_RE.match(e.token)
        if xm:
            xdsr_mode[(e.pe, int(xm.group(1)))] = (fields.get("mode") or "").lower()

    def active(pe, prefix, idx):
        t = base_type.get((pe, prefix, idx))
        if t is None:
            return None                                 # no selector seen -> keep all
        if t == "e":
            return "fab_dsr"
        if t == "f":
            return "1d_dsr"
        try:
            mode = xdsr_mode.get((pe, int(t, 16)))
        except ValueError:
            return "dsr"
        return {"4d": "4d_dsr", "cb": "circ_buf_dsr"}.get(mode, "dsr")

    kept, dropped = [], 0
    for line in lines:                                  # pass 2: keep the active view
        e = parse_dump_line(normalize_line(line))
        if e is not None:
            m = _DSR_RE.match(e.token)
            if m:
                act = active(e.pe, m.group(1), m.group(3))
                if act is not None and m.group(2) != act:
                    dropped += 1
                    continue
        kept.append(line)
    note(f"  canon dsr: dropped {dropped} redundant DSR view(s), kept {len(kept)} line(s)",
         "green")
    return kept


# ================================================================ preflight, cache

def preflight(call):
    """One cheap request against the static `setting` endpoint before committing to a
    heavy dump. A dead host, a missing VPN or a wrong GSV_URL should fail in seconds -
    otherwise every band burns the full retry ladder first. Nothing is caught here on
    purpose: gsv already turns both an API error and a transport failure into the
    right diagnostic."""
    call("setting")


def _chief_tag():
    """A short hash of the chief directory behind GSV_URL, for the cache filename: two
    different jobs with the SAME rect must not alias to one cached dump and silently
    read each other's data. Keyed on the chief - the data identity - so cosmetically
    different URLs for the same artifacts still share a cache entry."""
    url = os.environ.get("GSV_URL", "")
    chief = (parse_qs(urlsplit(url).query).get("chief_directory") or [""])[0] or url
    return hashlib.sha1(chief.encode()).hexdigest()[:8]


def _cache_path(cache, src, x, y, w, h):
    if not cache:
        return None
    return os.path.join(cache, f"{src}_{x}_{y}_{w}x{h}_{_chief_tag()}.txt")


def _valid_dump(path, expect_pes):
    """True when `path` is a complete, uncorrupted cached dump - used to reuse a prior
    dump and skip re-hitting the server, the biggest avoidable load while iterating."""
    if not (path and os.path.exists(path) and os.path.getsize(path) > 0):
        return False
    pes = set()
    with open(path, "rb") as f:
        for raw in f:
            if b"\x00" in raw:          # a recovering worker returns NUL-padded garbage
                return False
            if raw[:1] == b"(":
                pes.add(raw.split(b")", 1)[0])
    return len(pes) >= expect_pes


def _cached(cache, src, x, y, w, h, refresh, produce):
    """produce() the dump, or reuse `<cache>/<src>_<rect>_<chief>.txt` when complete."""
    if not cache:
        return produce()
    os.makedirs(cache, exist_ok=True)
    path = _cache_path(cache, src, x, y, w, h)
    if not refresh and _valid_dump(path, w * h):
        note(f"  cache: reusing {os.path.basename(path)} ({w * h} PEs), no server request",
             "green")
        with open(path) as f:
            return [ln.rstrip("\n") for ln in f]
    lines = produce()
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return lines


# ================================================================== the comparison

SRAM_START = 0x0
SRAM_END = 0x7fff       # current-gen CE data-memory top; later generations may grow

# Named by the dfd command each section came from - the distinction that matters, and
# what you would re-run by hand to check a value.
TITLES = {"sym": "SYMBOLS via symbol_read", "reg": "REGISTERS via register_read",
          "sram": "SRAM via memory_read"}

SOURCES = ("sym", "reg", "sram")        # fixed report order, whatever order flags came
DEFAULT_SOURCES = ("sym", "reg")        # --sram is opt-in: 32k addresses per PE


def report_diffs(title, lines, all_pes, keep=None, whole=False, max_distinct=2,
                 singleton_only=True):
    """Group a dump by TOKEN and report only the entries where a PE stands apart.

    Each token's items are diffed INDEPENDENTLY - per field for a register, per word
    for a symbol - so a single bad field or word is not masked by a sibling. That
    matters: many symbols carry one by-design per-position word (a row or column
    index) next to real config words, and diffed whole that one varying word pushes
    the entry past `max_distinct` and hides all of it. `whole=True` diffs each token
    as one value instead, for a compact view.

    A PE missing a token entirely is reported as absent rather than ignored."""
    toks = {}
    for line in lines:
        e = parse_dump_line(normalize_line(line))
        if e is None or (keep and not keep(e.token)):
            continue
        rec = toks.get(e.token)
        if rec is None:
            # `seen` alongside `labels` purely for speed: a big buffer symbol has
            # thousands of words, and an `in list` membership test per word per PE
            # turns the report quadratic.
            rec = toks[e.token] = {"addr": e.addr, "size": e.size, "pes": {},
                                   "labels": [], "seen": set()}
        for label, _v in e.items:
            if label not in rec["seen"]:
                rec["seen"].add(label)
                rec["labels"].append(label)
        rec["pes"][e.pe] = dict(e.items)

    emit(f"{title} ({len(toks)} compared):")
    ndiff = 0
    for token in sorted(toks, key=lambda t: (toks[t]["addr"], t)):
        rec = toks[token]
        addr, labels, pes = rec["addr"], rec["labels"], rec["pes"]
        if whole:
            body = grouped_diff(
                {pe: tuple(pes[pe][lb] for lb in labels) if pe in pes else None
                 for pe in all_pes},
                render=lambda t: " ".join(NOT_READ if v is None else render_value(v)
                                          for v in t),
                absent_label="(token absent on this PE)",
                max_distinct=max_distinct, singleton_only=singleton_only)
        else:
            body = []
            for label in labels:
                gl = grouped_diff({pe: pes.get(pe, {}).get(label) for pe in all_pes},
                                  render=render_value, max_distinct=max_distinct,
                                  singleton_only=singleton_only)
                if not gl:
                    continue
                if len(labels) == 1:        # one item: naming it adds nothing
                    body += gl
                else:
                    body.append(f"    {label_display(label, addr)}:")
                    body += ["    " + ln for ln in gl]
        if body:
            ndiff += 1
            # A memory token already carries its address ('mem[0x16]'), so repeating
            # it as '@0x16 size 1' is noise; symbols and registers need both.
            emit(f"  {token}:" if f"0x{addr:x}" in token
                 else f"  {token} @0x{addr:x} size {rec['size']}:", "yellow")
            for ln in body:
                emit(ln)
    if not ndiff:
        emit("  (nothing differs"
             + (f" within max-distinct={max_distinct}" if max_distinct is not None else "")
             + ")", "dim")


def compare(call, x, y, w, h, sources=DEFAULT_SOURCES, match=None, exclude=None,
            whole=False, max_distinct=2, singleton_only=True,
            max_pes=MAX_PES_PER_BAND, sram_range=None, cache=None, refresh=False):
    """Dump each requested source over the rect and report the lone outliers.

    The sources are reported SEPARATELY, never merged, because they mean different
    things: symbols are code and constants that must match across same-kernel PEs,
    registers hold runtime state that legitimately varies, and raw SRAM is a mix of
    both plus scratch. Merging them would put a real defect next to by-design noise
    with nothing to tell them apart."""
    lo, hi = SRAM_START, SRAM_END
    if "sram" in sources:
        if sram_range:
            try:
                a, b = sram_range.split(",")
                lo, hi = int(a, 0), int(b, 0)
            except ValueError:
                sys.exit(f"gsv cmp: --sram-range wants 'START,END' (e.g. 0x0,0x7fff), "
                         f"got {sram_range!r}")
            if hi < lo:
                sys.exit("gsv cmp: --sram-range END must be >= START")
        else:
            note(f"  assuming SRAM is 0x0-0x{SRAM_END:x} (current gen); override with "
                 f"--sram-range START,END", "yellow")

    scope = ((f" /{match}/" if match else " (ALL)")
             + (f" minus /{exclude}/" if exclude else ""))
    note(f"rect x={x} y={y} w={w} h={h} ({w * h} PEs), comparing "
         f"{'+'.join(sources)}{scope}")
    if w * h < 3:
        note("fewer than 3 PEs: with no majority to deviate from, a lone-PE outlier "
             "cannot be told from its peer", "yellow")
    # Skipped when every source is already cached, so a cached run needs no network at
    # all and can be re-read offline.
    if any(refresh or not _valid_dump(_cache_path(cache, src, x, y, w, h), w * h)
           for src in sources):
        preflight(call)
    if w * h > 2000:
        note(f"large rect ({w * h} PEs) - heavy on a shared server; consider a smaller "
             f"region or off-peak", "yellow")

    emit(f"gsv cmp x={x} y={y} w={w} h={h}{scope} - PEs grouped by shared value, "
         f"only DIFFERING entries shown:")
    for src in sources:
        if src == "sram":
            lines = _cached(cache, src, x, y, w, h, refresh,
                            lambda: dump_memory(call, x, y, w, h, lo, hi))
            title = f"{TITLES[src]} [0x{lo:x}-0x{hi:x}]"
        else:
            ctype = {"sym": "symbol_read", "reg": "register_read"}[src]
            lines = _cached(cache, src, x, y, w, h, refresh,
                            lambda ct=ctype: dump(call, x, y, w, h, ct, max_pes=max_pes))
            title = TITLES[src]
        if not lines:
            note(f"  {src}: nothing returned; skipping this source", "yellow")
            continue
        if src == "reg":
            lines = canonicalize_dsr(lines)
        # The PE set comes from the DUMP, not the rect: a PE the server refused is
        # absent data, and calling it "absent on this PE" for every entry would bury
        # the report in noise.
        all_pes = {e.pe for ln in lines if (e := parse_dump_line(normalize_line(ln)))}
        report_diffs(title, lines, sorted(all_pes), keep=name_filter(match, exclude),
                     whole=whole, max_distinct=max_distinct,
                     singleton_only=singleton_only)


# ============================================================================ cli

EPILOG = """\
examples:
  gsv cmp 381,624                      the 3x3 around one PE: symbols + registers
  gsv cmp 380,620,5,5 --reg            registers only, over an explicit rect
  gsv cmp 379,622 383,626 --sym        symbols only, two corners -> bounding rect
  gsv cmp 381,624 --sram               raw data memory, diffed per address
  gsv cmp 381,624 --sym --reg --sram   all three, each in its own section
  gsv cmp 381,624 --exclude ce_oq_mem  drop a family that is per-PE by design
  gsv cmp 381,624 --all-splits --max-distinct 0   show every difference

To centre a radius-r box on a suspect (sx,sy), pass x=sx-r, y=sy-r, w=h=2r+1 -
anchoring at the suspect only sees the peers below and right and misses the ones
above and left, where an upstream producer usually is. Radius 2 around (121,152)
is 119,150,5,5.

All the PEs compared must be on ONE chief - the one in GSV_URL. Never compare
across chiefs: chiefs are pipeline stages programmed differently, so the same
(x,y) on another chief is not a like-for-like peer.
"""


def main(argv, call):
    # The dfd all-symbols read is a heavy server-side op (tens of seconds per band),
    # well past gsv's 120s default, so raise the read budget - unless the user chose
    # one. Set HERE and not at module scope: at import it would leak into whichever
    # other subcommand happened to load this file, and a dead endpoint would sit for
    # 300s instead of failing.
    os.environ.setdefault("GSV_TIMEOUT", "300")
    ap = argparse.ArgumentParser(
        prog="gsv cmp", description=__doc__, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec", nargs="+", metavar="RECT",
                    help="'x,y' (3x3 around it), 'x,y,w,h', or 'x0,y0 x1,y1'")
    what = ap.add_argument_group(
        "what to compare", "Combine freely; each gets its own section. "
        "Default: --sym --reg.")
    what.add_argument("--sym", action="store_true",
                      help="every symbol (dfd symbol_read), diffed per word - code "
                           "and constants, which must match across same-kernel PEs")
    what.add_argument("--reg", action="store_true",
                      help="every register (dfd register_read), diffed per field - "
                           "runtime state, so an outlier is a lead not a fault")
    what.add_argument("--sram", action="store_true",
                      help="raw data memory (dfd memory_read), diffed per address - "
                           "the widest net and the most expensive")
    show = ap.add_argument_group("what to show")
    show.add_argument("--match", metavar="REGEX",
                      help="keep only entries whose name matches. Leave this off the "
                           "first run - it hides what you did not think to name")
    show.add_argument("--exclude", metavar="REGEX",
                      help="drop entries whose name matches, for a family you have "
                           "judged to be per-PE by design, e.g. --exclude ce_oq_mem "
                           "(output-queue FIFO slots)")
    show.add_argument("--max-distinct", type=int, default=2, metavar="N",
                      help="hide entries with more than N distinct values; 0 for no "
                           "limit (default 2)")
    show.add_argument("--all-splits", action="store_true",
                      help="also show multi-PE splits, not just lone-PE outliers")
    show.add_argument("--whole", action="store_true",
                      help="diff each entry as one value instead of per field/word")
    how = ap.add_argument_group("reading")
    how.add_argument("--sram-range", metavar="START,END",
                     help=f"data-memory window for --sram "
                          f"(default 0x0,0x{SRAM_END:x})")
    how.add_argument("--max-pes", type=int, default=MAX_PES_PER_BAND, metavar="N",
                     help=f"PEs per dfd request (default {MAX_PES_PER_BAND})")
    how.add_argument("--cache", metavar="DIR",
                     help="keep the raw dumps in DIR and reuse a complete one, so "
                          "re-runs cost the server nothing")
    how.add_argument("--refresh", action="store_true",
                     help="ignore a cached dump and re-fetch")
    args = ap.parse_args(argv)

    x, y, w, h = parse_rect(args.spec, prog="gsv cmp", pad=1)
    # Fixed order regardless of how the flags were typed, so two runs of the same
    # sources always produce comparable output.
    sources = tuple(src for src in SOURCES if getattr(args, src)) or DEFAULT_SOURCES
    compare(call, x, y, w, h, sources=sources, match=args.match, exclude=args.exclude,
            whole=args.whole, max_distinct=args.max_distinct or None,
            singleton_only=not args.all_splits, max_pes=args.max_pes,
            sram_range=args.sram_range, cache=args.cache, refresh=args.refresh)
