"""gsv dp - display everything that is not a per-PE value read.

`gsv rd` reads VALUES out of a PE; this explains what is THERE. Whatever the backend
serves that is not a `dfd` read lands here:

    gsv dp compile 714,194     the compiler's view of one PE: params, the symbol
                               table (name -> address/size), the color map, and the
                               disassembly with source lines
    gsv dp routes              color routing: which colors route, and the on/off-ramp
                               PEs for each
    gsv dp summary             the stall summary the UI opens with
    gsv dp <endpoint> [k=v]    any endpoint by name, incl. ones added later

`compile` and `routes` get a rendered view because their raw payloads are unreadable
(a compile info is thousands of entries; a routes payload here was 673k route legs).
Everything else prints as JSON. `--json` forces the raw payload for any of them, so
nothing the backend serves is out of reach.

Imported by `gsv`, which passes in its `call()`. Nothing here talks to the network
directly.
"""

import argparse
import json
import os
import re
import shutil
import sys
import textwrap

from gsvlib import emit, note, parse_rect

# Friendly name -> endpoint. Only where the endpoint name is not the obvious word;
# anything else is passed through as typed, so a new endpoint needs no change here.
ALIAS = {"compile": "pe_compile_info", "options": "fabric_options",
         "kernels": "kernel_tree", "logical": "logical_view"}

RENDERED = ("compile", "routes")        # topics with a view of their own


def _wrap(items, indent="  "):
    """A comma-joined name list, WRAPPED to the terminal. --names-only exists to be a
    compact survey, and 1670 params on one line is not one."""
    width = max(40, min(shutil.get_terminal_size((100, 24)).columns, 120))
    return textwrap.fill(", ".join(items), width=width, initial_indent=indent,
                         subsequent_indent=indent, break_long_words=False,
                         break_on_hyphens=False)


def show_json(body):
    if isinstance(body, dict) and "dfd_read" in body:
        print("\n".join(body["dfd_read"]))
    else:
        print(json.dumps(body, indent=2))


# ============================================================ compile (per PE)

def _instr_at(instrs, addr):
    """The instruction covering `addr` -> (entry, offset), or (None, None).

    Instruction addresses step by 2 in these payloads (a 32-bit instruction is two
    16-bit words), so an address landing on the second word belongs to the
    instruction below it - hence "covering" rather than an exact match."""
    below = [i for i in instrs if int(i.get("addr", -1)) <= addr]
    if not below:
        return None, None
    best = max(below, key=lambda i: int(i.get("addr", -1)))
    off = addr - int(best.get("addr", 0))
    return (best, off) if off <= 2 else (None, None)


def report_at(px, py, body, addr):
    """Reverse lookup: what lives at one address on this PE.

    The point of this is turning a bare number - an `mt_ip`, a jump target, a DSR
    base, an outlier address out of `gsv cmp` - into the named symbol and the source
    line it belongs to."""
    emit(f"PE ({px},{py}) at 0x{addr:x}:", "cyan")
    hits = []
    for name, d in (body.get("symbols") or {}).items():
        if not isinstance(d, dict):
            continue
        sa, sz = int(d.get("address", 0)), int(d.get("size", 0))
        if sa <= addr < sa + max(sz, 1):
            hits.append((sa, sz, name))
    if hits:
        emit("  SYMBOL:")
        for sa, sz, name in sorted(hits):
            emit(f"    {name}  @0x{sa:x} size {sz}   (+0x{addr - sa:x} into it)")
    else:
        emit("  SYMBOL:  (no named data symbol covers this address)", "dim")
    instr, off = _instr_at(body.get("instructions") or [], addr)
    if instr:
        where = f"   (+{off} into it)" if off else ""
        emit("  INSTRUCTION:")
        emit(f"    @0x{int(instr.get('addr', 0)):x}{where}  {instr.get('text', '').strip()}")
        if instr.get("src_line"):
            emit(f"    {instr['src_line']}", "dim")
    else:
        emit("  INSTRUCTION:  (no instruction at or just below this address)", "dim")


def report_compile(px, py, body, match=None, names_only=False, no_instr=False):
    """params + symbol table + color map + disassembly, filtered by ONE regex.

    One regex over all four because what you have in hand is usually just a name - a
    module, a color id, a param, a source file - and not which of them it lives in."""
    rx = re.compile(match) if match else None
    scope = f" matching /{match}/" if match else ""
    out = []

    params = sorted((k, v) for k, v in (body.get("params") or {}).items()
                    if not rx or rx.search(k))
    if params:
        out.append(f"PARAMS ({len(params)}{scope}):")
        out.append(_wrap(k for k, _ in params) if names_only
                   else "\n".join(f"  {k} = {v}" for k, v in params))

    syms = sorted(((n, d) for n, d in (body.get("symbols") or {}).items()
                   if (not rx or rx.search(n)) and isinstance(d, dict)),
                  key=lambda kv: int(kv[1].get("address", 0)))
    if syms:
        out.append(f"SYMBOLS ({len(syms)}{scope}):")
        out.append(_wrap(n for n, _ in syms) if names_only
                   else "\n".join(f"  {n}  @0x{int(d.get('address', 0)):x} "
                                  f"size {int(d.get('size', 0))}" for n, d in syms))

    cols = [(k, v) for k, v in (body.get("colors") or {}).items()
            if not rx or rx.search(f"{k} {v}")]
    # Numeric ids first and in order; a non-numeric key sorts after them.
    cols.sort(key=lambda kv: (0, int(kv[0]), "")
              if str(kv[0]).lstrip("-").isdigit() else (1, 0, str(kv[0])))
    if cols:
        out.append(f"COLORS ({len(cols)}{scope}):")
        out.append("\n".join(f"  {k} = {v}" for k, v in cols))

    instrs = [i for i in (body.get("instructions") or [])
              if not rx or rx.search(f"{i.get('text', '')} {i.get('src_line', '')}")]
    if instrs and not no_instr:
        instrs.sort(key=lambda i: int(i.get("addr", 0)))
        out.append(f"INSTRUCTIONS ({len(instrs)}{scope}):")
        if names_only:
            out.append(_wrap(f"0x{int(i.get('addr', 0)):x}" for i in instrs))
        else:
            out.append("\n".join(
                f"  @0x{int(i.get('addr', 0)):x}  {i.get('text', '').strip()}"
                + (f"\n      {i['src_line']}" if i.get("src_line") else "")
                for i in instrs))

    if not out:
        emit(f"PE ({px},{py}): nothing{scope} (no matching params/symbols/colors/"
             f"instructions; the color map is often absent)", "dim")
        return
    emit(f"PE ({px},{py}) compile info:", "cyan")
    emit("\n".join(out))


def do_compile(call, spec, args):
    if not spec:
        sys.exit("gsv dp compile: needs a PE - 'x,y' (see: gsv dp --help)")
    x, y, w, h = parse_rect(spec, prog="gsv dp compile", pad=0)
    pes = [(xx, yy) for yy in range(y, y + h) for xx in range(x, x + w)]
    if len(pes) > 20:
        note(f"gsv dp compile: {len(pes)} PEs, and pe_compile_info has no rect form - "
             f"that is {len(pes)} requests. Narrow the location.", "yellow")
    addr = None
    if args.at is not None:
        try:
            addr = int(args.at, 0)
        except ValueError:
            sys.exit(f"gsv dp compile: --at wants an address, got {args.at!r}")
    for px, py in pes:
        body = call("pe_compile_info", peX=px, peY=py)
        if args.json:
            show_json(body)
        elif addr is not None:
            report_at(px, py, body, addr)
        else:
            report_compile(px, py, body, match=args.match,
                           names_only=args.names_only, no_instr=args.no_instr)


# ================================================================ routes

def report_routes(body, color=None):
    """Color routing, summarised. The raw payload is hundreds of thousands of route
    legs, so what is useful at the shell is which colors route at all and where each
    one enters and leaves the fabric.

    PE positions here are FLAT indices, printed as served: turning them into (x,y)
    needs the grid width, and no endpoint hands that out."""
    routing = body.get("colors_with_routing") or []
    on, off = body.get("on_ramp_pes") or {}, body.get("off_ramp_pes") or {}
    routes = body.get("routes") or []
    if color is not None:
        routing = [c for c in routing if int(c) == color]
        on = {k: v for k, v in on.items() if int(k) == color}
        off = {k: v for k, v in off.items() if int(k) == color}
        if not (routing or on or off):
            emit(f"color {color}: no routing, and no on/off-ramp PEs", "dim")
            return

    def npes(d, key):
        return len((d.get(key) or {}).get("pe_indices") or [])

    if color is None:
        emit(f"COLORS WITH ROUTING ({len(routing)}):", "cyan")
        emit("  " + ", ".join(str(c) for c in routing))
        emit(f"ROUTE LEGS: {len(routes)}", "cyan")
    keys = sorted({*on, *off}, key=lambda k: (0, int(k)) if str(k).lstrip("-").isdigit()
                  else (1, 0))
    emit(f"RAMP PEs per color ({len(keys)} colors):", "cyan")
    emit(f"  {'color':>6}  {'on-ramp':>8}  {'off-ramp':>8}")
    for k in keys:
        emit(f"  {k:>6}  {npes(on, k):>8}  {npes(off, k):>8}")
    emit("  (counts of PEs; positions are flat indices - the API serves no grid "
         "width to turn them into x,y. --json for the raw payload.)", "dim")


# ==================================================================== cli

EPILOG = """\
examples:
  gsv dp compile 714,194                 params, symbols, colors, disassembly
  gsv dp compile 714,194 --match sigm    ... only entries matching one regex
  gsv dp compile 714,194 --names-only    ... names/addresses only, a compact survey
  gsv dp compile 714,194 --no-instr      ... skip the disassembly
  gsv dp compile 714,194 --at 0x41e      what is AT an address: symbol + instruction
  gsv dp routes                          which colors route, and their ramp PEs
  gsv dp routes --color 7                just that color
  gsv dp summary                         the stall summary
  gsv dp setting
  gsv dp kernel_tree
  gsv dp <endpoint> key=value ...        any endpoint by name
  gsv dp <topic> --json                  the raw payload, for jq

topics: compile (pe_compile_info), routes, summary, setting, options
(fabric_options), kernels (kernel_tree), logical (logical_view), kernel_annotation,
annotation, symbolmap - plus any endpoint name the backend grows later.

To read VALUES off a PE - registers, data memory, a symbol's words - use `gsv rd`.
"""


def main(argv, call):
    ap = argparse.ArgumentParser(
        prog="gsv dp", description=__doc__, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("topic", metavar="TOPIC",
                    help="compile, routes, summary, setting, ... or any endpoint name")
    ap.add_argument("rest", nargs="*", metavar="ARG",
                    help="a PE 'x,y' for compile; otherwise key=value query params")
    ap.add_argument("--json", action="store_true",
                    help="print the raw payload instead of a rendered view")
    comp = ap.add_argument_group("compile")
    comp.add_argument("--match", metavar="REGEX",
                      help="keep only params/symbols/colors/instructions matching")
    comp.add_argument("--names-only", action="store_true",
                      help="list names and addresses without values")
    comp.add_argument("--no-instr", action="store_true",
                      help="skip the disassembly (it is the bulk of the output)")
    comp.add_argument("--at", metavar="ADDR",
                      help="what is at this address: the symbol covering it and the "
                           "instruction there")
    rt = ap.add_argument_group("routes")
    rt.add_argument("--color", type=int, metavar="N", help="limit to one color")
    args = ap.parse_args(argv)

    topic = args.topic
    if topic == "compile":
        do_compile(call, args.rest, args)
        return

    endpoint = ALIAS.get(topic, topic)
    params = {}
    for kv in args.rest:
        k, _, v = kv.partition("=")
        if not v:
            sys.exit(f"gsv dp: bad param {kv!r}, expected key=value "
                     f"(a PE location is only for `gsv dp compile`)")
        params[k] = v
    # Announce the request: these are single blocking calls with no progress of their
    # own, and an endpoint that never answers is indistinguishable from a hang until
    # the read timeout fires.
    note(f"gsv dp: requesting {endpoint} (up to "
         f"{float(os.environ.get('GSV_TIMEOUT', '120')):.0f}s)...")
    body = call(endpoint, **params)

    if topic == "routes" and not args.json:
        report_routes(body, color=args.color)
        return
    show_json(body)
