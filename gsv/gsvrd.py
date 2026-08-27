"""gsv rd - read one thing off a PE, or off a rect of PEs.

Location first, then what to read - the same three sources `gsv cmp` compares:

  --reg    registers (dfd register_read). Named, or every register if you name none.
  --sram   raw data memory (dfd memory_read), from an address for a word count.
  --sym    symbols (dfd symbol_read). Named; `--sym all` for the whole table.

A bare 'x,y' is ONE PE here - unlike `gsv cmp`, where it means the 3x3 around it,
because comparing needs neighbours and reading does not.

The flags combine; a section header appears only when more than one is asked for, so
a single-source read stays bare lines that pipe into grep and awk.

For the compiler's view of a PE - params, the symbol TABLE, colors, disassembly - see
`gsv dp compile`. This reads VALUES out of the machine; that explains what is there.

Imported by `gsv`, which passes in its `call()`. Nothing here talks to the network
directly.
"""

import argparse
import re
import sys
from concurrent import futures

from gsvlib import emit, note, parse_rect

WORKERS = 8


def _dfd(call, **params):
    body = call("dfd", **params)
    return body.get("dfd_read", []) if isinstance(body, dict) else []


def _read_named(call, rect, names, command_type, kind):
    """One request PER name, concurrently -> printed lines.

    One per name because the endpoint takes a SINGLE name: a comma-separated list
    comes back as [] with HTTP 200 rather than an error, so this fan-out is what
    makes naming several of anything work at all. Concurrent because each request
    costs seconds server-side, so serially the wait is the sum instead of the max;
    `map` keeps the output in the order asked for."""
    def one(name):
        return _dfd(call, commandType=command_type, memoryLocations=name, rect=rect)

    with futures.ThreadPoolExecutor(max_workers=min(len(names), WORKERS)) as pool:
        for name, lines in zip(names, pool.map(one, names)):
            if not lines:
                note(f"gsv rd: {name}: nothing returned "
                     f"(unknown {kind}, or absent on this PE?)", "yellow")
            for line in lines:
                print(line)


def read_reg(call, rect, names):
    """Registers over the rect; every register when no name is given."""
    _read_named(call, rect, list(names) or ["all"], "register_read", "register")


def read_sym(call, rect, names):
    """Symbols over the rect. Names are required, or the literal `all`.

    `all` is opt-in rather than the default because it is a different kind of
    request: the server aggregates the PE's whole symbol table in one heavy op that
    takes tens of seconds, and on some PEs it fails outright (a known bug - a single
    named symbol on the same PE still works). Naming what you want is both faster and
    more reliable, so the expensive read has to be asked for."""
    names = list(names)
    if not names:
        sys.exit("gsv rd: --sym needs symbol name(s), or `--sym all` for the whole "
                 "table (one heavy aggregate request, and it fails on some PEs).\n"
                 "        `gsv dp compile <pe> --names-only` lists the names.")
    if "all" in names:
        if len(names) > 1:
            sys.exit("gsv rd: `--sym all` covers everything; drop the other names")
        note("gsv rd: reading the whole symbol table - one heavy aggregate request "
             "per PE, tens of seconds", "yellow")
    _read_named(call, rect, names, "symbol_read", "symbol")


def parse_addr(spec, words):
    """'--sram ADDR' plus '--words N' -> (start, count).

    'START,END' is also accepted, inclusive, because that is how `gsv cmp` spells a
    memory window (--sram-range) and guessing the same form here should not be an
    error. Naming both is the only thing that is."""
    parts = [p for p in re.split(r"[,\s]+", spec.strip()) if p]
    try:
        nums = [int(p, 0) for p in parts]
    except ValueError:
        sys.exit(f"gsv rd: --sram wants an address (0x1540) or a range "
                 f"(0x1540,0x1560), got {spec!r}")
    if len(nums) == 1:
        return nums[0], max(1, words or 1)
    if len(nums) == 2:
        if words:
            sys.exit("gsv rd: --sram START,END already gives the length; drop --words")
        if nums[1] < nums[0]:
            sys.exit(f"gsv rd: --sram END must be >= START, got {spec!r}")
        return nums[0], nums[1] - nums[0] + 1
    sys.exit(f"gsv rd: --sram wants 'ADDR' or 'START,END', got {spec!r}")


def read_sram(call, rect, spec, words):
    """`count` words of data memory from `start`, for every PE in the rect."""
    start, count = parse_addr(spec, words)
    lines = _dfd(call, commandType="memory_read", memoryLocations=hex(start),
                 rect=rect, size=count)
    if not lines:
        note(f"gsv rd: nothing returned for 0x{start:x}+{count} "
             f"(address out of range?)", "yellow")
    for line in lines:
        print(line)


EPILOG = """\
examples:
  gsv rd 381,624 --reg                       every register on that PE
  gsv rd 381,624 --reg ce_psr ce_pcr         just these two
  gsv rd 380,624,11,1 --reg fab_switch_cfg   over a rect
  gsv rd 714,194 --sram 0x1540 --words 2     two words of data memory
  gsv rd 714,194 --sram 0x1540,0x1560        the same, as an inclusive range
  gsv rd 714,194 --sym tree_reduce17.done    one symbol's words
  gsv rd 714,194 --sym all                   the whole symbol table (heavy)
  gsv rd 714,194 --reg ce_psr --sram 0x1540  both, each under its own header

A bare 'x,y' is ONE PE. 'x,y,w,h' is a rect growing right and down from that corner,
and 'x0,y0 x1,y1' is the box covering both. (`gsv cmp` reads a bare 'x,y' as the 3x3
around the PE instead, since it needs neighbours to compare against.)

To find out what a PE HAS rather than read a value out of it - the symbol table, the
params, the color map, the disassembly - use `gsv dp compile <pe>`.
"""


def main(argv, call):
    ap = argparse.ArgumentParser(
        prog="gsv rd", description=__doc__, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec", nargs="+", metavar="PE",
                    help="'x,y' (one PE), 'x,y,w,h', or 'x0,y0 x1,y1'")
    what = ap.add_argument_group(
        "what to read", "Combine freely; a section header appears only when you ask "
        "for more than one.")
    what.add_argument("--reg", nargs="*", metavar="NAME",
                      help="registers (dfd register_read); every register if you name "
                           "none")
    what.add_argument("--sram", metavar="ADDR",
                      help="raw data memory (dfd memory_read) from ADDR, --words long; "
                           "or 'START,END' inclusive")
    what.add_argument("--sym", nargs="*", metavar="NAME",
                      help="symbols (dfd symbol_read); names required, or `all` for "
                           "the whole table (heavy)")
    opt = ap.add_argument_group("options")
    opt.add_argument("--words", type=int, default=0, metavar="N",
                     help="words to read for --sram (default 1)")
    args = ap.parse_args(argv)

    x, y, w, h = parse_rect(args.spec, prog="gsv rd", pad=0)
    rect = f"{x},{y},{w},{h}"
    asked = [k for k, v in (("reg", args.reg is not None), ("sram", args.sram),
                            ("sym", args.sym is not None)) if v]
    if not asked:
        sys.exit("gsv rd: pick what to read: --reg, --sram or --sym "
                 "(see: gsv rd --help)")
    # Only label sections when there is more than one, so the common single-source
    # read stays bare lines and keeps piping into grep/awk.
    label = len(asked) > 1
    for src in asked:
        if src == "reg":
            if label:
                emit("REGISTERS via register_read:", "cyan")
            read_reg(call, rect, args.reg)
        elif src == "sram":
            if label:
                emit("SRAM via memory_read:", "cyan")
            read_sram(call, rect, args.sram, args.words)
        else:
            if label:
                emit("SYMBOLS via symbol_read:", "cyan")
            read_sym(call, rect, args.sym)
