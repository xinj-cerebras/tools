"""Shared by the `gsv` subcommands that take a PE location: output plumbing and the
coordinate parser.

Both `gsv rd` and `gsv cmp` accept the same location forms, so the parser lives here
rather than in either of them - a second copy is how the two would drift, and the
strictness below is exactly the kind of thing that would get fixed in one and not the
other.
"""

import os
import re
import sys

# Progress and chatter go to stderr, results to stdout, so `gsv ... > file` keeps the
# output and still shows progress on the terminal.
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_STYLE = {"bold": "1", "dim": "2", "red": "1;31", "green": "1;32",
          "yellow": "1;33", "cyan": "36", "magenta": "35"}


def c(text, style=None):
    if not _COLOR or not style:
        return str(text)
    return f"\033[{_STYLE[style]}m{text}\033[0m"


def note(text, style="dim"):
    print(c(text, style), file=sys.stderr)


def emit(text="", style=None):
    print(c(text, style))


# A FULL match, not a digit scrape: `findall(r'\d+')` happily reads '3x3' as the PE
# (3,3) and 'x=714,y=194' as (714,194), so a typo silently read a region nobody asked
# for - at real cost, since these can be heavy server reads.
_COORDS = re.compile(r"^\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*(\d+)\s*,\s*(\d+)\s*)?$")


def _bad(prog, pad, extra=""):
    one = (f"'x,y' (single PE -> the {2 * pad + 1}x{2 * pad + 1} around it)" if pad
           else "'x,y' (one PE)")
    sys.exit(f"{prog}: location must be 'x,y,w,h', {one}, or 'x0,y0 x1,y1' "
             f"(two corners), with non-negative integers{extra}")


def _coords(token, prog, pad, want_pair=False):
    m = _COORDS.match(token)
    if not m or (want_pair and m.group(3) is not None):
        _bad(prog, pad, f"; could not read {token!r}")
    return [int(g) for g in m.groups() if g is not None]


def parse_rect(tokens, prog="gsv", pad=0):
    """A location spec -> (x, y, w, h), top-left plus size. Accepts:
      'x,y,w,h'          that rect
      'x,y'              one PE, or the (2*pad+1) square CENTERED on it when pad > 0
      'x0,y0' 'x1,y1'    the bounding rectangle covering both corners, inclusive

    `pad` is the whole difference between the two subcommands' idea of a bare 'x,y':
    `rd` reads the PE you named (pad=0), while `cmp` compares it against its
    neighbours, so there it means the 3x3 around it (pad=1).
    """
    if len(tokens) == 2:
        (x0, y0), (x1, y1) = (_coords(t, prog, pad, want_pair=True) for t in tokens)
        return min(x0, x1), min(y0, y1), abs(x1 - x0) + 1, abs(y1 - y0) + 1
    if len(tokens) == 1:
        n = _coords(tokens[0], prog, pad)
        if len(n) == 4:
            x, y, w, h = n
            if w < 1 or h < 1:
                sys.exit(f"{prog}: w and h must be >= 1, got w={w} h={h}")
            return x, y, w, h
        return max(0, n[0] - pad), max(0, n[1] - pad), 2 * pad + 1, 2 * pad + 1
    _bad(prog, pad, f"; got {len(tokens)} arguments: {tokens}")
