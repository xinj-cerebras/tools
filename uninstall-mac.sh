#!/usr/bin/env bash
# uninstall-mac.sh - undo install-mac.sh.
#
#   ./uninstall-mac.sh            # drop the PATH block, bin/ and .venv/
#   ./uninstall-mac.sh --rc FILE  # strip the block from FILE instead of ~/.zshrc
#
# Removes only what install-mac.sh generated. The tools themselves, under
# <tool>/bin/, are left alone.

set -eu

BEGIN_MARK='# >>> tools (managed by install-mac.sh) >>>'
END_MARK='# <<< tools (managed by install-mac.sh) <<<'

ROOT=$(cd "$(dirname "$0")" && pwd)
VENV="$ROOT/.venv"
RC=""

while [ $# -gt 0 ]; do
    case "$1" in
        --rc)      RC="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,9p' "$0" | cut -c3-; exit 0 ;;
        *)         echo "uninstall-mac.sh: unknown option $1" >&2; exit 2 ;;
    esac
done
[ -n "$RC" ] || RC="$HOME/.zshrc"

if [ -f "$RC" ]; then
    awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
        $0 == b { skip = 1 }
        skip != 1 { print }
        $0 == e { skip = 0 }
    ' "$RC" > "$RC.tools.tmp"
    mv "$RC.tools.tmp" "$RC"
    echo "  removed PATH block from $RC"
fi

rm -rf "$ROOT/bin" "$VENV"
echo "  removed $ROOT/bin and $VENV"
echo ""
echo "open a new shell (or: source $RC) to pick it up"
