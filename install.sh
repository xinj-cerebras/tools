#!/usr/bin/env bash
# install.sh - put every tool in this repo on PATH, on macOS or Linux.
#
#   ./install.sh              # install / re-sync (safe to re-run)
#   ./install.sh --rc FILE    # write the PATH block to FILE instead of the default
#   ./install.sh --uninstall  # drop the PATH block and the generated bin/
#
# Default rc file: ~/.zshrc on macOS (or any zsh login shell), ~/.bashrc.local
# on Linux. bashrc.local is created and hooked into ~/.bashrc if missing.
#
# Written for bash 3.2 (what macOS still ships) - no readlink -f, no sed -i.

set -eu

BEGIN_MARK='# >>> tools (managed by ~/tools/install.sh) >>>'
END_MARK='# <<< tools (managed by ~/tools/install.sh) <<<'

ROOT=$(cd "$(dirname "$0")" && pwd)
RC=""
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --rc)        RC="${2:-}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help)   sed -n '2,12p' "$0" | cut -c3-; exit 0 ;;
        *)           echo "install.sh: unknown option $1" >&2; exit 2 ;;
    esac
done

# --------------------------------------------------------------------------
# Which rc file
# --------------------------------------------------------------------------
pick_rc() {
    case "${SHELL:-}" in
        */zsh) echo "$HOME/.zshrc"; return ;;
    esac
    if [ "$(uname -s)" = "Darwin" ]; then
        echo "$HOME/.zshrc"
    else
        echo "$HOME/.bashrc.local"
    fi
}
[ -n "$RC" ] || RC=$(pick_rc)

# ~/.bashrc.local is only read if ~/.bashrc sources it.
ensure_sourced() {
    case "$RC" in *.bashrc.local) ;; *) return ;; esac
    [ -f "$HOME/.bashrc" ] || return
    grep -q 'bashrc\.local' "$HOME/.bashrc" && return
    {
        echo ""
        echo "[ -f ~/.bashrc.local ] && . ~/.bashrc.local"
    } >> "$HOME/.bashrc"
    echo "  hooked ~/.bashrc.local into ~/.bashrc"
}

# Rewrite RC without the managed block. Also strips the older `$HOME/bin`
# layout's line if this repo used to live there.
strip_block() {
    [ -f "$RC" ] || return 0
    awk -v b="$BEGIN_MARK" -v e="$END_MARK" '
        $0 == b { skip = 1 }
        skip != 1 { print }
        $0 == e { skip = 0 }
    ' "$RC" > "$RC.tools.tmp"
    mv "$RC.tools.tmp" "$RC"
}

# --------------------------------------------------------------------------
# Uninstall
# --------------------------------------------------------------------------
if [ "$UNINSTALL" = 1 ]; then
    strip_block
    rm -rf "$ROOT/bin"
    echo "uninstalled: removed PATH block from $RC and $ROOT/bin"
    echo "open a new shell (or: source $RC) to pick it up"
    exit 0
fi

# --------------------------------------------------------------------------
# Link entry points:  <tool>/bin/*  ->  bin/*
# --------------------------------------------------------------------------
rm -rf "$ROOT/bin"
mkdir -p "$ROOT/bin"

linked=""
for exe in "$ROOT"/*/bin/*; do
    [ -f "$exe" ] || continue
    [ -x "$exe" ] || chmod +x "$exe"
    name=$(basename "$exe")
    if [ -e "$ROOT/bin/$name" ]; then
        echo "install.sh: two tools both provide '$name', skipping $exe" >&2
        continue
    fi
    # Relative link so the repo keeps working if it is moved or cloned
    # somewhere else.
    tool=$(basename "$(dirname "$(dirname "$exe")")")
    ln -s "../$tool/bin/$name" "$ROOT/bin/$name"
    linked="$linked $name"
done
[ -n "$linked" ] || { echo "install.sh: found no */bin/* entry points in $ROOT" >&2; exit 1; }

# --------------------------------------------------------------------------
# PATH block
# --------------------------------------------------------------------------
strip_block
[ -f "$RC" ] || : > "$RC"
{
    echo ""
    echo "$BEGIN_MARK"
    # NB: not TOOLS_HOME -- monolith's cross-build makefiles use `TOOLS_HOME ?=`
    # to locate the aarch64 buildroot SDK, so exporting it here hijacks them.
    echo "export CB_TOOLS_HOME=\"$ROOT\""
    echo 'case ":$PATH:" in'
    echo '    *":$CB_TOOLS_HOME/bin:"*) ;;'
    echo '    *) PATH="$CB_TOOLS_HOME/bin:$PATH" ;;'
    echo 'esac'
    echo 'export PATH'
    echo "$END_MARK"
} >> "$RC"
ensure_sourced

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------
missing=""
if command -v python3 >/dev/null 2>&1; then
    for req in "$ROOT"/*/requirements.txt; do
        [ -f "$req" ] || continue
        while read -r pkg; do
            case "$pkg" in ''|'#'*) continue ;; esac
            mod=$(echo "$pkg" | sed 's/[<>=!].*//' | tr '-' '_')
            python3 -c "import $mod" >/dev/null 2>&1 || missing="$missing $pkg"
        done < "$req"
    done
else
    echo "install.sh: python3 not found - install it (macOS: brew install python)" >&2
fi

# --------------------------------------------------------------------------
echo "installed:$linked"
echo "  repo: $ROOT"
echo "  PATH block written to: $RC"
if [ -n "$missing" ]; then
    echo ""
    echo "  missing python packages:$missing"
    echo "  install with: python3 -m pip install --user$missing"
fi
echo ""
echo "run:  source $RC"
