# tools

Personal command-line tools, one directory per tool. Works the same on a Linux
lab/bringup host and on macOS.

## Install

```sh
git clone <remote> ~/tools     # or: already at ~/tools on the lab host
cd ~/tools && ./install.sh     # on macOS: ./install-mac.sh
source ~/.bashrc.local         # on macOS: source ~/.zshrc
```

macOS has its own pair, `install-mac.sh` / `uninstall-mac.sh`, because
Homebrew's python is PEP 668 "externally managed" and refuses
`pip install --user`: the mac script puts the dependencies in a repo-local
`.venv/` and generates wrappers in `bin/` that run the tools under it. Both
`.venv/` and `bin/` stay inside the repo, and the wrappers locate the repo
from their own path, so `tools/` can live anywhere.

Either installer is idempotent — re-run it after adding a tool or pulling.
`install.sh`:

- symlinks every `<tool>/bin/*` entry point into `~/tools/bin/`,
- prepends that directory to `PATH` via a marked block in your rc file
  (`~/.zshrc` on macOS or under zsh, `~/.bashrc.local` on Linux — created and
  hooked into `~/.bashrc` if missing),
- reports any missing Python packages listed in `<tool>/requirements.txt`.

Options: `./install.sh --rc ~/.profile` to target a different rc file,
`./install.sh --uninstall` to remove the block and the generated `bin/`.

## Tools

| tool | what it does |
| --- | --- |
| [`gsv`](gsv/) | query a GSV (Global Stall View) debug-ui backend from the shell: `gsv rd` a PE's registers/memory/symbols, `gsv dp` compile info and routing, `gsv cmp` a PE against its neighbours to find the odd one out |
| [`disasm`](disasm/) | disassemble SDR/HBG/SBG instructions, or raw 16-bit memory words paired little-endian (`disasm-hbg`, `disasm-sbg`) |
| [`rdlreg`](rdlreg/) | print whole SystemRDL definition blocks by name (sdr by default, `-a` for other archs; set `GITTOP`) |

## Adding a tool

```
mytool/
├── bin/mytool          # executable, with a shebang; this is what lands on PATH
├── requirements.txt    # optional, python deps
└── README.md
```

Then re-run the installer — the new entry point is picked up automatically.

A python tool with more than one file keeps them all at its top level and makes
the entry point a relative symlink into them, which is what `gsv` does:

```
gsv/
├── bin/gsv -> ../gsv.py    # the entry point the installers link onto PATH
├── gsv.py                  # the CLI
├── gsvlib.py               # shared by the subcommands
├── gsvrd.py                # gsv rd
├── gsvdp.py                # gsv dp
├── gsvcmp.py               # gsv cmp
└── ...
```

Both installers follow the symlink (`-f`, `-x`, and the shebang sniff all do), so
it installs exactly like a plain script. The importing side needs
`sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))` — `realpath`
because what actually runs is never the file itself: it is reached through that
symlink, plus another symlink or a generated venv wrapper on PATH.

Anything under `<tool>/bin/` gets linked, so a tool can ship more than one
command. Keep entry points portable: `#!/usr/bin/env python3` / `#!/usr/bin/env bash`,
no GNU-only flags (macOS ships BSD `sed`/`readlink` and bash 3.2).
