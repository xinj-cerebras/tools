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
| [`gsv`](gsv/) | query a GSV (Global Stall View) debug-ui backend from the shell |

## Adding a tool

```
mytool/
├── bin/mytool          # executable, with a shebang; this is what lands on PATH
├── requirements.txt    # optional, python deps
└── README.md
```

Then re-run the installer — the new entry point is picked up automatically.
Anything under `<tool>/bin/` gets linked, so a tool can ship more than one
command.
Keep entry points portable: `#!/usr/bin/env python3` / `#!/usr/bin/env bash`,
no GNU-only flags (macOS ships BSD `sed`/`readlink` and bash 3.2).
