# gsv

Query a GSV (Global Stall View) debug-ui backend from the shell, instead of
clicking through the web UI.

## Setup

Paste the debug-ui URL straight from the browser:

```sh
export GSV_URL='http://172.23.135.79:8300/debug-ui/fabric_view/?artifact_directory=...&chief_directory=...'
```

The host must be reachable from wherever you run this — on a laptop that
usually means VPN plus, for lab-internal hosts, an SSH tunnel:

```sh
ssh -N -L 8300:172.23.135.79:8300 <jump-host>
export GSV_URL='http://localhost:8300/debug-ui/fabric_view/?artifact_directory=...&chief_directory=...'
```

## Use

```sh
gsv reg 381,624 ce_psr                    # read registers on one PE
gsv reg 381,624 ce_psr ce_pcr ce_mt_ip    # several registers
gsv reg 380,624,11,1 fab_switch_cfg       # a PE rect (x,y,w,h)
gsv reg 381,624 all                       # every register on that PE

gsv summary                               # any endpoint, as JSON
gsv setting
gsv pe_compile_info peX=381 peY=624
gsv dfd commandType=memory_read memoryLocations=0x1000 rect=381,624,1,1 size=64
```

Endpoints: `summary setting fabric_options routes kernel_tree kernel_annotation
logical_view symbolmap annotation dfd pe_compile_info`.

Why it exists: the directory query field differs per endpoint
(`workDirectory` vs `chiefDirectory`) and getting it wrong returns a Python
traceback; the register endpoint takes one register per request and silently
returns `[]` for a comma-separated list. `gsv` handles both.

Requires Python 3 and `requests`.
