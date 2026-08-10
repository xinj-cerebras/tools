# gsv

Query a GSV (Global Stall View) debug-ui backend from the shell, instead of
clicking through the web UI.

## Setup

Paste the debug-ui URL straight from the browser:

```sh
export GSV_URL='http://<host>:<port>/debug-ui/fabric_view/?artifact_directory=...&chief_directory=...'
```

The host must be reachable from wherever you run this — on a laptop that
usually means VPN plus, for lab-internal hosts, an SSH tunnel:

```sh
ssh -N -L <port>:<host>:<port> <jump-host>
export GSV_URL='http://localhost:<port>/debug-ui/fabric_view/?artifact_directory=...&chief_directory=...'
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

## Running ws_debug on the same artifacts

The paths the backend reads are already in the URL. `gsv path` unpacks them:

```sh
gsv path            # host, artifact dir, chief dir, and the files under it
gsv path dfd        # one bare path, for substitution
```

`dfd` is `<chief>/dataless_ckpt.pb`, the dataless fabric dump the `dfd` endpoint
reads — so `ws_debug read --dfd` sees the same register state as `gsv reg`:

```sh
ws_debug read --dfd "$(gsv path dfd)" --rect 381,624,1,1 -r ce_psr
ws_debug read --dfd "$(gsv path dfd)" --pe 381,624 --all-registers
```

Inside the container:

```sh
SIF=/cb/artifacts/builds/cbcore/latest-build-default/cbcore-0.0.0.sif
singularity exec -e "$SIF" /cbcore/bin/ws_debug read --dfd "$(gsv path dfd)" \
    --rect 381,624,1,1 -r ce_psr
```

Caveat: those paths belong to the debug-ui host, and a lab host's `/cb` is its
own local storage — the same path on shared EFS is a different filesystem. Run
`gsv path` to see what is actually readable here; anything marked
`(not on this host)` has to be copied over first (the `gsv-pull` skill does
this). Deriving the chief directory needs one API call when the URL omits
`chief_directory`; otherwise `gsv path` is offline.

## Register names

`gsv reg <pe> all` dumps what a PE has, but to look up a name before reading it,
ask `ws_debug` for the arch's register table (name, address, width, count):

```sh
SIF=/cb/artifacts/builds/cbcore/latest-build-default/cbcore-0.0.0.sif
singularity exec -e "$SIF" /cbcore/bin/ws_debug registers sdr   # or hbg / sbg
```

123 registers on SDR, 171 on HBG/SBG. `all` returns 113 of the SDR ones — the
10 it omits are the DSR views (`ce_dst_dsr`, `ce_dst_1d_dsr`, `ce_dst_4d_dsr`,
`ce_dst_circ_buf_dsr`, `ce_dst_fab_dsr`, and the `ce_s1_*` equivalents), which
are alternate decodings of the same address range (0x7ec0 / 0x7e80). Name them
explicitly to get the decoding you want:

```sh
gsv reg 381,624 ce_dst_dsr        # generic decode of 0x7ec0
gsv reg 381,624 ce_dst_fab_dsr    # same bits, fabric-DSR field names
```

Why it exists: the directory query field differs per endpoint
(`workDirectory` vs `chiefDirectory`) and getting it wrong returns a Python
traceback; the register endpoint takes one register per request and silently
returns `[]` for a comma-separated list. `gsv` handles both.

Requires Python 3 and `requests`.
