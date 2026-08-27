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

Four commands. `rd` and `cmp` take the PE location first, then what to look at:

| command | what |
| --- | --- |
| `gsv rd <pe>` | **read** values off a PE — `--reg`, `--sram`, `--sym` |
| `gsv dp <topic>` | **display** everything else — `compile`, `routes`, `summary`, any endpoint |
| `gsv cmp <pe>` | **compare** a PE with its neighbours and report the odd one out |
| `gsv path` | the artifact directories behind `GSV_URL` |

```sh
gsv rd 381,624 --reg                      # every register on that PE
gsv rd 381,624 --reg ce_psr ce_pcr        # just these two
gsv rd 380,624,11,1 --reg fab_switch_cfg  # over a rect (x,y,w,h)
gsv rd 714,194 --sram 0x1540 --words 2    # raw data memory
gsv rd 714,194 --sym rxbcast_wdsd         # one symbol's words

gsv dp compile 714,194                    # params, symbol table, colors, disassembly
gsv dp compile 714,194 --at 0x41e         # what is at an address
gsv dp routes                             # which colors route, and their ramp PEs
gsv dp summary                            # the stall summary

gsv cmp 381,624                           # find the odd PE out among its neighbours
gsv cmp 381,624 --reg                     # ... comparing registers only
```

A bare `x,y` is **one PE** to `rd` and **the 3x3 around it** to `cmp` — reading wants
the PE you named, comparing wants its neighbours. `x,y,w,h` and `x0,y0 x1,y1` mean the
same to both.

`rd` and `cmp` share the same three source flags, so `--reg` means registers to both.

## Reading a PE: `gsv rd`

| flag | what | replaces |
| --- | --- | --- |
| `--reg [NAME ...]` | registers (`dfd register_read`); every register if you name none | `gsv reg <pe> <name>` |
| `--sram ADDR` | data memory from `ADDR`, `--words N` long, or `START,END` inclusive | `gsv dfd commandType=memory_read …` |
| `--sym NAME ...` | symbols (`dfd symbol_read`); names required, or `--sym all` | `gsv dfd commandType=symbol_read …` |

The flags combine, and a section header appears **only** when more than one is asked
for — so a single-source read stays bare lines that pipe into `grep` and `awk`.

`--reg` and `--sym` send one request per name, fanned out 8 at a time: the endpoint
takes a single name, and a comma-separated list comes back as `[]` with HTTP 200
rather than an error.

`--sym all` is opt-in rather than the default because it is a different kind of
request — the server aggregates the whole symbol table in one heavy op that takes tens
of seconds, and on some PEs it fails outright (a known bug; a single named symbol on
the same PE still works). `gsv dp compile <pe> --names-only` lists the names to ask
for.

## Displaying everything else: `gsv dp`

Whatever the backend serves that is not a per-PE `dfd` read:

```sh
gsv dp compile 714,194                 # params, symbols, colors, disassembly
gsv dp compile 714,194 --match sigm    # ... only entries matching one regex
gsv dp compile 714,194 --names-only    # ... names and addresses only
gsv dp compile 714,194 --no-instr      # ... skip the disassembly (most of the output)
gsv dp compile 714,194 --at 0x41e      # what is AT an address
gsv dp routes                          # which colors route, and their ramp PEs
gsv dp routes --color 7                # just that color
gsv dp summary                         # the stall summary
gsv dp <endpoint> key=value ...        # any endpoint by name, incl. later additions
gsv dp <topic> --json                  # the raw payload, for jq
```

Topics are endpoint names, with a few short aliases: `compile` →`pe_compile_info`,
`options` → `fabric_options`, `kernels` → `kernel_tree`, `logical` → `logical_view`.

`compile` and `routes` get a rendered view because their raw payloads are unreadable
at a shell — a compile info is thousands of entries across four sections, and a
`routes` payload here was 673 546 route legs. `--json` forces the raw payload for any
topic, so nothing is out of reach.

`--at ADDR` is the reverse lookup: given a bare number — an `mt_ip`, a jump target, a
DSR base, an outlier address out of `gsv cmp` — it names the symbol covering it and
the instruction there, with its source line:

```
PE (714,194) at 0x41e:
  SYMBOL:  (no named data symbol covers this address)
  INSTRUCTION:
    @0x41e  mov16 r_bound1 = [${name}_sigm16_1ulp_bound] (ld16 r3 = [0x2a4])
    /kernels/../kernels_ws/lib/math/math_sigm.casm:628
```

`compile` is one request per PE (the endpoint has no rect form), so it warns past 20.
`routes` reports PE positions as flat indices, printed as served: converting them to
`(x,y)` needs the grid width and no endpoint hands that out.

## Comparing a PE with its neighbours

`gsv cmp` finds the odd PE out. PEs running the same kernel should hold the same
static state, so the one that differs from all its neighbours is the suspect.

Three things you can compare, one flag each. They combine, and each gets its own
section:

| flag | what | diffed per | notes |
| --- | --- | --- | --- |
| `--sym` | every symbol (`dfd symbol_read`) | word | code and constants, which *must* match across same-kernel PEs — an outlier is a defect |
| `--reg` | every register (`dfd register_read`) | field | runtime state, which legitimately varies — an outlier is a lead, not a fault |
| `--sram` | raw data memory (`dfd memory_read`) | address | the widest net and the most expensive: 32k addresses per PE. Sees words no symbol covers |

Default is `--sym --reg`.

```sh
gsv cmp 381,624                      # the 3x3 around one PE: symbols + registers
gsv cmp 380,620,5,5 --reg            # registers only, over an explicit rect
gsv cmp 379,622 383,626 --sym        # symbols only, two corners -> bounding rect
gsv cmp 381,624 --sram               # raw data memory, per address
gsv cmp 381,624 --sym --reg --sram   # all three
gsv cmp --help                       # every option
```

Output is the same shape whatever you compare — the entry, then each PE group and
its value. Each section is named for the `dfd` command behind it, which is also
what you would re-run by hand to check a value:

```
REGISTERS via register_read (307 compared):
  ce_xdsr[6] @0x7d58 size 4:
    length_reload:
          (713,193) (713,194) (713,195) (714,193) (714,195) (715,193) ...:  0x3d
          x714 y=194:  0x0
```

Each entry is diffed one part at a time, which is the point: many symbols carry one
by-design per-position word (a row or column index) next to real config words, and
diffed whole that one varying word hides the entire entry. `--whole` gives the
compact per-entry view instead.

The five `ce_<dst|s0|s1>_*_dsr` views are one physical register reinterpreted, so
`--reg` compares only the live view — otherwise one bad DSR reports five times, and
stale views get compared as if they were live.

### Reading the output

Only *interesting* differences are shown, which is what keeps the report short
enough to read:

- an entry identical on every PE is not a difference, so it never appears;
- `--max-distinct N` (default 2) hides entries with more than N distinct values —
  all-different is per-PE data, not an anomaly. `--max-distinct 0` lifts the limit;
- by default only a **lone-PE outlier** is shown. A whole-column or whole-row split
  is per-position config, i.e. by design. `--all-splits` shows those too.

Two things to get right:

- **Centre the box on the suspect.** For radius `r` around `(sx,sy)` pass
  `x=sx-r, y=sy-r, w=h=2r+1`. Anchoring at the suspect only sees the peers below
  and to the right and misses the ones above and left, where an upstream producer
  usually sits. A bare `x,y` already does this — it means the 3x3 around that PE.
- **Never compare across chiefs.** Chiefs are pipeline stages programmed
  differently, so the same `(x,y)` on another chief is not a like-for-like peer.
  Everything compared comes from the one chief in `GSV_URL`.

Caveats: at least 3 PEs are needed before "lone outlier" means anything (with 2 it
is 1-vs-1 and everything looks like an outlier); `cmp` warns but still runs, since a
straight 2-PE diff is sometimes what you want. Same-kernel PEs legitimately hold
different per-PE *data* — each PE's own partial sum, index, state — so a difference
on a compute buffer is a lead, not a fault. Leave `--match` off the first run: the
report already self-filters to anomalies, and a regex on top pre-excludes every
name you did not think of.

Some register families are per-PE by design and show up as lone outliers every time
— `ce_oq_mem`, the output-queue FIFO slots, whose per-slot `ctrl` bit marks where
each PE's queue pointer happens to sit. Nothing is hidden by default, because which
families are noise depends on the workload; drop them once you have judged them:

```sh
gsv cmp 381,624 --reg --exclude 'ce_oq_mem|ce_icache_tags'
```

### Cost

`--sym` is heavy on the server (the aggregate all-symbols read is tens of seconds
per band), so `cmp` raises the read timeout to 300s unless `GSV_TIMEOUT` is set.
`--sram` is heavier still: 32768 addresses per PE.

`--cache DIR` keeps the raw dumps and reuses a complete one, which makes re-runs
free and works with no network at all; `--refresh` re-fetches. The cache key includes
the chief, so two jobs with the same rect never read each other's dump. A band that
keeps failing is split to isolate the culprit PE, and a PE whose aggregate symbol
read still fails — a known server bug that hits some PEs even for a 1x1 rect — falls
back to fetching its symbols one at a time.

## Running ws_debug on the same artifacts

The paths the backend reads are already in the URL. `gsv path` unpacks them:

```sh
gsv path            # host, artifact dir, chief dir, and the files under it
gsv path dfd        # one bare path, for substitution
```

`dfd` is `<chief>/dataless_ckpt.pb`, the dataless fabric dump the `dfd` endpoint
reads — so `ws_debug read --dfd` sees the same register state as `gsv rd --reg`:

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

`gsv rd <pe> --reg` dumps what a PE has, but to look up a name before reading it,
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
gsv rd 381,624 --reg ce_dst_dsr        # generic decode of 0x7ec0
gsv rd 381,624 --reg ce_dst_fab_dsr    # same bits, fabric-DSR field names
```

Why it exists: the directory query field differs per endpoint
(`workDirectory` vs `chiefDirectory`) and getting it wrong returns a Python
traceback; the register endpoint takes one register per request and silently
returns `[]` for a comma-separated list. `gsv` handles both.

Requires Python 3 and `requests`.
