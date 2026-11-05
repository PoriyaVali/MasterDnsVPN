# MasterDnsVPN Benchmark Suite

This directory contains the core benchmarking tools for MasterDnsVPN, now enhanced with high-precision timing and standalone tool capabilities inspired by the `slipstream-rust` methodology.

## Tools

### 1. `bench.go` (Go-based Orchestrator and Benchmarker)

The primary tool for end-to-end performance testing. It builds the server and client, orchestrates a local tunnel, and measures throughput using **First-Byte Timing**.

#### High-Precision Timing
Unlike simple timers, `bench.go` starts its measurement only when the **first byte** of the actual payload is sent or received. This ensures that connection establishment and handshake overheads do not skew the results, providing a true measure of tunnel throughput.

#### Usage (Full Orchestration)

To run a standard end-to-end benchmark through the MasterDnsVPN tunnel:

```bash
go run scripts/bench/bench.go -runs 3 -bytes 10485760
```

#### CLI Options
| Flag | Description | Default |
|------|-------------|---------|
| `-runs` | Number of runs for each direction | 3 |
| `-bytes` | Total payload size in bytes | 10MiB |
| `-force-build` | Rebuild server and client binaries | true |
| `-client-port` | Port for the local client listener | 18080 |
| `-server-port` | Port for the UDP server listener | 5300 |

---

### 2. Standalone Mode (Tool Mode)

`bench.go` can also be used as a standalone source/sink tool, similar to `tcp_bench.py`. This is useful for testing manual configurations or other TCP links.

#### Modes
- `sink`: Listens for a connection and discards received data (sends "OK" at the end).
- `source`: Listens for a connection and sends data.
- `send`: Connects to a target and sends data (waits for "OK" at the end).
- `recv`: Connects to a target and receives data.

#### Examples

**Start a sink server (receiver):**
```bash
go run scripts/bench/bench.go -mode sink -addr :9090
```

**Run a sender (client):**
```bash
go run scripts/bench/bench.go -mode send -addr 127.0.0.1:9090 -bytes 100000000
```

**JSON Output:**
To get raw data for analysis:
```bash
go run scripts/bench/bench.go -mode send -addr 127.0.0.1:9090 -json
```

---

### 3. `cpu/` (Server CPU per byte, Linux)

Measures the server's CPU time for each MiB it carries, with the real client in
the Android app's "balanced" profile (upload MTU 150, download MTU 512, packet
duplication 3) talking through simulated resolvers.

- `cpu/node` runs the server the way V2bX embeds it (`server.New`, ChaCha20) in
  its own process. SIGUSR1 starts a CPU profile, and SIGUSR2 stops it and writes
  the allocation profile beside it.
- `cpu/drv` runs that node and the client as separate processes and reads the
  node's CPU time from `/proc`. The resolvers (with delay, jitter and loss), the
  SOCKS5 egress and the target application run inside the driver. Every byte is
  checked.
- Every relay uses a distinct loopback IP. The driver checks the production
  resolver parser's retained count and every client's MTU-valid path summary,
  then requires traffic in both directions on every relay during byte-verified
  warmup. Client INFO logging is required for that startup check.
- The original CPU results used different ports on a single IP, so production
  IP deduplication reduced them to one path and one effective copy. Those
  results do not establish four-path performance; rerun both binaries with the
  corrected driver before drawing multipath conclusions.

```bash
mkdir -p .bench/cpu/bin
go build -o .bench/cpu/bin/node ./scripts/bench/cpu/node
go build -o .bench/cpu/bin/client ./cmd/client
go run ./scripts/bench/cpu/drv -phases idle,download,upload,rtt,connect
```

It reports, for each phase:

- wall time;
- node and client CPU;
- throughput;
- node CPU per MiB and per packet;
- latency percentiles;
- errors and corrupted transfers;
- per-path query/answer counts, configured duplication and its active-path cap
  (the cap is not a measured duplicate ratio);
- the node's peak RSS during the phase (VmHWM, reset through
  `/proc/PID/clear_refs` when the phase starts) and its RSS at the end, its
  thread count, and its voluntary and involuntary context switches summed over
  all of its threads; the clients' largest peak RSS and their summed RSS;
- with `-json`, every RTT and connect sample (`latency_ms`). Connect times are
  bimodal, answered either on a query already waiting at the node or on the
  client's next ping about 100 ms later, so a median of them flips between the
  two from run to run.

Any transfer error, corrupted/incomplete transfer, unexpected byte total, or
missing RTT/connection sample makes the driver exit nonzero after stopping its
child processes. With `-json`, completed phases and `valid=false` are saved
before that exit. Warmup/configuration failures abort before measurement.
Unreadable or malformed `/proc` CPU counters also abort; a missing CPU
measurement is never reported as zero CPU. Legitimate zero tick counts remain valid.

Useful flags:

- `-clients N` runs N users at once.
- `-srvenv GOMAXPROCS=1` limits only the node to one core, as on a small VPS.
- `-profile PREFIX` writes one CPU profile per phase.
- `-json FILE` appends the results as JSON.

To compare two builds, build each into its own directory, pass it with `-bin`,
and alternate runs. `cpu/compare/run.sh` does this in fresh, identical
containers (one image, CPU set and memory limit; the node pinned to its own
cores, the client, relays and driver to the others), over six scenarios: bulk
transfer, bulk transfer on a one-core node, six clients at once, a weak path
(40 ms, 20 ms jitter, 2% loss), latency, and ten idle clients. The order of the
builds rotates every round. `cpu/compare/analyze.py` then compares two of them
metric by metric, with each build's mean and spread and a permutation p-value:

```bash
root=$PWD
git worktree add .bench/cmp/src-old android-multiuser-20261023-2
cp -r scripts/bench/cpu .bench/cmp/src-old/scripts/bench/  # an older tree may lack this harness
for v in old new; do
  src=$root; [ $v = old ] && src=$root/.bench/cmp/src-old
  out=$root/.bench/cmp/$v; mkdir -p $out
  (cd $src && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $out/node ./scripts/bench/cpu/node &&
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $out/client ./cmd/client)
  CGO_ENABLED=0 go build -o $out/drv ./scripts/bench/cpu/drv  # one driver for both
done
scripts/bench/cpu/compare/run.sh .bench/cmp/out 6 old=.bench/cmp/old new=.bench/cmp/new
scripts/bench/cpu/compare/analyze.py .bench/cmp/out/results.jsonl old new
```

A release's own `mdns-linux-amd64` can stand in for `client`.

It needs Docker, four CPUs by default (`CPUSET`, `NODE_CPUS`, `CLIENT_CPUS`
change that) and an image with `taskset` (`IMG`, default
`debian:bookworm-slim`). Build every `node` and `client` with the same Go
release and flags, so the comparison is of the source and not the toolchain.

Preserve each JSONL sample, command, source/binary hashes
and profiles. Variation reached 5% in the old single-path fixture. In the
four-path fixture, node CPU per MiB varied 5-12% between runs with one client
and about 40% with six clients uploading; peak RSS varied under 5% in most
phases and up to 16% in upload phases. Plan on six rounds or more.

The fixture/phase validation helpers can also be tested on a non-Linux host:

```bash
go test -tags=benchcheck ./scripts/bench/cpu/drv
```

The actual CPU driver and its `/proc` measurements still require Linux.

## Directory Structure

- `.bench/local_snapshot_go/bin`: Compiled benchmark binaries.
- `.bench/local_snapshot_go/runtime`: Temporary configuration and log files.

## Methodology

1. **First-Byte Start**: The timer starts on the first successful `Read` or `Write` of the payload.
2. **ACK Synchronization**: For "Exfil" scenarios, the sink sends an "OK" acknowledgment to ensure all data has cleared the tunnel before the timer stops.
3. **Monotonic Timing**: Uses Go's monotonic clock for sub-millisecond precision.
