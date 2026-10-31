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
  (the cap is not a measured duplicate ratio).

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
and alternate runs. Preserve each JSONL sample, command, source/binary hashes
and profiles. Variation reached 5% in the old single-path fixture; establish
the new fixture's variation instead of assuming the same bound.

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
