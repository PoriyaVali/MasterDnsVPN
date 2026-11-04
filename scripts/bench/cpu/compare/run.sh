#!/bin/bash
# Compare server builds in fresh, identical containers: one image, one CPU set
# and memory limit, the node pinned to its own cores, and the client, relays
# and driver on the others. Every scenario runs once per build per round, and
# the order of the builds rotates each round, so drift does not favour one.
#
#   run.sh OUT ROUNDS NAME=DIR [NAME=DIR...]
#
# DIR holds `node`, `client` and `drv` built as in ../../README.md. Results go
# to OUT/results.jsonl, one line per run labelled NAME/SCENARIO, and each run's
# output to OUT/logs. Compare two builds with analyze.py. Needs Docker; the
# image needs taskset (util-linux).
set -u
out=$(mkdir -p "$1" && cd "$1" && pwd)
rounds=$2
shift 2
IMG=${IMG:-debian:bookworm-slim}
CPUSET=${CPUSET:-0-3}
NODE_CPUS=${NODE_CPUS:-2,3}
CLIENT_CPUS=${CLIENT_CPUS:-0,1}
MEMORY=${MEMORY:-2g}

declare -A scenario=(
  [bulk]="-clients 1 -phases download,upload -size 4194304 -streams 2"
  [bulk1c]="-clients 1 -phases download,upload -size 4194304 -streams 2 -srvenv NODE_CPUS=${NODE_CPUS##*,}"
  [multi]="-clients 6 -phases download,upload -size 1048576 -streams 2"
  [weak]="-clients 1 -delay 40 -jitter 20 -loss 0.02 -phases download,upload,rtt,connect -size 1048576 -streams 2 -rounds 30 -conns 10"
  [latency]="-clients 1 -phases rtt,connect -rounds 60 -conns 60"
  [idle]="-clients 10 -phases idle -idle 20"
)
order=${SCENARIOS:-"bulk bulk1c multi weak latency idle"}

names=()
mkdir -p "$out/logs" "$out/wrap"
for spec in "$@"; do
  name=${spec%%=*}
  dir=$(cd "${spec#*=}" && pwd)
  for f in node client drv; do
    [ -x "$dir/$f" ] || { echo "$dir/$f is missing" >&2; exit 2; }
  done
  # The driver starts /b/node and /b/client; these pin them before exec, so
  # the process the driver measures is the binary itself.
  w=$out/wrap/$name
  mkdir -p "$w"
  printf '#!/bin/sh\nexec taskset -c "${NODE_CPUS:-%s}" /real/node "$@"\n' "$NODE_CPUS" > "$w/node"
  printf '#!/bin/sh\nexec taskset -c %s /real/client "$@"\n' "$CLIENT_CPUS" > "$w/client"
  chmod +x "$w/node" "$w/client"
  eval "dir_$name=\$dir"
  names+=("$name")
done

for round in $(seq 1 "$rounds"); do
  k=$(( (round - 1) % ${#names[@]} ))
  turn=("${names[@]:$k}" "${names[@]:0:$k}")
  for sc in $order; do
    for name in "${turn[@]}"; do
      eval "dir=\$dir_$name"
      start=$(date +%s)
      timeout 900 docker run --rm --network none --cpuset-cpus "$CPUSET" --memory "$MEMORY" --memory-swap "$MEMORY" \
        -v "$dir":/real:ro -v "$out/wrap/$name":/b:ro -v "$out":/out "$IMG" \
        taskset -c "$CLIENT_CPUS" /real/drv -bin /b ${scenario[$sc]} -label "$name/$sc" -json /out/results.jsonl \
        > "$out/logs/$sc-$name-$round.log" 2>&1
      rc=$?
      echo "round $round $sc $name: exit $rc in $(( $(date +%s) - start ))s"
    done
  done
done
