#!/usr/bin/env python3
"""Compare two builds' runs from run.sh: analyze.py RESULTS.jsonl BASE CANDIDATE

For every scenario, phase and metric: each build's mean and standard deviation
over its runs, the change, and a two-sided permutation p-value for the
difference of the means (exact over every split of the pooled runs while there
are at most 200000 splits, else 20000 random ones). A change is called better
or worse only at p < 0.05; anything else is noise at this number of runs.

Connect times are bimodal: answered on a query already waiting at the node, or
on the client's next ping about 100 ms later. A median flips between the two
from run to run, so connects are also compared by each run's share of fast
connects and its mean, from every sample.
"""
import itertools
import json
import math
import random
import statistics as st
import sys
from collections import defaultdict

MIB = 1 << 20
FAST_CONNECT_MS = 80.0


def metrics(ph):
    """Each metric as (value, direction): +1 if higher is better, -1 if lower is."""
    m = {}
    if ph.get("bytes"):
        mib = ph["bytes"] / MIB
        m["throughput MiB/s"] = (ph["mib_per_s"], +1)
        m["node CPU ms/MiB"] = (ph["node_cpu_s"] * 1000 / mib, -1)
        m["client CPU ms/MiB"] = (ph["client_cpu_s"] * 1000 / mib, -1)
        m["node ctx switches/MiB"] = ((ph.get("node_ctx_voluntary", 0) + ph.get("node_ctx_involuntary", 0)) / mib, -1)
        m["packets/MiB"] = (ph["packets_up"] / mib, -1)
    if ph.get("p50_ms"):
        m["p50 ms"] = (ph["p50_ms"], -1)
        m["p95 ms"] = (ph["p95_ms"], -1)
    lat = ph.get("latency_ms")
    if lat:
        m["mean ms"] = (st.mean(lat), -1)
        if ph["phase"] == "connect":
            m["fast connects %"] = (100 * sum(v < FAST_CONNECT_MS for v in lat) / len(lat), +1)
    if ph["phase"] == "idle":
        m["node CPU %"] = (100 * ph["node_cpu_s"] / ph["wall_s"], -1)
        m["client CPU % (sum)"] = (100 * ph["client_cpu_s"] / ph["wall_s"], -1)
    if "node_rss_peak_kb" in ph:
        m["node peak RSS MiB"] = (ph["node_rss_peak_kb"] / 1024, -1)
        m["client peak RSS MiB"] = (ph["client_rss_peak_kb_max"] / 1024, -1)
    return m


def permutation_p(a, b, limit=200000, samples=20000):
    pooled = a + b
    observed = abs(st.mean(a) - st.mean(b)) - 1e-12
    n = len(a)

    def split_diff(chosen):
        x = [pooled[i] for i in chosen]
        y = [pooled[i] for i in range(len(pooled)) if i not in chosen]
        return abs(st.mean(x) - st.mean(y))

    if math.comb(len(pooled), n) <= limit:
        splits = [set(c) for c in itertools.combinations(range(len(pooled)), n)]
    else:
        rng = random.Random(1)
        splits = [set(rng.sample(range(len(pooled)), n)) for _ in range(samples)]
    return sum(split_diff(s) >= observed for s in splits) / len(splits)


def main(path, base, cand):
    data = defaultdict(lambda: defaultdict(list))
    invalid = []
    for line in open(path):
        run = json.loads(line)
        build, scenario = run["label"].split("/", 1)
        if not run.get("valid", False):
            invalid.append((run["label"], run.get("validation_errors")))
            continue
        for ph in run["results"]:
            for name, (value, direction) in metrics(ph).items():
                data[(scenario, ph["phase"], name, direction)][build].append(value)
    order = ["bulk", "bulk1c", "multi", "weak", "latency", "idle"]
    print(f"{'scenario/phase':<18}{'metric':<23}{base:>17}{cand:>17}{'change':>9}{'p':>7}  verdict")
    for key in sorted(data, key=lambda k: (order.index(k[0]) if k[0] in order else len(order), k[0], k[1], k[2])):
        scenario, phase, name, direction = key
        a, b = data[key].get(base, []), data[key].get(cand, [])
        if len(a) < 2 or len(b) < 2:
            continue
        ma, mb = st.mean(a), st.mean(b)
        change = (mb - ma) / ma * 100 if ma else 0.0
        p = permutation_p(a, b)
        verdict = ("better" if (mb - ma) * direction > 0 else "WORSE") if p < 0.05 else "same within noise"
        print(f"{scenario + '/' + phase:<18}{name:<23}{ma:>10.2f} ±{st.stdev(a):>5.2f}{mb:>10.2f} ±{st.stdev(b):>5.2f}"
              f"{change:>+8.1f}%{p:>7.3f}  {verdict} (n={len(a)}/{len(b)})")
    if invalid:
        print("\nInvalid runs, left out:")
        for label, errors in invalid:
            print(" ", label, errors)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:4])
