#!/usr/bin/env bash
#
# multi-seed-eval.sh
#
# Runs olsr-watchdog-eval on N seeds with the same attacker configuration.
# The same malicious node IDs (7,23) are used in every run, but because each
# seed produces a different random placement, the attackers occupy different
# physical positions in the topology. This lets us see whether the result
# we observed (Tx collapse during defense_vs_attack) is a property of the
# defense or an accident of one specific placement.
#
# Usage:  ./multi-seed-eval.sh
#
# Output: results/multi-seed.csv (one row per seed per phase).
#         The simulation appends to this file across runs.

set -euo pipefail

SEEDS=(1 10 20 30 40 50 100)
ATTACKERS="7,23"
NUM_NODES=50
OUT_DIR="results"
CSV_FILE="$OUT_DIR/multi-seed.csv"

mkdir -p "$OUT_DIR"
rm -f "$CSV_FILE"   # start with a clean CSV

echo "==> Building once..."
./ns3 build scratch/olsr-watchdog-eval >/dev/null 2>&1 || true

echo "==> Plan: ${#SEEDS[@]} seeds, sequential"
echo

for seed in "${SEEDS[@]}"; do
    echo "==> Running seed $seed..."
    start=$(date +%s)

    if ./ns3 run "scratch/olsr-watchdog-eval \
            --numNodes=$NUM_NODES \
            --seed=$seed \
            --maliciousNodes=$ATTACKERS \
            --csvFile=$CSV_FILE" \
            > "$OUT_DIR/seed-${seed}.log" 2>&1; then
        end=$(date +%s)
        printf "    [seed %d] OK  in %ds\n" "$seed" "$((end - start))"
    else
        printf "    [seed %d] FAILED  (see %s)\n" "$seed" "$OUT_DIR/seed-${seed}.log" >&2
    fi
done

echo
echo "==> SUMMARY: PDR (%) per phase, per seed"
echo

python3 - "$CSV_FILE" <<'PYEOF'
import csv
import sys
from collections import defaultdict

# Group rows by seed -> phase -> stats.
seeds = []
data = defaultdict(dict)
with open(sys.argv[1]) as f:
    reader = csv.DictReader(f)
    for row in reader:
        seed = int(row["seed_used"])
        phase = row["phase_name"]
        if seed not in seeds:
            seeds.append(seed)
        data[seed][phase] = {
            "tx": int(row["tx_packets"]),
            "rx": int(row["rx_packets"]),
            "pdr": float(row["pdr_percent"]),
            "thr": float(row["throughput_mbps"]),
        }

# Print per-seed table
phases = ["Baseline", "Attack only", "Defense only", "Attack + Defense"]
header_phases = "  ".join(f"{p:>20}" for p in phases)
print(f"{'Seed':>5}  {header_phases}")
print("-" * (5 + 2 + (22 * len(phases))))

for seed in seeds:
    row_str = f"{seed:>5}  "
    for ph in phases:
        if ph in data[seed]:
            d = data[seed][ph]
            cell = f"PDR={d['pdr']:5.1f}% Tx={d['tx']:>4}"
            row_str += f"{cell:>22}"
        else:
            row_str += f"{'(missing)':>22}"
    print(row_str)

# Compute aggregate stats
print()
print("==> AGGREGATE: mean / stdev across seeds")
print()

import statistics
print(f"{'Phase':<22} {'PDR mean':>10} {'PDR std':>10} "
      f"{'Tx mean':>10} {'Tx std':>10}")
print("-" * 65)

for ph in phases:
    pdrs = [data[s][ph]["pdr"] for s in seeds if ph in data[s]]
    txs = [data[s][ph]["tx"] for s in seeds if ph in data[s]]
    if not pdrs:
        continue
    pdr_mean = statistics.mean(pdrs)
    pdr_std = statistics.stdev(pdrs) if len(pdrs) > 1 else 0.0
    tx_mean = statistics.mean(txs)
    tx_std = statistics.stdev(txs) if len(txs) > 1 else 0.0
    print(f"{ph:<22} {pdr_mean:>10.2f} {pdr_std:>10.2f} "
          f"{tx_mean:>10.0f} {tx_std:>10.0f}")

# Headline: did the Tx collapse happen consistently?
print()
collapses = sum(1 for s in seeds
                if "Attack + Defense" in data[s]
                and data[s]["Attack + Defense"]["tx"] < 500)
print(f"==> 'Tx collapse' (Tx < 500 in defense_vs_attack):  "
      f"{collapses} / {len(seeds)} seeds")
PYEOF

echo
echo "==> Done. Raw CSV: $CSV_FILE"