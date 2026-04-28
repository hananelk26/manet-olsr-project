#!/usr/bin/env bash
#
# multi-seed-eval-highway.sh
#
# Same as multi-seed-eval.sh but runs olsr-watchdog-eval-highway instead.
# The highway variant uses a 1000x200m corridor shape (matching the original
# Baiad et al. paper) instead of the default 1000x1000m square. This gives
# every pair of nodes plenty of route redundancy, so isolating one bridge
# does not partition the network.
#
# Usage:  ./multi-seed-eval-highway.sh
#
# Output: results/multi-seed-highway.csv
#         results/seed-N-highway.log

set -euo pipefail

SEEDS=(1 10 20 30 40 50 100)
ATTACKERS="5,15,25,35"   # 4 attackers spread along the highway (8% of nodes)
SPOOF_COUNT=10           # Each attacker fakes 10 phantom neighbors in HELLO
NUM_NODES=50
OUT_DIR="results"
CSV_FILE="$OUT_DIR/multi-seed-highway-strong.csv"

mkdir -p "$OUT_DIR"
rm -f "$CSV_FILE"

echo "==> Building once..."
./ns3 build scratch/olsr-watchdog-eval-highway >/dev/null 2>&1 || true

echo "==> Plan: ${#SEEDS[@]} seeds, sequential (HIGHWAY topology)"
echo

for seed in "${SEEDS[@]}"; do
    echo "==> Running seed $seed..."
    start=$(date +%s)

    if ./ns3 run "scratch/olsr-watchdog-eval-highway \
            --numNodes=$NUM_NODES \
            --seed=$seed \
            --maliciousNodes=$ATTACKERS \
            --spoofCount=$SPOOF_COUNT \
            --csvFile=$CSV_FILE" \
            > "$OUT_DIR/seed-${seed}-highway-strong.log" 2>&1; then
        end=$(date +%s)
        printf "    [seed %d] OK  in %ds\n" "$seed" "$((end - start))"
    else
        printf "    [seed %d] FAILED  (see %s)\n" \
               "$seed" "$OUT_DIR/seed-${seed}-highway.log" >&2
    fi
done

echo
echo "==> SUMMARY: PDR (%) per phase, per seed (HIGHWAY)"
echo

python3 - "$CSV_FILE" <<'PYEOF'
import csv
import sys
from collections import defaultdict

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

print()
collapses = sum(1 for s in seeds
                if "Attack + Defense" in data[s]
                and data[s]["Attack + Defense"]["tx"] < 500)
print(f"==> 'Tx collapse' (Tx < 500 in defense_vs_attack):  "
      f"{collapses} / {len(seeds)} seeds")
PYEOF

echo
echo "==> Done. Raw CSV: $CSV_FILE"