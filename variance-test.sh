#!/usr/bin/env bash
#
# variance-test.sh
#
# Runs the OLSR watchdog validation simulation N times with different RNG
# seeds, then aggregates the per-phase metrics into a summary table.
#
# Purpose: prove (or disprove) that the previously observed results are
# stable across random seeds, not a lucky outcome of a single run.
#
# Usage:
#     ./variance-test.sh                  # default: 10 runs, 4 in parallel
#     ./variance-test.sh -n 20            # 20 runs
#     ./variance-test.sh -n 10 -j 1       # serialized (one at a time)
#     ./variance-test.sh -n 5 -j 2 -o /tmp/results
#
# Output:
#     results/run-N.csv      per-run raw output (one per seed)
#     results/all-runs.csv   concatenated raw data
#     results/summary.txt    human-readable summary table
#

set -euo pipefail

# ----- Defaults -----
N_RUNS=10
N_PARALLEL=4
OUTPUT_DIR="results"
SCRATCH_NAME="olsr-watchdog-validation"

# ----- Parse args -----
usage() {
    grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -n 25
    exit 1
}

while getopts "n:j:o:s:h" opt; do
    case "$opt" in
        n) N_RUNS="$OPTARG" ;;
        j) N_PARALLEL="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        s) SCRATCH_NAME="$OPTARG" ;;
        h|*) usage ;;
    esac
done

# ----- Sanity checks -----
if ! command -v ./ns3 &>/dev/null; then
    echo "ERROR: ./ns3 not found. Run this script from the ns-3 root directory." >&2
    exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required for the aggregation step." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/run-*.csv "$OUTPUT_DIR"/all-runs.csv "$OUTPUT_DIR"/summary.txt

# Build once before launching parallel runs (avoids race conditions in cmake).
echo "==> Building once before runs..."
./ns3 build "$SCRATCH_NAME" >/dev/null 2>&1 || true

echo "==> Plan: $N_RUNS runs, up to $N_PARALLEL in parallel"
echo "==> Output: $OUTPUT_DIR/"
echo

# ----- Run one simulation with a given seed. Used by xargs. -----
run_one() {
    local seed="$1"
    local out_csv="$OUTPUT_DIR/run-${seed}.csv"
    local log="$OUTPUT_DIR/run-${seed}.log"

    local start
    start=$(date +%s)
    if ./ns3 run "scratch/${SCRATCH_NAME} --run=${seed} --csv=${out_csv}" \
            >"$log" 2>&1; then
        local end
        end=$(date +%s)
        printf "  [seed %2d] OK  in %ds\n" "$seed" "$((end - start))"
    else
        printf "  [seed %2d] FAILED  (see %s)\n" "$seed" "$log" >&2
        return 1
    fi
}
export -f run_one
export OUTPUT_DIR SCRATCH_NAME

# ----- Run all seeds (in parallel via xargs) -----
SECONDS=0
echo "==> Running simulations..."
seq 1 "$N_RUNS" | xargs -I{} -P "$N_PARALLEL" bash -c 'run_one "$@"' _ {}
echo
echo "==> All runs done in ${SECONDS}s"

# ----- Aggregate via python -----
python3 - "$OUTPUT_DIR" <<'PYEOF'
import csv
import os
import statistics
import sys
from collections import defaultdict

out_dir = sys.argv[1]

# 1. Find every per-run CSV.
files = sorted(
    f for f in os.listdir(out_dir)
    if f.startswith("run-") and f.endswith(".csv")
)
if not files:
    print("ERROR: no per-run CSVs found - did all simulations fail?")
    sys.exit(1)

# 2. Load and concatenate.
rows = []
header = None
for fname in files:
    seed = int(fname.replace("run-", "").replace(".csv", ""))
    with open(os.path.join(out_dir, fname)) as f:
        reader = csv.reader(f)
        rows_local = list(reader)
        if header is None:
            header = ["Seed"] + rows_local[0]
        for r in rows_local[1:]:
            rows.append([seed] + r)

# Save concatenated CSV.
all_csv_path = os.path.join(out_dir, "all-runs.csv")
with open(all_csv_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(header)
    w.writerows(rows)

# 3. Aggregate per phase.
# Columns from the simulation:
#   Phase, Tx, Rx, PDR_pct, AvgDelayMs, ThroughputKbps,
#   NodesDetectingAtk1, NodesDetectingAtk2, NodesDetectingAny,
#   NodesDetectingBoth, NodesWithFalsePositives, TotalFalsePositives,
#   Atk1FlaggedSomewhere, Atk2FlaggedSomewhere, BackupWronglyFlagged
#
# We aggregate the most relevant numerical ones.
metrics_to_agg = [
    "PDR_pct",
    "AvgDelayMs",
    "ThroughputKbps",
    "NodesDetectingAny",
    "NodesDetectingBoth",
    "TotalFalsePositives",
]

# group rows by phase
by_phase = defaultdict(list)
phase_col = header.index("Phase")
for r in rows:
    by_phase[r[phase_col]].append(r)

# Preserve phase order of first run.
first_seed_phases = []
for r in rows:
    if r[0] == rows[0][0] and r[phase_col] not in first_seed_phases:
        first_seed_phases.append(r[phase_col])

def get_floats(rs, col_name):
    idx = header.index(col_name)
    out = []
    for r in rs:
        try:
            out.append(float(r[idx]))
        except ValueError:
            pass
    return out

# 4. Print summary table.
summary_lines = []
def emit(s=""):
    print(s)
    summary_lines.append(s)

emit(f"==> VARIANCE SUMMARY OVER {len(files)} RUNS")
emit("")

# One block per phase, one row per metric.
for phase in first_seed_phases:
    emit(f"------- {phase} -------")
    emit(f"{'Metric':<22} {'Mean':>10} {'StdDev':>10} {'Min':>10} {'Max':>10}")
    rs = by_phase[phase]
    for m in metrics_to_agg:
        vals = get_floats(rs, m)
        if not vals:
            continue
        mean = statistics.mean(vals)
        stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
        emit(f"{m:<22} {mean:>10.2f} {stdev:>10.2f} "
             f"{min(vals):>10.2f} {max(vals):>10.2f}")
    emit("")

# Cross-phase headline: PDR delta defense_vs_attack vs attack_only.
emit("==> KEY INSIGHT: PDR recovery (defense_vs_attack - attack_only)")
pdr_idx = header.index("PDR_pct")
recoveries = []
for fname in files:
    seed = int(fname.replace("run-", "").replace(".csv", ""))
    seed_rows = [r for r in rows if r[0] == seed]
    pdr_atk = pdr_def_atk = None
    for r in seed_rows:
        if r[phase_col] == "attack_only":
            pdr_atk = float(r[pdr_idx])
        if r[phase_col] == "defense_vs_attack":
            pdr_def_atk = float(r[pdr_idx])
    if pdr_atk is not None and pdr_def_atk is not None:
        recoveries.append((seed, pdr_def_atk - pdr_atk))

if recoveries:
    deltas = [d for _, d in recoveries]
    emit(f"  Mean recovery:   {statistics.mean(deltas):.2f} percentage points")
    emit(f"  StdDev:          {statistics.stdev(deltas) if len(deltas)>1 else 0:.2f}")
    emit(f"  Min recovery:    {min(deltas):.2f}  (seed={min(recoveries, key=lambda x:x[1])[0]})")
    emit(f"  Max recovery:    {max(deltas):.2f}  (seed={max(recoveries, key=lambda x:x[1])[0]})")
    emit("")
    emit("  Per-seed:")
    for seed, d in sorted(recoveries):
        bar = "#" * max(1, int(d / 5))
        emit(f"    seed {seed:3d}:  {d:>6.2f}  {bar}")

# Save summary.
with open(os.path.join(out_dir, "summary.txt"), "w") as f:
    f.write("\n".join(summary_lines))
print()
print(f"==> Saved: {all_csv_path}")
print(f"==> Saved: {os.path.join(out_dir, 'summary.txt')}")
PYEOF

echo
echo "==> DONE"