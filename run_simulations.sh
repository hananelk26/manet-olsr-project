#!/bin/bash
# =============================================================================
# run_simulations.sh
#   Resumable, parallel batch runner for the OLSR defense-evaluation harnesses
#   (FPNT / Watchdog / DCFM). Select a defense with --defense or --scratch.
#   POST-AUDIT REWRITE (Phase 2).
# =============================================================================
#
# CHANGELOG (Phase 2):
#   RUN-001: default = append+resume; --fresh opt-in for destructive wipe.
#   RUN-002: seed ledger in $OUT_DIR/.runstate/seeds.ledger.
#   RUN-003: --calibrate [N] pre-flight; auto-sets MAX_ATTEMPTS.
#   RUN-004: cooperates with harness staging (harness does atomic promotion;
#            runner does NOT touch CSVs except for header-check and final
#            summary).
#   RUN-005: state in $OUT_DIR/.runstate/ (persistent, no trap-rm).
#   RUN-006: header version check on startup.
#   RUN-007: pre-flight smoke run; abort on bad rc.
#   RUN-008: PDR summary reads windows_oracle.csv.
#   RUN-009: dead `export -f run_one` and `export HARNESS_ARGS` removed.
#            Worker parallelism relies on subshell inheritance + flock.
#   RUN-010: progress reporting every 50 attempts.
#   RUN-011: documented overshoot (up to JOBS-1 bonus accepted runs).
#   RUN-012: per-run JSON sidecars removed (runs.csv replaces them).
#
# CHANGELOG (Phase 3):
#   WIN-001: --random-window-order forwards --randomWindowOrder=1 to the
#            harness (shuffles the 4 measurement windows, seeded by --run).
#   WIN-004: --mixed-fraction F turns this script into an ORCHESTRATOR that
#            splits the target into a canonical-order batch and a
#            randomized-order batch, each in its own nested output dir
#            ($OUT_DIR/normal and $OUT_DIR/mixed), with disjoint seed ranges
#            for statistical independence. Each batch is run by re-invoking
#            this same script in single-mode (mixed-fraction = 0), so the
#            existing single-mode logic is reused unchanged.
#
# Requires bash >= 4.3 (wait -n, associative arrays).
# =============================================================================

set -u
shopt -s nullglob

# --- bash version guard -----------------------------------------------------
if [[ -z "${BASH_VERSINFO:-}" \
      || ${BASH_VERSINFO[0]} -lt 4 \
      || ( ${BASH_VERSINFO[0]} -eq 4 && ${BASH_VERSINFO[1]} -lt 3 ) ]]; then
  echo "ERROR: requires bash >= 4.3 (wait -n, associative arrays)." >&2
  exit 1
fi

# --- usage ------------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: ./run_simulations.sh -n NUM_ACCEPTED [options]

Required:
  -n, --num-accepted N        Target number of accepted runs.

Optional:
  -j, --jobs J                Parallel workers (default: 1).
  -o, --output-dir DIR        Output directory (default: ./simulations/features).
      --ns3-dir DIR           Path to ns-3-dev root (default: ./).
      --defense NAME          Convenience selector for the defense harness:
                              one of {fpnt, watchdog, dcfm}. Maps to the
                              matching scratch program. Mutually exclusive
                              with --scratch (unless they agree).
      --scratch NAME          Scratch program name (default: olsr-fpnt-eval-mitigation).
                              Use this to point at a non-standard binary;
                              otherwise prefer --defense.
      --start-seed S          Starting seed (default: 1).
      --max-attempts M        Hard cap on attempts (default: auto from --calibrate or 5x target).
      --calibrate [N]         Pre-flight N attempts (default 200 if no arg) to measure yield.
                              Auto-sets --max-attempts = ceil(N_TARGET / yield * 1.3).
      --fresh                 DESTRUCTIVE: wipe runstate + all CSVs before running.
      --skip-smoke            Skip the pre-flight smoke run (NOT RECOMMENDED).
      --extra "ARGS"          Extra args to forward to the harness (e.g. "--bMobility=true").
      --random-window-order   Randomize the 4 measurement windows per run
                              (forwards --randomWindowOrder=1; permutation
                              seeded by each run's seed).
      --mixed-fraction F      ORCHESTRATOR mode: split the target so a
                              fraction F (0<F<1) of runs use randomized window
                              order and the rest use canonical order. Writes
                              to $OUT_DIR/normal and $OUT_DIR/mixed. E.g.
                              -n 10000 --mixed-fraction 0.2 => 8000 normal +
                              2000 mixed.
      --mixed-seed-offset N   Seed offset added to the mixed batch's start
                              seed so the two batches use disjoint seed ranges
                              (default: 100000000).
  -h, --help                  This message.

Defaults match the audit plan; nothing else needs to be configured.

ENVIRONMENT NOTE on parallel overshoot:
  Workers may produce up to JOBS-1 additional accepted runs after the target
  is reached (because each worker is mid-simulation when the loop stops).
  These extra runs are kept; treat them as bonus data. The runner exits as
  soon as the ledger shows >= N_TARGET accepted entries.

OUTPUT LAYOUT (single-mode):
  $OUT_DIR/
    runs.csv              one row per accepted run (config/metadata)
    windows_features.csv  ML X-matrix (observable features only)
    windows_labels.csv    ML y-vector
    windows_oracle.csv    ground truth / leaky diagnostics (forbidden as ML input)
    probe.csv             per-attempt topology probe
    logs/seed_NNNNN.log   per-attempt simulator stdout/stderr
    .runstate/
      seeds.ledger        <seed>\t<status>\t<reason>\t<timestamp>
      accepted, rejected, errors   counters
      attempts.tsv        full attempt log
      calibration.json    measured yield (if --calibrate run)
      smoke.ok            marker that pre-flight smoke succeeded

OUTPUT LAYOUT (--mixed-fraction > 0, ORCHESTRATOR mode):
  $OUT_DIR/
    normal/   <full single-mode layout above; canonical window order>
    mixed/    <full single-mode layout above; randomized window order>
EOF
}

# --- defaults ---------------------------------------------------------------
N_TARGET=""
JOBS=1
OUT_DIR="./simulations/features"
NS3_DIR="./"
DEFENSE=""                            # GEN: --defense {fpnt|watchdog|dcfm} selector
SCRATCH="olsr-fpnt-eval-mitigation"   # default; overridden by --defense or --scratch
SCRATCH_EXPLICIT=0                     # set to 1 when --scratch is passed explicitly
START_SEED=1
MAX_ATTEMPTS=""
CALIBRATE_REQUESTED=0
CALIBRATE_N=200
FRESH=0
SKIP_SMOKE=0
EXTRA_ARGS=""
RANDOMIZE_WINDOWS=0          # WIN-001: forward --randomWindowOrder to harness
MIXED_FRACTION=0             # WIN-004: >0 => orchestrator split mode
MIXED_SEED_OFFSET=100000000  # WIN-004: disjoint seed range for mixed batch

# Absolute path to this script, for self-re-invocation in orchestrator mode.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# --- arg parsing ------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--num-accepted)   N_TARGET="$2"; shift 2 ;;
    -j|--jobs)           JOBS="$2"; shift 2 ;;
    -o|--output-dir)     OUT_DIR="$2"; shift 2 ;;
    --ns3-dir)           NS3_DIR="$2"; shift 2 ;;
    --scratch)           SCRATCH="$2"; SCRATCH_EXPLICIT=1; shift 2 ;;
    --defense)           DEFENSE="$2"; shift 2 ;;
    --start-seed)        START_SEED="$2"; shift 2 ;;
    --max-attempts)      MAX_ATTEMPTS="$2"; shift 2 ;;
    --calibrate)
      CALIBRATE_REQUESTED=1
      if [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]]; then CALIBRATE_N="$2"; shift 2
      else shift; fi ;;
    --fresh)             FRESH=1; shift ;;
    --skip-smoke)        SKIP_SMOKE=1; shift ;;
    --extra)             EXTRA_ARGS="$2"; shift 2 ;;
    --random-window-order) RANDOMIZE_WINDOWS=1; shift ;;
    --mixed-fraction)    MIXED_FRACTION="$2"; shift 2 ;;
    --mixed-seed-offset) MIXED_SEED_OFFSET="$2"; shift 2 ;;
    -h|--help)           usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$N_TARGET" ]]; then
  echo "ERROR: -n/--num-accepted is required." >&2; usage; exit 1
fi
if ! [[ "$N_TARGET" =~ ^[0-9]+$ && "$N_TARGET" -gt 0 ]]; then
  echo "ERROR: --num-accepted must be a positive integer." >&2; exit 1
fi
if ! [[ "$JOBS" =~ ^[0-9]+$ && "$JOBS" -gt 0 ]]; then
  echo "ERROR: --jobs must be a positive integer." >&2; exit 1
fi

# --- GEN: resolve --defense {fpnt|watchdog|dcfm} -> scratch program ----------
# --defense is a convenience selector mapping to the per-defense scratch binary.
# --scratch still works directly; passing both is an error unless they agree.
# Resolved here (before any orchestrator self-re-invocation) so child batches
# inherit the concrete --scratch.
if [[ -n "$DEFENSE" ]]; then
  case "$DEFENSE" in
    fpnt)     mapped="olsr-fpnt-eval-mitigation" ;;
    watchdog) mapped="olsr-watchdog-eval-mitigation" ;;
    dcfm)     mapped="olsr-dcfm-eval-mitigation" ;;
    *) echo "ERROR: --defense must be one of: fpnt, watchdog, dcfm." >&2; exit 1 ;;
  esac
  if [[ $SCRATCH_EXPLICIT -eq 1 && "$SCRATCH" != "$mapped" ]]; then
    echo "ERROR: --defense '$DEFENSE' implies --scratch '$mapped', but" >&2
    echo "       --scratch '$SCRATCH' was also given. Pass only one." >&2
    exit 1
  fi
  SCRATCH="$mapped"
fi

# Human-readable defense label (console/summary banners only), derived from the
# final scratch program name so it is correct whether set via --defense,
# --scratch, or the default.
case "$SCRATCH" in
  *fpnt*)     DEFENSE_LABEL="FPNT-OLSR" ;;
  *watchdog*) DEFENSE_LABEL="Watchdog-OLSR" ;;
  *dcfm*)     DEFENSE_LABEL="DCFM-OLSR" ;;
  *)          DEFENSE_LABEL="$SCRATCH" ;;
esac

# --- canonicalize paths -----------------------------------------------------
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
if [[ ! -d "$NS3_DIR" ]]; then
  echo "ERROR: --ns3-dir '$NS3_DIR' not found." >&2; exit 1
fi
NS3_DIR="$(cd "$NS3_DIR" && pwd)"
if [[ ! -x "$NS3_DIR/ns3" ]]; then
  echo "ERROR: '$NS3_DIR/ns3' is not executable (build ns-3 first)." >&2; exit 1
fi

# --- validate the new Phase-3 flags ----------------------------------------
if ! [[ "$MIXED_FRACTION" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "ERROR: --mixed-fraction must be a number in [0,1) (e.g. 0.2)." >&2; exit 1
fi
if ! awk -v f="$MIXED_FRACTION" 'BEGIN{exit !(f>=0 && f<1)}'; then
  echo "ERROR: --mixed-fraction must be in [0,1)." >&2; exit 1
fi
if ! [[ "$MIXED_SEED_OFFSET" =~ ^[0-9]+$ ]]; then
  echo "ERROR: --mixed-seed-offset must be a non-negative integer." >&2; exit 1
fi

# --- WIN-004: orchestrator (mixed-fraction) mode ----------------------------
# When --mixed-fraction > 0 this invocation does NOT run simulations itself;
# it splits the target into a canonical-order batch and a randomized-order
# batch and re-invokes itself once per batch in single-mode. Disjoint seed
# ranges (via --mixed-seed-offset) keep the two batches independent.
if awk -v f="$MIXED_FRACTION" 'BEGIN{exit !(f>0)}'; then
  TARGET_MIXED=$(awk -v n="$N_TARGET" -v f="$MIXED_FRACTION" \
                 'BEGIN{printf "%d", n*f + 0.5}')
  TARGET_NORMAL=$(( N_TARGET - TARGET_MIXED ))
  if [[ $TARGET_NORMAL -lt 1 || $TARGET_MIXED -lt 1 ]]; then
    echo "ERROR: --mixed-fraction $MIXED_FRACTION with -n $N_TARGET yields" >&2
    echo "  normal=$TARGET_NORMAL mixed=$TARGET_MIXED; both must be >= 1." >&2
    exit 1
  fi

  NORMAL_DIR="$OUT_DIR/normal"
  MIXED_DIR="$OUT_DIR/mixed"

  # Handle --fresh ONCE here (single confirmation), then re-invoke children
  # WITHOUT --fresh so they don't prompt again.
  if [[ $FRESH -eq 1 ]]; then
    echo "======================================================================="
    echo "  --fresh (orchestrator): WIPING"
    echo "    $NORMAL_DIR"
    echo "    $MIXED_DIR"
    echo "======================================================================="
    read -r -p "Confirm by typing YES: " confirm
    if [[ "$confirm" != "YES" ]]; then echo "Aborted."; exit 1; fi
    rm -rf "$NORMAL_DIR" "$MIXED_DIR"
    echo "Wiped."
  fi

  # Common pass-through args (NOT -n, -o, --fresh, --start-seed,
  # --mixed-fraction, --random-window-order; those are set per child).
  PASS=( --ns3-dir "$NS3_DIR" --scratch "$SCRATCH" )
  [[ "$JOBS" != "1" ]]             && PASS+=( -j "$JOBS" )
  [[ -n "$MAX_ATTEMPTS" ]]         && PASS+=( --max-attempts "$MAX_ATTEMPTS" )
  [[ $CALIBRATE_REQUESTED -eq 1 ]] && PASS+=( --calibrate "$CALIBRATE_N" )
  [[ -n "$EXTRA_ARGS" ]]           && PASS+=( --extra "$EXTRA_ARGS" )

  echo "#######################################################################"
  echo "# ORCHESTRATOR (WIN-004)"
  echo "#   target            : $N_TARGET   (mixed-fraction=$MIXED_FRACTION)"
  echo "#   normal (canonical): $TARGET_NORMAL  -> $NORMAL_DIR"
  echo "#   mixed  (random)   : $TARGET_MIXED  -> $MIXED_DIR"
  echo "#   normal seed range : from $START_SEED"
  echo "#   mixed  seed range : from $(( START_SEED + MIXED_SEED_OFFSET ))"
  echo "#######################################################################"

  # (a) Canonical-order batch.
  bash "$SELF" -n "$TARGET_NORMAL" -o "$NORMAL_DIR" \
          --start-seed "$START_SEED" "${PASS[@]}"
  rc_normal=$?

  # (b) Randomized-order batch. Disjoint seed range; smoke skipped because the
  #     binary was already validated by the canonical batch's smoke run.
  bash "$SELF" -n "$TARGET_MIXED" -o "$MIXED_DIR" \
          --start-seed "$(( START_SEED + MIXED_SEED_OFFSET ))" \
          --random-window-order --skip-smoke "${PASS[@]}"
  rc_mixed=$?

  echo "#######################################################################"
  echo "# ORCHESTRATOR SUMMARY"
  echo "#   normal batch rc=$rc_normal   ($NORMAL_DIR)"
  echo "#   mixed  batch rc=$rc_mixed   ($MIXED_DIR)"
  echo "#   To combine for analysis: concatenate normal/ and mixed/ CSVs;"
  echo "#   the random_window_order column in runs.csv distinguishes them."
  echo "#######################################################################"

  if [[ $rc_normal -eq 0 && $rc_mixed -eq 0 ]]; then exit 0; else exit 1; fi
fi

# ===========================================================================
# SINGLE-MODE path (mixed-fraction == 0). Everything below runs exactly as
# before, with the only addition being the optional --randomWindowOrder
# pass-through wired into run_one (RWO_ARG).
# ===========================================================================
RWO_ARG=""
if [[ $RANDOMIZE_WINDOWS -eq 1 ]]; then RWO_ARG="--randomWindowOrder=true"; fi

# --- output paths -----------------------------------------------------------
RUNS_FILE="$OUT_DIR/runs.csv"
FEATURES_FILE="$OUT_DIR/windows_features.csv"
LABELS_FILE="$OUT_DIR/windows_labels.csv"
ORACLE_FILE="$OUT_DIR/windows_oracle.csv"
PROBE_FILE="$OUT_DIR/probe.csv"
DEFPARAMS_FILE="$OUT_DIR/defense_params.txt"   # GEN-004: provenance sidecar (not an ML input)
LOG_DIR="$OUT_DIR/logs"
RUNSTATE_DIR="$OUT_DIR/.runstate"
LEDGER="$RUNSTATE_DIR/seeds.ledger"
ATTEMPTS_TSV="$RUNSTATE_DIR/attempts.tsv"
COUNTER_ACC="$RUNSTATE_DIR/accepted"
COUNTER_REJ="$RUNSTATE_DIR/rejected"
COUNTER_ERR="$RUNSTATE_DIR/errors"
CALIB_JSON="$RUNSTATE_DIR/calibration.json"
SMOKE_OK="$RUNSTATE_DIR/smoke.ok"
RUNNER_CONFIG="$OUT_DIR/runner.config"
RUNNER_SUMMARY="$OUT_DIR/runner.summary"

# --- --fresh: destructive wipe ---------------------------------------------
if [[ $FRESH -eq 1 ]]; then
  echo "======================================================================="
  echo "  --fresh: WIPING $OUT_DIR"
  echo "  Targets: runs.csv, windows_features.csv, windows_labels.csv,"
  echo "           windows_oracle.csv, probe.csv, defense_params.txt,"
  echo "           .runstate/, .staging/"
  echo "======================================================================="
  read -r -p "Confirm by typing YES: " confirm
  if [[ "$confirm" != "YES" ]]; then
    echo "Aborted."; exit 1
  fi
  rm -rf "$RUNSTATE_DIR" "$OUT_DIR/.staging"
  rm -f  "$RUNS_FILE" "$FEATURES_FILE" "$LABELS_FILE" "$ORACLE_FILE" "$PROBE_FILE" "$DEFPARAMS_FILE"
  echo "Wiped. Resuming."
fi

mkdir -p "$LOG_DIR" "$RUNSTATE_DIR"

# --- helper: atomic counter increment via flock -----------------------------
incr_counter() {
  local file="$1"
  local fd
  exec {fd}>>"$file"
  flock -x "$fd"
  local cur=0
  [[ -s "$file" ]] && cur="$(<"$file")"
  cur=$((cur + 1))
  printf "%s" "$cur" > "$file"
  flock -u "$fd"
  exec {fd}>&-
  printf "%s" "$cur"
}

read_counter() {
  local file="$1"
  [[ -s "$file" ]] && cat "$file" || echo 0
}

# --- helper: ledger operations ---------------------------------------------
# Returns 0 if seed already attempted, 1 otherwise.
seed_in_ledger() {
  local seed="$1"
  [[ -s "$LEDGER" ]] || return 1
  # First column is seed; tab-separated.
  awk -v s="$seed" -F'\t' '$1==s {found=1; exit} END {exit !found}' "$LEDGER"
}

# Append: seed<TAB>status<TAB>reason<TAB>iso8601
ledger_append() {
  local seed="$1" status="$2" reason="$3"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local fd
  exec {fd}>>"$LEDGER"
  flock -x "$fd"
  printf "%s\t%s\t%s\t%s\n" "$seed" "$status" "$reason" "$ts" >> "$LEDGER"
  flock -u "$fd"
  exec {fd}>&-
}

# --- helper: read rejection reason from a log file --------------------------
extract_rejection_reason() {
  local logfile="$1"
  if grep -q "Run REJECTED:" "$logfile" 2>/dev/null; then
    grep "Run REJECTED:" "$logfile" | head -1 \
      | sed -E 's/.*Run REJECTED: ([a-z_]+).*/\1/'
  else
    echo ""
  fi
}

# --- header-version check (RUN-006) -----------------------------------------
# Compares headers in any existing CSVs against what the harness currently
# would emit. Aborts on mismatch.
verify_headers() {
  # Get current headers from the harness.
  local hdr_output
  if ! hdr_output="$(cd "$NS3_DIR" && ./ns3 run "$SCRATCH --emit-header" 2>/dev/null)"; then
    echo "ERROR: failed to run --emit-header; cannot verify schema." >&2
    echo "  Check that the scratch program builds: cd $NS3_DIR && ./ns3 build" >&2
    return 1
  fi
  local cur_runs cur_feat cur_lab cur_ora cur_ver
  cur_runs="$(grep '^RUNS_HEADER:'     <<<"$hdr_output" | sed 's/^RUNS_HEADER://')"
  cur_feat="$(grep '^FEATURES_HEADER:' <<<"$hdr_output" | sed 's/^FEATURES_HEADER://')"
  cur_lab="$( grep '^LABELS_HEADER:'   <<<"$hdr_output" | sed 's/^LABELS_HEADER://')"
  cur_ora="$( grep '^ORACLE_HEADER:'   <<<"$hdr_output" | sed 's/^ORACLE_HEADER://')"
  cur_ver="$( grep '^HEADER_VERSION:'  <<<"$hdr_output" | sed 's/^HEADER_VERSION://')"

  # Defensive: empty cur_* means --emit-header didn't produce expected output.
  if [[ -z "$cur_runs" || -z "$cur_feat" || -z "$cur_lab" || -z "$cur_ora" ]]; then
    echo "ERROR: --emit-header did not print all expected header lines." >&2
    echo "  Got:" >&2
    echo "$hdr_output" | sed 's/^/    /' >&2
    return 1
  fi

  local mismatch=0
  check_one() {
    local path="$1" expected="$2" name="$3"
    [[ -s "$path" ]] || return 0
    local existing
    existing="$(head -1 "$path")"
    if [[ "$existing" != "$expected" ]]; then
      echo "ERROR: header mismatch in $name ($path):" >&2
      echo "  Existing : $existing" >&2
      echo "  Expected : $expected" >&2
      mismatch=1
    fi
  }
  check_one "$RUNS_FILE"     "$cur_runs" "runs.csv"
  check_one "$FEATURES_FILE" "$cur_feat" "windows_features.csv"
  check_one "$LABELS_FILE"   "$cur_lab"  "windows_labels.csv"
  check_one "$ORACLE_FILE"   "$cur_ora"  "windows_oracle.csv"

  if [[ $mismatch -ne 0 ]]; then
    cat >&2 <<EOF

REMEDIATION:
  Existing CSVs were produced with a different schema than this harness
  build emits. To continue, either:
    (a) point --output-dir at a fresh directory, or
    (b) re-run with --fresh to wipe and start over.
EOF
    return 1
  fi
  echo "[verify_headers] OK. HEADER_VERSION=$cur_ver"
  return 0
}

# --- worker: run a single attempt ------------------------------------------
# Args: $1 = seed
# Returns: rc 0 = accepted, 2 = rejected, other = error.
# Updates ledger and counters atomically.
run_one() {
  local seed="$1"
  local logfile="$LOG_DIR/seed_$(printf '%05d' "$seed").log"

  # The harness writes to all four output files directly (with internal
  # flock for atomicity). We just pass paths and the seed.
  (cd "$NS3_DIR" && ./ns3 run "$SCRATCH \
      --run=$seed \
      --seed=1 \
      --runsFile=$RUNS_FILE \
      --featuresFile=$FEATURES_FILE \
      --labelsFile=$LABELS_FILE \
      --oracleFile=$ORACLE_FILE \
      --topologyProbeFile=$PROBE_FILE \
      --defenseParamsFile=$DEFPARAMS_FILE \
      --outputDir=$OUT_DIR \
      $EXTRA_ARGS $RWO_ARG" \
      ) >"$logfile" 2>&1
  local rc=$?
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf "%s\t%d\t%d\n" "$ts" "$seed" "$rc" >> "$ATTEMPTS_TSV"

  case $rc in
    0)
      ledger_append "$seed" "accepted" "ok"
      incr_counter "$COUNTER_ACC" >/dev/null
      ;;
    2)
      local reason
      reason="$(extract_rejection_reason "$logfile")"
      [[ -z "$reason" ]] && reason="rejected"
      ledger_append "$seed" "rejected" "$reason"
      incr_counter "$COUNTER_REJ" >/dev/null
      ;;
    *)
      ledger_append "$seed" "error" "rc=$rc"
      incr_counter "$COUNTER_ERR" >/dev/null
      ;;
  esac
  return $rc
}

# --- pre-flight smoke test (RUN-007) ---------------------------------------
preflight_smoke() {
  if [[ $SKIP_SMOKE -eq 1 ]]; then
    echo "[smoke] skipped by --skip-smoke"
    return 0
  fi
  if [[ -f "$SMOKE_OK" ]]; then
    echo "[smoke] previous run marker found; skipping"
    return 0
  fi
  local seed
  seed=$(( START_SEED ))
  # Pick the smallest unattempted seed to avoid double-attempting.
  while seed_in_ledger "$seed"; do
    seed=$(( seed + 1 ))
  done
  echo "[smoke] running pre-flight with seed=$seed"
  run_one "$seed"
  local rc=$?
  if [[ $rc -ne 0 && $rc -ne 2 ]]; then
    echo "ERROR: pre-flight smoke run returned rc=$rc (not 0 or 2)." >&2
    echo "  Log: $LOG_DIR/seed_$(printf '%05d' "$seed").log" >&2
    echo "  Aborting. Fix the harness or rerun with --skip-smoke." >&2
    return 1
  fi
  touch "$SMOKE_OK"
  echo "[smoke] OK (rc=$rc)"
  return 0
}

# --- calibration (RUN-003) -------------------------------------------------
run_calibration() {
  if [[ $CALIBRATE_REQUESTED -eq 0 && -n "$MAX_ATTEMPTS" ]]; then return 0; fi
  if [[ $CALIBRATE_REQUESTED -eq 0 && $N_TARGET -lt 500 ]]; then return 0; fi
  if [[ -f "$CALIB_JSON" && $CALIBRATE_REQUESTED -eq 0 ]]; then
    echo "[calibrate] previous result found at $CALIB_JSON; reusing"
    return 0
  fi

  local n_calib=$CALIBRATE_N
  echo "[calibrate] running $n_calib sequential attempts to measure yield"
  local t0 t1
  t0="$(date +%s)"
  local acc_before
  acc_before="$(read_counter "$COUNTER_ACC")"
  local rej_before
  rej_before="$(read_counter "$COUNTER_REJ")"

  local seed=$START_SEED
  local done_n=0
  while [[ $done_n -lt $n_calib ]]; do
    while seed_in_ledger "$seed"; do
      seed=$(( seed + 1 ))
    done
    run_one "$seed" || true
    seed=$(( seed + 1 ))
    done_n=$(( done_n + 1 ))
  done

  t1="$(date +%s)"
  local elapsed=$(( t1 - t0 ))
  local acc_after rej_after
  acc_after="$(read_counter "$COUNTER_ACC")"
  rej_after="$(read_counter "$COUNTER_REJ")"
  local accepted=$(( acc_after - acc_before ))
  local rejected=$(( rej_after - rej_before ))

  local yield
  if [[ $n_calib -gt 0 ]]; then
    yield="$(awk -v a="$accepted" -v n="$n_calib" 'BEGIN{printf "%.6f", a/n}')"
  else
    yield="0.000000"
  fi
  local mean_wall
  if [[ $n_calib -gt 0 ]]; then
    mean_wall="$(awk -v e="$elapsed" -v n="$n_calib" 'BEGIN{printf "%.2f", e/n}')"
  else
    mean_wall="0.00"
  fi

  # Auto-set MAX_ATTEMPTS if not explicit.
  if [[ -z "$MAX_ATTEMPTS" ]]; then
    if (( $(awk -v y="$yield" 'BEGIN{print (y>0)}') )); then
      MAX_ATTEMPTS="$(awk -v t="$N_TARGET" -v y="$yield" \
        'BEGIN{printf "%d", (t/y)*1.3 + 0.5}')"
    else
      echo "ERROR: zero accepted runs in calibration; cannot proceed." >&2
      echo "  Tune harness parameters and try again." >&2
      return 1
    fi
  fi

  local proj_total
  proj_total="$(awk -v t="$N_TARGET" -v y="$yield" \
                'BEGIN{ if (y>0) printf "%d", t/y; else print 0 }')"

  cat > "$CALIB_JSON" <<EOF
{
  "n_calibration_attempts": $n_calib,
  "accepted": $accepted,
  "rejected": $rejected,
  "yield": $yield,
  "mean_wall_clock_seconds": $mean_wall,
  "elapsed_seconds": $elapsed,
  "projected_attempts_for_${N_TARGET}_accepted": $proj_total,
  "selected_max_attempts": $MAX_ATTEMPTS
}
EOF
  echo "[calibrate] yield=$yield mean_wall=${mean_wall}s max_attempts=$MAX_ATTEMPTS"
  return 0
}

# --- main loop --------------------------------------------------------------
echo "======================================================================="
echo "  $DEFENSE_LABEL Batch Runner"
echo "  Target accepted runs : $N_TARGET"
echo "  Jobs                 : $JOBS"
echo "  Output dir           : $OUT_DIR"
echo "  ns-3 dir             : $NS3_DIR"
echo "  Scratch program      : $SCRATCH"
echo "  Start seed           : $START_SEED"
echo "  Window order         : $( [[ $RANDOMIZE_WINDOWS -eq 1 ]] && echo RANDOMIZED || echo canonical )"
echo "  Mode                 : append+resume (--fresh to wipe)"
echo "======================================================================="

# Write runner config snapshot (RUN-005).
cat > "$RUNNER_CONFIG" <<EOF
N_TARGET=$N_TARGET
JOBS=$JOBS
OUT_DIR=$OUT_DIR
NS3_DIR=$NS3_DIR
SCRATCH=$SCRATCH
START_SEED=$START_SEED
MAX_ATTEMPTS=${MAX_ATTEMPTS:-auto}
CALIBRATE_REQUESTED=$CALIBRATE_REQUESTED
CALIBRATE_N=$CALIBRATE_N
EXTRA_ARGS=$EXTRA_ARGS
RANDOMIZE_WINDOWS=$RANDOMIZE_WINDOWS
DATE_STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# Step 1: header check (only if any CSV already exists).
if ! verify_headers; then
  echo "Aborting due to header verification failure." >&2
  exit 3
fi

# Step 2: pre-flight smoke run (single sequential attempt).
if ! preflight_smoke; then
  exit 4
fi

# Step 3: calibration (optional).
if ! run_calibration; then
  exit 5
fi

# Default max-attempts if still unset (no calibration; small target).
if [[ -z "$MAX_ATTEMPTS" ]]; then
  MAX_ATTEMPTS=$(( N_TARGET * 5 ))
  echo "[runner] MAX_ATTEMPTS defaulted to $MAX_ATTEMPTS (5x target; no calibration)"
fi

# Step 4: main parallel loop.
echo "[runner] entering main loop; target=$N_TARGET, max_attempts=$MAX_ATTEMPTS"
START_TIME="$(date +%s)"
SEED_CURSOR=$START_SEED
attempts_dispatched=0
last_report_attempts=0
declare -A active_pids=()   # pid -> seed (init=() satisfies set -u)

dispatch_one() {
  while seed_in_ledger "$SEED_CURSOR"; do
    SEED_CURSOR=$(( SEED_CURSOR + 1 ))
  done
  local seed=$SEED_CURSOR
  SEED_CURSOR=$(( SEED_CURSOR + 1 ))
  run_one "$seed" &
  local pid=$!
  active_pids[$pid]=$seed
  attempts_dispatched=$(( attempts_dispatched + 1 ))
}

reap_one() {
  # Wait for any one background job to finish; remove from active map.
  if [[ ${#active_pids[@]} -eq 0 ]]; then return; fi
  wait -n 2>/dev/null
  # Determine which pid finished by checking which are no longer running.
  for pid in "${!active_pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      unset 'active_pids[$pid]'
    fi
  done
}

report_progress() {
  local acc rej err
  acc="$(read_counter "$COUNTER_ACC")"
  rej="$(read_counter "$COUNTER_REJ")"
  err="$(read_counter "$COUNTER_ERR")"
  local total=$(( acc + rej + err ))
  local now elapsed rolling_yield eta_sec
  now="$(date +%s)"
  elapsed=$(( now - START_TIME ))
  if [[ $total -gt 0 ]]; then
    rolling_yield="$(awk -v a="$acc" -v t="$total" 'BEGIN{printf "%.3f", a/t}')"
  else
    rolling_yield="0.000"
  fi
  if [[ $acc -gt 0 && $elapsed -gt 0 ]]; then
    local remaining=$(( N_TARGET - acc ))
    if [[ $remaining -lt 0 ]]; then remaining=0; fi
    local rate
    rate="$(awk -v a="$acc" -v e="$elapsed" 'BEGIN{printf "%.6f", a/e}')"
    eta_sec="$(awk -v r="$remaining" -v rt="$rate" \
               'BEGIN{ if (rt>0) printf "%d", r/rt; else print 0 }')"
  else
    eta_sec="?"
  fi
  printf "[progress] elapsed=%ds attempts=%d acc=%d rej=%d err=%d yield=%s eta=%ss\n" \
    "$elapsed" "$total" "$acc" "$rej" "$err" "$rolling_yield" "$eta_sec"
}

# Main scheduler.
while :; do
  ACC="$(read_counter "$COUNTER_ACC")"
  TOT=$(( ACC + $(read_counter "$COUNTER_REJ") + $(read_counter "$COUNTER_ERR") ))
  if [[ $ACC -ge $N_TARGET ]]; then
    echo "[runner] target reached: $ACC accepted (>= $N_TARGET)"
    break
  fi
  if [[ $TOT -ge $MAX_ATTEMPTS ]]; then
    echo "[runner] MAX_ATTEMPTS=$MAX_ATTEMPTS reached; acc=$ACC; stopping." >&2
    break
  fi

  # Saturate up to JOBS active workers.
  while [[ ${#active_pids[@]} -lt $JOBS ]]; do
    local_check_acc="$(read_counter "$COUNTER_ACC")"
    if [[ $local_check_acc -ge $N_TARGET ]]; then break; fi
    if [[ $TOT -ge $MAX_ATTEMPTS ]]; then break; fi
    dispatch_one
    TOT=$(( TOT + 1 ))
  done

  reap_one

  if [[ $(( attempts_dispatched - last_report_attempts )) -ge 50 ]]; then
    report_progress
    last_report_attempts=$attempts_dispatched
  fi
done

# Drain remaining workers.
echo "[runner] draining ${#active_pids[@]} active workers"
while [[ ${#active_pids[@]} -gt 0 ]]; do
  reap_one
done

# --- final summary ----------------------------------------------------------
END_TIME="$(date +%s)"
TOTAL_ELAPSED=$(( END_TIME - START_TIME ))
ACC_FINAL="$(read_counter "$COUNTER_ACC")"
REJ_FINAL="$(read_counter "$COUNTER_REJ")"
ERR_FINAL="$(read_counter "$COUNTER_ERR")"
TOT_FINAL=$(( ACC_FINAL + REJ_FINAL + ERR_FINAL ))
YIELD_FINAL="0.000"
if [[ $TOT_FINAL -gt 0 ]]; then
  YIELD_FINAL="$(awk -v a="$ACC_FINAL" -v t="$TOT_FINAL" \
                 'BEGIN{printf "%.4f", a/t}')"
fi

# RUN-008: PDR summary reads windows_oracle.csv (was metrics.csv).
PDR_SUMMARY="(unavailable)"
if [[ -s "$ORACLE_FILE" ]]; then
  PDR_SUMMARY="$(awk -F',' '
    NR==1 {
      for (i=1; i<=NF; i++) if ($i == "pdr_percent") col=i;
      if (col=="") { print "(pdr_percent column not found)"; exit }
      next
    }
    NF >= col && $col != "" {
      s += $col; n++
      if ($col > mx) mx = $col
      if ($col < mn || n==1) mn = $col
    }
    END {
      if (n>0)
        printf "windows=%d  pdr_mean=%.2f%%  pdr_min=%.2f%%  pdr_max=%.2f%%",
               n, s/n, mn, mx
      else
        print "(no oracle rows)"
    }' "$ORACLE_FILE")"
fi

# Reject reasons breakdown from ledger.
REJ_REASONS=""
if [[ -s "$LEDGER" ]]; then
  REJ_REASONS="$(awk -F'\t' '$2=="rejected"{print $3}' "$LEDGER" \
                 | sort | uniq -c | sort -rn | head -10)"
fi

cat > "$RUNNER_SUMMARY" <<EOF
============================================================
$DEFENSE_LABEL Batch Runner -- Summary
============================================================
Date completed : $(date -u +%Y-%m-%dT%H:%M:%SZ)
Total elapsed  : ${TOTAL_ELAPSED}s ($(awk -v s="$TOTAL_ELAPSED" 'BEGIN{printf "%.2f", s/3600}')h)

Attempts       : $TOT_FINAL
  Accepted     : $ACC_FINAL  (target: $N_TARGET)
  Rejected     : $REJ_FINAL
  Errors       : $ERR_FINAL
Yield          : $YIELD_FINAL
Window order   : $( [[ $RANDOMIZE_WINDOWS -eq 1 ]] && echo RANDOMIZED || echo canonical )

PDR summary (oracle table):
  $PDR_SUMMARY

Rejection reasons (top 10):
$REJ_REASONS

Output files:
  $RUNS_FILE
  $FEATURES_FILE
  $LABELS_FILE
  $ORACLE_FILE
  $PROBE_FILE
  $DEFPARAMS_FILE  (defense parameters; provenance, NOT an ML input)
  (per-attempt logs in $LOG_DIR)

ML pipeline note:
  Load ONLY $FEATURES_FILE (as X) and $LABELS_FILE (as y).
  $ORACLE_FILE contains ground-truth columns that are NOT
  observable from the wire and MUST NOT be used as features.
============================================================
EOF

cat "$RUNNER_SUMMARY"

# Exit 0 if target met, 1 otherwise (so CI can react).
if [[ $ACC_FINAL -ge $N_TARGET ]]; then
  exit 0
else
  exit 1
fi