#!/usr/bin/env python3
"""
run_watchdog_base_multi_seeds.py
=================================

Runs the OLSR Blackhole/Watchdog simulation with N different RNG seeds and
prints a summary table comparing PDR across the four phases:
    Baseline (no attack, no defense)
    Attack-only
    Defense-only
    Defense vs. Attack

If a seed fails the connectivity check at t=59.9s (any node has fewer than
nNodes-1 routing-table entries), or the attacker selection fails (NEIGHBOR_ABORT
or NO_ATTACKER), that seed is discarded and the next candidate seed is tried,
until --num-seeds successful runs are collected.

USAGE
-----
    # From your ns-3 root directory:
    python3 run_watchdog_base_multi_seeds.py

OPTIONS
-------
    --ns3            Path to the `ns3` wrapper script (default: ./ns3)
    --program        Name of the simulation program (default: watchdogBaseSimulation)
    --num-seeds      How many successful runs to collect (default: 10)
    --max-attempts   How many seeds to try in total before giving up (default: 100)
    --start-seed     First seed to try (default: 1)
    --output-csv     Optional path for a CSV dump of the results
    --extra-args     Extra args forwarded to the simulation, in quotes
                     (e.g. --extra-args "--spoofedLinks=2")

PRE-REQUISITES
--------------
    1. Place watchdogBaseSimulation.cc in scratch/ in your ns-3 root.
    2. ./ns3 configure
    3. ./ns3 build
"""

import argparse
import csv
import os
import re
import subprocess
import sys
import time
from typing import Optional


# --------------------------------------------------------------------------
# Output line parsing
# --------------------------------------------------------------------------
RESULT_LINE_RE = re.compile(r"^RESULT,(.+)$")


def parse_result_line(line: str) -> Optional[dict]:
    """Parse a `RESULT,key=val,key=val,...` line into a dict, or None."""
    m = RESULT_LINE_RE.match(line.strip())
    if not m:
        return None
    out = {}
    for pair in m.group(1).split(","):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        k, v = k.strip(), v.strip()
        try:
            if "." in v:
                out[k] = float(v)
            else:
                out[k] = int(v)
        except ValueError:
            out[k] = v
    return out


# --------------------------------------------------------------------------
# Single ns-3 run
# --------------------------------------------------------------------------
def run_simulation(ns3_path: str, program: str, seed: int,
                   extra_args: str, timeout: int = 600) -> dict:
    """Run one simulation; return parsed RESULT dict (always includes 'STATUS')."""
    program_args = f"{program} --run={seed} {extra_args}".strip()
    cmd = [ns3_path, "run", program_args, "--no-build"]

    print(f"  -> executing: {' '.join(cmd)}")
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {"STATUS": "TIMEOUT", "run": seed,
                "stdout": "", "stderr": "timeout"}
    elapsed = time.time() - t0

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    result = None
    for line in stdout.splitlines():
        parsed = parse_result_line(line)
        if parsed:
            result = parsed

    if result is None:
        return {
            "STATUS": "ERROR_NO_RESULT_LINE",
            "run": seed,
            "elapsed_s": elapsed,
            "stdout_tail": "\n".join(stdout.splitlines()[-25:]),
            "stderr_tail": "\n".join(stderr.splitlines()[-25:]),
        }

    result["elapsed_s"] = elapsed
    return result


# --------------------------------------------------------------------------
# Pretty-printing the results table
# --------------------------------------------------------------------------
def format_pdr(value) -> str:
    if isinstance(value, (int, float)):
        return f"{value*100:6.2f}%"
    return f"{str(value):>7}"


def print_results_table(rows: list):
    if not rows:
        print("No successful runs.")
        return

    headers = ["#", "Seed", "Atk",
               "Baseline PDR", "Attack PDR",
               "Defense PDR", "Defense+Attack PDR",
               "Recovery", "Time (s)"]

    col_w = [4, 6, 5, 14, 12, 13, 20, 13, 9]

    sep = "+" + "+".join("-" * (w + 2) for w in col_w) + "+"
    fmt = "| " + " | ".join("{:<%d}" % w for w in col_w) + " |"

    print()
    print(sep)
    print(fmt.format(*headers))
    print(sep)

    sums = {"baseline": 0.0, "attack": 0.0, "defense": 0.0, "both": 0.0,
            "recovered": 0.0}
    n = 0
    for i, r in enumerate(rows, 1):
        b = r.get("baseline_pdr"); a = r.get("attack_pdr")
        d = r.get("defense_pdr");  bo = r.get("both_pdr")
        rec = (bo - a) if (isinstance(a, float) and isinstance(bo, float)) else None

        line = fmt.format(
            i, r.get("run", "-"), r.get("attacker_id", "-"),
            format_pdr(b), format_pdr(a),
            format_pdr(d), format_pdr(bo),
            (format_pdr(rec) if rec is not None else "  -"),
            f"{r.get('elapsed_s', 0):.1f}",
        )
        print(line)
        if all(isinstance(x, float) for x in (b, a, d, bo)):
            sums["baseline"]  += b
            sums["attack"]    += a
            sums["defense"]   += d
            sums["both"]      += bo
            sums["recovered"] += (bo - a)
            n += 1
    print(sep)

    if n > 0:
        avg = fmt.format(
            "AVG", f"({n})", "-",
            format_pdr(sums["baseline"] / n),
            format_pdr(sums["attack"] / n),
            format_pdr(sums["defense"] / n),
            format_pdr(sums["both"] / n),
            format_pdr(sums["recovered"] / n),
            "-",
        )
        print(avg)
        print(sep)
    print()


def print_skip_log(skipped: list):
    if not skipped:
        return
    print("Seeds skipped (no full connectivity / no usable attacker / errors):")
    for s in skipped:
        reason = s.get("STATUS", "?")
        if reason == "NO_CONNECTIVITY":
            reason = (f"NO_CONNECTIVITY (min routes={s.get('minRoutes','?')}"
                      f" at node {s.get('failingNode','?')},"
                      f" expected {s.get('expected','?')})")
        elif reason == "NEIGHBOR_ABORT":
            reason = "NEIGHBOR_ABORT (Node 1 is a 1-hop neighbor of Node 0)"
        elif reason == "NO_ATTACKER":
            reason = "NO_ATTACKER (no node in [2..N-1] is a 1-hop neighbor of Node 0)"
        print(f"  seed={s.get('run','?'):<4}  reason={reason}")
    print()


def write_csv(path: str, rows: list):
    if not rows:
        return
    keys = sorted({k for r in rows for k in r.keys()})
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"CSV written to: {path}")


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=__doc__)
    ap.add_argument("--ns3", default="./ns3",
                    help="Path to the ns3 wrapper script")
    ap.add_argument("--program", default="watchdogBaseSimulation",
                    help="Simulation program name (without .cc)")
    ap.add_argument("--num-seeds", type=int, default=10,
                    help="How many *successful* runs to collect")
    ap.add_argument("--max-attempts", type=int, default=100,
                    help="Maximum total seeds to try")
    ap.add_argument("--start-seed", type=int, default=1)
    ap.add_argument("--output-csv", default=None)
    ap.add_argument("--extra-args", default="--spoofedLinks=3",
                    help='Extra args forwarded verbatim, e.g. --extra-args "--spoofedLinks=2"')
    ap.add_argument("--timeout", type=int, default=900,
                    help="Per-run timeout in seconds")
    args = ap.parse_args()

    if not os.path.exists(args.ns3):
        sys.exit(f"ERROR: ns3 wrapper not found at {args.ns3}. "
                 f"Run this script from your ns-3 root or pass --ns3.")

    print("Building ns-3 once before starting the seed sweep...")
    build = subprocess.run([args.ns3, "build"], capture_output=True, text=True)
    if build.returncode != 0:
        print("Build FAILED:")
        print(build.stdout[-2000:])
        print(build.stderr[-2000:])
        sys.exit(1)
    print("Build OK.\n")

    successful = []
    skipped    = []
    seed       = args.start_seed
    attempts   = 0

    while len(successful) < args.num_seeds and attempts < args.max_attempts:
        attempts += 1
        print(f"[Attempt {attempts}] seed={seed} "
              f"(have {len(successful)}/{args.num_seeds} successful)")
        result = run_simulation(args.ns3, args.program, seed,
                                args.extra_args, timeout=args.timeout)
        status = result.get("STATUS", "?")

        if status == "OK":
            successful.append(result)
            print(f"  [OK] seed={seed} attacker={result.get('attacker_id','?')}  "
                  f"baseline={result.get('baseline_pdr',0)*100:.1f}% "
                  f"attack={result.get('attack_pdr',0)*100:.1f}% "
                  f"defense={result.get('defense_pdr',0)*100:.1f}% "
                  f"both={result.get('both_pdr',0)*100:.1f}%")
        else:
            skipped.append(result)
            if status == "NO_CONNECTIVITY":
                print(f"  [SKIP] seed={seed} -- incomplete connectivity "
                      f"(min routes={result.get('minRoutes','?')} at node "
                      f"{result.get('failingNode','?')}, expected "
                      f"{result.get('expected','?')})")
            elif status == "NEIGHBOR_ABORT":
                print(f"  [SKIP] seed={seed} -- Node 1 is a 1-hop neighbor of "
                      f"Node 0 (no multi-hop route to attack)")
            elif status == "NO_ATTACKER":
                print(f"  [SKIP] seed={seed} -- no suitable attacker "
                      f"(no node is a 1-hop neighbor of Node 0)")
            else:
                print(f"  [SKIP] seed={seed} -- status={status}")
                if "stdout_tail" in result:
                    print("    --- stdout tail ---")
                    for line in result["stdout_tail"].splitlines():
                        print(f"      {line}")
                if "stderr_tail" in result:
                    print("    --- stderr tail ---")
                    for line in result["stderr_tail"].splitlines():
                        print(f"      {line}")
        seed += 1

    print()
    print("=" * 78)
    print(f"  Collected {len(successful)} / {args.num_seeds} successful runs "
          f"in {attempts} attempts")
    print("=" * 78)

    print_skip_log(skipped)
    print_results_table(successful)

    if args.output_csv:
        write_csv(args.output_csv, successful)

    return 0 if len(successful) == args.num_seeds else 1


if __name__ == "__main__":
    sys.exit(main())