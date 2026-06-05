/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Watchdog-OLSR Evaluation Harness  (Cross-Layer Cooperative Watchdog, Baiad 2014)
 * ==========================================================
 *
 * CHANGELOG SUMMARY (see Phase 2 plan for details):
 *   LEAK-001/002/003: defense internal state, attacker-on-path, defense
 *                     config moved out of features into oracle/labels/runs.
 *   OBS-001: HELLO filtered in MAC and PHY callbacks. hello_count and
 *            olsr_control_bytes_with_hello go to oracle only.
 *   OBS-002: MacTx repurposed for MSDU/IP parsing (no WifiMacHeader peek).
 *            PhyTxBegin connected via failsafe; phy_trace_available flag.
 *   OBS-003: FlowMonitor and UdpServer columns -> oracle only.
 *   OBS-004: End-to-end latency from on-air IP-id correlation, not
 *            sender's IP-Tx hook.
 *   OBS-005: Data Tx/Rx counts from on-air MacTx capture.
 *   OBS-006: ThroughputBitsPerSecond uses delivered on-air bytes.
 *   RUN-004: Per-run staging directory + atomic promotion at end of main.
 *
 * CHANGELOG (Phase 3):
 *   WIN-001: measurement-window order can be randomized per run via
 *            --randomWindowOrder. The permutation is drawn from a SEPARATE
 *            std::mt19937 seeded by --run, so it is fully reproducible and
 *            does NOT consume any ns-3 RNG draws (identical topology for a
 *            given seed in both modes). Canonical order is the identity
 *            permutation [baseline, attack_only, defense_only,
 *            defense_vs_attack].
 *   WIN-002: timeline generalized so the t=[0,60) initial stabilization and
 *            the acceptance gates ALWAYS run in the neutral (attack OFF,
 *            defense OFF) state, regardless of window order. Each of the
 *            four slots then gets an identical 60 s post-transition
 *            stabilization + 40 s measurement. SIMULATION_END moves from
 *            400 s to 460 s as a result (60 + 4*100).
 *   WIN-003: runs.csv gains random_window_order, window_order_perm, and
 *            slot0_scenario columns. HEADER_VERSION bumped 1 -> 2.
 *
 * CHANGELOG (Phase 5):
 *   WBR-001 (revised): slot-transition cold start. The defense object's
 *            accumulated state is wiped to its freshly-loaded defaults at the
 *            START of each slot's 60 s stabilization period (an unconditional
 *            ForceDefenseColdStart() at the end of ApplyScenarioState, t =
 *            SlotTransitionTime(slot)), NOT at the measurement-window start.
 *            This gives the defense the full stabilization window to warm up,
 *            so the measurement window observes a fully-warmed defense -- while
 *            still inheriting nothing from the previous slot, because the
 *            transition reset is UNCONDITIONAL (it fires on every slot even
 *            when the (attack,defense) state did not change, so two consecutive
 *            defense-enabled slots cannot leak across the boundary). All three
 *            harnesses reset at this same instant. The wipe reuses the defense's
 *            existing symmetric SetEnabled cold-start (toggled off->on, or
 *            on->off->on) so ALL accumulated Watchdog state (per-neighbor
 *            forwarding-evidence counters, RTS/CTS and MAC-failure tallies,
 *            self-reliability bookkeeping, blacklist/probation timers, ...) is
 *            cleared and the window's intended enabled/disabled value is
 *            restored. This resets ONLY state owned
 *            by the defense object; physical simulation state (channel load,
 *            MAC queues, route churn) is NOT defense state and is left
 *            untouched by design. Schema unchanged (HEADER_VERSION still 2).
 *   WBR-002: optional --debugDefenseState flag (default off). When set, the
 *            harness prints the aggregate sizes of the defense's accumulated
 *            state containers at the start of each measurement window. If the
 *            cold start works they read zero; any non-zero value is direct
 *            evidence of a leak through defense state. stdout only -- no CSV
 *            column is added. HARNESS_VERSION bumped 2.0.0 -> 2.1.0 for
 *            provenance (lets fixed rows be told apart from pre-fix rows via
 *            the existing harness_version column; the CSV SCHEMA is unchanged).
 *
 * CHANGELOG (cross-harness generalization / cleanup):
 *   GEN-001: shared collector renamed fpnt_features.h ->
 *            olsr_window_features.h; namespace ns3::fpnt -> ns3::olsreval
 *            (the collector is defense-agnostic; the FPNT name was a
 *            historical artifact of that harness being written first).
 *   GEN-002: NS_LOG component + console banner are now Watchdog-specific
 *            ("OlsrWatchdogEvalMitigation") so per-binary logs are
 *            unambiguous when several harnesses run with --verbose.
 *   GEN-003: the seven FPNT-only runs.csv parameter columns AND
 *            redundant_mpr are all written as the sentinel -1 (N/A for this
 *            defense); the matching CLI flags are kept (for an identical
 *            command-line interface across harnesses) but flagged inert.
 *   GEN-004: new --defenseParamsFile writes this build's effective Watchdog
 *            parameters once per output dir (provenance sidecar; not an ML
 *            input and not part of any CSV schema).
 *   NOTE: HARNESS_VERSION was "2.2.0" at GEN time; the WBR-002 note above predates the
 *         2.1.0 -> 2.2.0 bump and is kept for history.
 *
 * CHANGELOG (observability tightening / schema v3):
 *   OBS-007: RTS/CTS/ACK are 1-hop MAC control frames with the same
 *            observability limit as HELLO -- a remote passive attacker
 *            cannot reliably sniff them. PhyTxBeginCallback now drops them
 *            before any feature observation (mirror of the OBS-001 HELLO
 *            filter), and the five features derived from them
 *            (RtsRateLocal, CtsRateLocal, AckRateLocal, AckDelayMean,
 *            AckDelayStd) are removed from the shared collector
 *            (olsr_window_features.h). Feature columns: 86 -> 81.
 *            Layer2RetransmissionRate (retry bit read from the data
 *            frame's own header), ChannelBusyTimeFraction and
 *            InterFrameSpacingMean are retained and now accumulate over
 *            observable frames only. HEADER_VERSION bumped 2 -> 3.
 *            Applied identically to all three harnesses.
 *
 * CHANGELOG (multi-flow traffic generation, TRF-001..TRF-004):
 *   TRF-001: each measurement window now carries NUM_DATA_FLOWS (= 3)
 *            SIMULTANEOUS UDP flows instead of the single node1 -> node0
 *            flow, so several different nodes transmit and the defense's
 *            network-level footprint (emergent isolation around the
 *            attacker) becomes observable. Flow 0 is ALWAYS the legacy
 *            node1 -> node0 pair (its acceptance gate is unchanged); the
 *            additional pairs are selected deterministically by
 *            SelectDataFlowPairs() from a SEPARATE std::mt19937 seeded by
 *            a fixed mix of --seed and --run (mirror of WIN-001: no ns-3
 *            RNG draw is consumed, so topology and the accept/reject
 *            decision are unchanged for a given seed). Selected pairs
 *            exclude attackers as src/dst, are endpoint-disjoint across
 *            flows, and obey a geometric lower bound that guarantees
 *            >= minHops OLSR hops. Per-flow timing/size/budget are
 *            IDENTICAL to the original flow (start offset +4 s in window,
 *            18 x 512 B at 2 s intervals), so the aggregate offered load
 *            is ~6 kb/s of application traffic -- far below saturation.
 *   TRF-002: on-air packet correlation is keyed by the passively
 *            observable triple (src, dst, IP-id) -- ns-3 assigns the IP
 *            Identification per (src,dst,protocol) starting at 0 on EVERY
 *            node, so concurrent flows collide on the bare 16-bit id.
 *            Delivery detection generalizes from the single victim MAC to
 *            a flow-destination IP -> MAC map (same last-hop logic,
 *            applied per destination).
 *   TRF-003: the t=60 minHops gate checks EVERY flow pair (flow 0's check
 *            and rejection-reason strings are unchanged).
 *            ObserveAttackerOnPath walks every flow's OLSR path:
 *            attacker_on_path (labels) = 1 iff the attacker sits on AT
 *            LEAST ONE flow path; path_hops_internal (oracle) = rounded
 *            MEAN hop count over flows with a valid path.
 *   TRF-004: oracle UDP counters sum over the per-flow UdpServers;
 *            udp_expected_in_window is now NUM_DATA_FLOWS * 18 = 54 and
 *            udp_loss_percent is computed against it. CSV schemas are
 *            UNCHANGED (column sets, counts and order identical;
 *            HEADER_VERSION stays 3); HARNESS_VERSION bumped
 *            2.2.0 -> 2.3.0 so multi-flow rows are distinguishable from
 *            single-flow rows via the existing harness_version column.
 *            Applied identically in all three harness .cc files;
 *            olsr_window_features.h is untouched.
 *
 * Output files (replaces single metrics.csv):
 *   --runsFile          one row per accepted run (config/metadata)
 *   --featuresFile      one row per (run_id, scenario) -- ML X-matrix only
 *   --labelsFile        one row per (run_id, scenario) -- y-vector
 *   --oracleFile        one row per (run_id, scenario) -- forbidden as ML input
 *   --topologyProbeFile one row per attempted run (unchanged)
 *
 * Special CLI modes:
 *   --emit-header       print all four headers to stdout and exit 0
 *   --self-test         run cycle-counter unit tests and exit 0/1
 *
 * Topology, traffic, and acceptance gates are unchanged from the original
 * harness. The window TIMELINE is generalized (see WIN-002) so that both
 * the canonical and randomized window orders share one timeline.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/olsr-module.h"
#include "ns3/olsr-watchdog-defense.h"
#include "ns3/udp-client-server-helper.h"
#include "ns3/llc-snap-header.h"

#include "olsr_window_features.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <queue>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <sys/file.h>
#include <tuple>
#include <unistd.h>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("OlsrWatchdogEvalMitigation");

// ============================================================================
// Version markers (RUN-006 / reproducibility)
// ============================================================================
#define HARNESS_VERSION "2.3.0"
#define HEADER_VERSION  4

// ============================================================================
// Phase / window timing constants  (WIN-002: generalized, shared by both
// canonical and randomized window order)
// ============================================================================
//
// TIMELINE
//   t in [0, INITIAL_STABILIZATION)        : neutral stabilization
//                                            (attack OFF, defense OFF). The
//                                            acceptance gates fire at
//                                            t = INITIAL_STABILIZATION in
//                                            this neutral state, so the
//                                            accept/reject decision is
//                                            independent of window order.
//   For slot k in [0, NUM_SLOTS):
//     transition  @ INITIAL_STABILIZATION + k*SLOT_DURATION
//     stabilize    [transition, transition + SLOT_STABILIZATION)
//     measurement  [transition + SLOT_STABILIZATION,
//                   transition + SLOT_STABILIZATION + MEASUREMENT_DURATION)
//
// Fixed (canonical) and randomized modes share this timeline; they differ
// only in which scenario is assigned to which slot (see g_scenarioOrder).
// Every window gets an identical 60 s post-transition stabilization.
static constexpr double INITIAL_STABILIZATION  = 60.0;
static constexpr double SLOT_STABILIZATION     = 60.0;
static constexpr double MEASUREMENT_DURATION   = 40.0;
static constexpr double SLOT_DURATION          =
    SLOT_STABILIZATION + MEASUREMENT_DURATION;          // 100.0
static constexpr int    NUM_SLOTS              = 4;

static constexpr double SIMULATION_END  =
    INITIAL_STABILIZATION + NUM_SLOTS * SLOT_DURATION;  // 60 + 400 = 460
static constexpr double SIMULATION_TAIL = SIMULATION_END + 2.0;  // 462

static constexpr double UDP_START_OFFSET_IN_WINDOW = 4.0;
static constexpr uint32_t UDP_PACKETS_PER_WINDOW   = 18;
static constexpr double UDP_PACKET_INTERVAL        = 2.0;
static constexpr uint32_t UDP_PACKET_SIZE          = 512;
static constexpr uint16_t UDP_PORT                 = 80;

// TRF-001: number of SIMULTANEOUS UDP flows per measurement window. Flow 0 is
// ALWAYS the legacy node1 -> node0 pair; the remaining pairs are selected per
// run by SelectDataFlowPairs(). Tunable; every flow reuses the per-flow
// constants above unchanged (same in-window start offset, packet budget,
// interval and size), so the aggregate offered load scales linearly:
// NUM_DATA_FLOWS x 18 x 512 B per 40 s window (~6 kb/s of application
// traffic) -- far below channel saturation.
static constexpr uint32_t NUM_DATA_FLOWS = 3;
static_assert (NUM_DATA_FLOWS >= 1,
               "NUM_DATA_FLOWS must include at least the legacy flow 0");

// TRF-004: total expected UDP receptions per window across ALL flows (the
// oracle's udp_expected_in_window column and the udp_loss_percent
// denominator).
static constexpr uint32_t UDP_EXPECTED_PER_WINDOW =
    NUM_DATA_FLOWS * UDP_PACKETS_PER_WINDOW;

// Slot timing helpers (callable with a runtime slot index).
static constexpr double SlotTransitionTime (int k)
{ return INITIAL_STABILIZATION + k * SLOT_DURATION; }
static constexpr double SlotWindowStart (int k)
{ return INITIAL_STABILIZATION + k * SLOT_DURATION + SLOT_STABILIZATION; }
static constexpr double SlotWindowEnd (int k)
{ return SlotWindowStart (k) + MEASUREMENT_DURATION; }

// ============================================================================
// Scenario specification (WIN-001)
//
// Each scenario is one cell of the 2x2 (attack, defense) factorial. The name
// dictates the labels written to windows_labels.csv. In canonical order the
// slots are assigned scenarios [0,1,2,3] in this exact order; in randomized
// mode the assignment is a per-run permutation (g_scenarioOrder).
// ============================================================================
struct ScenarioSpec
{
  const char* name;
  bool        attackEnabled;
  bool        defenseEnabled;
};
static const ScenarioSpec SCENARIOS[NUM_SLOTS] = {
  { "baseline",          false, false },
  { "attack_only",       true,  false },
  { "defense_only",      false, true  },
  { "defense_vs_attack", true,  true  },
};

// WIN-001 (reproducibility): portable Fisher-Yates shuffle of the slot order.
//
// std::shuffle / std::uniform_int_distribution consume the URBG in an
// IMPLEMENTATION-DEFINED way, so libstdc++ and libc++ produce DIFFERENT
// permutations from the same seeded mt19937. std::mt19937's *output stream*,
// by contrast, is fully specified by the C++ standard and is bit-identical on
// every conforming implementation. This routine therefore draws only raw
// mt19937 outputs and does unbiased index selection by explicit rejection
// sampling, guaranteeing the SAME permutation for a given seed on any
// compiler / standard library. (Canonical order never calls this; it is the
// identity permutation.)
static void
DeterministicShuffle (std::array<int, NUM_SLOTS>& a, uint32_t seed)
{
  std::mt19937 rng (seed);                  // standardized output sequence
  for (int i = NUM_SLOTS - 1; i > 0; --i)
    {
      const uint64_t range = 0x100000000ULL;            // 2^32 = |mt19937 range|
      const uint64_t bound = static_cast<uint64_t> (i) + 1ULL;
      const uint64_t limit = range - (range % bound);   // largest exact multiple
      uint32_t r;
      do { r = rng (); } while (static_cast<uint64_t> (r) >= limit);
      const int j = static_cast<int> (static_cast<uint64_t> (r) % bound);
      std::swap (a[i], a[j]);
    }
}

// TRF-001: unbiased uniform draw in [0, bound) from raw mt19937 outputs via
// rejection sampling -- the same portability rationale as DeterministicShuffle
// (std::uniform_int_distribution consumes the URBG in an implementation-
// defined way; mt19937's raw output stream is bit-identical on every
// conforming standard library).
static uint32_t
DeterministicDraw (std::mt19937& rng, uint32_t bound)
{
  if (bound == 0) return 0;   // defensive; callers always pass bound >= 1
  const uint64_t range = 0x100000000ULL;            // 2^32 = |mt19937 range|
  const uint64_t b     = static_cast<uint64_t> (bound);
  const uint64_t limit = range - (range % b);       // largest exact multiple
  uint32_t r;
  do { r = rng (); } while (static_cast<uint64_t> (r) >= limit);
  return static_cast<uint32_t> (static_cast<uint64_t> (r) % b);
}

static constexpr uint32_t UDP_SERVER_NODE_ID = 0;
static constexpr uint32_t UDP_CLIENT_NODE_ID = 1;

// TRF-001: deterministic per-run selection of the data-flow (src,dst) pairs.
//
// Flow 0 is ALWAYS the legacy pair (UDP_CLIENT_NODE_ID -> UDP_SERVER_NODE_ID),
// so its t=60 acceptance gate -- and therefore the accept/reject behavior of
// every previously accepted seed -- is unchanged. Flows 1..NUM_DATA_FLOWS-1
// are drawn here so that:
//   * no attacker is a source or a destination of any flow,
//   * every endpoint is DISTINCT across all flows (including nodes 0/1):
//     NUM_DATA_FLOWS distinct sources and NUM_DATA_FLOWS distinct
//     destinations, maximal topological diversity, exactly one UdpServer
//     per node,
//   * the straight-line distance of every selected pair exceeds
//     (minHops-1)*radioRange. Under RangePropagationLossModel one hop covers
//     at most radioRange metres, so ANY route between such a pair --
//     including the OLSR route checked by the t=60 gate -- must have at
//     least minHops hops. The geometric filter therefore guarantees the
//     extended AssertMinHops gate passes for the added pairs whenever a
//     route exists at all (and AssertConnectivity already rejects runs in
//     which any route is missing).
//
// Determinism (mirror of WIN-001): every draw comes from a SEPARATE
// std::mt19937 (seeded by the caller from --seed and --run) using the same
// raw-output rejection sampling as DeterministicShuffle, so the selection is
// bit-identical on every conforming standard library and consumes NO ns-3
// RNG draw -- the topology for a given seed is unchanged from the
// single-flow harness.
//
// Positions are read from the already-installed mobility models at CONFIG
// time (t=0). With the default static topology this is exact; under
// --bMobility the geometric bound erodes as nodes move, but the t=60 OLSR
// gate remains the single acceptance arbiter either way.
static std::vector<std::pair<uint32_t, uint32_t>>
SelectDataFlowPairs (NodeContainer& nodes,
                     const std::set<uint32_t>& attackerSet,
                     uint32_t minHops, double radioRange, uint32_t pairSeed)
{
  std::vector<std::pair<uint32_t, uint32_t>> flows;
  flows.emplace_back (UDP_CLIENT_NODE_ID, UDP_SERVER_NODE_ID);  // legacy flow 0

  const uint32_t n = nodes.GetN ();
  std::vector<Vector> pos (n);
  for (uint32_t i = 0; i < n; ++i)
    {
      Ptr<MobilityModel> mm = nodes.Get (i)->GetObject<MobilityModel> ();
      pos[i] = mm ? mm->GetPosition () : Vector (0, 0, 0);
    }
  auto euclid = [&pos] (uint32_t a, uint32_t b) {
    const double dx = pos[a].x - pos[b].x;
    const double dy = pos[a].y - pos[b].y;
    const double dz = pos[a].z - pos[b].z;
    return std::sqrt (dx * dx + dy * dy + dz * dz);
  };
  const double minDist =
      (minHops >= 1) ? (minHops - 1) * radioRange : 0.0;

  // Candidate endpoints: everything except attackers and the endpoints
  // already consumed by flow 0 (nodes 0 and 1).
  std::vector<uint32_t> cand;
  for (uint32_t i = 0; i < n; ++i)
    {
      if (attackerSet.count (i)) continue;
      if (i == UDP_SERVER_NODE_ID || i == UDP_CLIENT_NODE_ID) continue;
      cand.push_back (i);
    }
  NS_ABORT_MSG_IF (cand.size () + 2 < 2 * NUM_DATA_FLOWS,
                   "not enough non-attacker nodes for NUM_DATA_FLOWS="
                   << NUM_DATA_FLOWS << " endpoint-disjoint flows");

  // Portable Fisher-Yates over the candidate list (same construction as
  // DeterministicShuffle, generalized to a runtime-sized vector).
  std::mt19937 rng (pairSeed);
  for (std::size_t i = cand.size (); i > 1; --i)
    {
      const uint32_t j = DeterministicDraw (rng, static_cast<uint32_t> (i));
      std::swap (cand[i - 1], cand[j]);
    }

  while (flows.size () < NUM_DATA_FLOWS)
    {
      bool made = false;
      for (std::size_t si = 0; si < cand.size () && !made; ++si)
        for (std::size_t di = 0; di < cand.size (); ++di)
          {
            if (di == si) continue;
            if (euclid (cand[si], cand[di]) <= minDist) continue;
            flows.emplace_back (cand[si], cand[di]);
            std::cout << "[flow_select] flow " << (flows.size () - 1)
                      << ": " << cand[si] << " -> " << cand[di]
                      << " (euclid=" << euclid (cand[si], cand[di])
                      << " m > bound=" << minDist << " m)" << std::endl;
            // Erase the larger index first so the smaller one stays valid.
            const std::size_t hi = std::max (si, di);
            const std::size_t lo = std::min (si, di);
            cand.erase (cand.begin () + static_cast<std::ptrdiff_t> (hi));
            cand.erase (cand.begin () + static_cast<std::ptrdiff_t> (lo));
            made = true;
            break;
          }
      if (!made)
        {
          // No remaining pair satisfies the geometric bound (essentially
          // impossible for the default 50-node 750x1000 m grid). Fall back
          // to the maximum-distance remaining pair; the extended t=60 OLSR
          // gate stays the single acceptance arbiter and rejects the run
          // ("too_close") if the pair is genuinely too close.
          std::size_t bi = 0, bj = 1;
          double best = -1.0;
          for (std::size_t a = 0; a < cand.size (); ++a)
            for (std::size_t b = 0; b < cand.size (); ++b)
              {
                if (a == b) continue;
                const double d = euclid (cand[a], cand[b]);
                if (d > best) { best = d; bi = a; bj = b; }
              }
          flows.emplace_back (cand[bi], cand[bj]);
          std::cout << "[flow_select] flow " << (flows.size () - 1)
                    << " FALLBACK (no pair beyond geometric bound): "
                    << cand[bi] << " -> " << cand[bj]
                    << " (euclid=" << best << " m, bound=" << minDist
                    << " m); the t=60 gate will arbitrate" << std::endl;
          const std::size_t hi = std::max (bi, bj);
          const std::size_t lo = std::min (bi, bj);
          cand.erase (cand.begin () + static_cast<std::ptrdiff_t> (hi));
          cand.erase (cand.begin () + static_cast<std::ptrdiff_t> (lo));
        }
    }
  return flows;
}

// ============================================================================
// Configuration (populated from CLI)
// ============================================================================
struct SimulationConfig
{
  uint32_t nNodes      = 50;
  double   gridX       = 750.0;
  double   gridY       = 1000.0;
  double   txGain      = 0.0;
  double   radioRange  = 190.0;
  bool     bMobility   = false;
  bool     bHighRange  = false;

  uint32_t run         = 1;
  uint32_t seed        = 1;

  std::string maliciousNodesList = "2";
  uint32_t    spoofCount         = 5;
  double      attackerJitter     = 25.0;

  uint32_t    minHops            = 3;

  bool     redundantMpr            = false;
  double   maliciousThreshold      = 0.2;
  double   uncertaintyBeta         = 0.6;
  double   fadingFactor            = 0.7;
  double   maxLoad                 = 1.0e6;
  double   maxDelay                = 0.5;
  uint32_t cheatThreshold          = 2;
  Time     trustUpdateInterval     = Seconds (5.0);

  // OBS-001/002/003/004/005/006: four output files instead of one CSV.
  std::string runsFile          = "";
  std::string featuresFile      = "";
  std::string labelsFile        = "";
  std::string oracleFile        = "";
  std::string topologyProbeFile = "";
  std::string defenseParamsFile = "";   // GEN-004: provenance sidecar (write-once)
  std::string outputDir         = "./simulations/features/";

  // RUN-004: staging dir for atomic per-run promotion.
  std::string stagingDir        = "";

  // Special modes.
  bool emitHeaderOnly = false;
  bool selfTest       = false;
  bool verbose        = false;

  // WIN-001: randomize the measurement-window order (seeded by run).
  bool randomWindowOrder = false;

  // WBR-002: print defense-state container sizes at each window start (off
  // by default). Verification only; emits nothing to any CSV.
  bool debugDefenseState = false;
};

// ============================================================================
// Globals
// ============================================================================
static uint64_t g_helloCount               = 0;   // oracle only
static uint64_t g_tcCount                  = 0;
static uint32_t g_midCount                 = 0;
static uint32_t g_hnaCount                 = 0;
static uint64_t g_totalTcRows              = 0;
static uint64_t g_olsrControlBytesWithHello = 0;  // oracle only (OBS-001)

static std::vector<uint32_t> g_macTxPerNode;     // oracle only
static std::vector<uint32_t> g_macDropPerNode;   // oracle only
static uint64_t g_macTxAtWindowStart   = 0;
static uint64_t g_macDropAtWindowStart = 0;

// LEAK-002: kept but routed to oracle/labels only.
static uint32_t g_pathHopsPrevWindow       = 0;
static bool     g_attackerOnPathPrevWindow = false;

// TRF-003: per-window flow-level breakdown of the attacker-on-path walk
// (console/seed-log only; NOT written to any CSV).
static uint32_t g_flowsWithAttackerOnPath  = 0;
static uint32_t g_flowsWithValidPath       = 0;

// LEAK-001: kept but routed to oracle only.
static double   g_minAttackerTrust   = 1.0;
static double   g_avgAttackerTrust   = 1.0;
static uint32_t g_blacklistMaxSize   = 0;

// Feature collector.
static ns3::olsreval::FeatureCollector g_features;
static bool                        g_featuresActive = false;

// PHY-trace availability flag (OBS-002b / DEG-003).
static bool g_phyTraceAvailable = false;

static Ptr<FlowMonitor>       g_flowMonitor = nullptr;
static FlowMonitorHelper      g_flowHelper;

// TRF-004: one UdpServer per flow destination (order matches g_flowPairs).
// g_udpReceivedAtWindowStart snapshots the SUM of the per-flow counters at
// window start; the counters are monotonic, so the window delta of the sum
// equals the sum of the per-flow window deltas.
static std::vector<Ptr<UdpServer>> g_udpServers;
static uint64_t               g_udpReceivedAtWindowStart = 0;

static bool                   g_runRejected   = false;
static std::string            g_rejectReason  = "";
static double                 g_rejectedAtSec = 0.0;

static std::string            g_topologyProbeFile = "";
static bool                   g_probeMobility     = false;
static uint32_t               g_currentRun        = 1;

// WIN-001: measurement-window order. g_scenarioOrder[slot] is the index into
// SCENARIOS[] assigned to that slot. Canonical order is the identity. The
// permutation (when randomized) is computed once in main() from a separate
// std::mt19937 seeded by --run, so it never touches the ns-3 RNG stream.
static std::array<int, NUM_SLOTS> g_scenarioOrder = {{0, 1, 2, 3}};
static bool g_randomWindowOrder = false;

// Tracks the currently-applied (attack, defense) state so slot transitions
// only toggle what actually changes between consecutive slots.
static bool g_attackCurrentlyOn  = false;
static bool g_defenseCurrentlyOn = false;

// WBR-001/002: handle to the node container (set once in main) so the
// per-window cold start and the optional state-size debug print can reach
// every node's defense object. Points at main()'s local NodeContainer, which
// outlives Simulator::Run() -- the same lifetime pattern already used for the
// &nodes argument bound into ObserveAttackerOnPath.
static NodeContainer*         g_simNodes          = nullptr;
static bool                   g_debugDefenseState = false;

static std::map<Ipv4Address, uint32_t> g_ipToNode;
static std::map<uint32_t, Mac48Address> g_nodeToMac;       // for first-hop-MAC
static Ipv4Address            g_clientIp;

// TRF-001/002: the per-run selected data flows (node-id pairs;
// g_flowPairs[0] is ALWAYS the legacy node1 -> node0 pair) plus the
// per-destination lookups that replace the old single-victim globals:
// node id -> main IPv4 address (t=60 gate, oracle path walk), and
// flow-destination IP -> destination MAC (PHY-level last-hop delivery
// detection, see PhyTxBeginCallback Branch B).
static std::vector<std::pair<uint32_t, uint32_t>> g_flowPairs;
static std::map<uint32_t, Ipv4Address>            g_nodeToIp;
static std::map<Ipv4Address, Mac48Address>        g_flowDstMacByIp;

// OBS-004 (TRF-002): (src, dst, IP-id) -> on-air observation record. Used
// to correlate per-packet observations across multiple trace events:
//   * First observation: source's Ipv4::Tx -- record firstSeenTime,
//     bytes, src/dst, lastTtl. Counted as "packet sent."
//   * Subsequent observations: each forwarder's Ipv4::Tx -- update
//     lastSeenTime, lastTtl, observationCount, capture firstHopMac
//     from the SECOND observation.
//   * Delivery: declared in PhyTxBeginCallback when a data frame's
//     L2 destination MAC equals the MAC of the node owning the frame's
//     IP destination -- and that destination is one of this run's flow
//     destinations (i.e., the genuine last-hop transmission). This is
//     the ONLY reliable observable
//     delivery signal -- counting observationCount alone would falsely
//     credit packets the attacker blackholes after one or more relays
//     pick them up.
//
// Map cleared at window-start (ResetOlsrCounters) and window-end
// (FinalizeInFlightDeliveries). Undelivered IP-ids at window-end stay
// undelivered -- matching the oracle's accounting.
struct FirstOnAirRec
{
  double       firstSeenTime    = 0.0;
  double       lastSeenTime     = 0.0;
  uint32_t     bytes            = 0;
  Ipv4Address  src;
  Ipv4Address  dst;
  Mac48Address firstHopMac;            // L2 src of the SECOND observation
  uint8_t      lastTtl          = 0;   // (unused for delivery; kept for diagnostics)
  uint32_t     observationCount = 0;   // (kept for diagnostics)
};
// TRF-002: with NUM_DATA_FLOWS concurrent sources the bare IP-id is NOT
// unique on the medium -- ns-3 assigns the IP Identification per
// (src,dst,protocol) starting at 0 on EVERY node, so simultaneous flows
// collide on the 16-bit id alone. The correlation key is therefore the
// passively observable triple (src, dst, IP-id), all read from the IP
// header on the air.
using FlowPacketKey = std::tuple<uint32_t, uint32_t, uint16_t>;
static inline FlowPacketKey
MakeFlowPacketKey (Ipv4Address src, Ipv4Address dst, uint16_t ipId)
{
  return FlowPacketKey (src.Get (), dst.Get (), ipId);
}
static std::map<FlowPacketKey, FirstOnAirRec> g_firstOnAirByFlowIpId;

// RUN-004: staging file paths and persistent counters.
struct StagingFiles
{
  std::string runs;
  std::string features;
  std::string labels;
  std::string oracle;
  std::vector<std::string> featureRows;   // buffered
  std::vector<std::string> labelRows;
  std::vector<std::string> oracleRows;
  std::string runRow;
};
static StagingFiles g_staging;

// Topology probe state (unchanged structure).
struct ProbeFeatures
{
  bool     captured                  = false;
  double   avgNei                    = 0.0;
  double   stdNei                    = 0.0;
  double   minNei                    = 0.0;
  double   maxNei                    = 0.0;
  double   avgTwo                    = 0.0;
  double   stdTwo                    = 0.0;
  double   avgRt                     = 0.0;
  double   stdRt                     = 0.0;
  uint32_t fullyConverged            = 0;
  int      node1IsNeighborOfNode0    = 0;
  double   avgMinDist                = 0.0;
};
static ProbeFeatures g_probeFeatures;

// ============================================================================
// Forward declarations
// ============================================================================
static Ptr<olsr::RoutingProtocol> GetOlsrProtocol (Ptr<Node> node);
static std::vector<uint32_t>      WalkOlsrPath   (NodeContainer& nodes,
                                                  Ipv4Address src,
                                                  Ipv4Address dst);
static void                       AssertMinHops  (NodeContainer* cont,
                                                  uint32_t minHops);
static void                       CheckAndReportConnectivity (NodeContainer* cont);
static void                       ResetOlsrCounters ();

// ============================================================================
// Header strings (single source of truth; used both by --emit-header and by
// the per-table write paths)
// ============================================================================
static const char* RUNS_HEADER =
  "run_id,rng_run,rng_seed,harness_version,header_version,"
  "n_nodes,grid_x,grid_y,mobility,radio_range,min_hops_required,"
  "num_attackers,attackers_list,spoof_count,attacker_jitter,"
  "defense_variant,redundant_mpr,malicious_threshold,uncertainty_beta,"
  "fading_factor,max_load,max_delay,cheat_threshold,"
  "trust_update_interval_s,phy_trace_available,wall_clock_seconds,"
  "random_window_order,window_order_perm,slot0_scenario";

static const char* LABELS_HEADER =
  "run_id,scenario,window_start,window_end,"
  "defense_enabled,attack_enabled,"
  "attacker_on_path,num_attackers_label";

static const char* ORACLE_HEADER =
  "run_id,scenario,window_start,window_end,"
  "throughput_mbps,pdr_percent,avg_delay_s,"
  "tx_packets,rx_packets,rx_bytes,"
  "udp_rx_in_window,udp_expected_in_window,udp_loss_percent,overhead_ratio,"
  "hello_count,olsr_control_bytes_with_hello,"
  "path_hops_internal,"
  "min_attacker_trust,avg_attacker_trust,blacklist_max_size,"
  "mac_tx_in_window,mac_drop_in_window,mac_tx_total,mac_drop_total";

// FEATURES_HEADER is built from the identifier prefix + g_features header.
static std::string BuildFeaturesHeader ()
{
  std::string h =
    "run_id,scenario,window_start,window_end,window_duration_s,";
  h += ns3::olsreval::FeatureCollector::FeatureCsvHeader ();
  return h;
}

// ============================================================================
// Small numeric helpers
// ============================================================================
static double ComputeMean (const std::vector<double>& v)
{
  if (v.empty ()) return 0.0;
  double s = 0.0;
  for (double x : v) s += x;
  return s / v.size ();
}

static double ComputeStdDev (const std::vector<double>& v, double mean)
{
  if (v.size () < 2) return 0.0;
  double s = 0.0;
  for (double x : v)
    {
      const double d = x - mean;
      s += d * d;
    }
  return std::sqrt (s / v.size ());
}

// ============================================================================
// OLSR routing-protocol access helpers (unchanged)
// ============================================================================
static Ptr<olsr::RoutingProtocol>
GetOlsrProtocol (Ptr<Node> node)
{
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
  if (!ipv4) return nullptr;
  Ptr<Ipv4ListRouting> list = DynamicCast<Ipv4ListRouting> (ipv4->GetRoutingProtocol ());
  if (!list) return nullptr;
  for (uint32_t i = 0; i < list->GetNRoutingProtocols (); ++i)
    {
      int16_t prio;
      Ptr<Ipv4RoutingProtocol> child = list->GetRoutingProtocol (i, prio);
      Ptr<olsr::RoutingProtocol> olsrProto = DynamicCast<olsr::RoutingProtocol> (child);
      if (olsrProto) return olsrProto;
    }
  return nullptr;
}

static std::vector<uint32_t>
WalkOlsrPath (NodeContainer& nodes, Ipv4Address src, Ipv4Address dst)
{
  std::vector<uint32_t> path;
  std::set<Ipv4Address> visited;
  Ipv4Address current = src;
  const uint32_t maxHops = nodes.GetN () + 2;
  for (uint32_t step = 0; step < maxHops; ++step)
    {
      if (visited.count (current)) return {};
      visited.insert (current);
      auto it = g_ipToNode.find (current);
      if (it == g_ipToNode.end ()) return {};
      const uint32_t nodeIdx = it->second;
      path.push_back (nodeIdx);
      if (current == dst) return path;
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (nodes.Get (nodeIdx));
      if (!proto) return {};
      const auto entries = proto->GetRoutingTableEntries ();
      Ipv4Address nextHop;
      bool found = false;
      for (const auto& e : entries)
        {
          if (e.destAddr == dst)
            {
              nextHop = e.nextAddr;
              found = true;
              break;
            }
        }
      if (!found) return {};
      current = nextHop;
    }
  return {};
}

// ============================================================================
// Context parser
// ============================================================================
static uint32_t
ParseNodeIdFromContext (const std::string& context)
{
  std::size_t start = context.find ("/NodeList/");
  if (start == std::string::npos) return 0;
  start += 10;
  std::size_t end = context.find ("/", start);
  if (end == std::string::npos) return 0;
  return static_cast<uint32_t> (std::stoul (context.substr (start, end - start)));
}
// ============================================================================
// Trace callbacks  (POST-AUDIT REWRITE)
// ============================================================================

// --------- Mac/MacTx callback (oracle-only per-node counter) ----------------
// We previously tried to parse the IP datagram at MacTx, but at this trace
// point the packet has an LLC/SNAP header (8 bytes) prepended by
// WifiNetDevice::Send() before being handed to the MAC layer. The IP
// datagram is NOT at offset 0. To avoid LLC-handling complexity, we
// observe data packets at Ipv4::Tx instead (where the packet is the bare
// IP datagram). MacTx is kept only for the per-node oracle counter.
static void
MacTxOracleOnlyCallback (std::string context, Ptr<const Packet> /*packet*/)
{
  const uint32_t nodeId = ParseNodeIdFromContext (context);
  if (nodeId < g_macTxPerNode.size ()) g_macTxPerNode[nodeId]++;
}

// Called at end of each measurement window to clear in-flight entries.
// Delivery is now declared at PHY level inside PhyTxBeginCallback (when
// the L2 destination MAC equals the flow destination's MAC), so the only
// thing left here is to drop any entries that were sent but never reached
// their destination --
// these are the genuinely-undelivered packets (dropped, lost, or still
// in flight at window end). They contribute to PacketsSentCount but not
// to PacketsDeliveredCount or to the latency / throughput totals,
// matching the oracle's accounting.
//
// If PHY trace is unavailable, no deliveries get declared at all -- the
// G-group features degrade gracefully and phy_trace_available=0 in
// runs.csv records the fact (just like F-group).
static void
FinalizeInFlightDeliveries ()
{
  g_firstOnAirByFlowIpId.clear ();
}

// --------- MacTxDrop: oracle-only per-node drop count (OBS-001) -------------
// We no longer treat MacTxDrop as a "collision" or "unack'd reception"
// (MIS-002). It is a sender-side pre-air drop. Count for the oracle and stop.
static void
MacTxDropCallback (std::string context, Ptr<const Packet> packet)
{
  (void) packet;
  const uint32_t nodeId = ParseNodeIdFromContext (context);
  if (nodeId < g_macDropPerNode.size ()) g_macDropPerNode[nodeId]++;
}

// --------- PhyTxBegin sniffer: real MAC header (OBS-002b) -------------------
// At PhyTxBegin the frame has its WifiMacHeader attached. We drop 1-hop
// RTS/CTS/ACK control frames (OBS-007), HELLO-filter (by parsing the MSDU
// under the MAC header), then feed F-group features.
//
// The signature of MonitorSnifferTx / PhyTxBegin has varied across ns-3
// versions; we connect via a failsafe wrapper that catches and skips on
// signature mismatch.
//
// Expected ns-3-dev signature (current main): (Ptr<const Packet>, double txPowerW)
// We use a single-argument variant as a fallback if 2-arg fails.
static void
PhyTxBeginCallback (std::string context, Ptr<const Packet> packet, double /*txPowerW*/)
{
  if (!g_featuresActive) return;
  if (!g_phyTraceAvailable) return;

  // Peek the WifiMacHeader (now valid at PHY layer).
  Ptr<Packet> p = packet->Copy ();
  WifiMacHeader macHdr;
  if (p->PeekHeader (macHdr) == 0) return;
  p->RemoveHeader (macHdr);

  // OBS-007: RTS/CTS/ACK are 1-hop MAC control frames with the same
  // observability limit as HELLO -- a remote passive attacker cannot
  // reliably sniff them. Drop them BEFORE any feature observation
  // (mirror of the OBS-001 HELLO filter). See olsr_window_features.h.
  if (macHdr.IsRts () || macHdr.IsCts () || macHdr.IsAck ()) return;

  const bool isData = macHdr.IsData ();
  const bool isRetry = macHdr.IsRetry ();
  const double now = Simulator::Now ().GetSeconds ();
  const double durSec = macHdr.GetDuration ().GetSeconds ();

  // HELLO filter AND delivery detection. At PHY layer the MSDU layout is:
  //   WifiMacHeader (already removed above)
  // + LlcSnapHeader (8 bytes added by WifiNetDevice::Send)
  // + IP + UDP + payload
  // + WifiMacTrailer (4-byte FCS, NOT present at IP-layer trace)
  //
  // We must (a) skip LLC before parsing IP, (b) bound OLSR parsing by the
  // packetLength field so we don't deserialize FCS bytes as a fake OLSR
  // message header (which would trip NS_ASSERT and abort).
  //
  // Two purposes here:
  //   * For OLSR (UDP port 698): filter HELLO out of F-group features.
  //   * For DATA (UDP port 80): if the L2 dst MAC equals the MAC of the
  //     node owning the frame's IP destination -- one of this run's flow
  //     destinations -- this is the genuine LAST-HOP transmission of that
  //     flow, and we declare delivery for the corresponding
  //     (src,dst,IP-id) key (TRF-002). This is the ONLY reliable
  //     delivery signal observable to an eavesdropper -- using
  //     observationCount alone would falsely count packets the attacker
  //     blackholes (they accumulate observations at the relays before
  //     the attacker drops them).
  if (isData)
    {
      Ptr<Packet> msduCopy = packet->Copy ();
      WifiMacHeader skipMac;
      msduCopy->RemoveHeader (skipMac);
      LlcSnapHeader skipLlc;
      if (msduCopy->GetSize () < skipLlc.GetSerializedSize ())
        { g_features.ObserveMacFrame (now, durSec, isData, isRetry); return; }
      msduCopy->RemoveHeader (skipLlc);
      Ipv4Header ipHdr;
      if (msduCopy->GetSize () >= ipHdr.GetSerializedSize ())
        {
          msduCopy->RemoveHeader (ipHdr);
          if (ipHdr.GetProtocol () == 17)
            {
              UdpHeader udpHdr;
              if (msduCopy->GetSize () >= udpHdr.GetSerializedSize ())
                {
                  msduCopy->RemoveHeader (udpHdr);
                  const uint16_t dstPort = udpHdr.GetDestinationPort ();

                  // --- Branch A: OLSR (port 698) -- HELLO filter only ---
                  if (dstPort == 698)
                    {
                      olsr::PacketHeader olsrHdr;
                      const uint32_t olsrHdrSize = olsrHdr.GetSerializedSize ();
                      if (msduCopy->GetSize () >= olsrHdrSize)
                        {
                          msduCopy->RemoveHeader (olsrHdr);
                          uint32_t remaining = 0;
                          if (olsrHdr.GetPacketLength () >= olsrHdrSize)
                            remaining = olsrHdr.GetPacketLength () - olsrHdrSize;
                          if (remaining > msduCopy->GetSize ())
                            remaining = msduCopy->GetSize ();
                          while (remaining >= 12)
                            {
                              uint8_t firstByte = 0;
                              if (msduCopy->CopyData (&firstByte, 1) != 1) break;
                              if (firstByte < 1 || firstByte > 4) break;
                              olsr::MessageHeader m;
                              const uint32_t before = msduCopy->GetSize ();
                              msduCopy->RemoveHeader (m);
                              const uint32_t after = msduCopy->GetSize ();
                              const uint32_t consumed =
                                  (before >= after) ? (before - after) : 0;
                              if (consumed == 0 || consumed > remaining) break;
                              remaining -= consumed;
                              // FEAT-008: record on-air relay of this TC
                              // copy (transmitter = MAC Addr2). Feeds the
                              // schema's group-A suppression features;
                              // copies are deduplicated by
                              // (originator, msg-seq) inside the collector.
                              if (m.GetMessageType ()
                                  == olsr::MessageHeader::TC_MESSAGE)
                                {
                                  g_features.ObserveTcRelayOnAir (
                                      m.GetOriginatorAddress (),
                                      m.GetMessageSequenceNumber (),
                                      m.GetHopCount (),
                                      macHdr.GetAddr2 ());
                                }
                              if (m.GetMessageType ()
                                  == olsr::MessageHeader::HELLO_MESSAGE)
                                return;  // skip HELLO from F-group features
                            }
                        }
                    }
                  // --- Branch B: data to a flow destination (port 80) ---
                  // Last-hop detection (TRF-002): this transmission is
                  // addressed at L2 to the MAC of the node that owns the
                  // frame's IP destination, and that destination is one of
                  // this run's flow destinations. That makes this the final
                  // hop; no forwarder will retransmit, the packet has been
                  // delivered.
                  else if (dstPort == UDP_PORT && g_featuresActive)
                    {
                      // FEAT-008: every observed DATA forward feeds the
                      // group-B isolation-breadth features (forwarder =
                      // MAC Addr2, next-hop = MAC Addr1). Reroute detection
                      // and distinct-pair counting happen in the collector.
                      g_features.ObserveDataForwardOnAir (
                          macHdr.GetAddr2 (), macHdr.GetAddr1 (),
                          ipHdr.GetDestination ());
                      const auto dstIt =
                          g_flowDstMacByIp.find (ipHdr.GetDestination ());
                      if (dstIt != g_flowDstMacByIp.end ()
                          && macHdr.GetAddr1 () == dstIt->second)
                        {
                          const FlowPacketKey key = MakeFlowPacketKey (
                              ipHdr.GetSource (), ipHdr.GetDestination (),
                              ipHdr.GetIdentification ());
                          auto it = g_firstOnAirByFlowIpId.find (key);
                          if (it != g_firstOnAirByFlowIpId.end ())
                            {
                              const double lat = std::max (
                                  0.0, now - it->second.firstSeenTime);
                              g_features.ObserveDataDeliveredOnAir (
                                  it->second.src, it->second.dst,
                                  ipHdr.GetTtl (), lat,
                                  it->second.firstHopMac, now);
                              g_features.AddDeliveredBytes (it->second.bytes);
                              g_firstOnAirByFlowIpId.erase (it);
                            }
                        }
                    }
                }
            }
        }
    }

  g_features.ObserveMacFrame (now, durSec, isData, isRetry);
}

// Failsafe trace connect. Uses Config::ConnectFailSafe which returns
// false if no objects match the path (instead of NS_FATAL_ERROR'ing
// like the regular Config::Connect). Catches std::exception for any
// other failure mode. On any failure, sets g_phyTraceAvailable=false
// and the F-group features emit 0.
//
// NOTE: a signature mismatch (e.g. PhyTxBegin callback type changed in
// some future ns-3 version) would manifest as a compile error, not a
// runtime failure -- the build would fail before we ever get here.
static bool
TryConnectPhyTrace ()
{
  try
    {
      const bool ok = Config::ConnectFailSafe (
          "/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxBegin",
          MakeCallback (&PhyTxBeginCallback));
      if (!ok)
        {
          std::cerr << "[phy_trace] no matching trace sources for "
                       "Phy/PhyTxBegin; F-group features will emit 0"
                    << std::endl;
        }
      return ok;
    }
  catch (std::exception& e)
    {
      std::cerr << "[phy_trace] connect failed: " << e.what () << std::endl;
      return false;
    }
  catch (...)
    {
      std::cerr << "[phy_trace] connect failed: unknown exception" << std::endl;
      return false;
    }
}

// --------- Ipv4 Tx trace: OLSR control parsing AND data observation -------
// At Ipv4::Tx the packet is the bare IP datagram (no LLC, no MAC header).
// This trace fires for every IP transmission from this node: originated
// packets (Send()) AND forwarded packets (IpForward()).
//
// We dispatch by UDP destination port:
//   port 698 -> OLSR control (TC/MID/HNA -> features, HELLO -> oracle)
//   port 80  -> data packet -> on-air observation ((src,dst,IP-id)
//               correlation, TRF-002)
//
// We pass Ptr<Ipv4> to get the originating node ID (needed for
// first-hop-MAC tracking via g_nodeToMac).
static void
TraceOlsrPacket (Ptr<const Packet> packet, Ptr<Ipv4> ipv4, uint32_t /*interface*/)
{
  Ptr<Packet> pktCopy = packet->Copy ();
  Ipv4Header ipHeader;
  if (pktCopy->GetSize () < ipHeader.GetSerializedSize ()) return;
  pktCopy->RemoveHeader (ipHeader);
  if (ipHeader.GetProtocol () != 17) return;
  UdpHeader udpHeader;
  if (pktCopy->GetSize () < udpHeader.GetSerializedSize ()) return;
  pktCopy->RemoveHeader (udpHeader);
  const uint16_t dstPort = udpHeader.GetDestinationPort ();

  // ===== Branch A: OLSR control traffic (port 698) =========================
  if (dstPort == 698)
    {
      const Ipv4Address senderIfaceAddr = ipHeader.GetSource ();
      g_olsrControlBytesWithHello += packet->GetSize ();   // oracle only

      olsr::PacketHeader olsrHeader;
      const uint32_t olsrHdrSize = olsrHeader.GetSerializedSize ();
      if (pktCopy->GetSize () < olsrHdrSize) return;
      pktCopy->RemoveHeader (olsrHeader);

      // Bound parsing by OLSR's own length field (defensive: avoids
      // any chance of mis-parsing trailing bytes as a fake message).
      uint32_t remaining = 0;
      if (olsrHeader.GetPacketLength () >= olsrHdrSize)
        remaining = olsrHeader.GetPacketLength () - olsrHdrSize;
      if (remaining > pktCopy->GetSize ()) remaining = pktCopy->GetSize ();

      while (remaining >= 12)        // OLSR MessageHeader min = 12 bytes
        {
          // Validate message type byte before RemoveHeader to avoid
          // tripping the NS_ASSERT on corrupt/non-OLSR bytes.
          uint8_t firstByte = 0;
          if (pktCopy->CopyData (&firstByte, 1) != 1) break;
          if (firstByte < 1 || firstByte > 4) break;

          olsr::MessageHeader msg;
          const uint32_t before = pktCopy->GetSize ();
          pktCopy->RemoveHeader (msg);
          const uint32_t after = pktCopy->GetSize ();
          const uint32_t consumed = (before >= after) ? (before - after) : 0;
          if (consumed == 0 || consumed > remaining) break;
          remaining -= consumed;

          const uint32_t msgSize = msg.GetSerializedSize ();
          const Ipv4Address originator = msg.GetOriginatorAddress ();
          switch (msg.GetMessageType ())
            {
            case olsr::MessageHeader::HELLO_MESSAGE:
              ++g_helloCount;          // oracle only -- HELLO is non-observable
              break;
            case olsr::MessageHeader::TC_MESSAGE:
              ++g_tcCount;
              g_totalTcRows += msg.GetTc ().neighborAddresses.size ();
              if (g_featuresActive)
                g_features.ObserveTc (senderIfaceAddr, originator, msg,
                                      msg.GetTc (), msgSize);
              break;
            case olsr::MessageHeader::MID_MESSAGE:
              ++g_midCount;
              if (g_featuresActive) g_features.ObserveMid (originator, msgSize);
              break;
            case olsr::MessageHeader::HNA_MESSAGE:
              ++g_hnaCount;
              if (g_featuresActive) g_features.ObserveHna (originator, msgSize);
              break;
            default:
              break;
            }
        }
      return;
    }

  // ===== Branch B: UDP data traffic of the measured flows (port 80) ========
  if (dstPort != UDP_PORT) return;
  if (!g_featuresActive) return;

  const double      now      = Simulator::Now ().GetSeconds ();
  const uint16_t    ipId     = ipHeader.GetIdentification ();
  const Ipv4Address ipSrc    = ipHeader.GetSource ();
  const Ipv4Address ipDst    = ipHeader.GetDestination ();
  const uint8_t     ttl      = ipHeader.GetTtl ();
  const uint32_t    pktBytes = packet->GetSize ();

  // Identify the originating node from Ptr<Ipv4>.
  uint32_t nodeId = std::numeric_limits<uint32_t>::max ();
  if (ipv4)
    {
      Ptr<Node> node = ipv4->GetObject<Node> ();
      if (node) nodeId = node->GetId ();
    }

  const FlowPacketKey key = MakeFlowPacketKey (ipSrc, ipDst, ipId);
  auto it = g_firstOnAirByFlowIpId.find (key);
  if (it == g_firstOnAirByFlowIpId.end ())
    {
      // First observation = source's Ipv4::Tx (initial TTL=64).
      FirstOnAirRec rec;
      rec.firstSeenTime    = now;
      rec.lastSeenTime     = now;
      rec.bytes            = pktBytes;
      rec.src              = ipSrc;
      rec.dst              = ipDst;
      rec.firstHopMac      = Mac48Address ();
      rec.lastTtl          = ttl;
      rec.observationCount = 1;
      g_firstOnAirByFlowIpId[key] = rec;
      g_features.ObserveDataSentOnAir (ipSrc, ipDst, pktBytes, now);
    }
  else
    {
      // Subsequent observation = a forwarder's Ipv4::Tx.
      it->second.lastSeenTime = now;
      it->second.lastTtl      = ttl;
      it->second.observationCount++;
      // BUG-004: the SECOND observation (first forwarder) gives the
      // first-hop MAC. Subsequent observations leave it unchanged.
      if (it->second.firstHopMac == Mac48Address ()
          && nodeId != std::numeric_limits<uint32_t>::max ())
        {
          auto macIt = g_nodeToMac.find (nodeId);
          if (macIt != g_nodeToMac.end ())
            it->second.firstHopMac = macIt->second;
        }
      // Delivery is declared at PHY layer (in PhyTxBeginCallback) when the
      // last-hop transmission addressed to the flow's destination is observed.
    }
}
// ============================================================================
// Connectivity gates (unchanged)
// ============================================================================
static void
AssertConnectivity (NodeContainer* cont)
{
  if (g_runRejected) return;
  const uint32_t N = cont->GetN ();
  for (uint32_t i = 0; i < N; ++i)
    {
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (cont->Get (i));
      if (!proto)
        {
          std::cout << "*** No OLSR proto on node " << i << ". Terminated."
                    << std::endl;
          g_runRejected = true;
          g_rejectReason = "no_olsr";
          g_rejectedAtSec = Simulator::Now ().GetSeconds ();
          Simulator::Stop ();
          return;
        }
      const auto entries = proto->GetRoutingTableEntries ();
      std::set<Ipv4Address> uniqueDests;
      for (const auto& e : entries) uniqueDests.insert (e.destAddr);
      if (uniqueDests.size () < N - 1)
        {
          std::cout << "*** Assert connectivity failed at node " << i
                    << " (unique destinations " << uniqueDests.size ()
                    << ", expected at least " << (N - 1) << "). Terminated."
                    << std::endl;
          g_runRejected = true;
          g_rejectReason = "assert_connectivity";
          g_rejectedAtSec = Simulator::Now ().GetSeconds ();
          Simulator::Stop ();
          return;
        }
    }
}

static void
AssertMinHops (NodeContainer* cont, uint32_t minHops)
{
  if (g_runRejected) return;
  if (cont->GetN () < 2) return;
  // TRF-003: the gate now checks EVERY selected flow pair. g_flowPairs[0]
  // is the legacy node1 -> node0 pair, so its check -- and the
  // run-acceptance behavior of every previously accepted seed -- is
  // unchanged; the additional pairs satisfy the geometric >= minHops bound
  // by construction, so they can only reject here in the (essentially
  // impossible) selection-fallback case. Rejection reason strings are
  // UNCHANGED.
  for (std::size_t f = 0; f < g_flowPairs.size (); ++f)
    {
      const uint32_t srcId = g_flowPairs[f].first;
      const uint32_t dstId = g_flowPairs[f].second;
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (cont->Get (srcId));
      if (!proto)
        {
          std::cout << "*** No OLSR proto on flow " << f << " source node "
                    << srcId << ". Terminated." << std::endl;
          g_runRejected = true;
          g_rejectReason = "no_olsr_on_client";
          g_rejectedAtSec = Simulator::Now ().GetSeconds ();
          Simulator::Stop ();
          return;
        }
      const auto ipIt = g_nodeToIp.find (dstId);
      const Ipv4Address dstAddr =
          (ipIt != g_nodeToIp.end ()) ? ipIt->second : Ipv4Address ();
      uint32_t distance = 0;
      bool found = false;
      for (const auto& e : proto->GetRoutingTableEntries ())
        {
          if (e.destAddr == dstAddr)
            {
              distance = e.distance;
              found = true;
              break;
            }
        }
      if (!found)
        {
          std::cout << "*** No route for flow " << f << " (" << srcId
                    << " -> " << dstId << ") at t=60. Terminated."
                    << std::endl;
          g_runRejected = true;
          g_rejectReason = "no_route_to_victim";
          g_rejectedAtSec = Simulator::Now ().GetSeconds ();
          Simulator::Stop ();
          return;
        }
      if (distance < minHops)
        {
          std::cout << "*** Flow " << f << " (" << srcId << " -> " << dstId
                    << ") too close: " << distance
                    << " hops, need at least " << minHops << ". Terminated."
                    << std::endl;
          g_runRejected = true;
          g_rejectReason = "too_close";
          g_rejectedAtSec = Simulator::Now ().GetSeconds ();
          Simulator::Stop ();
          return;
        }
      std::cout << "Distance flow " << f << " (" << srcId << " -> " << dstId
                << ") at t=60: " << distance << " hops (>= " << minHops
                << " required). OK." << std::endl;
    }
}

static void
CheckAndReportConnectivity (NodeContainer* cont)
{
  if (g_runRejected) return;
  uint32_t fullyConnected = 0;
  const uint32_t N = cont->GetN ();
  for (uint32_t i = 0; i < N; ++i)
    {
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (cont->Get (i));
      if (!proto) continue;
      const auto entries = proto->GetRoutingTableEntries ();
      std::set<Ipv4Address> uniqueDests;
      for (const auto& e : entries) uniqueDests.insert (e.destAddr);
      if (uniqueDests.size () >= N - 1) fullyConnected++;
    }
  const double ratio = (double) fullyConnected / N;
  std::cout << "Connectivity check: " << fullyConnected << "/" << N
            << " nodes fully connected (" << (ratio * 100.0) << "%)" << std::endl;
}

// ============================================================================
// Topology probe (unchanged structure; writes to probe.csv)
// ============================================================================
static void
FlushTopologyProbe (const std::string& status,
                    const std::string& rejectReason,
                    double rejectedAtSec)
{
  if (g_topologyProbeFile.empty ()) return;
  int fd = open (g_topologyProbeFile.c_str (), O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0)
    {
      std::cerr << "[topology_probe] open failed for " << g_topologyProbeFile
                << " (errno=" << errno << ")" << std::endl;
      return;
    }
  if (flock (fd, LOCK_EX) < 0)
    {
      std::cerr << "[topology_probe] flock failed (errno=" << errno << ")" << std::endl;
      close (fd);
      return;
    }
  off_t sz = lseek (fd, 0, SEEK_END);
  if (sz == 0)
    {
      const char* hdr =
          "seed,run_id,mobility,status,rejection_reason,rejected_at_s,"
          "probe_captured,"
          "avg_neighbor_count,std_neighbor_count,"
          "min_neighbor_count,max_neighbor_count,"
          "avg_two_hop_count,std_two_hop_count,"
          "avg_routing_table_size,std_routing_table_size,"
          "fully_converged_nodes,node1_is_neighbor_of_node0,"
          "avg_min_euclidean_dist\n";
      ssize_t hw = write (fd, hdr, std::strlen (hdr));
      (void) hw;
    }
  std::ostringstream row;
  row << std::fixed << std::setprecision (6);
  row << RngSeedManager::GetRun () << ","
      << g_currentRun << ","
      << (g_probeMobility ? 1 : 0) << ","
      << status << ","
      << (rejectReason.empty () ? "none" : rejectReason) << ","
      << rejectedAtSec << ","
      << (g_probeFeatures.captured ? 1 : 0) << ","
      << g_probeFeatures.avgNei << "," << g_probeFeatures.stdNei << ","
      << g_probeFeatures.minNei << "," << g_probeFeatures.maxNei << ","
      << g_probeFeatures.avgTwo << "," << g_probeFeatures.stdTwo << ","
      << g_probeFeatures.avgRt  << "," << g_probeFeatures.stdRt  << ","
      << g_probeFeatures.fullyConverged << ","
      << g_probeFeatures.node1IsNeighborOfNode0 << ","
      << g_probeFeatures.avgMinDist << "\n";
  const std::string s = row.str ();
  ssize_t w = write (fd, s.c_str (), s.size ());
  (void) w;
  flock (fd, LOCK_UN);
  close (fd);
}

static void
RecordTopologyProbe (NodeContainer* cont, double radioRange)
{
  if (g_topologyProbeFile.empty ()) return;
  if (cont == nullptr || cont->GetN () == 0) return;
  const uint32_t N = cont->GetN ();
  std::vector<Vector> pos (N);
  for (uint32_t i = 0; i < N; ++i)
    {
      Ptr<MobilityModel> mm = cont->Get (i)->GetObject<MobilityModel> ();
      pos[i] = mm ? mm->GetPosition () : Vector (0, 0, 0);
    }
  const double r2 = radioRange * radioRange;
  std::vector<std::vector<uint32_t>> adj (N);
  for (uint32_t i = 0; i < N; ++i)
    for (uint32_t j = i + 1; j < N; ++j)
      {
        const double dx = pos[i].x - pos[j].x;
        const double dy = pos[i].y - pos[j].y;
        const double dz = pos[i].z - pos[j].z;
        if (dx * dx + dy * dy + dz * dz <= r2)
          {
            adj[i].push_back (j);
            adj[j].push_back (i);
          }
      }
  std::vector<double> neighborCounts (N), twoHopCounts (N), rtSizes (N);
  uint32_t fullyConverged = 0;
  double minNei = std::numeric_limits<double>::infinity ();
  double maxNei = -std::numeric_limits<double>::infinity ();
  for (uint32_t i = 0; i < N; ++i)
    {
      const double deg = (double) adj[i].size ();
      neighborCounts[i] = deg;
      if (deg < minNei) minNei = deg;
      if (deg > maxNei) maxNei = deg;
      std::set<uint32_t> oneHop (adj[i].begin (), adj[i].end ());
      std::set<uint32_t> twoHop;
      for (uint32_t u : oneHop)
        for (uint32_t v : adj[u])
          {
            if (v == i) continue;
            if (oneHop.count (v)) continue;
            twoHop.insert (v);
          }
      twoHopCounts[i] = (double) twoHop.size ();
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (cont->Get (i));
      const uint32_t rtSize = proto ? proto->GetRoutingTableEntries ().size () : 0;
      rtSizes[i] = (double) rtSize;
      if (rtSize == N - 1) fullyConverged++;
    }
  if (!std::isfinite (minNei)) minNei = 0.0;
  if (!std::isfinite (maxNei)) maxNei = 0.0;
  const double avgNei = ComputeMean (neighborCounts);
  const double stdNei = ComputeStdDev (neighborCounts, avgNei);
  const double avgTwo = ComputeMean (twoHopCounts);
  const double stdTwo = ComputeStdDev (twoHopCounts, avgTwo);
  const double avgRt  = ComputeMean (rtSizes);
  const double stdRt  = ComputeStdDev (rtSizes, avgRt);
  int node1IsNeighbor = 0;
  if (N >= 2)
    for (uint32_t v : adj[UDP_CLIENT_NODE_ID])
      if (v == UDP_SERVER_NODE_ID) { node1IsNeighbor = 1; break; }
  double sumMinDist = 0.0;
  uint32_t counted = 0;
  for (uint32_t i = 0; i < N; ++i)
    {
      double localMin = std::numeric_limits<double>::infinity ();
      for (uint32_t j = 0; j < N; ++j)
        {
          if (i == j) continue;
          const double dx = pos[i].x - pos[j].x;
          const double dy = pos[i].y - pos[j].y;
          const double dz = pos[i].z - pos[j].z;
          const double d = std::sqrt (dx*dx + dy*dy + dz*dz);
          if (d < localMin) localMin = d;
        }
      if (std::isfinite (localMin)) { sumMinDist += localMin; counted++; }
    }
  const double avgMinDist = (counted > 0) ? (sumMinDist / counted) : 0.0;
  g_probeFeatures.captured              = true;
  g_probeFeatures.avgNei                = avgNei;
  g_probeFeatures.stdNei                = stdNei;
  g_probeFeatures.minNei                = minNei;
  g_probeFeatures.maxNei                = maxNei;
  g_probeFeatures.avgTwo                = avgTwo;
  g_probeFeatures.stdTwo                = stdTwo;
  g_probeFeatures.avgRt                 = avgRt;
  g_probeFeatures.stdRt                 = stdRt;
  g_probeFeatures.fullyConverged        = fullyConverged;
  g_probeFeatures.node1IsNeighborOfNode0 = node1IsNeighbor;
  g_probeFeatures.avgMinDist            = avgMinDist;
}

// ============================================================================
// UDP server snapshot helpers
// ============================================================================
static void
SnapshotUdpReceived ()
{
  // TRF-004: snapshot the SUM of the per-flow server counters; the counters
  // are monotonic, so the window delta of the sum equals the sum of the
  // per-flow window deltas.
  g_udpReceivedAtWindowStart = 0;
  for (const auto& srv : g_udpServers)
    if (srv) g_udpReceivedAtWindowStart += srv->GetReceived ();
}

// LEAK-001/002: this now ONLY populates the global state for the
// ORACLE row (not features). attacker_on_path goes to labels; trust
// values and path_hops go to oracle.
static void
ObserveAttackerOnPath (NodeContainer* nodes,
                       std::vector<uint32_t> attackerIds,
                       std::vector<std::pair<Ipv4Address, Ipv4Address>> flowAddrPairs)
{
  g_attackerOnPathPrevWindow = false;
  g_pathHopsPrevWindow       = 0;
  g_flowsWithAttackerOnPath  = 0;
  g_flowsWithValidPath       = 0;
  g_minAttackerTrust         = 1.0;
  g_avgAttackerTrust         = 1.0;
  g_blacklistMaxSize         = 0;

  if (nodes == nullptr || nodes->GetN () == 0) return;

  // TRF-003: walk EVERY flow's current OLSR path. attacker_on_path (labels)
  // is 1 iff the attacker sits on AT LEAST ONE flow path; path_hops_internal
  // (oracle) is the rounded MEAN hop count over flows with a valid path --
  // the same scale and interpretation as the old single-flow value.
  if (!attackerIds.empty ())
    {
      std::set<uint32_t> attSet (attackerIds.begin (), attackerIds.end ());
      double hopsSum = 0.0;
      for (const auto& fp : flowAddrPairs)
        {
          const auto path = WalkOlsrPath (*nodes, fp.first, fp.second);
          if (path.empty ()) continue;
          ++g_flowsWithValidPath;
          hopsSum += static_cast<double> (path.size () - 1);
          for (uint32_t v : path)
            if (attSet.count (v))
              {
                g_attackerOnPathPrevWindow = true;
                ++g_flowsWithAttackerOnPath;
                break;
              }
        }
      if (g_flowsWithValidPath > 0)
        g_pathHopsPrevWindow = static_cast<uint32_t> (
            std::lround (hopsSum / g_flowsWithValidPath));
    }

  std::set<uint32_t> attSet (attackerIds.begin (), attackerIds.end ());
  double sumTrust  = 0.0;
  uint32_t samples = 0;
  double minTrust  = 1.0;
  uint32_t maxBlSz = 0;

  for (uint32_t i = 0; i < nodes->GetN (); ++i)
    {
      if (attSet.count (i)) continue;
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (nodes->Get (i));
      if (!proto) continue;
      PointerValue pv;
      proto->GetAttribute ("DefenseStrategy", pv);
      Ptr<olsr::OlsrDefenseStrategy> def =
          DynamicCast<olsr::OlsrDefenseStrategy> (pv.Get<olsr::OlsrDefenseStrategy> ());
      if (!def) continue;
      const auto bl = def->GetBlacklist ();
      if (bl.size () > maxBlSz) maxBlSz = bl.size ();
      for (uint32_t attId : attackerIds)
        {
          if (attId >= nodes->GetN ()) continue;
          Ptr<olsr::RoutingProtocol> attProto =
              GetOlsrProtocol (nodes->Get (attId));
          if (!attProto) continue;
          const Ipv4Address attAddr = attProto->GetMainAddress ();
          // Option (b): the Watchdog base interface exposes no GetNodeTrust;
          // derive a binary trust proxy from the (per-node) blacklist instead --
          // 0.0 = this node has blacklisted the attacker, 1.0 = it has not.
          // Keeps oracle columns min/avg_attacker_trust populated with a
          // truthful value without adding an artificial method to the shared
          // OlsrDefenseStrategy contract.
          const double t = (bl.find (attAddr) != bl.end ()) ? 0.0 : 1.0;
          sumTrust += t;
          samples++;
          if (t < minTrust) minTrust = t;
        }
    }
  g_blacklistMaxSize = maxBlSz;
  if (samples > 0)
    {
      g_avgAttackerTrust = sumTrust / samples;
      g_minAttackerTrust = minTrust;
    }
}

static void
ReportNumReceivedPackets ()
{
  uint64_t total = 0;                                  // TRF-004: sum flows
  for (const auto& srv : g_udpServers)
    if (srv) total += srv->GetReceived ();
  std::cout << "Packets (cumulative across all windows, all "
            << g_udpServers.size () << " flows): " << total << std::endl;
}

// ============================================================================
// Attack / defense activation (unchanged)
// ============================================================================
static void
SetAttackState (NodeContainer nodes, std::vector<uint32_t> attackerIds,
                uint32_t spoofCount, bool active)
{
  if (g_runRejected) return;
  for (uint32_t id : attackerIds)
    {
      if (id >= nodes.GetN ()) continue;
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (nodes.Get (id));
      if (!proto) continue;
      proto->SetAttribute ("IsMalicious", BooleanValue (active));
      proto->SetAttribute ("SpoofedLinksCount",
                           UintegerValue (active ? spoofCount : 0));
    }
  std::cout << "[t=" << Simulator::Now ().GetSeconds () << "s] Attack "
            << (active ? "ACTIVATED" : "DEACTIVATED") << std::endl;
}

static void
SetDefenseState (NodeContainer nodes, bool active)
{
  if (g_runRejected) return;
  for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (nodes.Get (i));
      if (!proto) continue;
      PointerValue pv;
      proto->GetAttribute ("DefenseStrategy", pv);
      Ptr<olsr::OlsrWatchdogDefense> def =
          DynamicCast<olsr::OlsrWatchdogDefense> (pv.Get<olsr::OlsrDefenseStrategy> ());
      if (def) def->SetAttribute ("Enabled", BooleanValue (active));
    }
  std::cout << "[t=" << Simulator::Now ().GetSeconds () << "s] Defense "
            << (active ? "ACTIVATED" : "DEACTIVATED") << std::endl;
}

// Forward declarations: ForceDefenseColdStart() and PrintDefenseStateSizes()
// are defined further below but are invoked from ApplyScenarioState (the
// slot-transition cold start). Declare them here so the calls compile.
static void ForceDefenseColdStart ();
static void PrintDefenseStateSizes ();

// WIN-001: apply the (attack, defense) state required by the scenario assigned
// to `slot`, toggling only what actually changes from the currently-applied
// state. Scheduled at each slot transition (t = SlotTransitionTime(slot)).
// The slot-0 transition fires at t=INITIAL_STABILIZATION, immediately AFTER
// the acceptance gates (which run in the neutral state) by scheduling order.
static void
ApplyScenarioState (NodeContainer nodes, std::vector<uint32_t> attackerIds,
                    uint32_t spoofCount, int slot)
{
  if (g_runRejected) return;
  const ScenarioSpec& sc = SCENARIOS[g_scenarioOrder[slot]];
  if (sc.attackEnabled != g_attackCurrentlyOn)
    {
      SetAttackState (nodes, attackerIds, spoofCount, sc.attackEnabled);
      g_attackCurrentlyOn = sc.attackEnabled;
    }
  if (sc.defenseEnabled != g_defenseCurrentlyOn)
    {
      SetDefenseState (nodes, sc.defenseEnabled);
      g_defenseCurrentlyOn = sc.defenseEnabled;
    }
  std::cout << "[t=" << Simulator::Now ().GetSeconds () << "s] Slot " << slot
            << " -> scenario '" << sc.name << "' (attack="
            << (sc.attackEnabled ? 1 : 0) << ", defense="
            << (sc.defenseEnabled ? 1 : 0) << ")" << std::endl;

  // WBR-001 (revised): UNCONDITIONAL defense cold-start reset at the slot
  // transition. This is now the SOLE reset point. It runs on every slot
  // regardless of whether attack/defense changed, so it wipes ALL accumulated
  // defense state even between two consecutive defense-on slots (no inter-slot
  // leak), while leaving the defense the full 60 s stabilization window to warm
  // up before measurement begins. Both this and ApplyScenarioState's enable
  // toggles run at t = SlotTransitionTime(slot) = SlotWindowStart(slot) - 60.
  ForceDefenseColdStart ();
  // WBR-002: optional verification that the reset emptied the defense state.
  // Runs immediately AFTER the reset, so every value MUST read zero.
  if (g_debugDefenseState) PrintDefenseStateSizes ();
}

// ============================================================================
// Per-window measurement bracket
// ============================================================================
static void
ResetOlsrCounters ()
{
  g_helloCount               = 0;
  g_tcCount                  = 0;
  g_midCount                 = 0;
  g_hnaCount                 = 0;
  g_totalTcRows              = 0;
  g_olsrControlBytesWithHello = 0;
  g_firstOnAirByFlowIpId.clear ();   // OBS-004: bound the latency-correlation map
}

// WBR-001 (revised): slot-transition cold start of the defense object.
//
// At each slot transition (t = SlotTransitionTime(slot), the start of the 60 s
// stabilization period) we force every node's Watchdog object back to its
// freshly-loaded state -- unconditionally, regardless of whether the
// (attack,defense) state changed between the previous slot and this one. This
// closes the cross-window leakage channel through defense-INTERNAL state
// (the local blacklist, per-neighbor pending-packet tracking, per-neighbor
// evidence/probation counters, the learned MAC<->IP map, the self-drop window
// counter, and the self-reliability score). Without it, two consecutive
// defense-enabled slots would let the second inherit the blacklist/evidence the
// first built up, so the observable features would depend on window history
// rather than on the scenario alone. Performing the reset at the transition
// (not at the measurement-window start) gives the watchdog the full 60 s
// stabilization window to re-warm (15 s warmup + evidence accumulation + 2 s
// probation all fit comfortably), so the measurement window observes a
// fully-warmed watchdog exhibiting its genuine, paper-faithful behavior.
//
// Mechanism: OlsrWatchdogDefense::SetEnabled() performs a FULL SYMMETRIC
// cold-start reset on every state transition -- both enable->disable and
// disable->enable clear ALL accumulated state. Two opposite toggles therefore
// wipe everything and restore the slot's intended enabled/disabled value,
// leaving the object identical to a fresh load. Both toggles run synchronously
// inside this call (no simulator events fire between them), so the brief
// intermediate flip has no observable effect on the run.
//
// SCOPE: this resets ONLY state owned by the defense object. Physical
// simulation state (channel occupancy, MAC queues, in-flight route churn) is
// NOT defense state and is intentionally left untouched -- it cannot, and must
// not, be reset from here.
static void
ForceDefenseColdStart ()
{
  if (g_runRejected) return;
  if (g_simNodes == nullptr) return;
  for (uint32_t i = 0; i < g_simNodes->GetN (); ++i)
    {
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (g_simNodes->Get (i));
      if (!proto) continue;
      PointerValue pv;
      proto->GetAttribute ("DefenseStrategy", pv);
      Ptr<olsr::OlsrWatchdogDefense> def =
          DynamicCast<olsr::OlsrWatchdogDefense> (pv.Get<olsr::OlsrDefenseStrategy> ());
      if (!def) continue;
      const bool cur = def->GetEnabled ();
      def->SetEnabled (!cur);   // transition #1: full symmetric cold-start wipe
      def->SetEnabled (cur);    // transition #2: wipe again, restore ON/OFF state
    }
}

// WBR-002: optional runtime verification that ForceDefenseColdStart actually
// emptied the defense state. Aggregates the sizes of every accumulated-state
// container across all nodes and prints one line. Called immediately AFTER the
// cold start, so every value MUST read zero; any non-zero value is direct
// evidence of a leak through defense state. Off unless --debugDefenseState.
static void
PrintDefenseStateSizes ()
{
  if (g_simNodes == nullptr) return;
  std::size_t enabledNodes  = 0;
  std::size_t sumBlacklist  = 0, maxBlacklist = 0;
  std::size_t sumPendNbr    = 0, sumPendTot   = 0;
  std::size_t sumStats      = 0, sumMacToIp   = 0, sumSelfDrops = 0;
  for (uint32_t i = 0; i < g_simNodes->GetN (); ++i)
    {
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (g_simNodes->Get (i));
      if (!proto) continue;
      PointerValue pv;
      proto->GetAttribute ("DefenseStrategy", pv);
      Ptr<olsr::OlsrWatchdogDefense> def =
          DynamicCast<olsr::OlsrWatchdogDefense> (pv.Get<olsr::OlsrDefenseStrategy> ());
      if (!def) continue;
      if (def->GetEnabled ()) ++enabledNodes;
      const olsr::OlsrWatchdogDefense::DebugStateSizes s = def->GetDebugStateSizes ();
      sumBlacklist += s.blacklist;  maxBlacklist = std::max (maxBlacklist, s.blacklist);
      sumPendNbr   += s.pendingNeighbors;
      sumPendTot   += s.pendingTotal;
      sumStats     += s.neighborStats;
      sumMacToIp   += s.macToIp;
      sumSelfDrops += s.selfDropsWindow;
    }
  std::cout << "[defense_state @ t=" << Simulator::Now ().GetSeconds () << "s]"
            << " enabled_nodes=" << enabledNodes
            << " blacklist(sum=" << sumBlacklist << ",max=" << maxBlacklist << ")"
            << " pendingNbr=" << sumPendNbr
            << " pendingTot=" << sumPendTot
            << " neighborStats=" << sumStats
            << " macToIp=" << sumMacToIp
            << " selfDrops=" << sumSelfDrops
            << "  [expect all 0 right after cold start]" << std::endl;
}

static void
StartMeasurementWindow ()
{
  if (g_runRejected) return;

  // WBR-001 (revised): the per-window defense cold-start reset was MOVED to the
  // slot transition -- see the unconditional ForceDefenseColdStart() at the end
  // of ApplyScenarioState (t = SlotTransitionTime(slot)). The defense is reset
  // at the START of the 60 s stabilization period so it is fully warmed up by
  // the time this measurement window opens, while still inheriting nothing from
  // the previous slot (the transition reset is unconditional). Nothing defense-
  // related is reset here at window start.

  SnapshotUdpReceived ();
  ResetOlsrCounters ();
  if (g_flowMonitor) g_flowMonitor->ResetAllStats ();
  g_macTxAtWindowStart   = 0;
  g_macDropAtWindowStart = 0;
  for (uint32_t v : g_macTxPerNode)   g_macTxAtWindowStart   += v;
  for (uint32_t v : g_macDropPerNode) g_macDropAtWindowStart += v;
  g_features.Reset (Simulator::Now ().GetSeconds ());
  g_featuresActive = true;
}

// ----------- Per-window labels/features/oracle row builders ----------------

// Derives explicit binary labels from the scenario name (LEAK-003). Looks the
// name up in SCENARIOS[] so the written label is ALWAYS consistent with the
// (attack, defense) state actually applied by ApplyScenarioState -- a single
// source of truth, with no risk of the two definitions drifting apart.
static std::pair<int,int>
LabelsForScenario (const std::string& s)
{
  // (attack_enabled, defense_enabled)
  for (int i = 0; i < NUM_SLOTS; ++i)
    if (s == SCENARIOS[i].name)
      return { SCENARIOS[i].attackEnabled ? 1 : 0,
               SCENARIOS[i].defenseEnabled ? 1 : 0 };
  return {0, 0};
}

static uint32_t
CountAttackers (const std::string& list)
{
  uint32_t n = 0;
  std::stringstream ss (list);
  std::string seg;
  while (std::getline (ss, seg, ','))
    if (!seg.empty ()) n++;
  return n;
}

static std::string
PipeJoinAttackers (const std::string& list)
{
  std::string out;
  std::stringstream ss (list);
  std::string seg;
  while (std::getline (ss, seg, ','))
    {
      if (seg.empty ()) continue;
      if (!out.empty ()) out += "|";
      out += seg;
    }
  if (out.empty ()) out = "none";
  return out;
}

// Per-window finalizer. Builds the three rows and appends them to the
// staging buffers (RUN-004). Promotion happens at end of main() if
// !g_runRejected.
static void
EndMeasurementWindow (const std::string& scenarioName,
                      double windowStart, double windowEnd,
                      const SimulationConfig& cfg)
{
  if (g_runRejected) return;
  g_featuresActive = false;

  // Drop any entries still in the in-flight map. Deliveries are declared
  // at PHY layer (in PhyTxBeginCallback) when the last-hop TX to a flow
  // destination is observed; anything still in the map at window-end was
  // sent but never reached its destination (dropped, lost, or in flight at
  // boundary). They contribute to PacketsSentCount but not
  // PacketsDeliveredCount -- matching the oracle's accounting.
  FinalizeInFlightDeliveries ();

  const double duration = windowEnd - windowStart;

  // ---- Oracle row ----
  uint64_t txPackets = 0, rxPackets = 0, rxBytes = 0;
  double   delaySumSec = 0.0;
  if (g_flowMonitor)
    {
      g_flowMonitor->CheckForLostPackets ();
      const auto stats = g_flowMonitor->GetFlowStats ();
      for (const auto& kv : stats)
        {
          const auto& s = kv.second;
          txPackets   += s.txPackets;
          rxPackets   += s.rxPackets;
          rxBytes     += s.rxBytes;
          delaySumSec += s.delaySum.GetSeconds ();
        }
    }
  const double throughputMbps = (duration > 0)
      ? (rxBytes * 8.0) / (duration * 1.0e6) : 0.0;
  const double pdrPercent = (txPackets > 0)
      ? (100.0 * rxPackets) / txPackets : 0.0;
  const double avgDelaySec = (rxPackets > 0)
      ? (delaySumSec / rxPackets) : 0.0;
  uint64_t udpReceivedTotalNow = 0;                  // TRF-004: sum flows
  for (const auto& srv : g_udpServers)
    if (srv) udpReceivedTotalNow += srv->GetReceived ();
  const uint64_t udpReceivedInWindow =
      udpReceivedTotalNow - g_udpReceivedAtWindowStart;
  uint64_t macTxTotal = 0, macDropTotal = 0;
  for (uint32_t v : g_macTxPerNode)   macTxTotal   += v;
  for (uint32_t v : g_macDropPerNode) macDropTotal += v;
  const uint64_t macTxInWin   = macTxTotal   - g_macTxAtWindowStart;
  const uint64_t macDropInWin = macDropTotal - g_macDropAtWindowStart;
  const double overheadRatio = (rxBytes > 0)
      ? (static_cast<double> (g_olsrControlBytesWithHello) / rxBytes) : 0.0;
  const uint64_t udpMissing =
      (udpReceivedInWindow >= UDP_EXPECTED_PER_WINDOW)
          ? 0u
          : (UDP_EXPECTED_PER_WINDOW - udpReceivedInWindow);
  const double udpLossPercent = (UDP_EXPECTED_PER_WINDOW > 0)
      ? (100.0 * static_cast<double> (udpMissing) / UDP_EXPECTED_PER_WINDOW)
      : 0.0;

  std::ostringstream oracleRow;
  oracleRow << std::fixed << std::setprecision (6);
  oracleRow << g_currentRun << ","
            << scenarioName << ","
            << windowStart << "," << windowEnd << ","
            << throughputMbps << "," << pdrPercent << "," << avgDelaySec << ","
            << txPackets << "," << rxPackets << "," << rxBytes << ","
            << udpReceivedInWindow << "," << UDP_EXPECTED_PER_WINDOW << ","
            << udpLossPercent << "," << overheadRatio << ","
            << g_helloCount << "," << g_olsrControlBytesWithHello << ","
            << g_pathHopsPrevWindow << ","
            << g_minAttackerTrust << "," << g_avgAttackerTrust << ","
            << g_blacklistMaxSize << ","
            << macTxInWin << "," << macDropInWin << ","
            << macTxTotal << "," << macDropTotal << "\n";
  g_staging.oracleRows.push_back (oracleRow.str ());

  // ---- Labels row ----
  auto [attEn, defEn] = LabelsForScenario (scenarioName);
  std::ostringstream labelsRow;
  labelsRow << std::fixed << std::setprecision (6);
  labelsRow << g_currentRun << ","
            << scenarioName << ","
            << windowStart << "," << windowEnd << ","
            << defEn << "," << attEn << ","
            << (g_attackerOnPathPrevWindow ? 1 : 0) << ","
            << CountAttackers (cfg.maliciousNodesList) << "\n";
  g_staging.labelRows.push_back (labelsRow.str ());

  // ---- Features row ----
  std::ostringstream featRow;
  featRow << std::fixed << std::setprecision (6);
  featRow << g_currentRun << ","
          << scenarioName << ","
          << windowStart << "," << windowEnd << "," << duration << ","
          << g_features.EmitFeatureCsv (windowEnd)
          << "\n";
  g_staging.featureRows.push_back (featRow.str ());

  // Console summary (for the seed log).
  std::cout << "----- " << scenarioName << " window ["
            << windowStart << "s, " << windowEnd << "s] -----" << std::endl
            << "  Throughput  : " << throughputMbps << " Mbps (oracle)" << std::endl
            << "  PDR         : " << pdrPercent << " % (oracle)" << std::endl
            << "  UDP rx win  : " << udpReceivedInWindow
            << " / " << UDP_EXPECTED_PER_WINDOW << std::endl
            << "  Att on path : " << (g_attackerOnPathPrevWindow ? "yes" : "no")
            << " (" << g_flowsWithAttackerOnPath << "/" << g_flowPairs.size ()
            << " flows, mean hops=" << g_pathHopsPrevWindow << ")" << std::endl
            << "  Trust min/avg : " << g_minAttackerTrust
            << " / " << g_avgAttackerTrust << std::endl;
}

// Generic per-slot measurement bracket (WIN-001). The scenario assigned to a
// slot is looked up through g_scenarioOrder, so the same two functions serve
// both the canonical and randomized window orders.
static void StartSlot (int /*slot*/) { StartMeasurementWindow (); }

static void EndSlot (int slot, SimulationConfig* cfg)
{
  const ScenarioSpec& sc = SCENARIOS[g_scenarioOrder[slot]];
  EndMeasurementWindow (sc.name, SlotWindowStart (slot), SlotWindowEnd (slot),
                        *cfg);
}

// WIN-003: render the slot->scenario permutation as a pipe-joined string of
// canonical scenario indices, e.g. "0|2|1|3" (slot 0 ran scenario 0, etc.).
static std::string
WindowOrderPermString ()
{
  std::ostringstream s;
  for (int k = 0; k < NUM_SLOTS; ++k)
    {
      if (k) s << "|";
      s << g_scenarioOrder[k];
    }
  return s.str ();
}
// ============================================================================
// Staging promotion (RUN-004)  -- atomic per-run append on success
// ============================================================================
//
// At end of main(), iff !g_runRejected: take flocks in alphabetical order
// on the four target files; for each, ensure the header is written, then
// append the staged rows; release locks; clear the staging buffers.
//
// On rejection: do nothing (buffered rows are discarded with the process).
//
// Header-once is preserved per file via the same `lseek == 0` check that
// the original code used. flock guarantees the check-then-write is atomic
// against other workers.
static bool
AppendUnderLock (const std::string& path, const std::string& header,
                 const std::string& body)
{
  if (path.empty () || body.empty ()) return true;
  int fd = open (path.c_str (), O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0)
    {
      std::cerr << "[promote] open failed " << path
                << " errno=" << errno << std::endl;
      return false;
    }
  if (flock (fd, LOCK_EX) < 0)
    {
      std::cerr << "[promote] flock failed " << path
                << " errno=" << errno << std::endl;
      close (fd);
      return false;
    }
  off_t sz = lseek (fd, 0, SEEK_END);
  if (sz == 0 && !header.empty ())
    {
      std::string h = header + "\n";
      ssize_t hw = write (fd, h.c_str (), h.size ());
      (void) hw;
    }
  ssize_t w = write (fd, body.c_str (), body.size ());
  (void) w;
  flock (fd, LOCK_UN);
  close (fd);
  return true;
}

static void
PromoteStagedRows (const SimulationConfig& cfg, double wallClockSec)
{
  if (g_runRejected) return;

  // Build the runs.csv row.
  // Watchdog-OLSR: a single fixed variant name. redundant_mpr and every
  // FPNT-specific numeric parameter column are written as the sentinel -1
  // below (they have no meaning for this defense); the runs.csv HEADER and
  // column set remain byte-for-byte identical to the FPNT harness so the
  // researcher can union the per-defense outputs unchanged.
  const std::string defenseVariant = "Watchdog-OLSR";
  const std::string attackersPipe = PipeJoinAttackers (cfg.maliciousNodesList);
  const uint32_t    numAttackers  = CountAttackers (cfg.maliciousNodesList);

  std::ostringstream runsRow;
  runsRow << std::fixed << std::setprecision (6);
  runsRow << g_currentRun << ","
          << RngSeedManager::GetRun () << ","
          << cfg.seed << ","
          << HARNESS_VERSION << ","
          << HEADER_VERSION << ","
          << cfg.nNodes << ","
          << cfg.gridX << "," << cfg.gridY << ","
          << (cfg.bMobility ? 1 : 0) << ","
          << cfg.radioRange << ","
          << cfg.minHops << ","
          << numAttackers << "," << attackersPipe << ","
          << cfg.spoofCount << "," << cfg.attackerJitter << ","
          << defenseVariant << "," << -1 << ","  // defense_variant, redundant_mpr (FPNT-only -> sentinel -1)
          << -1 << ","                            // malicious_threshold      (FPNT-only -> sentinel -1)
          << -1 << ","                            // uncertainty_beta         (FPNT-only -> sentinel -1)
          << -1 << ","                            // fading_factor            (FPNT-only -> sentinel -1)
          << -1 << ","                            // max_load                 (FPNT-only -> sentinel -1)
          << -1 << ","                            // max_delay                (FPNT-only -> sentinel -1)
          << -1 << ","                            // cheat_threshold          (FPNT-only -> sentinel -1)
          << -1 << ","                            // trust_update_interval_s  (FPNT-only -> sentinel -1)
          << (g_phyTraceAvailable ? 1 : 0) << ","
          << wallClockSec << ","
          << (g_randomWindowOrder ? 1 : 0) << ","
          << WindowOrderPermString () << ","
          << SCENARIOS[g_scenarioOrder[0]].name << "\n";

  // Build feature/label/oracle bodies.
  std::string featuresBody, labelsBody, oracleBody;
  for (const auto& r : g_staging.featureRows) featuresBody += r;
  for (const auto& r : g_staging.labelRows)   labelsBody   += r;
  for (const auto& r : g_staging.oracleRows)  oracleBody   += r;

  // Append under flock, in alphabetical order to bound deadlock risk
  // (no two workers should ever hold two of these locks simultaneously
  // in opposite orders).
  AppendUnderLock (cfg.featuresFile, BuildFeaturesHeader (), featuresBody);
  AppendUnderLock (cfg.labelsFile,   LABELS_HEADER,          labelsBody);
  AppendUnderLock (cfg.oracleFile,   ORACLE_HEADER,          oracleBody);
  AppendUnderLock (cfg.runsFile,     RUNS_HEADER,            runsRow.str ());

  // Clear staging buffers.
  g_staging.featureRows.clear ();
  g_staging.labelRows.clear ();
  g_staging.oracleRows.clear ();
}

// ============================================================================
// Pretty-printer
// ============================================================================
static void
PrintSimStats (const SimulationConfig& cfg, const std::vector<uint32_t>& attackerIds)
{
  std::cout << "================================================================" << std::endl
            << "  Watchdog-OLSR Mitigation Harness v" << HARNESS_VERSION << std::endl
            << "  Header version: " << HEADER_VERSION << std::endl
            << "  PHY trace available: " << (g_phyTraceAvailable ? "yes" : "no")
            << std::endl
            << "================================================================" << std::endl
            << "Seed (RngRun)   : " << RngSeedManager::GetRun () << std::endl
            << "Run id          : " << g_currentRun << std::endl
            << "Nodes           : " << cfg.nNodes << std::endl
            << "Grid            : " << cfg.gridX << " x " << cfg.gridY << " m" << std::endl
            << "Radio range     : " << cfg.radioRange << " m"
            << (cfg.bHighRange ? " (high range)" : "") << std::endl
            << "Mobility        : " << (cfg.bMobility ? "on" : "off") << std::endl
            << "Attackers       : ";
  if (attackerIds.empty ()) std::cout << "(none)";
  for (size_t i = 0; i < attackerIds.size (); ++i)
    {
      if (i) std::cout << ",";
      std::cout << attackerIds[i];
    }
  std::cout << std::endl
            << "Data flows      : ";
  for (std::size_t f = 0; f < g_flowPairs.size (); ++f)
    {
      if (f) std::cout << ", ";
      std::cout << g_flowPairs[f].first << "->" << g_flowPairs[f].second;
    }
  std::cout << std::endl
            << "Spoofed links   : " << cfg.spoofCount << std::endl
            << "Defense variant : "
            << "Watchdog-OLSR" << std::endl
            << "Window order    : "
            << (g_randomWindowOrder ? "RANDOMIZED" : "canonical")
            << " [" << WindowOrderPermString () << "] -> "
            << SCENARIOS[g_scenarioOrder[0]].name << ", "
            << SCENARIOS[g_scenarioOrder[1]].name << ", "
            << SCENARIOS[g_scenarioOrder[2]].name << ", "
            << SCENARIOS[g_scenarioOrder[3]].name << std::endl
            << "================================================================" << std::endl;
}

// ============================================================================
// Output directory creation
// ============================================================================
static void
CreateOutputDirectories (const SimulationConfig& cfg)
{
  if (cfg.outputDir.empty ()) return;
  std::string cmd = "mkdir -p '" + cfg.outputDir + "'";
  int rc = std::system (cmd.c_str ());
  (void) rc;
}

// GEN-004: write the defense's effective parameters once per output dir.
// Provenance ONLY -- this file is NOT an ML input and is NOT part of any CSV
// schema (the runs.csv column set is unchanged). Write-once-if-empty under an
// exclusive flock, so parallel workers cooperate and the file is written
// exactly once per batch (the parameters are fixed for a given binary).
static void
WriteDefenseParamsOnce (const SimulationConfig& cfg)
{
  if (cfg.defenseParamsFile.empty ()) return;
  int fd = open (cfg.defenseParamsFile.c_str (),
                 O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) return;
  if (flock (fd, LOCK_EX) < 0) { close (fd); return; }
  if (lseek (fd, 0, SEEK_END) == 0)
    {
      std::ostringstream os;
      os << "# Effective defense parameters (provenance; not an ML input).\n"
         << "# Watchdog tunables are hardcoded in the install block; mirrored here.\n"
         << "harness_version=" << HARNESS_VERSION << "\n"
         << "header_version=" << HEADER_VERSION << "\n"
         << "defense_variant=Watchdog-OLSR\n"
         << "forward_timeout_ms=500\n"
         << "periodic_interval_s=1.0\n"
         << "warmup_duration_s=15.0\n"
         << "blacklist_threshold=3\n"
         << "rts_to_data_ratio_threshold=3.0\n"
         << "self_drops_threshold=5\n"
         << "mac_failure_threshold=3\n"
         << "min_rts_for_heuristic=5\n"
         << "min_self_reliability=0.6\n"
         << "probation_duration_s=2.0\n"
         << "mac_failure_rate_threshold=0.4\n"
         << "min_data_observations=2\n";
      const std::string s = os.str ();
      ssize_t w = write (fd, s.c_str (), s.size ());
      (void) w;
    }
  flock (fd, LOCK_UN);
  close (fd);
}

// ============================================================================
// --emit-header mode
// ============================================================================
static void
EmitHeadersAndExit ()
{
  std::cout << "RUNS_HEADER:"     << RUNS_HEADER << std::endl;
  std::cout << "FEATURES_HEADER:" << BuildFeaturesHeader () << std::endl;
  std::cout << "LABELS_HEADER:"   << LABELS_HEADER << std::endl;
  std::cout << "ORACLE_HEADER:"   << ORACLE_HEADER << std::endl;
  std::cout << "HARNESS_VERSION:" << HARNESS_VERSION << std::endl;
  std::cout << "HEADER_VERSION:"  << HEADER_VERSION << std::endl;
  std::exit (0);
}

// ============================================================================
// --self-test mode (BUG-007 cycle counter verification)
// ============================================================================
static int
RunSelfTest ()
{
  bool allPass = true;
  auto check = [&] (const std::string& name,
                    const std::vector<std::vector<uint32_t>>& adj,
                    uint64_t exp3, uint64_t exp4,
                    uint64_t exp5, uint64_t exp6) {
    using ns3::olsreval::FeatureCollector;
    uint64_t c3 = FeatureCollector::TestCountCyclesOfLength (adj, 3);
    uint64_t c4 = FeatureCollector::TestCountCyclesOfLength (adj, 4);
    uint64_t c5 = FeatureCollector::TestCountCyclesOfLength (adj, 5);
    uint64_t c6 = FeatureCollector::TestCountCyclesOfLength (adj, 6);
    bool ok = (c3 == exp3 && c4 == exp4 && c5 == exp5 && c6 == exp6);
    std::cout << name << ":  triangles=" << c3
              << " 4-cycles=" << c4
              << " 5-cycles=" << c5
              << " 6-cycles=" << c6
              << "   [exp " << exp3 << "/" << exp4 << "/" << exp5 << "/" << exp6
              << "] " << (ok ? "OK" : "FAIL") << std::endl;
    if (!ok) allPass = false;
  };
  // K3
  {
    std::vector<std::vector<uint32_t>> a (3);
    a[0] = {1,2}; a[1] = {0,2}; a[2] = {0,1};
    check ("K3   ", a, 1, 0, 0, 0);
  }
  // K4
  {
    std::vector<std::vector<uint32_t>> a (4);
    a[0] = {1,2,3}; a[1] = {0,2,3}; a[2] = {0,1,3}; a[3] = {0,1,2};
    // K4: triangles = C(4,3) = 4; 4-cycles = 3 (each pair of opposite
    // edges); 5-cycles = 0; 6-cycles = 0.
    check ("K4   ", a, 4, 3, 0, 0);
  }
  // C6 (single cycle on 6 vertices)
  {
    std::vector<std::vector<uint32_t>> a (6);
    for (uint32_t i = 0; i < 6; ++i)
      {
        a[i].push_back ((i + 5) % 6);
        a[i].push_back ((i + 1) % 6);
        std::sort (a[i].begin (), a[i].end ());
      }
    check ("C6   ", a, 0, 0, 0, 1);
  }
  // K3,3 (complete bipartite 3x3)
  {
    std::vector<std::vector<uint32_t>> a (6);
    // partition: {0,1,2} on one side, {3,4,5} on the other; all cross-edges.
    for (uint32_t i = 0; i < 3; ++i)
      for (uint32_t j = 3; j < 6; ++j)
        { a[i].push_back (j); a[j].push_back (i); }
    for (auto& nb : a)
      { std::sort (nb.begin (), nb.end ());
        nb.erase (std::unique (nb.begin (), nb.end ()), nb.end ()); }
    // K3,3: triangles = 0 (bipartite). 4-cycles = C(3,2)*C(3,2) = 9.
    // 6-cycles = 3! * 3! / (2*6) = 36/12 = 3 ... actually:
    //   Number of Hamiltonian 6-cycles in K3,3 = 6 (canonical form).
    //   This is well-known. Use 6.
    // 5-cycles in bipartite graph = 0.
    check ("K3,3 ", a, 0, 9, 0, 6);
  }
  std::cout << (allPass ? "ALL PASS" : "FAILURES PRESENT") << std::endl;
  return allPass ? 0 : 1;
}

// ============================================================================
// main
// ============================================================================
int
main (int argc, char* argv[])
{
  auto wallStart = std::chrono::steady_clock::now ();
  Time::SetResolution (Time::NS);

  SimulationConfig cfg;
  CommandLine cmd;
  cmd.AddValue ("nNodes",          "Number of nodes",                   cfg.nNodes);
  cmd.AddValue ("nMaxGridX",       "Grid X side length (m)",            cfg.gridX);
  cmd.AddValue ("nMaxGridY",       "Grid Y side length (m)",            cfg.gridY);
  cmd.AddValue ("bMobility",       "Enable RandomWalk2D mobility",      cfg.bMobility);
  cmd.AddValue ("bHighRange",      "Use 250 m radio range (else 190)",  cfg.bHighRange);
  cmd.AddValue ("txGain",          "Wifi PHY TX gain (dB)",             cfg.txGain);
  cmd.AddValue ("run",             "RngSeedManager::SetRun() value",    cfg.run);
  cmd.AddValue ("seed",            "RngSeedManager::SetSeed() value",   cfg.seed);
  cmd.AddValue ("maliciousNodes",  "Comma-separated malicious node IDs",cfg.maliciousNodesList);
  cmd.AddValue ("spoofCount",      "Spoofed links per attacker",        cfg.spoofCount);
  cmd.AddValue ("attackerJitter",  "Random offset (m) around centre",   cfg.attackerJitter);
  cmd.AddValue ("minHops",         "Min OLSR hops from src to dst @ t=60",
                                                                       cfg.minHops);
  cmd.AddValue ("redundantMpr",        "Inert in Watchdog build (CLI compat)", cfg.redundantMpr);
  cmd.AddValue ("maliciousThreshold",  "FPNT-only; inert in this build", cfg.maliciousThreshold);
  cmd.AddValue ("uncertaintyBeta",     "FPNT-only; inert in this build", cfg.uncertaintyBeta);
  cmd.AddValue ("fadingFactor",        "FPNT-only; inert in this build", cfg.fadingFactor);
  cmd.AddValue ("maxLoad",             "FPNT-only; inert in this build", cfg.maxLoad);
  cmd.AddValue ("maxDelay",            "FPNT-only; inert in this build", cfg.maxDelay);
  cmd.AddValue ("cheatThreshold",      "FPNT-only; inert in this build", cfg.cheatThreshold);
  cmd.AddValue ("trustUpdateInterval", "FPNT-only; inert in this build", cfg.trustUpdateInterval);
  // New: four output files (replaces --csvFile).
  cmd.AddValue ("runsFile",          "runs.csv path (per-run metadata)", cfg.runsFile);
  cmd.AddValue ("featuresFile",      "windows_features.csv path",        cfg.featuresFile);
  cmd.AddValue ("labelsFile",        "windows_labels.csv path",          cfg.labelsFile);
  cmd.AddValue ("oracleFile",        "windows_oracle.csv path",          cfg.oracleFile);
  cmd.AddValue ("topologyProbeFile", "Topology probe CSV file",          cfg.topologyProbeFile);
  cmd.AddValue ("defenseParamsFile", "defense_params.txt path (provenance sidecar; written once; not an ML input)", cfg.defenseParamsFile);
  cmd.AddValue ("outputDir",         "Base output directory",            cfg.outputDir);
  cmd.AddValue ("verbose",           "Enable info logging",              cfg.verbose);
  // Special modes.
  cmd.AddValue ("emit-header",       "Print headers and exit",           cfg.emitHeaderOnly);
  cmd.AddValue ("self-test",         "Run cycle-counter self-test and exit",
                                                                         cfg.selfTest);
  // WIN-001: randomize the 4 measurement windows (permutation seeded by --run).
  cmd.AddValue ("randomWindowOrder",
                "Shuffle the 4 measurement windows (permutation seeded by --run)",
                cfg.randomWindowOrder);
  // WBR-002: optional per-window dump of defense-state container sizes.
  cmd.AddValue ("debugDefenseState",
                "Print defense-state container sizes at each window start "
                "(verification only; emits no CSV column)",
                cfg.debugDefenseState);

  cmd.Parse (argc, argv);

  // ---- Special modes (no simulation) -------------------------------------
  if (cfg.emitHeaderOnly) EmitHeadersAndExit ();
  if (cfg.selfTest) return RunSelfTest ();

  if (cfg.verbose) LogComponentEnable ("OlsrWatchdogEvalMitigation", LOG_LEVEL_INFO);
  if (cfg.bHighRange) cfg.radioRange = 250.0;
  RngSeedManager::SetSeed (cfg.seed);
  RngSeedManager::SetRun  (cfg.run);
  g_currentRun        = cfg.run;
  g_topologyProbeFile = cfg.topologyProbeFile;
  g_probeMobility     = cfg.bMobility;
  g_debugDefenseState = cfg.debugDefenseState;   // WBR-002

  // WIN-001: determine the measurement-window order. The permutation is drawn
  // from a SEPARATE std::mt19937 seeded by --run, so it is (a) fully
  // reproducible across wall-clock time and (b) does NOT consume any ns-3 RNG
  // draws -- therefore the topology (and the accept/reject decision) is
  // identical for a given seed whether or not the window order is randomized.
  // Canonical order is the identity permutation.
  g_randomWindowOrder = cfg.randomWindowOrder;
  for (int k = 0; k < NUM_SLOTS; ++k) g_scenarioOrder[k] = k;
  if (g_randomWindowOrder)
    DeterministicShuffle (g_scenarioOrder, cfg.run);

  CreateOutputDirectories (cfg);
  WriteDefenseParamsOnce (cfg);   // GEN-004: provenance sidecar (write-once)
  // ----- 1. Nodes & WiFi ---------------------------------------------------
  NodeContainer nodes;
  nodes.Create (cfg.nNodes);
  // WBR-001/002: publish the node container so the per-window cold start and
  // the optional state-size print can reach every defense object. `nodes`
  // outlives Simulator::Run(), matching the &nodes lifetime already relied on
  // by ObserveAttackerOnPath.
  g_simNodes = &nodes;
  g_macTxPerNode.assign   (nodes.GetN (), 0);
  g_macDropPerNode.assign (nodes.GetN (), 0);

  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211g);
  wifi.SetRemoteStationManager ("ns3::AarfWifiManager",
                                "RtsCtsThreshold", UintegerValue (0));

  YansWifiChannelHelper channel;
  channel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  channel.AddPropagationLoss ("ns3::RangePropagationLossModel",
                              "MaxRange", DoubleValue (cfg.radioRange));

  YansWifiPhyHelper phy;
  phy.SetChannel (channel.Create ());
  phy.SetErrorRateModel ("ns3::NistErrorRateModel");
  phy.Set ("TxPowerStart", DoubleValue (16.0));
  phy.Set ("TxPowerEnd",   DoubleValue (16.0));
  phy.Set ("RxGain",       DoubleValue (0.0));
  phy.Set ("TxGain",       DoubleValue (cfg.txGain));

  WifiMacHelper mac;
  mac.SetType ("ns3::AdhocWifiMac", "QosSupported", BooleanValue (false));

  NetDeviceContainer devices = wifi.Install (phy, mac, nodes);

  // Build node -> MAC map for first-hop-MAC tracking (BUG-004).
  g_nodeToMac.clear ();
  for (uint32_t i = 0; i < devices.GetN (); ++i)
    {
      Ptr<NetDevice> nd = devices.Get (i);
      g_nodeToMac[i] = Mac48Address::ConvertFrom (nd->GetAddress ());
    }

  // ----- 2. Parse attacker list -------------------------------------------
  std::vector<uint32_t> attackerIds;
  {
    std::stringstream ss (cfg.maliciousNodesList);
    std::string seg;
    while (std::getline (ss, seg, ','))
      {
        if (seg.empty ()) continue;
        try
          {
            const uint32_t id = std::stoul (seg);
            if (id < cfg.nNodes && id != UDP_SERVER_NODE_ID && id != UDP_CLIENT_NODE_ID)
              attackerIds.push_back (id);
            else
              NS_LOG_WARN ("Attacker ID " << id << " invalid; ignoring");
          }
        catch (...)
          {
            NS_LOG_WARN ("Malformed attacker id: '" << seg << "'");
          }
      }
  }
  const std::set<uint32_t> attackerSet (attackerIds.begin (), attackerIds.end ());

  // ----- 3. Mobility -------------------------------------------------------
  {
    Ptr<UniformRandomVariable> rngX = CreateObject<UniformRandomVariable> ();
    Ptr<UniformRandomVariable> rngY = CreateObject<UniformRandomVariable> ();
    Ptr<UniformRandomVariable> rngJ = CreateObject<UniformRandomVariable> ();
    rngX->SetAttribute ("Min", DoubleValue (0.0));
    rngX->SetAttribute ("Max", DoubleValue (cfg.gridX));
    rngY->SetAttribute ("Min", DoubleValue (0.0));
    rngY->SetAttribute ("Max", DoubleValue (cfg.gridY));
    rngJ->SetAttribute ("Min", DoubleValue (-cfg.attackerJitter));
    rngJ->SetAttribute ("Max", DoubleValue ( cfg.attackerJitter));

    const double centerX = cfg.gridX / 2.0;
    const double centerY = cfg.gridY / 2.0;

    NodeContainer attackerNodes, normalNodes;
    Ptr<ListPositionAllocator> attackerAlloc = CreateObject<ListPositionAllocator> ();
    Ptr<ListPositionAllocator> normalAlloc   = CreateObject<ListPositionAllocator> ();

    for (uint32_t i = 0; i < cfg.nNodes; ++i)
      {
        if (attackerSet.count (i))
          {
            const double x = std::clamp (centerX + rngJ->GetValue (),
                                         0.0, cfg.gridX);
            const double y = std::clamp (centerY + rngJ->GetValue (),
                                         0.0, cfg.gridY);
            attackerAlloc->Add (Vector (x, y, 0.0));
            attackerNodes.Add (nodes.Get (i));
          }
        else
          {
            normalAlloc->Add (Vector (rngX->GetValue (),
                                       rngY->GetValue (),
                                       0.0));
            normalNodes.Add (nodes.Get (i));
          }
      }
    {
      MobilityHelper mh;
      mh.SetPositionAllocator (attackerAlloc);
      mh.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
      mh.Install (attackerNodes);
    }
    {
      MobilityHelper mh;
      mh.SetPositionAllocator (normalAlloc);
      if (cfg.bMobility)
        {
          mh.SetMobilityModel (
              "ns3::RandomWalk2dMobilityModel",
              "Bounds", RectangleValue (Rectangle (0, cfg.gridX, 0, cfg.gridY)),
              "Speed",  StringValue ("ns3::UniformRandomVariable[Min=1.5|Max=2.0]"),
              "Time",   TimeValue (Seconds (3.0)),
              "Mode",   StringValue ("Time"));
        }
      else
        {
          mh.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
        }
      mh.Install (normalNodes);
    }
  }

  // ----- 4. Internet stack with OLSR ---------------------------------------
  OlsrHelper olsr;
  Ipv4ListRoutingHelper list;
  list.Add (olsr, 100);
  InternetStackHelper internet;
  internet.SetRoutingHelper (list);
  internet.Install (nodes);
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer interfaces = ipv4.Assign (devices);

  g_ipToNode.clear ();
  g_nodeToIp.clear ();
  for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
      g_ipToNode[interfaces.GetAddress (i)] = i;
      g_nodeToIp[i] = interfaces.GetAddress (i);  // TRF-003: gate/oracle lookup
    }
  g_clientIp = interfaces.GetAddress (UDP_CLIENT_NODE_ID);

  // ----- 5. Install Watchdog defense (initially DISABLED) -----------------
  // Cross-layer cooperative watchdog (Baiad et al., IWCMC 2014). All tuning
  // parameters are HARDCODED to the paper/design defaults (each defense runs on
  // its own machine, so per-run CLI tuning is unnecessary). WarmupDuration is
  // kept at the original 15 s: with the reset performed at the slot transition
  // (option C), the 15 s warmup + evidence accumulation + 2 s probation all
  // complete well within the 60 s stabilization window, so the measurement
  // window observes a fully-warmed watchdog with its genuine behavior.
  for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (nodes.Get (i));
      NS_ASSERT_MSG (proto, "OLSR protocol not found on node " << i);
      Ptr<olsr::OlsrWatchdogDefense> def = CreateObject<olsr::OlsrWatchdogDefense> ();
      def->SetAttribute ("Enabled",                 BooleanValue (false));
      def->SetAttribute ("ForwardTimeout",          TimeValue     (MilliSeconds (500)));
      def->SetAttribute ("PeriodicInterval",        TimeValue     (Seconds (1.0)));
      def->SetAttribute ("WarmupDuration",          TimeValue     (Seconds (15.0)));
      def->SetAttribute ("BlacklistThreshold",      UintegerValue (3));
      def->SetAttribute ("RtsToDataRatioThreshold", DoubleValue   (3.0));
      def->SetAttribute ("SelfDropsThreshold",      UintegerValue (5));
      def->SetAttribute ("MacFailureThreshold",     UintegerValue (3));
      def->SetAttribute ("MinRtsForHeuristic",      UintegerValue (5));
      def->SetAttribute ("MinSelfReliability",      DoubleValue   (0.6));
      def->SetAttribute ("ProbationDuration",       TimeValue     (Seconds (2.0)));
      def->SetAttribute ("MacFailureRateThreshold", DoubleValue   (0.4));
      def->SetAttribute ("MinDataObservations",     UintegerValue (2));
      proto->SetAttribute ("DefenseStrategy", PointerValue (def));
      // NOTE: RedundantMprCoverage is an FPNT-OLSR-only routing-protocol
      // attribute and does NOT exist on the Watchdog OLSR build; setting it
      // would abort. The --redundantMpr CLI flag is retained (inert) only to
      // keep the command-line interface identical across all defense harnesses.
    }

  // ----- 5b. Per-run data-flow pair selection (TRF-001) --------------------
  // Drawn from a dedicated mt19937 (no ns-3 RNG draw is consumed), seeded by
  // a fixed Knuth multiplicative mix of --seed and --run, so the pairs are a
  // pure, portable function of (seed, run) and reproduce bit-identically on
  // any standard library -- the same guarantee as the WIN-001 window shuffle.
  const uint32_t pairSeed = cfg.seed * 2654435761u + cfg.run;
  g_flowPairs = SelectDataFlowPairs (nodes, attackerSet, cfg.minHops,
                                     cfg.radioRange, pairSeed);

  // TRF-002: flow-destination IP -> destination MAC (PHY last-hop delivery).
  g_flowDstMacByIp.clear ();
  for (const auto& fp : g_flowPairs)
    {
      const auto macIt = g_nodeToMac.find (fp.second);
      if (macIt != g_nodeToMac.end ())
        g_flowDstMacByIp[interfaces.GetAddress (fp.second)] = macIt->second;
    }

  // ----- 6. Per-flow UDP servers and per-window clients (TRF-001) ----------
  // One UdpServer per flow destination (endpoints are disjoint across flows,
  // so exactly one server per node, all on UDP_PORT). Every flow reuses the
  // SAME in-window timing as the original single flow: start at
  // winStart + UDP_START_OFFSET_IN_WINDOW, UDP_PACKETS_PER_WINDOW packets of
  // UDP_PACKET_SIZE bytes at UDP_PACKET_INTERVAL intervals, stop at winEnd.
  g_udpServers.clear ();
  for (const auto& fp : g_flowPairs)
    {
      UdpServerHelper serverHelper (UDP_PORT);
      ApplicationContainer serverApp =
          serverHelper.Install (nodes.Get (fp.second));
      serverApp.Start (Seconds (0.0));
      serverApp.Stop  (Seconds (SIMULATION_TAIL));
      Ptr<UdpServer> srv = DynamicCast<UdpServer> (serverApp.Get (0));
      NS_ASSERT_MSG (srv, "Failed to retrieve UdpServer instance for flow dst "
                     << fp.second);
      g_udpServers.push_back (srv);
    }

  // TRF-003: the attacker-on-path oracle walks EVERY flow's OLSR path; build
  // the (src,dst) address pairs once.
  std::vector<std::pair<Ipv4Address, Ipv4Address>> flowAddrPairs;
  for (const auto& fp : g_flowPairs)
    flowAddrPairs.emplace_back (interfaces.GetAddress (fp.first),
                                interfaces.GetAddress (fp.second));

  auto installWindow = [&] (double winStart, double winEnd) {
    const double startTime = winStart + UDP_START_OFFSET_IN_WINDOW;
    for (const auto& fp : g_flowPairs)
      {
        UdpClientHelper clientHelper (interfaces.GetAddress (fp.second),
                                      UDP_PORT);
        clientHelper.SetAttribute ("Interval",
                                   TimeValue (Seconds (UDP_PACKET_INTERVAL)));
        clientHelper.SetAttribute ("MaxPackets",
                                   UintegerValue (UDP_PACKETS_PER_WINDOW));
        clientHelper.SetAttribute ("PacketSize",
                                   UintegerValue (UDP_PACKET_SIZE));
        ApplicationContainer apps =
            clientHelper.Install (nodes.Get (fp.first));
        apps.Start (Seconds (startTime));
        apps.Stop  (Seconds (winEnd));
      }
    Simulator::Schedule (Seconds (startTime - 2.0),
                         &ObserveAttackerOnPath, &nodes, attackerIds,
                         flowAddrPairs);
  };

  for (int slot = 0; slot < NUM_SLOTS; ++slot)
    installWindow (SlotWindowStart (slot), SlotWindowEnd (slot));

  Simulator::Schedule (Seconds (SIMULATION_END - 1.0), &ReportNumReceivedPackets);

  // ----- 7. FlowMonitor + per-slot scheduling (WIN-002) --------------------
  g_flowMonitor = g_flowHelper.InstallAll ();

  // Scheduling order at t = INITIAL_STABILIZATION (60 s) matters. ns-3 fires
  // same-timestamp events in insertion order, so we schedule:
  //   (1) the topology probe at t=59 (strictly before the gates),
  //   (2) the acceptance gates at t=60 -- they run in the NEUTRAL state
  //       because slot 0's scenario state is applied only afterwards,
  //   (3) the per-slot scenario-state transitions (slot 0 also at t=60,
  //       inserted AFTER the gates so the gates see the neutral state),
  //   (4) the per-slot measurement brackets.

  // (1) Topology probe (before the gates).
  Simulator::Schedule (Seconds (59.0),
                       &RecordTopologyProbe, &nodes, cfg.radioRange);

  // (2) Acceptance gates in the neutral (attack OFF, defense OFF) state.
  //     A rejection here short-circuits every later handler.
  Simulator::Schedule (Seconds (INITIAL_STABILIZATION),
                       &AssertConnectivity, &nodes);
  Simulator::Schedule (Seconds (INITIAL_STABILIZATION),
                       &AssertMinHops, &nodes, cfg.minHops);
  Simulator::Schedule (Seconds (INITIAL_STABILIZATION),
                       &CheckAndReportConnectivity, &nodes);

  // (3) Per-slot scenario-state transitions. Slot 0 transitions at t=60
  //     (immediately AFTER the gates by insertion order); subsequent slots
  //     at 60 + k*SLOT_DURATION.
  for (int slot = 0; slot < NUM_SLOTS; ++slot)
    Simulator::Schedule (Seconds (SlotTransitionTime (slot)),
                         &ApplyScenarioState, nodes, attackerIds,
                         cfg.spoofCount, slot);

  // (4) Per-slot measurement brackets.
  for (int slot = 0; slot < NUM_SLOTS; ++slot)
    {
      Simulator::Schedule (Seconds (SlotWindowStart (slot)),
                           &StartSlot, slot);
      Simulator::Schedule (Seconds (SlotWindowEnd (slot)),
                           &EndSlot, slot, &cfg);
    }

  // ----- 8. Trace hooks (POST-AUDIT) ---------------------------------------
  //
  // Mac/MacTx -> oracle-only per-node counter. (We do NOT parse the
  // packet here because at MacTx the IP datagram is preceded by an 8-byte
  // LLC/SNAP header added by WifiNetDevice::Send. Data observation is
  // performed at Ipv4::Tx instead, where the packet is bare IP.)
  Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacTx",
                   MakeCallback (&MacTxOracleOnlyCallback));
  // MacTxDrop feeds oracle-only per-node drop counts.
  Config::Connect ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/MacTxDrop",
                   MakeCallback (&MacTxDropCallback));
  // OBS-002b: PHY-trace failsafe connect.
  g_phyTraceAvailable = TryConnectPhyTrace ();
  g_features.SetPhyAvailable (g_phyTraceAvailable);
  if (!g_phyTraceAvailable)
    std::cout << "[phy_trace] unavailable; F-group features will be 0"
              << std::endl;

  // IPv4::Tx feeds both OLSR control parsing (port 698) AND data-packet
  // on-air observation (port 80) — see TraceOlsrPacket for the dispatch.
  // At this trace point the packet is the bare IP datagram (no LLC, no
  // MAC header), which is the right layer for both purposes.
  for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
      Ptr<Ipv4> ipv4Node = nodes.Get (i)->GetObject<Ipv4> ();
      ipv4Node->TraceConnectWithoutContext ("Tx", MakeCallback (&TraceOlsrPacket));
    }

  // ----- 9. Run -----------------------------------------------------------
  PrintSimStats (cfg, attackerIds);

  Simulator::Stop (Seconds (SIMULATION_TAIL));
  Simulator::Run ();
  Simulator::Destroy ();

  if (g_runRejected)
    {
      std::cout << "*** Run REJECTED: " << g_rejectReason
                << " at t=" << g_rejectedAtSec << "s" << std::endl;
    }

  auto wallEnd = std::chrono::steady_clock::now ();
  const double elapsed = std::chrono::duration<double> (wallEnd - wallStart).count ();
  std::cout << "Wall-clock runtime: " << elapsed << " seconds" << std::endl;

  // ----- 10. Topology probe row (every attempt) ---------------------------
  const std::string status = g_runRejected ? "rejected" : "accepted";
  FlushTopologyProbe (status, g_rejectReason, g_rejectedAtSec);

  // ----- 11. Promote staged rows iff accepted (RUN-004) -------------------
  if (!g_runRejected)
    PromoteStagedRows (cfg, elapsed);

  return g_runRejected ? 2 : 0;
}