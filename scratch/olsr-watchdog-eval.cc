/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

/*
 * Watchdog-OLSR Evaluation Harness
 * =================================
 *
 * Adapted verbatim from the FPNT-OLSR evaluation harness; only the defense
 * class binding and its configuration attributes have been swapped to match
 * OlsrWatchdogDefense. The four-phase scenario, topology generation,
 * connectivity check, traffic generation, FlowMonitor wiring, reporting,
 * and CSV output logic are byte-identical to the original. This is
 * intentional: identical evaluation harness => directly comparable metrics
 * across defense families.
 *
 * Automated four-phase simulation scenario for measuring the efficacy of the
 * Watchdog-OLSR cross-layer defense against blackhole attackers in a random
 * 2-D wireless ad-hoc network.
 *
 * Topology:
 *   N nodes distributed uniformly at random across an A x A square.
 *   Connectivity (via disk graph with radius R) is verified before the
 *   simulation runs; if the random placement is disconnected, a new
 *   placement is drawn with a reseeded RNG until connectivity holds.
 *
 * Timeline (total: 400 seconds):
 *
 *   [  0,  60)  Phase 1 warm-up   -- no attack, no defense, topology converges
 *   [ 60, 100)  Phase 1 measure   -- baseline
 *   [100, 160)  Phase 2 warm-up   -- attack ACTIVATED at t = 100
 *   [160, 200)  Phase 2 measure   -- attack only
 *   [200, 260)  Phase 3 warm-up   -- attack stopped, defense ACTIVATED at t=200
 *   [260, 300)  Phase 3 measure   -- defense only (no threat)
 *   [300, 360)  Phase 4 warm-up   -- attack REACTIVATED at t = 300
 *   [360, 400)  Phase 4 measure   -- attack + defense
 *
 * Metrics per measurement window:
 *   - Throughput (Mbps)
 *   - Packet delivery ratio (%)
 *   - Average end-to-end delay (s)
 *   - Tx / Rx packets
 *   - Rx bytes
 *
 * Output format:
 *   Human-readable summary to stdout.
 *   Optional CSV (one row per phase, appended) via --csvFile.
 *
 * Runtime toggle:
 *   Defense enable/disable uses the OlsrWatchdogDefense "Enabled" attribute,
 *   which turns every API call into a transparent no-op when false. The
 *   defense object itself is installed unconditionally at simulation
 *   startup, avoiding the architectural complexity of swapping
 *   defense pointers mid-run.
 *
 *   Attacker enable/disable uses the routing protocol's "IsMalicious"
 *   attribute, toggled via Simulator::Schedule callbacks.
 *
 * Usage examples:
 *   ./ns3 run "olsr-watchdog-eval --numNodes=50 --seed=1 --maliciousNodes=7,23"
 *   ./ns3 run "olsr-watchdog-eval --numNodes=50 --seed=1 --maliciousNodes=7,23 \
 *               --csvFile=results.csv"
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/olsr-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/olsr-watchdog-defense.h"

#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <vector>
#include <set>
#include <queue>
#include <cmath>
#include <algorithm>
#include <limits>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("OlsrWatchdogEval");

// ============================================================================
// Configuration (populated from CLI)
// ============================================================================

struct SimulationConfig
{
  // Topology.
  uint32_t numNodes       = 50;
  double   areaSize       = 1000.0;    // meters (square side)
  double   radioRange     = 250.0;     // meters (RangePropagationLossModel)
  uint32_t seed           = 1;         // RNG seed; drives node placement

  // Attacker configuration.
  std::string maliciousNodesList = "";    // CSV list of malicious node IDs
  uint32_t    spoofCount         = 5;     // Spoofed links per attacker

  // Defense configuration (OlsrWatchdogDefense attributes).
  // Defaults match the values baked into OlsrWatchdogDefense::GetTypeId.
  // They can be overridden from the CLI for sensitivity studies.
  Time     forwardTimeout         = MilliSeconds (500);
  Time     periodicInterval       = Seconds (1.0);
  Time     warmupDuration         = Seconds (15.0);
  uint32_t blacklistThreshold     = 10;
  double   rtsToDataRatioThresh   = 3.0;
  uint32_t selfDropsThreshold     = 5;
  uint32_t macFailureThreshold    = 3;
  uint32_t minRtsForHeuristic     = 5;
  double   minSelfReliability     = 0.3;

  // Traffic configuration.
  uint32_t numFlows                = 6;      // Randomly placed CBR flows
  uint32_t flowPacketSize          = 512;    // bytes
  std::string flowDataRate         = "64Kbps";
  uint32_t flowMinHops             = 2;      // Force multi-hop routing

  // Output.
  std::string csvFile              = "";
  bool        verbose              = false;

  // Derived placement data (filled by PlaceNodes).
  std::vector<Vector> positions;
};

// Phase definitions (seconds).
struct PhaseTiming
{
  double startTime;
  double measureStart;
  double measureEnd;
  std::string name;
  bool attackActive;
  bool defenseActive;
};

static const std::vector<PhaseTiming> kPhases = {
  {   0.0,  60.0, 100.0, "Baseline",               false, false },
  { 100.0, 160.0, 200.0, "Attack only",            true,  false },
  { 200.0, 260.0, 300.0, "Defense only",           false, true  },
  { 300.0, 360.0, 400.0, "Attack + Defense",       true,  true  },
};
constexpr double kTotalSimTime = 400.0;

// ============================================================================
// Connectivity Check
// ============================================================================

// Generates random uniform placements until the resulting disk graph with
// radius `range` is fully connected. Returns the positions and updates the
// seed so reruns can reproduce results. Aborts after maxAttempts to prevent
// infinite loops on pathological configurations.
static std::vector<Vector>
PlaceNodesConnected (uint32_t numNodes, double area, double range,
                     uint32_t seedIn, uint32_t& seedOutUsed,
                     uint32_t maxAttempts = 100)
{
  Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable> ();
  for (uint32_t attempt = 0; attempt < maxAttempts; ++attempt)
    {
      const uint32_t currentSeed = seedIn + attempt;
      RngSeedManager::SetSeed (currentSeed);
      RngSeedManager::SetRun (1);
      rng->SetStream (0);   // Reset stream association under the new seed.

      // Draw placements.
      std::vector<Vector> pos;
      pos.reserve (numNodes);
      for (uint32_t i = 0; i < numNodes; ++i)
        {
          pos.emplace_back (rng->GetValue (0.0, area),
                            rng->GetValue (0.0, area),
                            0.0);
        }

      // Build adjacency (disk graph).
      const double range2 = range * range;
      std::vector<std::vector<uint32_t>> adj (numNodes);
      for (uint32_t i = 0; i < numNodes; ++i)
        {
          for (uint32_t j = i + 1; j < numNodes; ++j)
            {
              const double dx = pos[i].x - pos[j].x;
              const double dy = pos[i].y - pos[j].y;
              if (dx * dx + dy * dy <= range2)
                {
                  adj[i].push_back (j);
                  adj[j].push_back (i);
                }
            }
        }

      // BFS from node 0.
      std::vector<bool> visited (numNodes, false);
      std::queue<uint32_t> bfs;
      visited[0] = true;
      bfs.push (0);
      uint32_t reached = 1;
      while (!bfs.empty ())
        {
          const uint32_t u = bfs.front ();
          bfs.pop ();
          for (const uint32_t v : adj[u])
            {
              if (!visited[v])
                {
                  visited[v] = true;
                  ++reached;
                  bfs.push (v);
                }
            }
        }

      if (reached == numNodes)
        {
          seedOutUsed = currentSeed;
          NS_LOG_INFO ("Connected placement found at attempt "
                       << attempt + 1 << " (seed " << currentSeed << ")");
          return pos;
        }

      NS_LOG_DEBUG ("Attempt " << attempt + 1 << ": disconnected ("
                    << reached << "/" << numNodes << " reachable)");
    }

  NS_FATAL_ERROR ("Failed to generate connected placement after "
                  << maxAttempts << " attempts. Try increasing the node "
                  << "count, area density, or radio range.");
}

// Returns shortest-path hop counts from `src` to all other nodes using BFS
// on the disk graph. UINT32_MAX for unreachable. Used to guide flow
// selection (force multi-hop).
static std::vector<uint32_t>
HopCountsFrom (const std::vector<Vector>& pos, uint32_t src, double range)
{
  const uint32_t n = pos.size ();
  const double range2 = range * range;
  std::vector<uint32_t> hops (n, std::numeric_limits<uint32_t>::max ());
  std::queue<uint32_t> bfs;
  hops[src] = 0;
  bfs.push (src);
  while (!bfs.empty ())
    {
      const uint32_t u = bfs.front ();
      bfs.pop ();
      for (uint32_t v = 0; v < n; ++v)
        {
          if (v == u || hops[v] != std::numeric_limits<uint32_t>::max ())
            continue;
          const double dx = pos[u].x - pos[v].x;
          const double dy = pos[u].y - pos[v].y;
          if (dx * dx + dy * dy <= range2)
            {
              hops[v] = hops[u] + 1;
              bfs.push (v);
            }
        }
    }
  return hops;
}

// ============================================================================
// Per-Node Helper: Find the OLSR routing protocol on a node
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
      Ptr<olsr::RoutingProtocol> olsr = DynamicCast<olsr::RoutingProtocol> (child);
      if (olsr) return olsr;
    }
  return nullptr;
}

// ============================================================================
// Phase Control Callbacks
// ============================================================================

static void
SetAttackState (NodeContainer nodes, const std::vector<uint32_t>& attackerIds,
                uint32_t spoofCount, bool active)
{
  for (uint32_t id : attackerIds)
    {
      if (id >= nodes.GetN ()) continue;
      Ptr<olsr::RoutingProtocol> olsr = GetOlsrProtocol (nodes.Get (id));
      if (!olsr) continue;
      olsr->SetAttribute ("IsMalicious", BooleanValue (active));
      olsr->SetAttribute ("SpoofedLinksCount",
                          UintegerValue (active ? spoofCount : 0));
    }
  std::cout << "[t=" << Simulator::Now ().GetSeconds () << "s] Attack "
            << (active ? "ACTIVATED" : "DEACTIVATED")
            << " on " << attackerIds.size () << " nodes" << std::endl;
}

static void
SetDefenseState (NodeContainer nodes, bool active)
{
  for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
      Ptr<olsr::RoutingProtocol> olsr = GetOlsrProtocol (nodes.Get (i));
      if (!olsr) continue;
      PointerValue pv;
      olsr->GetAttribute ("DefenseStrategy", pv);
      Ptr<olsr::OlsrWatchdogDefense> def =
          DynamicCast<olsr::OlsrWatchdogDefense> (pv.Get<olsr::OlsrDefenseStrategy> ());
      if (def)
        {
          def->SetAttribute ("Enabled", BooleanValue (active));
        }
    }
  std::cout << "[t=" << Simulator::Now ().GetSeconds () << "s] Defense "
            << (active ? "ACTIVATED" : "DEACTIVATED") << std::endl;
}

// ============================================================================
// Metrics Collection
// ============================================================================

struct PhaseStats
{
  std::string name;
  double measureStart = 0.0;
  double measureEnd   = 0.0;
  bool   attackActive  = false;
  bool   defenseActive = false;

  uint64_t txPackets   = 0;
  uint64_t rxPackets   = 0;
  uint64_t rxBytes     = 0;
  double   delaySumSec = 0.0;

  double ThroughputMbps () const
  {
    const double dur = measureEnd - measureStart;
    return (dur > 0) ? (rxBytes * 8.0) / (dur * 1.0e6) : 0.0;
  }
  double PdrPercent () const
  {
    return (txPackets > 0) ? (100.0 * rxPackets) / txPackets : 0.0;
  }
  double AvgDelaySec () const
  {
    return (rxPackets > 0) ? (delaySumSec / rxPackets) : 0.0;
  }
};

// Captures a flat snapshot of per-flow cumulative counters at the current
// simulation time. Phase deltas are computed by subtracting snapshots
// taken at the start and end of each measurement window.
struct FlowMonitorSnapshot
{
  uint64_t txPackets   = 0;
  uint64_t rxPackets   = 0;
  uint64_t rxBytes     = 0;
  double   delaySumSec = 0.0;
};

static FlowMonitorSnapshot
TakeSnapshot (Ptr<FlowMonitor> monitor)
{
  monitor->CheckForLostPackets ();
  const auto stats = monitor->GetFlowStats ();
  FlowMonitorSnapshot snap;
  for (const auto& [flowId, s] : stats)
    {
      snap.txPackets   += s.txPackets;
      snap.rxPackets   += s.rxPackets;
      snap.rxBytes     += s.rxBytes;
      snap.delaySumSec += s.delaySum.GetSeconds ();
    }
  return snap;
}

// Scheduled callbacks that read the FlowMonitor at phase boundaries and
// fill the corresponding PhaseStats struct via subtraction.
static void
CapturePhaseStart (Ptr<FlowMonitor> monitor,
                   std::vector<FlowMonitorSnapshot>* startSnaps,
                   size_t phaseIdx)
{
  (*startSnaps)[phaseIdx] = TakeSnapshot (monitor);
  std::cout << "[t=" << Simulator::Now ().GetSeconds () << "s] "
            << "Measurement START for phase " << phaseIdx + 1 << std::endl;
}

static void
CapturePhaseEnd (Ptr<FlowMonitor> monitor,
                 std::vector<FlowMonitorSnapshot>* startSnaps,
                 std::vector<PhaseStats>* phaseStats,
                 size_t phaseIdx)
{
  const auto end = TakeSnapshot (monitor);
  const auto& start = (*startSnaps)[phaseIdx];
  PhaseStats& ps = (*phaseStats)[phaseIdx];
  ps.txPackets   = end.txPackets   - start.txPackets;
  ps.rxPackets   = end.rxPackets   - start.rxPackets;
  ps.rxBytes     = end.rxBytes     - start.rxBytes;
  ps.delaySumSec = end.delaySumSec - start.delaySumSec;
  std::cout << "[t=" << Simulator::Now ().GetSeconds () << "s] "
            << "Measurement END   for phase " << phaseIdx + 1 << std::endl;
}

// ============================================================================
// Reporting
// ============================================================================

static void
PrintHumanReport (const SimulationConfig& cfg,
                  const std::vector<PhaseStats>& phases,
                  uint32_t seedUsed,
                  const std::vector<uint32_t>& attackerIds)
{
  std::cout << "\n";
  std::cout << "================================================================\n";
  std::cout << "          WATCHDOG-OLSR EVALUATION REPORT                       \n";
  std::cout << "================================================================\n";

  std::cout << "-- Topology --\n";
  std::cout << "  Nodes           : " << cfg.numNodes << "\n";
  std::cout << "  Area            : " << cfg.areaSize << " x " << cfg.areaSize << " m\n";
  std::cout << "  Radio range     : " << cfg.radioRange << " m\n";
  std::cout << "  Seed (used)     : " << seedUsed << "\n";
  std::cout << "\n";

  std::cout << "-- Attacker --\n";
  std::cout << "  Malicious nodes : ";
  for (size_t i = 0; i < attackerIds.size (); ++i)
    {
      if (i) std::cout << ",";
      std::cout << attackerIds[i];
    }
  if (attackerIds.empty ()) std::cout << "(none)";
  std::cout << "\n";
  std::cout << "  Spoofed links   : " << cfg.spoofCount << "\n";
  std::cout << "\n";

  std::cout << "-- Defense (OlsrWatchdogDefense) --\n";
  std::cout << "  ForwardTimeout      : " << cfg.forwardTimeout.GetSeconds () << " s\n";
  std::cout << "  PeriodicInterval    : " << cfg.periodicInterval.GetSeconds () << " s\n";
  std::cout << "  WarmupDuration      : " << cfg.warmupDuration.GetSeconds () << " s\n";
  std::cout << "  BlacklistThreshold  : " << cfg.blacklistThreshold << "\n";
  std::cout << "  RtsToDataRatio thr  : " << cfg.rtsToDataRatioThresh << "\n";
  std::cout << "  SelfDropsThreshold  : " << cfg.selfDropsThreshold << "\n";
  std::cout << "  MacFailureThreshold : " << cfg.macFailureThreshold << "\n";
  std::cout << "  MinRtsForHeuristic  : " << cfg.minRtsForHeuristic << "\n";
  std::cout << "  MinSelfReliability  : " << cfg.minSelfReliability << "\n";
  std::cout << "\n";

  std::cout << "-- Phase Results --\n";
  std::cout << std::setw (22) << std::left << "Phase"
            << std::setw (10) << std::right << "Attack"
            << std::setw (10) << "Defense"
            << std::setw (12) << "Thr(Mbps)"
            << std::setw (10) << "PDR(%)"
            << std::setw (12) << "Delay(s)"
            << std::setw (10) << "Rx pkts"
            << std::setw (10) << "Tx pkts"
            << "\n";
  std::cout << std::string (96, '-') << "\n";

  for (const auto& ps : phases)
    {
      std::cout << std::setw (22) << std::left << ps.name
                << std::setw (10) << std::right << (ps.attackActive  ? "on" : "off")
                << std::setw (10) << (ps.defenseActive ? "on" : "off")
                << std::setw (12) << std::fixed << std::setprecision (4) << ps.ThroughputMbps ()
                << std::setw (10) << std::fixed << std::setprecision (2) << ps.PdrPercent ()
                << std::setw (12) << std::fixed << std::setprecision (4) << ps.AvgDelaySec ()
                << std::setw (10) << ps.rxPackets
                << std::setw (10) << ps.txPackets
                << "\n";
    }
  std::cout << "================================================================\n";
}

static void
AppendCsvRow (const std::string& csvFile,
              const SimulationConfig& cfg,
              const std::vector<PhaseStats>& phases,
              uint32_t seedUsed,
              const std::vector<uint32_t>& attackerIds)
{
  if (csvFile.empty ()) return;

  // Header: write only if the file does not yet exist (or is empty).
  bool needHeader = false;
  {
    std::ifstream probe (csvFile);
    if (!probe.good () || probe.peek () == std::ifstream::traits_type::eof ())
      {
        needHeader = true;
      }
  }

  std::ofstream out (csvFile, std::ios::app);
  if (!out)
    {
      NS_LOG_ERROR ("Could not open CSV file for writing: " << csvFile);
      return;
    }

  if (needHeader)
    {
      out << "seed_used,num_nodes,area,range,"
          << "num_attackers,attackers,spoof_count,"
          << "forward_timeout_s,periodic_interval_s,warmup_duration_s,"
          << "blacklist_threshold,rts_to_data_ratio_thresh,"
          << "self_drops_threshold,mac_failure_threshold,"
          << "min_rts_for_heuristic,min_self_reliability,"
          << "phase_idx,phase_name,attack_on,defense_on,"
          << "tx_packets,rx_packets,rx_bytes,"
          << "throughput_mbps,pdr_percent,avg_delay_s\n";
    }

  std::stringstream attackerStr;
  for (size_t i = 0; i < attackerIds.size (); ++i)
    {
      if (i) attackerStr << "|";
      attackerStr << attackerIds[i];
    }

  for (size_t i = 0; i < phases.size (); ++i)
    {
      const auto& ps = phases[i];
      out << seedUsed << ","
          << cfg.numNodes << ","
          << cfg.areaSize << ","
          << cfg.radioRange << ","
          << attackerIds.size () << ","
          << attackerStr.str () << ","
          << cfg.spoofCount << ","
          << cfg.forwardTimeout.GetSeconds () << ","
          << cfg.periodicInterval.GetSeconds () << ","
          << cfg.warmupDuration.GetSeconds () << ","
          << cfg.blacklistThreshold << ","
          << cfg.rtsToDataRatioThresh << ","
          << cfg.selfDropsThreshold << ","
          << cfg.macFailureThreshold << ","
          << cfg.minRtsForHeuristic << ","
          << cfg.minSelfReliability << ","
          << i + 1 << ","
          << "\"" << ps.name << "\","
          << (ps.attackActive  ? "1" : "0") << ","
          << (ps.defenseActive ? "1" : "0") << ","
          << ps.txPackets << ","
          << ps.rxPackets << ","
          << ps.rxBytes << ","
          << std::fixed << std::setprecision (6) << ps.ThroughputMbps () << ","
          << std::fixed << std::setprecision (4) << ps.PdrPercent () << ","
          << std::fixed << std::setprecision (6) << ps.AvgDelaySec ()
          << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

int main (int argc, char *argv[])
{
  SimulationConfig cfg;

  CommandLine cmd;
  // Topology.
  cmd.AddValue ("numNodes",   "Number of nodes to place",          cfg.numNodes);
  cmd.AddValue ("areaSize",   "Side length of the square area (m)", cfg.areaSize);
  cmd.AddValue ("range",      "Radio range (m, disk graph)",        cfg.radioRange);
  cmd.AddValue ("seed",       "RNG seed for node placement",        cfg.seed);

  // Attacker.
  cmd.AddValue ("maliciousNodes", "Comma-separated malicious node IDs",
                cfg.maliciousNodesList);
  cmd.AddValue ("spoofCount", "Spoofed-link count per attacker",    cfg.spoofCount);

  // Defense (OlsrWatchdogDefense parameters).
  cmd.AddValue ("forwardTimeout",      "Wait time before suspecting a missed forward (ms units accepted via Time syntax)",
                cfg.forwardTimeout);
  cmd.AddValue ("periodicInterval",    "Defense PeriodicCheck() interval",
                cfg.periodicInterval);
  cmd.AddValue ("warmupDuration",      "Warmup window after enabling defense",
                cfg.warmupDuration);
  cmd.AddValue ("blacklistThreshold",  "Evidence count required to blacklist a neighbor",
                cfg.blacklistThreshold);
  cmd.AddValue ("rtsToDataRatioThresh","RTS:DATA ratio above which a neighbor is suspicious",
                cfg.rtsToDataRatioThresh);
  cmd.AddValue ("selfDropsThreshold",  "Local PHY drops above which self-reliability degrades",
                cfg.selfDropsThreshold);
  cmd.AddValue ("macFailureThreshold", "MAC TX failures above which we suppress accusations",
                cfg.macFailureThreshold);
  cmd.AddValue ("minRtsForHeuristic",  "Minimum RTS count to enable RTS-without-DATA heuristic",
                cfg.minRtsForHeuristic);
  cmd.AddValue ("minSelfReliability",  "Floor value for self-reliability score",
                cfg.minSelfReliability);

  // Traffic.
  cmd.AddValue ("numFlows",       "Number of random CBR flows",   cfg.numFlows);
  cmd.AddValue ("flowPacketSize", "CBR packet size (bytes)",      cfg.flowPacketSize);
  cmd.AddValue ("flowDataRate",   "CBR data rate (e.g. 64Kbps)",  cfg.flowDataRate);
  cmd.AddValue ("flowMinHops",    "Minimum hop count source->destination",
                cfg.flowMinHops);

  // Output.
  cmd.AddValue ("csvFile", "Append per-phase results to this CSV file",
                cfg.csvFile);
  cmd.AddValue ("verbose", "Enable verbose logging", cfg.verbose);

  cmd.Parse (argc, argv);

  if (cfg.verbose)
    {
      LogComponentEnable ("OlsrWatchdogEval", LOG_LEVEL_INFO);
    }

  // ----- 1. Placement with connectivity check ---------------------------
  uint32_t seedUsed = cfg.seed;
  cfg.positions = PlaceNodesConnected (cfg.numNodes, cfg.areaSize,
                                        cfg.radioRange, cfg.seed, seedUsed);

  std::cout << "Generated connected placement with seed " << seedUsed
            << " (" << cfg.numNodes << " nodes)" << std::endl;

  // ----- 2. Build ns-3 topology ----------------------------------------
  NodeContainer nodes;
  nodes.Create (cfg.numNodes);

  // Wifi configuration mirrors the user's original script.
  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211g);
  wifi.SetRemoteStationManager ("ns3::AarfWifiManager",
                                "RtsCtsThreshold", UintegerValue (0));

  YansWifiPhyHelper wifiPhy;
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel",
                                  "MaxRange", DoubleValue (cfg.radioRange));

  wifiPhy.SetChannel (wifiChannel.Create ());
  wifiPhy.SetErrorRateModel ("ns3::NistErrorRateModel");
  wifiPhy.Set ("TxPowerStart", DoubleValue (16.0));
  wifiPhy.Set ("TxPowerEnd",   DoubleValue (16.0));
  wifiPhy.Set ("RxGain",       DoubleValue (0));
  wifiPhy.Set ("TxGain",       DoubleValue (0));

  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac", "QosSupported", BooleanValue (false));

  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);

  // Mobility: constant positions from the validated placement.
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> alloc = CreateObject<ListPositionAllocator> ();
  for (const auto& p : cfg.positions)
    {
      alloc->Add (p);
    }
  mobility.SetPositionAllocator (alloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes);

  // Routing.
  OlsrHelper olsr;
  Ipv4ListRoutingHelper list;
  list.Add (olsr, 100);

  InternetStackHelper internet;
  internet.SetRoutingHelper (list);
  internet.Install (nodes);

  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = ipv4.Assign (devices);

  // ----- 3. Install defense on every node (initially disabled) ---------
  // The defense is always installed. We toggle its Enabled attribute at
  // phase boundaries, which turns its public API into a transparent no-op.
  for (uint32_t i = 0; i < nodes.GetN (); ++i)
    {
      Ptr<olsr::RoutingProtocol> proto = GetOlsrProtocol (nodes.Get (i));
      NS_ASSERT_MSG (proto, "OLSR protocol not found on node " << i);

      Ptr<olsr::OlsrWatchdogDefense> def = CreateObject<olsr::OlsrWatchdogDefense> ();
      def->SetAttribute ("Enabled",                BooleanValue  (false));
      def->SetAttribute ("ForwardTimeout",         TimeValue     (cfg.forwardTimeout));
      def->SetAttribute ("PeriodicInterval",       TimeValue     (cfg.periodicInterval));
      def->SetAttribute ("WarmupDuration",         TimeValue     (cfg.warmupDuration));
      def->SetAttribute ("BlacklistThreshold",     UintegerValue (cfg.blacklistThreshold));
      def->SetAttribute ("RtsToDataRatioThreshold",DoubleValue   (cfg.rtsToDataRatioThresh));
      def->SetAttribute ("SelfDropsThreshold",     UintegerValue (cfg.selfDropsThreshold));
      def->SetAttribute ("MacFailureThreshold",    UintegerValue (cfg.macFailureThreshold));
      def->SetAttribute ("MinRtsForHeuristic",     UintegerValue (cfg.minRtsForHeuristic));
      def->SetAttribute ("MinSelfReliability",     DoubleValue   (cfg.minSelfReliability));

      proto->SetAttribute ("DefenseStrategy", PointerValue (def));
    }

  // ----- 4. Parse malicious nodes list ---------------------------------
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
            if (id < cfg.numNodes)
              {
                attackerIds.push_back (id);
              }
            else
              {
                NS_LOG_WARN ("Attacker ID " << id << " out of range; ignoring");
              }
          }
        catch (...)
          {
            NS_LOG_WARN ("Malformed attacker id: '" << seg << "'");
          }
      }
  }

  // ----- 5. Install traffic flows --------------------------------------
  // We place numFlows random CBR flows. Each (src, dst) pair is chosen
  // such that dst is at least flowMinHops hops from src on the disk graph,
  // which forces the routing protocol to relay through intermediate nodes.
  // Flows run continuously across the whole simulation so every phase
  // measures under consistent offered load.
  uint16_t sinkPort = 9000;
  PacketSinkHelper sinkHelper ("ns3::UdpSocketFactory",
                               Address (InetSocketAddress (Ipv4Address::GetAny (), sinkPort)));
  ApplicationContainer sinks = sinkHelper.Install (nodes);
  sinks.Start (Seconds (0.0));
  sinks.Stop  (Seconds (kTotalSimTime));

  {
    Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable> ();
    rng->SetStream (seedUsed * 7919u + 13u);   // stable per-seed stream

    const std::set<uint32_t> attackerSet (attackerIds.begin (), attackerIds.end ());
    uint32_t installed = 0;
    uint32_t tries     = 0;
    const uint32_t maxTries = cfg.numFlows * 40u + 100u;

    while (installed < cfg.numFlows && tries < maxTries)
      {
        ++tries;
        const uint32_t src = rng->GetInteger (0, cfg.numNodes - 1);
        const uint32_t dst = rng->GetInteger (0, cfg.numNodes - 1);
        if (src == dst) continue;
        // Avoid flows whose endpoints are attackers -- the paper measures
        // traffic through the attacker, not originating/terminating at it.
        if (attackerSet.count (src) || attackerSet.count (dst)) continue;

        const auto hops = HopCountsFrom (cfg.positions, src, cfg.radioRange);
        if (hops[dst] == std::numeric_limits<uint32_t>::max ()) continue;
        if (hops[dst] < cfg.flowMinHops) continue;

        OnOffHelper onoff ("ns3::UdpSocketFactory",
                           InetSocketAddress (interfaces.GetAddress (dst), sinkPort));
        onoff.SetAttribute ("OnTime",  StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
        onoff.SetAttribute ("PacketSize", UintegerValue (cfg.flowPacketSize));
        onoff.SetAttribute ("DataRate",   StringValue  (cfg.flowDataRate));

        ApplicationContainer app = onoff.Install (nodes.Get (src));
        app.Start (Seconds (0.5));   // nonzero to avoid simultaneous-start artifacts
        app.Stop  (Seconds (kTotalSimTime));
        ++installed;

        NS_LOG_INFO ("Flow " << installed << ": node " << src << " -> node " << dst
                     << " (" << hops[dst] << " hops)");
      }

    if (installed < cfg.numFlows)
      {
        NS_LOG_WARN ("Only " << installed << " of " << cfg.numFlows
                     << " flows could be placed. The topology may be too "
                     "dense or the flowMinHops value too large.");
      }
    std::cout << "Installed " << installed << " CBR flows" << std::endl;
  }

  // ----- 6. FlowMonitor + phase-boundary callbacks ---------------------
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  std::vector<FlowMonitorSnapshot> startSnaps (kPhases.size ());
  std::vector<PhaseStats>          phaseStats (kPhases.size ());

  for (size_t i = 0; i < kPhases.size (); ++i)
    {
      const auto& ph = kPhases[i];
      phaseStats[i].name          = ph.name;
      phaseStats[i].measureStart  = ph.measureStart;
      phaseStats[i].measureEnd    = ph.measureEnd;
      phaseStats[i].attackActive  = ph.attackActive;
      phaseStats[i].defenseActive = ph.defenseActive;
    }

  // Phase-transition events: toggle attack/defense, snapshot the monitor.
  // Phase 1 starts at t=0 with both off (no action needed at t=0).
  // Phase 2 at t=100: attack on.
  Simulator::Schedule (Seconds (kPhases[1].startTime),
                       &SetAttackState, nodes, attackerIds, cfg.spoofCount, true);
  // Phase 3 at t=200: attack off, defense on.
  Simulator::Schedule (Seconds (kPhases[2].startTime),
                       &SetAttackState, nodes, attackerIds, cfg.spoofCount, false);
  Simulator::Schedule (Seconds (kPhases[2].startTime),
                       &SetDefenseState, nodes, true);
  // Phase 4 at t=300: attack on (defense remains on).
  Simulator::Schedule (Seconds (kPhases[3].startTime),
                       &SetAttackState, nodes, attackerIds, cfg.spoofCount, true);

  // Measurement-window boundaries.
  for (size_t i = 0; i < kPhases.size (); ++i)
    {
      Simulator::Schedule (Seconds (kPhases[i].measureStart),
                           &CapturePhaseStart, monitor, &startSnaps, i);
      Simulator::Schedule (Seconds (kPhases[i].measureEnd),
                           &CapturePhaseEnd,   monitor, &startSnaps, &phaseStats, i);
    }

  // ----- 7. Run ----------------------------------------------------------
  Simulator::Stop (Seconds (kTotalSimTime));
  Simulator::Run ();

  // ----- 8. Reporting ---------------------------------------------------
  PrintHumanReport (cfg, phaseStats, seedUsed, attackerIds);
  AppendCsvRow     (cfg.csvFile, cfg, phaseStats, seedUsed, attackerIds);

  Simulator::Destroy ();
  return 0;
}