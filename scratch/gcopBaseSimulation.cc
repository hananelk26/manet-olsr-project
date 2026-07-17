// /*
//  * watchdogBaseSimulation.cc
//  * =========================
//  * OLSR Blackhole Attack & GCOP Defense - NS-3 Simulation.
//  *
//  * Methodology (matches partner's iolsr simulation):
//  *   - All 50 nodes are placed RANDOMLY in a 750x1000 m area.
//  *   - At t=60s, after OLSR has converged:
//  *       * Connectivity is verified (every node must have nNodes-1 routes).
//  *       * The attacker is selected dynamically as the first node found that
//  *         is a direct (1-hop) neighbor of the UDP destination (Node 0).
//  *       * If Node 1 (the UDP source) is also a direct neighbor of Node 0,
//  *         the run is rejected (NEIGHBOR_ABORT) because the route Node 1 ->
//  *         Node 0 would be 1-hop and never traverse the attacker.
//  *   - This dynamic selection guarantees the attacker is on a route that
//  *     actually carries traffic, so the attack/defense can be measured.
//  *     This is the standard methodology in OLSR attack research; it does NOT
//  *     bias toward "easy" attacker positions, only toward attacker positions
//  *     that are actually capable of intercepting traffic.
//  *
//  * Four phases (single 402 s run):
//  *   0 - 60   Initial stabilization + connectivity check + attacker selection
//  *   60- 100  Baseline                (no attack, no defense)        -- window
//  *   100-160  Attack stabilization
//  *   160-200  Attack-only             (attack on, no defense)        -- window
//  *   200-260  Defense stabilization
//  *   260-300  Defense-only            (no attack, defense on)        -- window
//  *   300-360  Defense+Attack stab.
//  *   360-400  Defense vs. Attack      (both on)                      -- window
//  *
//  * Each window: UdpClient on node 1 sends 18 packets of 512 bytes every 2 s
//  * to UdpServer on node 0 (10.0.0.1), starting 4 s into the window.
//  * PDR per phase = received_in_window / 18.
//  *
//  * The result line is printed to stdout in the form:
//  *   RESULT,run=<N>,STATUS=OK,attacker_id=<I>,baseline_pdr=...,attack_pdr=...,...
//  * or one of:
//  *   RESULT,run=<N>,STATUS=NO_CONNECTIVITY,...
//  *   RESULT,run=<N>,STATUS=NEIGHBOR_ABORT,...
//  *   RESULT,run=<N>,STATUS=NO_ATTACKER,...
//  */

// #include "ns3/core-module.h"
// #include "ns3/network-module.h"
// #include "ns3/internet-module.h"
// #include "ns3/olsr-module.h"
// #include "ns3/mobility-module.h"
// #include "ns3/wifi-module.h"
// #include "ns3/applications-module.h"
// #include "ns3/traffic-control-module.h"

// #include "ns3/ipv4-list-routing.h"
// #include "ns3/olsr-routing-protocol.h"
// #include "ns3/olsr-defense-strategy.h"
// #include "ns3/olsr-defense-gcop.h"

// #include <iostream>
// #include <iomanip>
// #include <limits>
// #include <cmath>
// #include <map>
// #include <vector>

// using namespace ns3;
// using namespace ns3::olsr;

// NS_LOG_COMPONENT_DEFINE("OlsrBlackholeDefense");

// // ---------------------------------------------------------------------------
// // Globals (used by scheduled callbacks)
// // ---------------------------------------------------------------------------
// static uint32_t          g_attackerId = UINT32_MAX;     // selected dynamically
// static uint32_t          g_spoofedLinks = 0;             // CLI-controlled
// static NodeContainer     g_nodes;
// static Ptr<UdpServer>    g_udpServer;

// // Run-status flags set by CheckConnectivityAndPickAttacker()
// static bool g_neighborAbort  = false;   // Node 1 is a 1-hop neighbor of Node 0
// static bool g_noAttacker     = false;   // No suitable attacker found

// static uint64_t g_rxBaselineStart = 0, g_rxBaselineEnd = 0;
// static uint64_t g_rxAttackStart   = 0, g_rxAttackEnd   = 0;
// static uint64_t g_rxDefenseStart  = 0, g_rxDefenseEnd  = 0;
// static uint64_t g_rxBothStart     = 0, g_rxBothEnd     = 0;

// static bool     g_connectivityOk = false;
// static uint32_t g_minRoutes      = 0;
// static uint32_t g_failingNode    = 0;

// // ---------------------------------------------------------------------------
// // Helper: extract the OLSR routing protocol pointer from a node
// // ---------------------------------------------------------------------------
// static Ptr<RoutingProtocol>
// GetOlsrProto(Ptr<Node> node)
// {
//     Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
//     if (!ipv4) return nullptr;
//     Ptr<Ipv4RoutingProtocol> rp = ipv4->GetRoutingProtocol();
//     Ptr<Ipv4ListRouting> list = DynamicCast<Ipv4ListRouting>(rp);
//     if (!list) return DynamicCast<RoutingProtocol>(rp);
//     for (uint32_t i = 0; i < list->GetNRoutingProtocols(); ++i)
//     {
//         int16_t prio;
//         Ptr<Ipv4RoutingProtocol> sub = list->GetRoutingProtocol(i, prio);
//         Ptr<RoutingProtocol> olsrRp = DynamicCast<RoutingProtocol>(sub);
//         if (olsrRp) return olsrRp;
//     }
//     return nullptr;
// }

// // ---------------------------------------------------------------------------
// // Phase activation events
// // ---------------------------------------------------------------------------
// static void EnableAttack()
// {
//     if (g_attackerId == UINT32_MAX)
//     {
//         // Attacker selection failed at t=60 (NEIGHBOR_ABORT or NO_ATTACKER);
//         // simulation already aborted, this should not be reached.
//         return;
//     }
//     Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(g_attackerId));
//     NS_ASSERT(rp);
//     rp->SetAttribute("SpoofedLinksCount", UintegerValue(g_spoofedLinks));
//     rp->SetAttribute("IsMalicious", BooleanValue(true));
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Attack ENABLED on node " << g_attackerId
//               << " (spoofedLinks=" << g_spoofedLinks << ")" << std::endl;
// }

// static void DisableAttack()
// {
//     if (g_attackerId == UINT32_MAX) return;
//     Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(g_attackerId));
//     NS_ASSERT(rp);
//     rp->SetAttribute("IsMalicious", BooleanValue(false));
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Attack DISABLED on node " << g_attackerId << std::endl;
// }

// static void EnableDefenseEverywhere()
// {
//     if (g_attackerId == UINT32_MAX) return;
//     uint32_t count = 0;
//     for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
//     {
//         if (i == g_attackerId) continue;          // attacker keeps Null defense
//         Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(i));
//         NS_ASSERT(rp);
//         Ptr<OlsrDefenseGcop> def = CreateObject<OlsrDefenseGcop>();
//         rp->SetAttribute("DefenseStrategy", PointerValue(def));
//         rp->ReactivateDefenseStrategy();
//         ++count;
//     }
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Defense (GCOP) ENABLED on " << count << " benign nodes." << std::endl;
// }

// // ---------------------------------------------------------------------------
// // Disable the forced RTS/CTS that the modified OLSR enables in DoInitialize.
// // The modified OlsrRoutingProtocol forces RtsCtsThreshold=0 on every node so
// // that defense Algorithm 1 can monitor RTS/CTS traffic. With dense control
// // traffic (50 nodes broadcasting HELLO/TC) the resulting MAC contention
// // prevents stable MPR selection and TC propagation. The defense strategy
// // used here (GCOP) does NOT use the RTS/CTS hooks, so we restore the standard
// // 802.11 default of 2200 bytes.
// // ---------------------------------------------------------------------------
// static void DisableForcedRtsCts()
// {
//     uint32_t fixed = 0;
//     for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
//     {
//         Ptr<Node> node = g_nodes.Get(i);
//         for (uint32_t d = 0; d < node->GetNDevices(); ++d)
//         {
//             Ptr<WifiNetDevice> wifiDev = DynamicCast<WifiNetDevice>(node->GetDevice(d));
//             if (!wifiDev) continue;
//             Ptr<WifiRemoteStationManager> mgr = wifiDev->GetRemoteStationManager();
//             if (!mgr) continue;
//             mgr->SetAttribute("RtsCtsThreshold", UintegerValue(2200));
//             ++fixed;
//         }
//     }
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] RtsCtsThreshold restored to 2200 on " << fixed << " devices." << std::endl;
// }

// // ---------------------------------------------------------------------------
// // UDP receive snapshots
// // One dedicated function per snapshot point - avoids passing std::string
// // to Simulator::Schedule, which can be brittle with template deduction.
// // ---------------------------------------------------------------------------
// static void SnapshotBaselineStart()
// {
//     g_rxBaselineStart = g_udpServer->GetReceived();
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Snapshot BASELINE_START = " << g_rxBaselineStart << std::endl;
// }
// static void SnapshotBaselineEnd()
// {
//     g_rxBaselineEnd = g_udpServer->GetReceived();
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Snapshot BASELINE_END   = " << g_rxBaselineEnd << std::endl;
// }
// static void SnapshotAttackStart()
// {
//     g_rxAttackStart = g_udpServer->GetReceived();
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Snapshot ATTACK_START   = " << g_rxAttackStart << std::endl;
// }
// static void SnapshotAttackEnd()
// {
//     g_rxAttackEnd = g_udpServer->GetReceived();
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Snapshot ATTACK_END     = " << g_rxAttackEnd << std::endl;
// }
// static void SnapshotDefenseStart()
// {
//     g_rxDefenseStart = g_udpServer->GetReceived();
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Snapshot DEFENSE_START  = " << g_rxDefenseStart << std::endl;
// }
// static void SnapshotDefenseEnd()
// {
//     g_rxDefenseEnd = g_udpServer->GetReceived();
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Snapshot DEFENSE_END    = " << g_rxDefenseEnd << std::endl;
// }
// static void SnapshotBothStart()
// {
//     g_rxBothStart = g_udpServer->GetReceived();
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Snapshot BOTH_START     = " << g_rxBothStart << std::endl;
// }
// static void SnapshotBothEnd()
// {
//     g_rxBothEnd = g_udpServer->GetReceived();
//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] Snapshot BOTH_END       = " << g_rxBothEnd << std::endl;
// }

// // ---------------------------------------------------------------------------
// // Helper: is `target` a 1-hop (symmetric) neighbor of node[viewerIndex]?
// // We check the viewer's routing table for an entry with distance == 1
// // whose destination matches `target`.
// // ---------------------------------------------------------------------------
// static bool IsOneHopNeighbor(uint32_t viewerIndex, Ipv4Address target)
// {
//     Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(viewerIndex));
//     if (!rp) return false;
//     for (auto const& e : rp->GetRoutingTableEntries())
//     {
//         if (e.destAddr == target && e.distance == 1) return true;
//     }
//     return false;
// }

// // ---------------------------------------------------------------------------
// // Run at t = 59.9 s (after OLSR has converged):
// //   1. Verify full connectivity (every node has nNodes-1 routes).
// //   2. Reject the run if Node 1 is a 1-hop neighbor of Node 0 - the route
// //      would be 1-hop and the attacker (multi-hop) cannot intercept.
// //   3. Pick the attacker as the first node in [3..nNodes-1] that is a
// //      1-hop neighbor of Node 0.
// // ---------------------------------------------------------------------------
// static void CheckConnectivityAndPickAttacker(uint32_t expectedRoutes)
// {
//     g_connectivityOk = true;
//     g_neighborAbort  = false;
//     g_noAttacker     = false;
//     g_minRoutes      = std::numeric_limits<uint32_t>::max();
//     g_failingNode    = 0;

//     // Build a histogram of routing-table sizes for diagnostics.
//     std::map<uint32_t, uint32_t> histogram;
//     uint32_t totalRoutes = 0;

//     for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
//     {
//         Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(i));
//         if (!rp)
//         {
//             g_connectivityOk = false;
//             std::cout << "[t=" << Simulator::Now().GetSeconds()
//                       << "] CONNECTIVITY: node " << i << " has NO OLSR protocol" << std::endl;
//             Simulator::Stop();
//             return;
//         }
//         size_t routes = rp->GetRoutingTableEntries().size();
//         histogram[(uint32_t) routes]++;
//         totalRoutes += (uint32_t) routes;
//         if (routes < g_minRoutes)
//         {
//             g_minRoutes   = (uint32_t) routes;
//             g_failingNode = i;
//         }
//         if (routes < expectedRoutes)
//         {
//             g_connectivityOk = false;
//         }
//     }

//     double avgRoutes = (double) totalRoutes / (double) g_nodes.GetN();

//     std::cout << "[t=" << Simulator::Now().GetSeconds()
//               << "] CONNECTIVITY: minRoutes=" << g_minRoutes
//               << " (node " << g_failingNode << ")"
//               << " avgRoutes=" << avgRoutes
//               << " expected=" << expectedRoutes
//               << " result=" << (g_connectivityOk ? "OK" : "FAIL") << std::endl;

//     if (!g_connectivityOk)
//     {
//         std::cout << "[t=" << Simulator::Now().GetSeconds()
//                   << "] Aborting run - incomplete connectivity." << std::endl;
//         Simulator::Stop();
//         return;
//     }

//     Ipv4Address node0Addr("10.0.0.1");

//     // 2. Reject if Node 1 is a 1-hop neighbor of Node 0
//     if (IsOneHopNeighbor(1, node0Addr))
//     {
//         g_neighborAbort = true;
//         std::cout << "[t=" << Simulator::Now().GetSeconds()
//                   << "] Aborting run - Node 1 is a 1-hop neighbor of Node 0;"
//                   << " no multi-hop route to attack." << std::endl;
//         Simulator::Stop();
//         return;
//     }

//     // 3. Pick the attacker: first node in [3..nNodes-1] that is a 1-hop
//     //    neighbor of Node 0. We start at 3 to keep nodes 0, 1, 2 reserved
//     //    (server, client, and a "buffer" index) - matches partner's logic.
//     g_attackerId = UINT32_MAX;
//     for (uint32_t i = 3; i < g_nodes.GetN(); ++i)
//     {
//         if (IsOneHopNeighbor(i, node0Addr))
//         {
//             g_attackerId = i;
//             std::cout << "[t=" << Simulator::Now().GetSeconds()
//                       << "] Attacker selected: node " << i
//                       << " (1-hop neighbor of Node 0)" << std::endl;
//             break;
//         }
//     }

//     if (g_attackerId == UINT32_MAX)
//     {
//         g_noAttacker = true;
//         std::cout << "[t=" << Simulator::Now().GetSeconds()
//                   << "] Aborting run - no suitable attacker found"
//                   << " (no node in [3..N-1] is a 1-hop neighbor of Node 0)." << std::endl;
//         Simulator::Stop();
//         return;
//     }
// }

// // ---------------------------------------------------------------------------
// // MAIN
// // ---------------------------------------------------------------------------
// int
// main(int argc, char* argv[])
// {
//     // ----- Default parameters (match partner's iolsr simulation) -----
//     uint32_t nNodes             = 50;
//     double   dMaxGridX          = 750.0;
//     double   dMaxGridY          = 1000.0;
//     double   dSimulationSeconds = 402.0;
//     uint32_t runNumber          = 1;
//     uint32_t spoofedLinks       = 0;
//     uint32_t udpPacketSize      = 512;
//     double   udpInterval        = 2.0;
//     uint32_t udpMaxPackets      = 18;
//     bool     verbose            = false;

//     // Phase boundaries (matches partner's iolsr simulation timing)
//     const double INITIAL_STAB        = 60.0;
//     const double BASELINE_START      = 60.0;
//     const double BASELINE_END        = 100.0;
//     const double ATTACK_STAB_START   = 100.0;
//     const double ATTACK_START        = 160.0;
//     const double ATTACK_END          = 200.0;
//     const double DEFENSE_STAB_START  = 200.0;
//     const double DEFENSE_START       = 260.0;
//     const double DEFENSE_END         = 300.0;
//     const double BOTH_STAB_START     = 300.0;
//     const double BOTH_START          = 360.0;
//     const double BOTH_END            = 400.0;
//     const double UDP_OFFSET          = 4.0;

//     CommandLine cmd(__FILE__);
//     cmd.AddValue("run",          "RngSeedManager run number",      runNumber);
//     cmd.AddValue("nNodes",       "Number of nodes",                nNodes);
//     cmd.AddValue("spoofedLinks", "Number of spoofed links by attacker", spoofedLinks);
//     cmd.AddValue("verbose",      "Verbose phase logging",          verbose);
//     cmd.Parse(argc, argv);

//     g_spoofedLinks = spoofedLinks;

//     RngSeedManager::SetRun(runNumber);
//     Time::SetResolution(Time::NS);

//     // ----- Nodes -----
//     g_nodes.Create(nNodes);

//     // ----- WiFi stack (matches partner's setup exactly) -----
//     const double WIFI_RANGE = 190.0;
//     std::cout << "[BUILD CHECK] WiFi MaxRange = " << WIFI_RANGE << " m" << std::endl;

//     // IMPORTANT: Build the channel helper from scratch (NOT
//     // YansWifiChannelHelper::Default()) because the default in NS-3 3.40+
//     // includes a LogDistancePropagationLossModel that adds losses on top of
//     // RangePropagationLossModel - this fragments the network into islands
//     // of "barely-reachable" nodes even though they are within range.
//     // The partner's old NS-3 simulation worked because the old default did
//     // not include LogDistance. Here we use only ConstantSpeedPropagationDelay
//     // + RangePropagationLossModel for clean binary in-range/out-of-range.
//     YansWifiChannelHelper wifiChannel;
//     wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
//     wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel",
//                                    "MaxRange", DoubleValue(WIFI_RANGE));
//     YansWifiPhyHelper wifiPhy;
//     wifiPhy.Set("TxGain", DoubleValue(12.4));
//     wifiPhy.SetChannel(wifiChannel.Create());

//     WifiHelper wifi;
//     wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager");

//     WifiMacHelper wifiMac;
//     wifiMac.SetType("ns3::AdhocWifiMac");

//     NetDeviceContainer adhocDevices = wifi.Install(wifiPhy, wifiMac, g_nodes);

//     // ----- Internet stack with OLSR routing -----
//     OlsrHelper olsr;
//     Ipv4ListRoutingHelper routeList;
//     routeList.Add(olsr, 100);
//     InternetStackHelper internet;
//     internet.SetRoutingHelper(routeList);
//     internet.Install(g_nodes);

//     // ----- Traffic Control -----
//     // PfifoFastQueueDisc: classic 3-band priority queue with an explicit
//     // MaxSize attribute. This works correctly with the cross-layer queue
//     // monitoring inside HandleDefenseTimer (which calls GetMaxSize on the
//     // root queue disc).
//     //
//     // (We tried a single FifoQueueDisc first; it caused all control traffic
//     // to silently drop in the multi-queue WiFi MAC. PfifoFastQueueDisc has
//     // 3 internal priority queues and is much more forgiving.)
//     TrafficControlHelper tch;
//     tch.SetRootQueueDisc("ns3::PfifoFastQueueDisc",
//                          "MaxSize", QueueSizeValue(QueueSize("1000p")));
//     tch.Install(adhocDevices);

//     Ipv4AddressHelper addresses;
//     addresses.SetBase("10.0.0.0", "255.0.0.0");
//     Ipv4InterfaceContainer interfaces = addresses.Assign(adhocDevices);

//     // ----- Mobility -----
//     // ALL nodes (including server, client, future attacker) are placed
//     // randomly in the area. The attacker is chosen dynamically at t=60s
//     // as the first 1-hop neighbor of Node 0 found in the routing tables.
//     Ptr<UniformRandomVariable> randX = CreateObject<UniformRandomVariable>();
//     randX->SetAttribute("Min", DoubleValue(0));
//     randX->SetAttribute("Max", DoubleValue(dMaxGridX));
//     Ptr<UniformRandomVariable> randY = CreateObject<UniformRandomVariable>();
//     randY->SetAttribute("Min", DoubleValue(0));
//     randY->SetAttribute("Max", DoubleValue(dMaxGridY));

//     Ptr<RandomRectanglePositionAllocator> randomPos =
//         CreateObject<RandomRectanglePositionAllocator>();
//     randomPos->SetX(randX);
//     randomPos->SetY(randY);

//     MobilityHelper mobility;
//     mobility.SetPositionAllocator(randomPos);
//     mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
//     mobility.Install(g_nodes);

//     // ----- Initial OLSR configuration -----
//     // Every node starts with OlsrDefenseNull and IsMalicious=false.
//     // SpoofedLinksCount and the attacker selection happen later, at t=60s,
//     // once OLSR has converged and we can find a 1-hop neighbor of Node 0.
//     for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
//     {
//         Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(i));
//         NS_ASSERT(rp);
//         Ptr<OlsrDefenseNull> nullDef = CreateObject<OlsrDefenseNull>();
//         rp->SetAttribute("DefenseStrategy", PointerValue(nullDef));
//         rp->SetAttribute("IsMalicious",     BooleanValue(false));
//     }

//     // ----- UDP server on Node 0 -----
//     UdpServerHelper udpServerHelper(80);
//     ApplicationContainer serverApps = udpServerHelper.Install(g_nodes.Get(0));
//     serverApps.Start(Seconds(0.0));
//     serverApps.Stop(Seconds(dSimulationSeconds));
//     g_udpServer = DynamicCast<UdpServer>(serverApps.Get(0));
//     NS_ASSERT_MSG(g_udpServer, "Failed to retrieve UdpServer from ApplicationContainer");

//     // ----- UDP clients (one per measurement window) on Node 1 -----
//     UdpClientHelper udpClient(Ipv4Address("10.0.0.1"), 80);
//     udpClient.SetAttribute("Interval",   TimeValue(Seconds(udpInterval)));
//     udpClient.SetAttribute("MaxPackets", UintegerValue(udpMaxPackets));
//     udpClient.SetAttribute("PacketSize", UintegerValue(udpPacketSize));

//     auto installWindow = [&](double startSec, double stopSec) {
//         ApplicationContainer apps = udpClient.Install(g_nodes.Get(1));
//         apps.Start(Seconds(startSec));
//         apps.Stop(Seconds(stopSec));
//     };
//     installWindow(BASELINE_START + UDP_OFFSET, BASELINE_END);
//     installWindow(ATTACK_START   + UDP_OFFSET, ATTACK_END);
//     installWindow(DEFENSE_START  + UDP_OFFSET, DEFENSE_END);
//     installWindow(BOTH_START     + UDP_OFFSET, BOTH_END);

//     // ----- Schedule connectivity check, snapshots, and phase activations -----
//     // Restore RTS/CTS threshold immediately after DoInitialize forces it to 0.
//     // DoInitialize runs at t=0, so 1 ms later is safe.
//     Simulator::Schedule(MilliSeconds(1), &DisableForcedRtsCts);

//     Simulator::Schedule(Seconds(INITIAL_STAB - 0.1),
//                         &CheckConnectivityAndPickAttacker, nNodes - 1);

//     // Baseline window snapshots
//     Simulator::Schedule(Seconds(BASELINE_START + UDP_OFFSET - 0.01), &SnapshotBaselineStart);
//     Simulator::Schedule(Seconds(BASELINE_END + 0.5),                 &SnapshotBaselineEnd);

//     // Attack-only phase
//     Simulator::Schedule(Seconds(ATTACK_STAB_START), &EnableAttack);
//     Simulator::Schedule(Seconds(ATTACK_START + UDP_OFFSET - 0.01),   &SnapshotAttackStart);
//     Simulator::Schedule(Seconds(ATTACK_END + 0.5),                   &SnapshotAttackEnd);

//     // Defense-only phase: turn off attack, turn on defense
//     Simulator::Schedule(Seconds(DEFENSE_STAB_START), &DisableAttack);
//     Simulator::Schedule(Seconds(DEFENSE_STAB_START), &EnableDefenseEverywhere);
//     Simulator::Schedule(Seconds(DEFENSE_START + UDP_OFFSET - 0.01),  &SnapshotDefenseStart);
//     Simulator::Schedule(Seconds(DEFENSE_END + 0.5),                  &SnapshotDefenseEnd);

//     // Defense-vs-Attack phase: re-enable attack (defense stays on)
//     Simulator::Schedule(Seconds(BOTH_STAB_START), &EnableAttack);
//     Simulator::Schedule(Seconds(BOTH_START + UDP_OFFSET - 0.01),     &SnapshotBothStart);
//     Simulator::Schedule(Seconds(BOTH_END + 0.5),                     &SnapshotBothEnd);

//     // ----- Run -----
//     std::cout << "Starting simulation, run=" << runNumber
//               << ", nNodes=" << nNodes
//               << ", area=" << dMaxGridX << "x" << dMaxGridY
//               << ", attacker=DYNAMIC (chosen at t=60s as 1-hop neighbor of Node 0)"
//               << ", spoofedLinks=" << spoofedLinks
//               << std::endl;

//     Simulator::Stop(Seconds(dSimulationSeconds));
//     Simulator::Run();
//     Simulator::Destroy();

//     // ----- Compute PDRs and report -----
//     auto pdr = [&](uint64_t a, uint64_t b) {
//         return (double)(b - a) / (double) udpMaxPackets;
//     };

//     std::cout << std::fixed << std::setprecision(4);
//     std::cout << "----- RESULTS -----" << std::endl;

//     if (!g_connectivityOk)
//     {
//         std::cout << "RESULT,run=" << runNumber
//                   << ",STATUS=NO_CONNECTIVITY"
//                   << ",minRoutes="   << g_minRoutes
//                   << ",failingNode=" << g_failingNode
//                   << ",expected="    << (nNodes - 1)
//                   << std::endl;
//         return 2;
//     }

//     if (g_neighborAbort)
//     {
//         std::cout << "RESULT,run=" << runNumber
//                   << ",STATUS=NEIGHBOR_ABORT"
//                   << ",reason=Node1_is_1hop_neighbor_of_Node0"
//                   << std::endl;
//         return 3;
//     }

//     if (g_noAttacker)
//     {
//         std::cout << "RESULT,run=" << runNumber
//                   << ",STATUS=NO_ATTACKER"
//                   << ",reason=No_node_in_3..N-1_is_1hop_neighbor_of_Node0"
//                   << std::endl;
//         return 4;
//     }

//     std::cout << "RESULT,run=" << runNumber
//               << ",STATUS=OK"
//               << ",attacker_id="  << g_attackerId
//               << ",baseline_pdr=" << pdr(g_rxBaselineStart, g_rxBaselineEnd)
//               << ",attack_pdr="   << pdr(g_rxAttackStart,   g_rxAttackEnd)
//               << ",defense_pdr="  << pdr(g_rxDefenseStart,  g_rxDefenseEnd)
//               << ",both_pdr="     << pdr(g_rxBothStart,     g_rxBothEnd)
//               << ",baseline_rx="  << (g_rxBaselineEnd - g_rxBaselineStart)
//               << ",attack_rx="    << (g_rxAttackEnd   - g_rxAttackStart)
//               << ",defense_rx="   << (g_rxDefenseEnd  - g_rxDefenseStart)
//               << ",both_rx="      << (g_rxBothEnd     - g_rxBothStart)
//               << ",sent_per_window=" << udpMaxPackets
//               << std::endl;
//     return 0;
// }





































/*
 * gcopBaseSimulation.cc
 * =========================
 * OLSR Blackhole Attack & GCOP Defense - NS-3 Simulation.
 *
 * Methodology (designed for feature-extraction / ML-training experiments):
 *   - 50 nodes total, 1000x750 m area, no mobility.
 *   - Node 0 (UDP server / victim) FIXED at (50, 50)        - top-left corner.
 *   - Node 1 (UDP client / sender) FIXED at (700, 700)      - bottom-right.
 *   - Node 2 (attacker)            FIXED at (500, 375)      - center.
 *   - Other 47 nodes: RANDOM placement per seed.
 *
 *   This guarantees that the multi-hop route from Node 1 to Node 0 must
 *   traverse the central region, so the attacker (positioned there) is
 *   reliably on the path. The randomness across the 47 background nodes
 *   provides per-seed topology diversity for ML feature extraction, while
 *   the fixed corner-to-corner sender/receiver layout removes the noise of
 *   "attacker not on route" cases that dominated earlier random-only runs.
 *
 *   At t=60s, after OLSR has converged:
 *     * Connectivity is verified (every node must have nNodes-1 routes).
 *
 * Four phases (single 402 s run):
 *   0 - 60   Initial stabilization + connectivity check
 *   60- 100  Baseline                (no attack, no defense)        -- window
 *   100-160  Attack stabilization
 *   160-200  Attack-only             (attack on, no defense)        -- window
 *   200-260  Defense stabilization
 *   260-300  Defense-only            (no attack, defense on)        -- window
 *   300-360  Defense+Attack stab.
 *   360-400  Defense vs. Attack      (both on)                      -- window
 *
 * Each window: UdpClient on node 1 sends 18 packets of 512 bytes every 2 s
 * to UdpServer on node 0 (10.0.0.1), starting 4 s into the window.
 * PDR per phase = received_in_window / 18.
 *
 * The result line is printed to stdout in the form:
 *   RESULT,run=<N>,STATUS=OK,attacker_id=2,baseline_pdr=...,attack_pdr=...,...
 * or
 *   RESULT,run=<N>,STATUS=NO_CONNECTIVITY,...
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/olsr-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/traffic-control-module.h"

#include "ns3/ipv4-list-routing.h"
#include "ns3/olsr-routing-protocol.h"
#include "ns3/olsr-defense-strategy.h"
#include "ns3/olsr-defense-gcop.h"

#include <iostream>
#include <iomanip>
#include <limits>
#include <cmath>
#include <map>
#include <vector>

using namespace ns3;
using namespace ns3::olsr;

NS_LOG_COMPONENT_DEFINE("OlsrBlackholeDefense");

// ---------------------------------------------------------------------------
// Globals (used by scheduled callbacks)
// ---------------------------------------------------------------------------
static uint32_t    g_attackerId = UINT32_MAX;          // Selected dynamically at t=60
static uint32_t          g_spoofedLinks = 0;            // CLI-controlled
static NodeContainer     g_nodes;
static Ptr<UdpServer>    g_udpServer;

static uint64_t g_rxBaselineStart = 0, g_rxBaselineEnd = 0;
static uint64_t g_rxAttackStart   = 0, g_rxAttackEnd   = 0;
static uint64_t g_rxDefenseStart  = 0, g_rxDefenseEnd  = 0;
static uint64_t g_rxBothStart     = 0, g_rxBothEnd     = 0;

static bool     g_connectivityOk = false;
static uint32_t g_minRoutes      = 0;
static uint32_t g_failingNode    = 0;

// New status flags for the dynamic-attacker logic at t=60
static bool g_neighborAbort = false;   // Node 1 is itself a neighbor of Node 0 (route would be 1-hop)
static bool g_noAttacker    = false;   // No suitable attacker neighbor found at all
// ---------------------------------------------------------------------------
// Helper: extract the OLSR routing protocol pointer from a node
// ---------------------------------------------------------------------------
static Ptr<RoutingProtocol>
GetOlsrProto(Ptr<Node> node)
{
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
    if (!ipv4) return nullptr;
    Ptr<Ipv4RoutingProtocol> rp = ipv4->GetRoutingProtocol();
    Ptr<Ipv4ListRouting> list = DynamicCast<Ipv4ListRouting>(rp);
    if (!list) return DynamicCast<RoutingProtocol>(rp);
    for (uint32_t i = 0; i < list->GetNRoutingProtocols(); ++i)
    {
        int16_t prio;
        Ptr<Ipv4RoutingProtocol> sub = list->GetRoutingProtocol(i, prio);
        Ptr<RoutingProtocol> olsrRp = DynamicCast<RoutingProtocol>(sub);
        if (olsrRp) return olsrRp;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Phase activation events
// ---------------------------------------------------------------------------
static void EnableAttack()
{
    if (g_attackerId == UINT32_MAX) return;  // attacker selection failed; no-op
    Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(g_attackerId));
    NS_ASSERT(rp);
    rp->SetAttribute("SpoofedLinksCount", UintegerValue(g_spoofedLinks));
    rp->SetAttribute("IsMalicious", BooleanValue(true));
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Attack ENABLED on node " << g_attackerId
              << " (spoofedLinks=" << g_spoofedLinks << ")" << std::endl;
}

static void DisableAttack()
{
    if (g_attackerId == UINT32_MAX) return;  // attacker selection failed; no-op
    Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(g_attackerId));
    NS_ASSERT(rp);
    rp->SetAttribute("IsMalicious", BooleanValue(false));
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Attack DISABLED on node " << g_attackerId << std::endl;
}

static void EnableDefenseEverywhere()
{
    if (g_attackerId == UINT32_MAX) return;  // attacker selection failed; no-op
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
    {
        if (i == g_attackerId) continue;       // attacker keeps Null defense
        Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(i));
        NS_ASSERT(rp);
        Ptr<OlsrDefenseGcop> def = CreateObject<OlsrDefenseGcop>();
        def->SetAttribute("Enabled", BooleanValue(true)); 
        def->SetAttribute("UseFictitiousNodes", BooleanValue(false));  // C-Rules: בלי הזרקת phantom
        rp->SetAttribute("DefenseStrategy", PointerValue(def));
        rp->ReactivateDefenseStrategy();
        ++count;
    }
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Defense (GCOP) ENABLED on " << count << " benign nodes." << std::endl;
}

// ---------------------------------------------------------------------------
// Disable the forced RTS/CTS that the modified OLSR enables in DoInitialize.
// The modified OlsrRoutingProtocol forces RtsCtsThreshold=0 on every node so
// that defense Algorithm 1 can monitor RTS/CTS traffic. With dense control
// traffic (50 nodes broadcasting HELLO/TC) the resulting MAC contention
// prevents stable MPR selection and TC propagation. The defense strategy
// used here (GCOP) does NOT use the RTS/CTS hooks, so we restore the standard
// 802.11 default of 2200 bytes.
// ---------------------------------------------------------------------------
static void DisableForcedRtsCts()
{
    uint32_t fixed = 0;
    for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
    {
        Ptr<Node> node = g_nodes.Get(i);
        for (uint32_t d = 0; d < node->GetNDevices(); ++d)
        {
            Ptr<WifiNetDevice> wifiDev = DynamicCast<WifiNetDevice>(node->GetDevice(d));
            if (!wifiDev) continue;
            Ptr<WifiRemoteStationManager> mgr = wifiDev->GetRemoteStationManager();
            if (!mgr) continue;
            mgr->SetAttribute("RtsCtsThreshold", UintegerValue(2200));
            ++fixed;
        }
    }
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] RtsCtsThreshold restored to 2200 on " << fixed << " devices." << std::endl;
}

// ---------------------------------------------------------------------------
// UDP receive snapshots
// One dedicated function per snapshot point - avoids passing std::string
// to Simulator::Schedule, which can be brittle with template deduction.
// ---------------------------------------------------------------------------
static void SnapshotBaselineStart()
{
    g_rxBaselineStart = g_udpServer->GetReceived();
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Snapshot BASELINE_START = " << g_rxBaselineStart << std::endl;
}
static void SnapshotBaselineEnd()
{
    g_rxBaselineEnd = g_udpServer->GetReceived();
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Snapshot BASELINE_END   = " << g_rxBaselineEnd << std::endl;
}
static void SnapshotAttackStart()
{
    g_rxAttackStart = g_udpServer->GetReceived();
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Snapshot ATTACK_START   = " << g_rxAttackStart << std::endl;
}
static void SnapshotAttackEnd()
{
    g_rxAttackEnd = g_udpServer->GetReceived();
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Snapshot ATTACK_END     = " << g_rxAttackEnd << std::endl;
}
static void SnapshotDefenseStart()
{
    g_rxDefenseStart = g_udpServer->GetReceived();
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Snapshot DEFENSE_START  = " << g_rxDefenseStart << std::endl;
}
static void SnapshotDefenseEnd()
{
    g_rxDefenseEnd = g_udpServer->GetReceived();
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Snapshot DEFENSE_END    = " << g_rxDefenseEnd << std::endl;
}
static void SnapshotBothStart()
{
    g_rxBothStart = g_udpServer->GetReceived();
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Snapshot BOTH_START     = " << g_rxBothStart << std::endl;
}
static void SnapshotBothEnd()
{
    g_rxBothEnd = g_udpServer->GetReceived();
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Snapshot BOTH_END       = " << g_rxBothEnd << std::endl;
}

// ---------------------------------------------------------------------------
// Helper: get the OLSR-neighbor set of a node (returns main IPv4 addresses)
// ---------------------------------------------------------------------------
static std::set<Ipv4Address> GetOneHopNeighbors(uint32_t nodeId)
{
    std::set<Ipv4Address> result;
    Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(nodeId));
    if (!rp) return result;
    for (const auto& nb : rp->GetNeighbors())
    {
        if (nb.status == NeighborTuple::STATUS_SYM)
        {
            result.insert(nb.neighborMainAddr);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Helper: convert a node ID to its OLSR main address
// ---------------------------------------------------------------------------
static Ipv4Address GetMainAddrOfNode(uint32_t nodeId)
{
    Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(nodeId));
    if (!rp) return Ipv4Address();
    return rp->GetMainAddress();
}

// ---------------------------------------------------------------------------
// Pick the attacker dynamically: first node ID >= 2 that is:
//   (1) a 1-hop symmetric neighbor of Node 0 (the UDP destination)
//   (2) NOT Node 1 (the UDP source)
//
// Sets g_attackerId on success.
// Sets g_neighborAbort = true if Node 1 itself is a neighbor of Node 0
//   (route Node1 -> Node0 would be 1-hop and bypass any attacker entirely).
// Sets g_noAttacker = true if no suitable attacker is found.
// ---------------------------------------------------------------------------
static void PickAttacker()
{
    std::set<Ipv4Address> node0Neighbors = GetOneHopNeighbors(0);

    // Reject: Node 1 (sender) is itself a 1-hop neighbor of Node 0 (receiver).
    Ipv4Address node1Addr = GetMainAddrOfNode(1);
    if (node0Neighbors.count(node1Addr))
    {
        g_neighborAbort = true;
        std::cout << "[t=" << Simulator::Now().GetSeconds()
                  << "] PickAttacker: Node 1 is a 1-hop neighbor of Node 0 "
                  << "-- aborting (route would not traverse any attacker)"
                  << std::endl;
        return;
    }

    // Walk through node IDs 2..N-1, pick the first one that is a neighbor of Node 0.
    for (uint32_t i = 2; i < g_nodes.GetN(); ++i)
    {
        Ipv4Address candidate = GetMainAddrOfNode(i);
        if (node0Neighbors.count(candidate))
        {
            g_attackerId = i;
            std::cout << "[t=" << Simulator::Now().GetSeconds()
                      << "] PickAttacker: chose Node " << i
                      << " (" << candidate << ") as attacker "
                      << "(neighbor of Node 0)" << std::endl;
            return;
        }
    }

    // No suitable attacker found.
    g_noAttacker = true;
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] PickAttacker: no suitable attacker found "
              << "(Node 0 has no 1-hop neighbors except possibly Node 1)"
              << std::endl;
}


// ---------------------------------------------------------------------------
// Connectivity check at t = 59.9 s
// (every node must have at least nNodes-1 routing-table entries)
// ---------------------------------------------------------------------------
static void CheckConnectivity(uint32_t expectedRoutes)
{
    g_connectivityOk = true;
    g_minRoutes      = std::numeric_limits<uint32_t>::max();
    g_failingNode    = 0;

    // Build a histogram of routing-table sizes for diagnostics.
    std::map<uint32_t, uint32_t> histogram;
    uint32_t totalRoutes = 0;

    for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
    {
        Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(i));
        if (!rp)
        {
            g_connectivityOk = false;
            std::cout << "[t=" << Simulator::Now().GetSeconds()
                      << "] CONNECTIVITY: node " << i << " has NO OLSR protocol" << std::endl;
            Simulator::Stop();
            return;
        }
        size_t routes = rp->GetRoutingTableEntries().size();
        histogram[(uint32_t) routes]++;
        totalRoutes += (uint32_t) routes;
        if (routes < g_minRoutes)
        {
            g_minRoutes   = (uint32_t) routes;
            g_failingNode = i;
        }
        if (routes < expectedRoutes)
        {
            g_connectivityOk = false;
        }
    }

    double avgRoutes = (double) totalRoutes / (double) g_nodes.GetN();

    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] CONNECTIVITY: minRoutes=" << g_minRoutes
              << " (node " << g_failingNode << ")"
              << " avgRoutes=" << avgRoutes
              << " expected=" << expectedRoutes
              << " result=" << (g_connectivityOk ? "OK" : "FAIL") << std::endl;

    if (!g_connectivityOk)
    {
        std::cout << "[t=" << Simulator::Now().GetSeconds()
                  << "] Aborting run - incomplete connectivity." << std::endl;
        Simulator::Stop();
        return;
    }

    // Connectivity OK -- now select the attacker dynamically.
    PickAttacker();

    if (g_neighborAbort || g_noAttacker)
    {
        std::cout << "[t=" << Simulator::Now().GetSeconds()
                  << "] Aborting run - attacker selection failed." << std::endl;
        Simulator::Stop();
    }
}

// ---------------------------------------------------------------------------
// MAIN
// ---------------------------------------------------------------------------
int
main(int argc, char* argv[])
{
    // ----- Default parameters (match partner's iolsr simulation) -----
    uint32_t nNodes             = 50;
    double   dMaxGridX          = 750.0;
    double   dMaxGridY          = 1000.0;
    double   dSimulationSeconds = 402.0;
    uint32_t runNumber          = 1;
    uint32_t spoofedLinks       = 0;
    uint32_t udpPacketSize      = 512;
    double   udpInterval        = 2.0;
    uint32_t udpMaxPackets      = 18;
    bool     verbose            = false;

    // Phase boundaries (matches partner's iolsr simulation timing)
    const double INITIAL_STAB        = 60.0;
    const double BASELINE_START      = 60.0;
    const double BASELINE_END        = 100.0;
    const double ATTACK_STAB_START   = 100.0;
    const double ATTACK_START        = 160.0;
    const double ATTACK_END          = 200.0;
    const double DEFENSE_STAB_START  = 200.0;
    const double DEFENSE_START       = 260.0;
    const double DEFENSE_END         = 300.0;
    const double BOTH_STAB_START     = 300.0;
    const double BOTH_START          = 360.0;
    const double BOTH_END            = 400.0;
    const double UDP_OFFSET          = 4.0;

    CommandLine cmd(__FILE__);
    cmd.AddValue("run",          "RngSeedManager run number",      runNumber);
    cmd.AddValue("nNodes",       "Number of nodes",                nNodes);
    cmd.AddValue("spoofedLinks", "Number of spoofed links by attacker", spoofedLinks);
    cmd.AddValue("verbose",      "Verbose phase logging",          verbose);
    cmd.Parse(argc, argv);

    g_spoofedLinks = spoofedLinks;

    RngSeedManager::SetRun(runNumber);
    Time::SetResolution(Time::NS);

    // ----- Nodes -----
    g_nodes.Create(nNodes);

    // ----- WiFi stack (matches partner's setup exactly) -----
    const double WIFI_RANGE = 190.0;
    std::cout << "[BUILD CHECK] WiFi MaxRange = " << WIFI_RANGE << " m" << std::endl;

    // IMPORTANT: Build the channel helper from scratch (NOT
    // YansWifiChannelHelper::Default()) because the default in NS-3 3.40+
    // includes a LogDistancePropagationLossModel that adds losses on top of
    // RangePropagationLossModel - this fragments the network into islands
    // of "barely-reachable" nodes even though they are within range.
    // The partner's old NS-3 simulation worked because the old default did
    // not include LogDistance. Here we use only ConstantSpeedPropagationDelay
    // + RangePropagationLossModel for clean binary in-range/out-of-range.
    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel",
                                   "MaxRange", DoubleValue(WIFI_RANGE));
    YansWifiPhyHelper wifiPhy;
    wifiPhy.Set("TxGain", DoubleValue(12.4));
    wifiPhy.SetChannel(wifiChannel.Create());

    WifiHelper wifi;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager");

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer adhocDevices = wifi.Install(wifiPhy, wifiMac, g_nodes);

    // ----- Internet stack with OLSR routing -----
    OlsrHelper olsr;
    Ipv4ListRoutingHelper routeList;
    routeList.Add(olsr, 100);
    InternetStackHelper internet;
    internet.SetRoutingHelper(routeList);
    internet.Install(g_nodes);

    // ----- Traffic Control -----
    // PfifoFastQueueDisc: classic 3-band priority queue with an explicit
    // MaxSize attribute. This works correctly with the cross-layer queue
    // monitoring inside HandleDefenseTimer (which calls GetMaxSize on the
    // root queue disc).
    //
    // (We tried a single FifoQueueDisc first; it caused all control traffic
    // to silently drop in the multi-queue WiFi MAC. PfifoFastQueueDisc has
    // 3 internal priority queues and is much more forgiving.)
    TrafficControlHelper tch;
    tch.SetRootQueueDisc("ns3::PfifoFastQueueDisc",
                         "MaxSize", QueueSizeValue(QueueSize("1000p")));
    tch.Install(adhocDevices);

    Ipv4AddressHelper addresses;
    addresses.SetBase("10.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer interfaces = addresses.Assign(adhocDevices);

    // ----- Mobility -----
    // FIXED positions for the three "structural" nodes:
    //   Node 0 (UDP server / victim)  at top-left:    (50, 50)
    //   Node 1 (UDP client / sender)  at bottom-right (700, 700)
    //   Node 2 (attacker)             at center:      (500, 375)
    // The other 47 nodes are placed RANDOMLY (per seed) within the area.
    // This guarantees the route Node1 -> Node0 traverses the central region
    // where the attacker sits, so the attack can actually impact PDR.
    Ptr<UniformRandomVariable> randX = CreateObject<UniformRandomVariable>();
    randX->SetAttribute("Min", DoubleValue(0));
    randX->SetAttribute("Max", DoubleValue(dMaxGridX));
    Ptr<UniformRandomVariable> randY = CreateObject<UniformRandomVariable>();
    randY->SetAttribute("Min", DoubleValue(0));
    randY->SetAttribute("Max", DoubleValue(dMaxGridY));

    Ptr<RandomRectanglePositionAllocator> randomPos =
        CreateObject<RandomRectanglePositionAllocator>();
    randomPos->SetX(randX);
    randomPos->SetY(randY);

    // All 50 nodes are placed randomly. The roles (server/client) are assigned
    // to specific node IDs, but their geographic positions are random per seed.
    NodeContainer randomNodes;
    for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
    {
        randomNodes.Add(g_nodes.Get(i));
    }
    MobilityHelper mobRandom;
    mobRandom.SetPositionAllocator(randomPos);
    mobRandom.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobRandom.Install(randomNodes);

    // ----- Initial OLSR configuration -----
    // Every node starts with OlsrDefenseNull and IsMalicious=false.
    // SpoofedLinksCount and the attacker selection happen later, at t=60s,
    // once OLSR has converged and we can find a 1-hop neighbor of Node 0.
    for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
    {
        Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(i));
        NS_ASSERT(rp);
        Ptr<OlsrDefenseNull> nullDef = CreateObject<OlsrDefenseNull>();
        rp->SetAttribute("DefenseStrategy", PointerValue(nullDef));
        rp->SetAttribute("IsMalicious",     BooleanValue(false));
    }

    // ----- UDP server on Node 0 -----
    UdpServerHelper udpServerHelper(80);
    ApplicationContainer serverApps = udpServerHelper.Install(g_nodes.Get(0));
    serverApps.Start(Seconds(0.0));
    serverApps.Stop(Seconds(dSimulationSeconds));
    g_udpServer = DynamicCast<UdpServer>(serverApps.Get(0));
    NS_ASSERT_MSG(g_udpServer, "Failed to retrieve UdpServer from ApplicationContainer");

    // ----- UDP clients (one per measurement window) on Node 1 -----
    UdpClientHelper udpClient(Ipv4Address("10.0.0.1"), 80);
    udpClient.SetAttribute("Interval",   TimeValue(Seconds(udpInterval)));
    udpClient.SetAttribute("MaxPackets", UintegerValue(udpMaxPackets));
    udpClient.SetAttribute("PacketSize", UintegerValue(udpPacketSize));

    auto installWindow = [&](double startSec, double stopSec) {
        ApplicationContainer apps = udpClient.Install(g_nodes.Get(1));
        apps.Start(Seconds(startSec));
        apps.Stop(Seconds(stopSec));
    };
    installWindow(BASELINE_START + UDP_OFFSET, BASELINE_END);
    installWindow(ATTACK_START   + UDP_OFFSET, ATTACK_END);
    installWindow(DEFENSE_START  + UDP_OFFSET, DEFENSE_END);
    installWindow(BOTH_START     + UDP_OFFSET, BOTH_END);

    // ----- Schedule connectivity check, snapshots, and phase activations -----
    // Restore RTS/CTS threshold immediately after DoInitialize forces it to 0.
    // DoInitialize runs at t=0, so 1 ms later is safe.
    Simulator::Schedule(MilliSeconds(1), &DisableForcedRtsCts);

    Simulator::Schedule(Seconds(INITIAL_STAB - 0.1), &CheckConnectivity, nNodes - 1);

    // Baseline window snapshots
    Simulator::Schedule(Seconds(BASELINE_START + UDP_OFFSET - 0.01), &SnapshotBaselineStart);
    Simulator::Schedule(Seconds(BASELINE_END + 0.5),                 &SnapshotBaselineEnd);

    // Attack-only phase
    Simulator::Schedule(Seconds(ATTACK_STAB_START), &EnableAttack);
    Simulator::Schedule(Seconds(ATTACK_START + UDP_OFFSET - 0.01),   &SnapshotAttackStart);
    Simulator::Schedule(Seconds(ATTACK_END + 0.5),                   &SnapshotAttackEnd);

    // Defense-only phase: turn off attack, turn on defense
    Simulator::Schedule(Seconds(DEFENSE_STAB_START), &DisableAttack);
    Simulator::Schedule(Seconds(DEFENSE_STAB_START), &EnableDefenseEverywhere);
    Simulator::Schedule(Seconds(DEFENSE_START + UDP_OFFSET - 0.01),  &SnapshotDefenseStart);
    Simulator::Schedule(Seconds(DEFENSE_END + 0.5),                  &SnapshotDefenseEnd);

    // Defense-vs-Attack phase: re-enable attack (defense stays on)
    Simulator::Schedule(Seconds(BOTH_STAB_START), &EnableAttack);
    Simulator::Schedule(Seconds(BOTH_START + UDP_OFFSET - 0.01),     &SnapshotBothStart);
    Simulator::Schedule(Seconds(BOTH_END + 0.5),                     &SnapshotBothEnd);

    // ----- Run -----
    std::cout << "Starting simulation, run=" << runNumber
              << ", nNodes=" << nNodes
              << ", area=" << dMaxGridX << "x" << dMaxGridY
              << ", attacker=DYNAMIC (selected at t=60 as 1-hop neighbor of Node 0)"
              << ", spoofedLinks=" << spoofedLinks
              << std::endl;

    Simulator::Stop(Seconds(dSimulationSeconds));
    Simulator::Run();
    Simulator::Destroy();

    // ----- Compute PDRs and report -----
    auto pdr = [&](uint64_t a, uint64_t b) {
        return (double)(b - a) / (double) udpMaxPackets;
    };

    std::cout << std::fixed << std::setprecision(4);
    std::cout << "----- RESULTS -----" << std::endl;

    if (!g_connectivityOk)
    {
        std::cout << "RESULT,run=" << runNumber
                  << ",STATUS=NO_CONNECTIVITY"
                  << ",minRoutes="   << g_minRoutes
                  << ",failingNode=" << g_failingNode
                  << ",expected="    << (nNodes - 1)
                  << std::endl;
        return 2;
    }

    if (g_neighborAbort)
    {
        std::cout << "RESULT,run=" << runNumber
                  << ",STATUS=NEIGHBOR_ABORT"
                  << ",reason=Node1_is_1hop_neighbor_of_Node0"
                  << std::endl;
        return 3;
    }

    if (g_noAttacker)
    {
        std::cout << "RESULT,run=" << runNumber
                  << ",STATUS=NO_ATTACKER"
                  << ",reason=Node0_has_no_neighbors_other_than_Node1"
                  << std::endl;
        return 4;
    }

    std::cout << "RESULT,run=" << runNumber
              << ",STATUS=OK"
              << ",attacker_id="  << g_attackerId
              << ",baseline_pdr=" << pdr(g_rxBaselineStart, g_rxBaselineEnd)
              << ",attack_pdr="   << pdr(g_rxAttackStart,   g_rxAttackEnd)
              << ",defense_pdr="  << pdr(g_rxDefenseStart,  g_rxDefenseEnd)
              << ",both_pdr="     << pdr(g_rxBothStart,     g_rxBothEnd)
              << ",baseline_rx="  << (g_rxBaselineEnd - g_rxBaselineStart)
              << ",attack_rx="    << (g_rxAttackEnd   - g_rxAttackStart)
              << ",defense_rx="   << (g_rxDefenseEnd  - g_rxDefenseStart)
              << ",both_rx="      << (g_rxBothEnd     - g_rxBothStart)
              << ",sent_per_window=" << udpMaxPackets
              << std::endl;
    return 0;
}