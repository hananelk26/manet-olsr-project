/*
 * watchdogBaseSimulation.cc
 * =========================
 * OLSR Blackhole Attack & Watchdog Defense - NS-3 Simulation.
 *
 * Methodology (designed for feature-extraction / ML-training experiments):
 *   - 50 nodes total, 1000x750 m area, no mobility.
 *   - Node 0 (UDP server / victim).
 *   - Node 1 (UDP client / sender).
 *   - Attacker selected DYNAMICALLY at t=60s as the first 1-hop neighbor
 *     of Node 0 (id >= 2, != 1).
 *   - All 50 nodes are placed RANDOMLY per seed in the area.
 *
 *   At t=60s, after OLSR has converged:
 *     * Connectivity is verified (every node must have nNodes-1 routes).
 *     * Attacker is selected dynamically; if Node 1 is itself a 1-hop
 *       neighbor of Node 0 (route would be 1-hop and bypass the attacker)
 *       the run is rejected (NEIGHBOR_ABORT).
 *
 * Four phases (single 402 s run):
 *   0 - 60   Initial stabilization + connectivity check + attacker selection
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
 *   RESULT,run=<N>,STATUS=OK,attacker_id=<I>,baseline_pdr=...,attack_pdr=...,...
 * or
 *   RESULT,run=<N>,STATUS=NO_CONNECTIVITY,...
 *   RESULT,run=<N>,STATUS=NEIGHBOR_ABORT,...
 *   RESULT,run=<N>,STATUS=NO_ATTACKER,...
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
#include "ns3/olsr-watchdog-defense.h"

#include <iostream>
#include <iomanip>
#include <limits>
#include <cmath>
#include <map>
#include <set>
#include <vector>

using namespace ns3;
using namespace ns3::olsr;

NS_LOG_COMPONENT_DEFINE("OlsrBlackholeDefenseWatchdog");

// ---------------------------------------------------------------------------
// Globals (used by scheduled callbacks)
// ---------------------------------------------------------------------------
static uint32_t          g_attackerId   = UINT32_MAX;     // selected dynamically at t=60
static uint32_t          g_spoofedLinks = 0;              // CLI-controlled
static NodeContainer     g_nodes;
static Ptr<UdpServer>    g_udpServer;

static uint64_t g_rxBaselineStart = 0, g_rxBaselineEnd = 0;
static uint64_t g_rxAttackStart   = 0, g_rxAttackEnd   = 0;
static uint64_t g_rxDefenseStart  = 0, g_rxDefenseEnd  = 0;
static uint64_t g_rxBothStart     = 0, g_rxBothEnd     = 0;

static bool     g_connectivityOk = false;
static uint32_t g_minRoutes      = 0;
static uint32_t g_failingNode    = 0;

// Status flags for dynamic-attacker logic at t=60
static bool g_neighborAbort = false;
static bool g_noAttacker    = false;

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
    if (g_attackerId == UINT32_MAX) return;
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
    if (g_attackerId == UINT32_MAX) return;
    Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(g_attackerId));
    NS_ASSERT(rp);
    rp->SetAttribute("IsMalicious", BooleanValue(false));
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Attack DISABLED on node " << g_attackerId << std::endl;
}

static void EnableDefenseEverywhere()
{
    if (g_attackerId == UINT32_MAX) return;
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_nodes.GetN(); ++i)
    {
        if (i == g_attackerId) continue;          // attacker keeps Null defense
        Ptr<RoutingProtocol> rp = GetOlsrProto(g_nodes.Get(i));
        NS_ASSERT(rp);
        Ptr<OlsrWatchdogDefense> def = CreateObject<OlsrWatchdogDefense>();
        rp->SetAttribute("DefenseStrategy", PointerValue(def));
        rp->ReactivateDefenseStrategy();
        ++count;
    }
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] Defense (Watchdog) ENABLED on " << count << " benign nodes." << std::endl;
}

// ---------------------------------------------------------------------------
// Disable the forced RTS/CTS that the modified OLSR enables in DoInitialize.
// The Watchdog defense is a pure promiscuous-overhearing monitor at the
// next-hop and does NOT depend on the RTS/CTS hooks. With dense control
// traffic (50 nodes broadcasting HELLO/TC) forced RTS/CTS causes MAC
// contention that prevents stable MPR selection and TC propagation, so we
// restore the standard 802.11 default of 2200 bytes (i.e. effectively off
// for our small data packets).
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
// ---------------------------------------------------------------------------
static void PickAttacker()
{
    std::set<Ipv4Address> node0Neighbors = GetOneHopNeighbors(0);

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

    g_noAttacker = true;
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "] PickAttacker: no suitable attacker found "
              << "(Node 0 has no 1-hop neighbors except possibly Node 1)"
              << std::endl;
}

// ---------------------------------------------------------------------------
// Connectivity check at t = 59.9 s
// ---------------------------------------------------------------------------
static void CheckConnectivity(uint32_t expectedRoutes)
{
    g_connectivityOk = true;
    g_minRoutes      = std::numeric_limits<uint32_t>::max();
    g_failingNode    = 0;

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
    // ----- Default parameters -----
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

    // Phase boundaries
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

    // ----- WiFi stack -----
    const double WIFI_RANGE = 190.0;
    std::cout << "[BUILD CHECK] WiFi MaxRange = " << WIFI_RANGE << " m" << std::endl;

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
    TrafficControlHelper tch;
    tch.SetRootQueueDisc("ns3::PfifoFastQueueDisc",
                         "MaxSize", QueueSizeValue(QueueSize("1000p")));
    tch.Install(adhocDevices);

    Ipv4AddressHelper addresses;
    addresses.SetBase("10.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer interfaces = addresses.Assign(adhocDevices);

    // ----- Mobility (random placement, no motion) -----
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

    MobilityHelper mobility;
    mobility.SetPositionAllocator(randomPos);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(g_nodes);

    // ----- Initial OLSR configuration: Null defense, not malicious -----
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
              << ", defense=Watchdog"
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