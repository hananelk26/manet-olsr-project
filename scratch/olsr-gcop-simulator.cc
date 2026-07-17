#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-helper.h"
#include "ns3/olsr-routing-protocol.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/ipv4-flow-classifier.h"

#include "ns3/olsr-defense-gcop.h"
#include "ns3/olsr-defense-strategy.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cmath>
#include <vector>

using namespace ns3;
using namespace ns3::olsr;

NS_LOG_COMPONENT_DEFINE("GcopBridgeTest");

// ============================================================
// Phase timing
// ============================================================
static const double BASELINE_MEAS_START        =  60.0;
static const double BASELINE_MEAS_END          = 100.0;

static const double ATTACK_STAB_START          = 100.0;
static const double ATTACK_MEAS_START          = 160.0;
static const double ATTACK_MEAS_END            = 200.0;

static const double DEFENSE_STAB_START         = 200.0;
static const double DEFENSE_MEAS_START         = 260.0;
static const double DEFENSE_MEAS_END           = 300.0;

static const double DEFENSE_ATTACK_STAB_START  = 300.0;
// static const double DEFENSE_ATTACK_MEAS_START  = 360.0;
// static const double DEFENSE_ATTACK_MEAS_END    = 400.0;

// static const double SIM_END                    = 402.0;

static const double DEFENSE_ATTACK_MEAS_START  = 400.0;
static const double DEFENSE_ATTACK_MEAS_END    = 440.0;
static const double SIM_END                    = 442.0;

// UDP: 18 packets per window, one every 2 seconds, start offset 4s into window.
static const double   UDP_START_OFFSET   =   4.0;
static const uint32_t UDP_MAX_PACKETS    =  18;
static const double   UDP_INTERVAL_SEC   =   2.0;
static const uint32_t UDP_PKT_SIZE_BYTES = 512;
static const uint16_t UDP_SERVER_PORT    =   9;

// Attack
static const uint32_t SPOOFED_LINKS_COUNT = 15;

// Topology - fixed indices
static const uint32_t VICTIM_IDX   = 0;
static const uint32_t SENDER_IDX   = 1;
static const uint32_t ATTACKER_IDX = 2;
static const uint32_t RELAY_IDX    = 3;

// ============================================================
// Global state
// ============================================================
static std::vector<Ptr<OlsrDefenseGcop>> g_defenses;
static FlowMonitorHelper                  g_flowHelper;
static Ptr<FlowMonitor>                   g_flowMonitor;

struct PhaseResult {
    std::string name;
    uint64_t    txPackets;
    uint64_t    rxPackets;
    double      pdr;
    double      avgDelayMs;
    uint32_t    nodesWithSuspects;
    bool        attackerBlacklistedAtVictim;
    std::string victimRouteNextHop;
    uint32_t    victimRouteDistance;
};
static std::vector<PhaseResult> g_results;

// Temporary holder for the next EndMeasurement() to pick up
static std::string g_lastVictimNextHop = "n/a";
static uint32_t    g_lastVictimDistance = 0;

// ============================================================
// Helpers
// ============================================================
static Ptr<olsr::RoutingProtocol> GetOlsrRp(Ptr<Node> node)
{
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
    if (!ipv4) return nullptr;
    Ptr<Ipv4ListRouting> listProto = DynamicCast<Ipv4ListRouting>(ipv4->GetRoutingProtocol());
    if (listProto) {
        for (uint32_t i = 0; i < listProto->GetNRoutingProtocols(); ++i) {
            int16_t p;
            Ptr<Ipv4RoutingProtocol> child = listProto->GetRoutingProtocol(i, p);
            if (child->GetInstanceTypeId().GetName() == "ns3::olsr::RoutingProtocol")
                return DynamicCast<olsr::RoutingProtocol>(child);
        }
    }
    return DynamicCast<olsr::RoutingProtocol>(ipv4->GetRoutingProtocol());
}

// Records the victim's route to the sender - who's the next hop? attacker or relay?
static void ProbeVictimRoute(NodeContainer* nodes,
                             const Ipv4InterfaceContainer* interfaces)
{
    Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(VICTIM_IDX));
    if (!rp) {
        g_lastVictimNextHop = "no-rp";
        g_lastVictimDistance = 0;
        return;
    }
    Ipv4Address senderIp = interfaces->GetAddress(SENDER_IDX);
    std::vector<olsr::RoutingTableEntry> rt = rp->GetRoutingTableEntries();

    g_lastVictimNextHop = "no-route";
    g_lastVictimDistance = 0;
    for (auto const& e : rt) {
        if (e.destAddr == senderIp) {
            std::ostringstream oss;
            oss << e.nextAddr;
            if (e.nextAddr == interfaces->GetAddress(ATTACKER_IDX))
                oss << " [ATTACKER]";
            else if (e.nextAddr == interfaces->GetAddress(RELAY_IDX))
                oss << " [RELAY-safe]";
            g_lastVictimNextHop  = oss.str();
            g_lastVictimDistance = e.distance;
            break;
        }
    }

    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "s] Victim (node 0) route to sender (node 1): nextHop="
              << g_lastVictimNextHop
              << " distance=" << g_lastVictimDistance << std::endl;
}

// ============================================================
// Attack / defense control
// ============================================================
static void EnableAttack(NodeContainer* nodes)
{
    Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(ATTACKER_IDX));
    if (!rp) return;
    rp->SetAttribute("IsMalicious",       BooleanValue(true));
    rp->SetAttribute("SpoofedLinksCount", UintegerValue(SPOOFED_LINKS_COUNT));
    std::cout << "\n[t=" << Simulator::Now().GetSeconds()
              << "s] >>> Black Hole attack ENABLED (node " << ATTACKER_IDX << ")" << std::endl;
}

static void DisableAttack(NodeContainer* nodes)
{
    Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(ATTACKER_IDX));
    if (!rp) return;
    rp->SetAttribute("IsMalicious",       BooleanValue(false));
    rp->SetAttribute("SpoofedLinksCount", UintegerValue(0));
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "s] >>> Attack DISABLED" << std::endl;
}

static void EnableDefense(NodeContainer* nodes)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < nodes->GetN(); ++i) {
        if (i == ATTACKER_IDX) continue;  // attacker keeps null defense
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(i));
        if (!rp) continue;
        g_defenses[i] = CreateObject<OlsrDefenseGcop>();
        rp->SetAttribute("DefenseStrategy", PointerValue(g_defenses[i]));
        rp->ReactivateDefenseStrategy();
        ++count;
    }
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "s] >>> GCOP defense ENABLED on " << count << " nodes" << std::endl;
}

// ============================================================
// Measurement boundaries
// ============================================================
static void StartMeasurement(const std::string& name)
{
    if (g_flowMonitor) g_flowMonitor->ResetAllStats();
    std::cout << "\n[t=" << Simulator::Now().GetSeconds()
              << "s] ===== START: " << name << " =====" << std::endl;
}

static void EndMeasurement(NodeContainer*    nodes,
                           const std::string& name,
                           double            startT,
                           double            endT,
                           const Ipv4InterfaceContainer* interfaces)
{
    (void)startT; (void)endT;
    PhaseResult r;
    r.name                         = name;
    r.txPackets                    = 0;
    r.rxPackets                    = 0;
    r.pdr                          = 0.0;
    r.avgDelayMs                   = 0.0;
    r.nodesWithSuspects            = 0;
    r.attackerBlacklistedAtVictim  = false;
    r.victimRouteNextHop           = g_lastVictimNextHop;
    r.victimRouteDistance          = g_lastVictimDistance;

    if (g_flowMonitor) {
        g_flowMonitor->CheckForLostPackets();
        double totalDelay = 0.0;
        for (auto& kv : g_flowMonitor->GetFlowStats()) {
            const FlowMonitor::FlowStats& fs = kv.second;
            if (!fs.txPackets && !fs.rxPackets) continue;
            r.txPackets += fs.txPackets;
            r.rxPackets += fs.rxPackets;
            totalDelay  += fs.delaySum.GetSeconds();
        }
        r.pdr        = (r.txPackets > 0) ? (100.0 * r.rxPackets / r.txPackets) : 0.0;
        r.avgDelayMs = (r.rxPackets > 0) ? (totalDelay / r.rxPackets * 1000.0) : 0.0;
    }

    for (uint32_t i = 0; i < nodes->GetN(); ++i) {
        if (g_defenses[i] && !g_defenses[i]->GetBlacklist().empty())
            ++r.nodesWithSuspects;
    }

    if (g_defenses[VICTIM_IDX] && interfaces) {
        Ipv4Address attackerIp = interfaces->GetAddress(ATTACKER_IDX);
        r.attackerBlacklistedAtVictim = g_defenses[VICTIM_IDX]->IsMalicious(attackerIp);
    }

    g_results.push_back(r);

    std::cout << "\n==============================\n"
              << "  PHASE:  " << name << "\n"
              << "------------------------------\n"
              << "  Tx:                " << r.txPackets << "\n"
              << "  Rx:                " << r.rxPackets << "\n"
              << std::fixed << std::setprecision(1)
              << "  PDR:               " << r.pdr << " %\n"
              << std::setprecision(2)
              << "  Avg delay:         " << r.avgDelayMs << " ms\n"
              << "  Nodes w/suspects:  " << r.nodesWithSuspects << "\n"
              << "  Attacker flagged:  "
              << (r.attackerBlacklistedAtVictim ? "YES" : "NO") << "\n"
              << "  Victim route:      nextHop=" << r.victimRouteNextHop
              << "  distance=" << r.victimRouteDistance << "\n"
              << "==============================" << std::endl;
}

// ============================================================
// Connectivity probe after initial stabilization
// ============================================================
static void CheckConnectivity(NodeContainer* nodes,
                              const Ipv4InterfaceContainer* interfaces)
{
    std::cout << "\n[t=" << Simulator::Now().GetSeconds()
              << "s] --- Connectivity check ---" << std::endl;

    Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(VICTIM_IDX));
    if (rp) {
        std::cout << "  Victim (node 0) has "
                  << rp->GetNeighbors().size() << " neighbors, "
                  << rp->GetTwoHopNeighbors().size() << " 2-hop neighbors, "
                  << rp->GetRoutingTableEntries().size() << " routing entries" << std::endl;
    }
    ProbeVictimRoute(nodes, interfaces);
    std::cout << "--------------------------------" << std::endl;
}

// ============================================================
// Final summary table + verdict
// ============================================================
static void PrintFinalSummary()
{
    std::cout << "\n\n";
    std::cout << "+======================================================================+\n";
    std::cout << "|              OLSR GCOP DEFENSE VALIDATION - RESULTS                  |\n";
    std::cout << "+======================================================================+\n";
    std::cout << "| Phase              | Tx  | Rx  |  PDR   | Attacker |  Victim nextHop |\n";
    std::cout << "|                    |     |     |   %    | flagged? |   to sender    |\n";
    std::cout << "+--------------------+-----+-----+--------+----------+-----------------+\n";
    for (auto const& r : g_results) {
        std::cout << "| " << std::left  << std::setw(18) << r.name
                  << " | " << std::right << std::setw(3)  << r.txPackets
                  << " | " << std::setw(3) << r.rxPackets
                  << " | " << std::setw(5) << std::fixed << std::setprecision(1) << r.pdr << "% "
                  << " | " << std::setw(8) << (r.attackerBlacklistedAtVictim ? "YES" : "NO")
                  << " | " << std::left << std::setw(15) << r.victimRouteNextHop
                  << " |\n";
    }
    std::cout << "+======================================================================+\n";

    // double pdrBase = -1, pdrAtk = -1, pdrDef = -1, pdrDefAtk = -1;
    // for (auto const& r : g_results) {
    //     if (r.name == "baseline")          pdrBase   = r.pdr;
    //     if (r.name == "attack_only")       pdrAtk    = r.pdr;
    //     if (r.name == "defense_only")      pdrDef    = r.pdr;
    //     if (r.name == "defense_vs_attack") pdrDefAtk = r.pdr;
    // }

    double pdrBase = -1, pdrAtk = -1, pdrDefAtk = -1;
    for (auto const& r : g_results) {
        if (r.name == "baseline")          pdrBase   = r.pdr;
        if (r.name == "attack_only")       pdrAtk    = r.pdr;
        if (r.name == "defense_vs_attack") pdrDefAtk = r.pdr;
    }

    std::cout << "\n=== VERDICTS ===" << std::endl;
    if (pdrBase >= 0 && pdrAtk >= 0) {
        if (pdrAtk < pdrBase - 10.0)
            std::cout << "  Attack IS effective: baseline=" << pdrBase
                      << "%, attack_only=" << pdrAtk << "%" << std::endl;
        else
            std::cout << "  Attack appears INEFFECTIVE: baseline=" << pdrBase
                      << "%, attack_only=" << pdrAtk << "%" << std::endl;
    }
    if (pdrAtk >= 0 && pdrDefAtk >= 0) {
        double imp = pdrDefAtk - pdrAtk;
        std::cout << "  PDR improvement from defense: "
                  << std::showpos << std::fixed << std::setprecision(1)
                  << imp << "%" << std::noshowpos << std::endl;
        if (imp > 30.0)       std::cout << "  ==> Defense HIGHLY EFFECTIVE" << std::endl;
        else if (imp > 10.0)  std::cout << "  ==> Defense EFFECTIVE" << std::endl;
        else if (imp > 0.0)   std::cout << "  ==> Defense PARTIALLY effective" << std::endl;
        else                  std::cout << "  ==> Defense shows MINIMAL effect" << std::endl;
    }
    std::cout << std::endl;
}

static void SaveCsv(const std::string& path)
{
    std::ofstream f(path.c_str());
    if (!f.is_open()) return;
    f << "Phase,Tx,Rx,PDR_pct,AvgDelayMs,NodesWithSuspects,AttackerFlaggedAtVictim,"
      << "VictimRouteNextHop,VictimRouteDistance\n";
    for (auto const& r : g_results) {
        f << r.name << ","
          << r.txPackets << "," << r.rxPackets << ","
          << std::fixed << std::setprecision(2) << r.pdr << ","
          << r.avgDelayMs << ","
          << r.nodesWithSuspects << ","
          << (r.attackerBlacklistedAtVictim ? 1 : 0) << ","
          << r.victimRouteNextHop << ","
          << r.victimRouteDistance << "\n";
    }
    f.close();
    std::cout << "[CSV] Results saved to: " << path << std::endl;
}

// ============================================================
// MAIN
// ============================================================
int main(int argc, char* argv[])
{
    uint32_t    nNodes    = 8;    // victim + sender + attacker + relay + 4 background
    double      txRange   = 250.0;
    uint32_t    runNumber = 1;
    std::string csvPath   = "gcop-bridge-results.csv";
    bool        verbose   = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nNodes",  "Number of nodes (min 4)", nNodes);
    cmd.AddValue("txRange", "WiFi range (m)",          txRange);
    cmd.AddValue("run",     "RNG run number",          runNumber);
    cmd.AddValue("csv",     "Output CSV path",         csvPath);
    cmd.AddValue("verbose", "Enable NS_LOG_INFO",      verbose);
    cmd.Parse(argc, argv);

    if (nNodes < 4) nNodes = 4;
    g_defenses.resize(nNodes, nullptr);

    if (verbose) {
        LogComponentEnable("GcopBridgeTest",  LOG_LEVEL_INFO);
        LogComponentEnable("OlsrDefenseGcop", LOG_LEVEL_INFO);
    }

    Time::SetResolution(Time::NS);
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(runNumber);

    std::cout << "===========================================\n"
              << "  GCOP Bridge-Topology Validation\n"
              << "  Nodes: " << nNodes << "  Range: " << txRange << "m\n"
              << "  RNG run: " << runNumber << "\n"
              << "===========================================\n\n";

    // ----------------------------------------------------------
    // Nodes
    // ----------------------------------------------------------
    NodeContainer nodes;
    nodes.Create(nNodes);

    // ----------------------------------------------------------
    // WiFi
    // ----------------------------------------------------------
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper wifiPhy;
    wifiPhy.Set("RxGain", DoubleValue(0));

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel",
                                    "MaxRange", DoubleValue(txRange));
    wifiPhy.SetChannel(wifiChannel.Create());

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, nodes);

    // ----------------------------------------------------------
    // Mobility (static)
    //
    // Node 0 = Victim   (100, 250)
    // Node 1 = Sender   (550, 250)
    // Node 2 = Attacker (350, 250)  <- primary bridge
    // Node 3 = Relay    (350, 150)  <- backup bridge
    // Nodes 4..N-1 = background at (550, varied Y)
    //
    // With range=250m:
    //   Victim <-> Attacker: 250m (edge neighbors)
    //   Victim <-> Relay   : ~269m (NOT neighbors - drives Victim through Attacker only!)
    //   Sender <-> Attacker: 200m (neighbors)
    //   Sender <-> Relay   : ~224m (neighbors)
    //   Victim <-> Sender  : 450m (NOT neighbors)
    //
    // Note: Victim's only 1-hop neighbor on the bridge side is Attacker.
    // When defense flags Attacker, Victim must route via a 2-hop path.
    // ----------------------------------------------------------
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();

    pos->Add(Vector(100.0, 250.0, 0.0));  // 0: Victim
    pos->Add(Vector(550.0, 250.0, 0.0));  // 1: Sender
    pos->Add(Vector(350.0, 250.0, 0.0));  // 2: Attacker
    pos->Add(Vector(350.0, 100.0, 0.0));  // 3: Relay
    pos->Add(Vector(200.0, 150.0, 0.0));  // 4: Helper (NEW)

    // Background nodes (now starting from index 5)
    for (uint32_t i = 5; i < nNodes; ++i) {
        double yOffset = 100.0 + (i - 5) * 50.0;
        pos->Add(Vector(550.0 + (i - 5) * 30.0, yOffset, 0.0));
    }

    mobility.SetPositionAllocator(pos);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // ----------------------------------------------------------
    // OLSR + Internet Stack
    // ----------------------------------------------------------
    OlsrHelper olsr;
    Ipv4ListRoutingHelper routeList;
    routeList.Add(olsr, 100);

    InternetStackHelper internet;
    internet.SetRoutingHelper(routeList);
    internet.Install(nodes);

    // Attacker always has a null defense
    {
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes.Get(ATTACKER_IDX));
        if (rp) rp->SetAttribute("DefenseStrategy",
                                  PointerValue(CreateObject<OlsrDefenseNull>()));
    }
    // All other nodes start with null defense too (swapped later)
    for (uint32_t i = 0; i < nNodes; ++i) {
        if (i == ATTACKER_IDX) continue;
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes.Get(i));
        if (rp) rp->SetAttribute("DefenseStrategy",
                                  PointerValue(CreateObject<OlsrDefenseNull>()));
    }

    // ----------------------------------------------------------
    // IP assignment
    // ----------------------------------------------------------
    Ipv4AddressHelper addr;
    addr.SetBase("10.0.0.0", "255.0.0.0");
    Ipv4InterfaceContainer interfaces = addr.Assign(devices);

    std::cout << ">> Victim  (server, node 0):  " << interfaces.GetAddress(VICTIM_IDX)   << "\n";
    std::cout << ">> Sender  (client, node 1):  " << interfaces.GetAddress(SENDER_IDX)   << "\n";
    std::cout << ">> Attacker        (node 2):  " << interfaces.GetAddress(ATTACKER_IDX) << "\n";
    std::cout << ">> Relay           (node 3):  " << interfaces.GetAddress(RELAY_IDX)    << "\n\n";

    // ----------------------------------------------------------
    // UDP server on victim
    // ----------------------------------------------------------
    UdpServerHelper serverHelper(UDP_SERVER_PORT);
    ApplicationContainer serverApp = serverHelper.Install(nodes.Get(VICTIM_IDX));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(SIM_END));

    // ----------------------------------------------------------
    // UDP client on sender - one installation per measurement window
    // This gives exactly 18 packets per window, cleanly.
    // ----------------------------------------------------------
    UdpClientHelper clientHelper(interfaces.GetAddress(VICTIM_IDX), UDP_SERVER_PORT);
    clientHelper.SetAttribute("Interval",   TimeValue(Seconds(UDP_INTERVAL_SEC)));
    clientHelper.SetAttribute("MaxPackets", UintegerValue(UDP_MAX_PACKETS));
    clientHelper.SetAttribute("PacketSize", UintegerValue(UDP_PKT_SIZE_BYTES));

    struct Window { double start; double end; };
    Window windows[4] = {
        { BASELINE_MEAS_START,        BASELINE_MEAS_END        },
        { ATTACK_MEAS_START,          ATTACK_MEAS_END          },
        { DEFENSE_MEAS_START,         DEFENSE_MEAS_END         },
        { DEFENSE_ATTACK_MEAS_START,  DEFENSE_ATTACK_MEAS_END  },
    };
    for (int i = 0; i < 4; ++i) {
        ApplicationContainer app = clientHelper.Install(nodes.Get(SENDER_IDX));
        app.Start(Seconds(windows[i].start + UDP_START_OFFSET));
        app.Stop (Seconds(windows[i].end));
    }

    // ----------------------------------------------------------
    // FlowMonitor
    // ----------------------------------------------------------
    g_flowMonitor = g_flowHelper.InstallAll();

    // ----------------------------------------------------------
    // Scheduling
    // ----------------------------------------------------------
    Simulator::Schedule(Seconds(BASELINE_MEAS_START - 2.0),
                        &CheckConnectivity, &nodes, &interfaces);

    // BASELINE
    Simulator::Schedule(Seconds(BASELINE_MEAS_START),
                        &StartMeasurement, std::string("baseline"));
    Simulator::Schedule(Seconds(BASELINE_MEAS_START + 2.0),
                        &ProbeVictimRoute, &nodes, &interfaces);
    Simulator::Schedule(Seconds(BASELINE_MEAS_END - 0.5),
                        &ProbeVictimRoute, &nodes, &interfaces);
    Simulator::Schedule(Seconds(BASELINE_MEAS_END),
                        &EndMeasurement, &nodes, std::string("baseline"),
                        BASELINE_MEAS_START, BASELINE_MEAS_END, &interfaces);

    // ATTACK ONLY
    Simulator::Schedule(Seconds(ATTACK_STAB_START), &EnableAttack, &nodes);
    Simulator::Schedule(Seconds(ATTACK_MEAS_START),
                        &StartMeasurement, std::string("attack_only"));
    Simulator::Schedule(Seconds(ATTACK_MEAS_START + 2.0),
                        &ProbeVictimRoute, &nodes, &interfaces);
    Simulator::Schedule(Seconds(ATTACK_MEAS_END - 0.5),
                        &ProbeVictimRoute, &nodes, &interfaces);
    Simulator::Schedule(Seconds(ATTACK_MEAS_END),
                        &EndMeasurement, &nodes, std::string("attack_only"),
                        ATTACK_MEAS_START, ATTACK_MEAS_END, &interfaces);

    // DEFENSE ONLY
    Simulator::Schedule(Seconds(DEFENSE_STAB_START), &DisableAttack,  &nodes);
    Simulator::Schedule(Seconds(DEFENSE_STAB_START), &EnableDefense,  &nodes);
    Simulator::Schedule(Seconds(DEFENSE_MEAS_START),
                        &StartMeasurement, std::string("defense_only"));
    Simulator::Schedule(Seconds(DEFENSE_MEAS_START + 2.0),
                        &ProbeVictimRoute, &nodes, &interfaces);
    Simulator::Schedule(Seconds(DEFENSE_MEAS_END - 0.5),
                        &ProbeVictimRoute, &nodes, &interfaces);
    Simulator::Schedule(Seconds(DEFENSE_MEAS_END),
                        &EndMeasurement, &nodes, std::string("defense_only"),
                        DEFENSE_MEAS_START, DEFENSE_MEAS_END, &interfaces);

    // DEFENSE + ATTACK
    Simulator::Schedule(Seconds(DEFENSE_ATTACK_STAB_START), &EnableAttack, &nodes);
    Simulator::Schedule(Seconds(DEFENSE_ATTACK_MEAS_START),
                        &StartMeasurement, std::string("defense_vs_attack"));
    Simulator::Schedule(Seconds(DEFENSE_ATTACK_MEAS_START + 2.0),
                        &ProbeVictimRoute, &nodes, &interfaces);
    Simulator::Schedule(Seconds(DEFENSE_ATTACK_MEAS_END - 0.5),
                        &ProbeVictimRoute, &nodes, &interfaces);
    Simulator::Schedule(Seconds(DEFENSE_ATTACK_MEAS_END),
                        &EndMeasurement, &nodes, std::string("defense_vs_attack"),
                        DEFENSE_ATTACK_MEAS_START, DEFENSE_ATTACK_MEAS_END, &interfaces);

    // ----------------------------------------------------------
    // Run
    // ----------------------------------------------------------
    Simulator::Stop(Seconds(SIM_END));
    std::cout << "Running simulation (" << SIM_END << "s)..." << std::endl;
    Simulator::Run();
    Simulator::Destroy();

    PrintFinalSummary();
    SaveCsv(csvPath);
    return 0;
}