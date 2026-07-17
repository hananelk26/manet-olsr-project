/*
 * olsr-watchdog-validation.cc
 *
 * Four-phase validation of OlsrWatchdogDefense against a Black Hole attack.
 *
 * Phases (each: 60s stabilization + 40s measurement window):
 *   1) baseline           - no attack, no defense
 *   2) attack_only        - attack enabled, no defense
 *   3) defense_only       - no attack, defense enabled
 *   4) defense_vs_attack  - both enabled (the real test)
 *
 * We compare baseline -> attack_only to confirm the attack is harmful,
 * and attack_only -> defense_vs_attack to measure the defense's recovery.
 *
 * Measurement strategy:
 *   - FlowMonitor counts UDP traffic (port 9) only; OLSR control (port 698)
 *     is filtered out.
 *   - We snapshot per-flow counters at the START of a window and diff
 *     against the counters at the END. This is resilient to FlowMonitor
 *     state quirks.
 *
 * Build / run:
 *   cp olsr-watchdog-validation.cc scratch/
 *   ./ns3 build
 *   ./ns3 run "scratch/olsr-watchdog-validation"
 *
 *   Optional CLI:
 *     --run=N         : set RNG run number (default 1)
 *     --csv=path.csv  : output file for results (default results.csv)
 *     --verbose       : enable NS_LOG_INFO on the defense and this module
 */

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

#include "ns3/olsr-watchdog-defense.h"
#include "ns3/olsr-defense-strategy.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

using namespace ns3;
using namespace ns3::olsr;

NS_LOG_COMPONENT_DEFINE("WatchdogValidation");

// =============================================================================
// Phase timing
// -----------------------------------------------------------------------------
// Each trigger (EnableAttack / EnableDefense / DisableAttack) is scheduled 1ms
// AFTER the preceding EndMeasurement, to avoid two events at the same instant.
// -----------------------------------------------------------------------------
// NOTE on the long initial stabilization: a previous run showed baseline PDR
// of ~60% while later phases hit ~100%. The leading hypothesis is that 60s
// is not enough for OLSR to fully converge to optimal MPR/routing state in a
// 22-node mesh, so the baseline window measured a still-converging network.
// We therefore give baseline a 160s stabilization budget. To prove (or
// disprove) the hypothesis, we also run a fifth diagnostic phase
// `baseline_late` AFTER all interventions are torn down: identical conditions
// to baseline, just much later in the simulation. If baseline_late ~= the
// later phases, the convergence theory holds; if baseline_late ~= baseline,
// something we did permanently changed network behavior.
// =============================================================================
static const double MEAS_SECS = 40.0;   // measurement window length

// Phase 1: BASELINE  (no attack, no defense)  - long warmup for OLSR convergence
static const double BASELINE_MEAS_START   = 160.0;
static const double BASELINE_MEAS_END     = 200.0;

// Phase 2: ATTACK ONLY
static const double ATTACK_ENABLE_T       = 200.001;
static const double ATTACK_MEAS_START     = 260.0;
static const double ATTACK_MEAS_END       = 300.0;

// Phase 3: DEFENSE ONLY (attack disabled, defense enabled)
static const double DEF_ONLY_TRIGGER_T    = 300.001;
static const double DEF_ONLY_MEAS_START   = 360.0;
static const double DEF_ONLY_MEAS_END     = 400.0;

// Phase 4: DEFENSE + ATTACK
static const double DEF_VS_ATK_TRIGGER_T  = 400.001;
static const double DEF_VS_ATK_MEAS_START = 460.0;
static const double DEF_VS_ATK_MEAS_END   = 500.0;

// Phase 5: BASELINE_LATE (DIAGNOSTIC) - both attack and defense disabled,
// network identical to phase 1 but with everything fully settled. This phase
// answers the question "would baseline have given different numbers if we
// had only waited longer?".
static const double BASELINE_LATE_TRIGGER_T  = 500.001;  // tear down attack
static const double BASELINE_LATE_MEAS_START = 560.0;
static const double BASELINE_LATE_MEAS_END   = 600.0;

static const double SIM_END = 601.0;

// =============================================================================
// Topology: two columns of nodes bridged by TWO attackers and ONE backup.
//
//           LEFT COLUMN                              RIGHT COLUMN
//           (sources 0..9)                           (sinks 10..19)
//             x=300                                      x=700
//              o                                          o
//              o                                          o
//              .                    (20) attacker 1       .
//              .                    at (500, 510)         .
//              o                                          o
//              .                    (21) attacker 2       .
//              .                    at (500, 470)         .
//              o                                          o
//              .                    (22) backup           .
//              .                    at (500, 350)  far    .
//
// Design intent:
//   - Two attackers in the dense middle (close to most senders/receivers)
//     are the FIRST PICK as relays for OLSR -> dominant path is malicious.
//   - One backup pushed down to y=350 is in range (~250m max from y=540
//     would be at y=290, so y=350 is comfortably inside) but is the LESS
//     attractive route, so OLSR uses it only when forced to.
//   - Without defense: PDR collapses since 2/3 of bridges drop traffic.
//   - With defense: attackers get blacklisted, backup carries everything.
// =============================================================================
static const uint32_t N_LEFT         = 10;
static const uint32_t N_RIGHT        = 10;
static const uint32_t ATTACKER1_IDX  = 20;
static const uint32_t ATTACKER2_IDX  = 21;
static const uint32_t BACKUP_IDX     = 22;
static const uint32_t N_TOTAL        = 23;

// =============================================================================
// Attack & Traffic configuration
// =============================================================================
static const uint32_t SPOOFED_LINKS_COUNT = 5;
static const double   TRAFFIC_START_SEC   = 5.0;
static const uint32_t UDP_PKT_SIZE        = 512;
static const char*    UDP_DATA_RATE       = "40kbps";
static const uint16_t UDP_PORT            = 9;
static const double   WIFI_MAX_RANGE      = 250.0;

// =============================================================================
// Global state used by the measurement callbacks
// =============================================================================
static FlowMonitorHelper g_flowHelper;
static Ptr<FlowMonitor>  g_flowMonitor;

struct FlowSnapshot
{
    uint64_t txPackets = 0;
    uint64_t rxPackets = 0;
    uint64_t rxBytes   = 0;
    double   delaySum  = 0.0;
};
static std::map<FlowId, FlowSnapshot> g_snapshotStart;

struct PhaseResult
{
    std::string name;
    uint64_t    txPackets                       = 0;
    uint64_t    rxPackets                       = 0;
    double      pdr                             = 0.0;
    double      avgDelayMs                      = 0.0;
    double      throughputKbps                  = 0.0;
    uint32_t    nodesDetectingAttacker1         = 0;
    uint32_t    nodesDetectingAttacker2         = 0;
    uint32_t    nodesDetectingAnyAttacker       = 0;  // either one
    uint32_t    nodesDetectingBothAttackers     = 0;  // both
    uint32_t    nodesWithFalsePositives         = 0;
    uint32_t    totalFalsePositives             = 0;
    bool        attacker1BlacklistedSomewhere   = false;
    bool        attacker2BlacklistedSomewhere   = false;
    bool        backupBlacklistedSomewhere      = false;
};
static std::vector<PhaseResult> g_results;

// =============================================================================
// Helpers
// =============================================================================
static Ptr<olsr::RoutingProtocol> GetOlsrRp(Ptr<Node> node)
{
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
    if (!ipv4) return nullptr;

    Ptr<Ipv4ListRouting> listProto =
        DynamicCast<Ipv4ListRouting>(ipv4->GetRoutingProtocol());
    if (listProto)
    {
        for (uint32_t i = 0; i < listProto->GetNRoutingProtocols(); ++i)
        {
            int16_t prio;
            Ptr<Ipv4RoutingProtocol> child = listProto->GetRoutingProtocol(i, prio);
            if (child->GetInstanceTypeId().GetName() == "ns3::olsr::RoutingProtocol")
            {
                return DynamicCast<olsr::RoutingProtocol>(child);
            }
        }
    }
    return DynamicCast<olsr::RoutingProtocol>(ipv4->GetRoutingProtocol());
}

// Filters FlowMonitor to application UDP flows only (port 9),
// excluding OLSR control (port 698) and any non-UDP traffic.
static bool IsApplicationFlow(const Ipv4FlowClassifier::FiveTuple& t)
{
    if (t.protocol != 17) return false; // 17 == UDP
    if (t.destinationPort != UDP_PORT) return false;
    return true;
}

// =============================================================================
// Attack / defense control
// =============================================================================
static void EnableAttack(NodeContainer* nodes)
{
    const uint32_t attackers[] = {ATTACKER1_IDX, ATTACKER2_IDX};
    for (uint32_t idx : attackers)
    {
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(idx));
        if (!rp) continue;
        rp->SetAttribute("IsMalicious",       BooleanValue(true));
        rp->SetAttribute("SpoofedLinksCount", UintegerValue(SPOOFED_LINKS_COUNT));
    }
    std::cout << "\n[t=" << Simulator::Now().GetSeconds()
              << "s] >>> Black Hole attack ENABLED at nodes "
              << ATTACKER1_IDX << " and " << ATTACKER2_IDX
              << std::endl;
}

static void DisableAttack(NodeContainer* nodes)
{
    const uint32_t attackers[] = {ATTACKER1_IDX, ATTACKER2_IDX};
    for (uint32_t idx : attackers)
    {
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(idx));
        if (!rp) continue;
        rp->SetAttribute("IsMalicious",       BooleanValue(false));
        rp->SetAttribute("SpoofedLinksCount", UintegerValue(0));
    }
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "s] >>> Black Hole attack DISABLED" << std::endl;
}

// Replaces the (Null) defense on every non-attacker node with a fresh
// OlsrWatchdogDefense instance, then calls ReactivateDefenseStrategy so
// OLSR invokes Setup() on the new instance.
static void EnableDefense(NodeContainer* nodes)
{
    uint32_t installed = 0;
    for (uint32_t i = 0; i < nodes->GetN(); ++i)
    {
        if (i == ATTACKER1_IDX || i == ATTACKER2_IDX) continue;
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(i));
        if (!rp) continue;

        Ptr<OlsrWatchdogDefense> defense = CreateObject<OlsrWatchdogDefense>();
        rp->SetAttribute("DefenseStrategy", PointerValue(defense));
        rp->ReactivateDefenseStrategy();
        ++installed;
    }
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "s] >>> Watchdog defense ENABLED on " << installed
              << " nodes" << std::endl;
}

// Tears the watchdog defense down by disposing of the current instance
// (which disconnects its WiFi traces) and replacing it with a Null strategy.
// Used by the diagnostic baseline_late phase to verify that observed PDR
// differences are not caused by the defense being present.
//
// The Dispose() call is critical: SetAttribute alone replaces the pointer
// but leaves the old object's PHY trace connections live, which causes
// segfaults when traces fire into a soon-to-be-destroyed object.
static void DisableDefense(NodeContainer* nodes)
{
    uint32_t replaced = 0;
    for (uint32_t i = 0; i < nodes->GetN(); ++i)
    {
        if (i == ATTACKER1_IDX || i == ATTACKER2_IDX) continue;
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(i));
        if (!rp) continue;

        // Grab the current strategy and dispose of it cleanly first.
        PointerValue pv;
        rp->GetAttribute("DefenseStrategy", pv);
        Ptr<OlsrDefenseStrategy> oldStrategy = pv.Get<OlsrDefenseStrategy>();
        if (oldStrategy)
        {
            oldStrategy->DoDispose();
        }

        rp->SetAttribute("DefenseStrategy",
                         PointerValue(CreateObject<OlsrDefenseNull>()));
        rp->ReactivateDefenseStrategy();
        ++replaced;
    }
    std::cout << "[t=" << Simulator::Now().GetSeconds()
              << "s] >>> Watchdog defense DISABLED on " << replaced
              << " nodes (replaced with Null)" << std::endl;
}

// =============================================================================
// Measurement
// =============================================================================
static void StartMeasurement(const std::string& name)
{
    std::cout << "\n[t=" << Simulator::Now().GetSeconds()
              << "s] ===== START window: " << name << " =====" << std::endl;

    if (!g_flowMonitor) return;
    g_flowMonitor->CheckForLostPackets();

    g_snapshotStart.clear();
    for (auto const& kv : g_flowMonitor->GetFlowStats())
    {
        FlowSnapshot s;
        s.txPackets = kv.second.txPackets;
        s.rxPackets = kv.second.rxPackets;
        s.rxBytes   = kv.second.rxBytes;
        s.delaySum  = kv.second.delaySum.GetSeconds();
        g_snapshotStart[kv.first] = s;
    }
}

static void EndMeasurement(NodeContainer*                nodes,
                           const std::string&            name,
                           const Ipv4InterfaceContainer* interfaces,
                           double                        windowSec)
{
    PhaseResult r;
    r.name = name;

    // --- FlowMonitor: diff counters against the start snapshot ---
    if (g_flowMonitor)
    {
        g_flowMonitor->CheckForLostPackets();
        Ptr<Ipv4FlowClassifier> classifier =
            DynamicCast<Ipv4FlowClassifier>(g_flowHelper.GetClassifier());

        double   totalDelaySec = 0.0;
        uint64_t totalRxBytes  = 0;

        for (auto const& kv : g_flowMonitor->GetFlowStats())
        {
            FlowId fid = kv.first;
            Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(fid);
            if (!IsApplicationFlow(t)) continue;

            uint64_t tx = kv.second.txPackets;
            uint64_t rx = kv.second.rxPackets;
            uint64_t rb = kv.second.rxBytes;
            double   ds = kv.second.delaySum.GetSeconds();

            auto itStart = g_snapshotStart.find(fid);
            if (itStart != g_snapshotStart.end())
            {
                tx -= itStart->second.txPackets;
                rx -= itStart->second.rxPackets;
                rb -= itStart->second.rxBytes;
                ds -= itStart->second.delaySum;
            }

            r.txPackets   += tx;
            r.rxPackets   += rx;
            totalRxBytes  += rb;
            totalDelaySec += ds;
        }

        r.pdr            = (r.txPackets > 0) ? (100.0 * r.rxPackets / r.txPackets) : 0.0;
        r.avgDelayMs     = (r.rxPackets > 0) ? (totalDelaySec / r.rxPackets * 1000.0) : 0.0;
        r.throughputKbps = (totalRxBytes * 8.0) / (windowSec * 1000.0);
    }

    // --- Blacklist analysis across all honest nodes ---
    Ipv4Address attacker1Ip = interfaces->GetAddress(ATTACKER1_IDX);
    Ipv4Address attacker2Ip = interfaces->GetAddress(ATTACKER2_IDX);
    Ipv4Address backupIp    = interfaces->GetAddress(BACKUP_IDX);

    std::set<Ipv4Address> honestIps;
    for (uint32_t i = 0; i < nodes->GetN(); ++i)
    {
        if (i == ATTACKER1_IDX || i == ATTACKER2_IDX) continue;
        honestIps.insert(interfaces->GetAddress(i));
    }

    for (uint32_t i = 0; i < nodes->GetN(); ++i)
    {
        if (i == ATTACKER1_IDX || i == ATTACKER2_IDX) continue;
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(i));
        if (!rp) continue;

        std::set<Ipv4Address> bl = rp->GetBlacklist();
        if (bl.empty()) continue;

        const bool detectsAtk1 = (bl.find(attacker1Ip) != bl.end());
        const bool detectsAtk2 = (bl.find(attacker2Ip) != bl.end());

        if (detectsAtk1)
        {
            ++r.nodesDetectingAttacker1;
            r.attacker1BlacklistedSomewhere = true;
        }
        if (detectsAtk2)
        {
            ++r.nodesDetectingAttacker2;
            r.attacker2BlacklistedSomewhere = true;
        }
        if (detectsAtk1 || detectsAtk2) ++r.nodesDetectingAnyAttacker;
        if (detectsAtk1 && detectsAtk2) ++r.nodesDetectingBothAttackers;

        if (bl.find(backupIp) != bl.end())
        {
            r.backupBlacklistedSomewhere = true;
        }

        uint32_t fpHere = 0;
        for (auto const& ip : bl)
        {
            if (honestIps.find(ip) != honestIps.end())
            {
                ++fpHere;
            }
        }
        if (fpHere > 0)
        {
            ++r.nodesWithFalsePositives;
            r.totalFalsePositives += fpHere;
        }
    }

    g_results.push_back(r);

    const uint32_t honestCount = N_TOTAL - 2; // excluding both attackers
    std::cout << "\n==============================\n"
              << "  PHASE: " << name << "\n"
              << "------------------------------\n"
              << "  Tx:                     " << r.txPackets << "\n"
              << "  Rx:                     " << r.rxPackets << "\n"
              << std::fixed << std::setprecision(1)
              << "  PDR:                    " << r.pdr << " %\n"
              << std::setprecision(2)
              << "  Avg delay:              " << r.avgDelayMs << " ms\n"
              << "  Throughput:             " << r.throughputKbps << " kbps\n"
              << "  Detecting ATK1 (n20):   " << r.nodesDetectingAttacker1
              << " / " << honestCount << "\n"
              << "  Detecting ATK2 (n21):   " << r.nodesDetectingAttacker2
              << " / " << honestCount << "\n"
              << "  Detecting >= 1 ATK:     " << r.nodesDetectingAnyAttacker
              << " / " << honestCount << "\n"
              << "  Detecting BOTH ATKs:    " << r.nodesDetectingBothAttackers
              << " / " << honestCount << "\n"
              << "  Nodes with FPs:         " << r.nodesWithFalsePositives << "\n"
              << "  Total FP entries:       " << r.totalFalsePositives << "\n"
              << "  Backup wrongly flagged: "
              << (r.backupBlacklistedSomewhere ? "YES (BAD)" : "no") << "\n"
              << "==============================" << std::endl;
}

// =============================================================================
// Sanity check a few seconds before the first measurement: is OLSR converged?
// =============================================================================
static void CheckConnectivity(NodeContainer* nodes)
{
    std::cout << "\n[t=" << Simulator::Now().GetSeconds()
              << "s] --- Connectivity probe ---" << std::endl;
    Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes->Get(0));
    if (rp)
    {
        std::cout << "  Node 0 has "
                  << rp->GetNeighbors().size() << " 1-hop neighbors, "
                  << rp->GetTwoHopNeighbors().size() << " 2-hop neighbors, "
                  << rp->GetRoutingTableEntries().size() << " routing entries"
                  << std::endl;
    }
    std::cout << "----------------------------" << std::endl;
}

// =============================================================================
// Summary / CSV
// =============================================================================
static void PrintFinalSummary()
{
    std::cout << "\n\n";
    std::cout << "+=========================================================================================+\n";
    std::cout << "|              OLSR WATCHDOG DEFENSE VALIDATION - RESULTS                                 |\n";
    std::cout << "+=========================================================================================+\n";
    std::cout << "| Phase              |  Tx  |  Rx  |  PDR   | Delay(ms) | Tput(kbps) | Atk1 | Atk2 | FPs | BkFP |\n";
    std::cout << "+--------------------+------+------+--------+-----------+------------+------+------+-----+------+\n";
    for (auto const& r : g_results)
    {
        std::cout << "| " << std::left  << std::setw(18) << r.name
                  << " | " << std::right << std::setw(4)  << r.txPackets
                  << " | " << std::setw(4) << r.rxPackets
                  << " | " << std::setw(5) << std::fixed << std::setprecision(1) << r.pdr << "% "
                  << " | " << std::setw(9) << std::setprecision(1) << r.avgDelayMs
                  << " | " << std::setw(10) << std::setprecision(1) << r.throughputKbps
                  << " | " << std::setw(4) << r.nodesDetectingAttacker1
                  << " | " << std::setw(4) << r.nodesDetectingAttacker2
                  << " | " << std::setw(3) << r.totalFalsePositives
                  << " | " << std::setw(4) << (r.backupBlacklistedSomewhere ? "YES" : "no ")
                  << " |\n";
    }
    std::cout << "+=========================================================================================+\n";
    std::cout << "Legend: Atk1/Atk2 = honest nodes that blacklisted attacker 1 / 2;\n"
              << "        FPs       = total false-positive entries (honest nodes wrongly flagged);\n"
              << "        BkFP      = was the honest backup wrongly flagged anywhere\n" << std::endl;

    // Verdicts
    double pdrBase = -1, pdrAtk = -1, pdrDef = -1, pdrDefAtk = -1;
    uint32_t fpDef = 0, fpDefAtk = 0;
    bool backupFlaggedDef = false, backupFlaggedDefAtk = false;
    uint32_t atk1DetectedInDefAtk = 0;
    uint32_t atk2DetectedInDefAtk = 0;
    uint32_t bothDetectedInDefAtk = 0;

    for (auto const& r : g_results)
    {
        if (r.name == "baseline")           pdrBase   = r.pdr;
        if (r.name == "attack_only")        pdrAtk    = r.pdr;
        if (r.name == "defense_only")
        {
            pdrDef           = r.pdr;
            fpDef            = r.totalFalsePositives;
            backupFlaggedDef = r.backupBlacklistedSomewhere;
        }
        if (r.name == "defense_vs_attack")
        {
            pdrDefAtk            = r.pdr;
            fpDefAtk             = r.totalFalsePositives;
            backupFlaggedDefAtk  = r.backupBlacklistedSomewhere;
            atk1DetectedInDefAtk = r.nodesDetectingAttacker1;
            atk2DetectedInDefAtk = r.nodesDetectingAttacker2;
            bothDetectedInDefAtk = r.nodesDetectingBothAttackers;
        }
    }

    std::cout << "\n=== VERDICTS ===" << std::endl;
    std::cout << std::fixed << std::setprecision(1);

    if (pdrBase >= 0 && pdrAtk >= 0)
    {
        if (pdrAtk < pdrBase - 10.0)
        {
            std::cout << "  [+] Attack IS effective: baseline=" << pdrBase
                      << "% -> attack_only=" << pdrAtk
                      << "%  (drop: " << (pdrBase - pdrAtk) << "%)" << std::endl;
        }
        else
        {
            std::cout << "  [!] Attack appears INEFFECTIVE: baseline=" << pdrBase
                      << "%, attack_only=" << pdrAtk << "%" << std::endl;
        }
    }

    if (pdrBase >= 0 && pdrDef >= 0)
    {
        double diff = pdrBase - pdrDef;
        if (diff < 5.0 && fpDef == 0 && !backupFlaggedDef)
        {
            std::cout << "  [+] Defense is SAFE when no attack: PDR=" << pdrDef
                      << "% (vs baseline " << pdrBase
                      << "%), zero false positives" << std::endl;
        }
        else
        {
            std::cout << "  [!] Defense has SIDE EFFECTS in clean conditions: PDR=" << pdrDef
                      << "% (vs baseline " << pdrBase
                      << "%), FP entries=" << fpDef
                      << (backupFlaggedDef ? ", BACKUP WRONGLY FLAGGED" : "")
                      << std::endl;
        }
    }

    if (pdrAtk >= 0 && pdrDefAtk >= 0)
    {
        double imp = pdrDefAtk - pdrAtk;
        std::cout << "  [=] PDR recovery from defense: "
                  << std::showpos << imp << "%" << std::noshowpos
                  << " (attack_only=" << pdrAtk
                  << "% -> defense_vs_attack=" << pdrDefAtk << "%)" << std::endl;
        if      (imp > 30.0) std::cout << "      ==> Defense HIGHLY EFFECTIVE" << std::endl;
        else if (imp > 10.0) std::cout << "      ==> Defense EFFECTIVE" << std::endl;
        else if (imp >  0.0) std::cout << "      ==> Defense PARTIALLY effective" << std::endl;
        else                 std::cout << "      ==> Defense shows MINIMAL effect" << std::endl;

        const uint32_t honestCount = N_TOTAL - 2;
        std::cout << "      Detected attacker1 at " << atk1DetectedInDefAtk
                  << " / " << honestCount << " honest nodes" << std::endl;
        std::cout << "      Detected attacker2 at " << atk2DetectedInDefAtk
                  << " / " << honestCount << " honest nodes" << std::endl;
        std::cout << "      Detected BOTH attackers at " << bothDetectedInDefAtk
                  << " / " << honestCount << " honest nodes" << std::endl;
    }

    if (pdrDefAtk >= 0)
    {
        if (fpDefAtk == 0 && !backupFlaggedDefAtk)
        {
            std::cout << "  [+] No false positives under attack "
                      << "(backup stayed healthy)" << std::endl;
        }
        else
        {
            std::cout << "  [!] False-positive entries under attack: " << fpDefAtk
                      << (backupFlaggedDefAtk ? ", BACKUP WRONGLY FLAGGED" : "")
                      << std::endl;
        }
    }
    std::cout << std::endl;
}

static void SaveCsv(const std::string& path)
{
    std::ofstream f(path.c_str());
    if (!f.is_open()) return;

    f << "Phase,Tx,Rx,PDR_pct,AvgDelayMs,ThroughputKbps,"
      << "NodesDetectingAtk1,NodesDetectingAtk2,NodesDetectingAny,NodesDetectingBoth,"
      << "NodesWithFalsePositives,TotalFalsePositives,"
      << "Atk1FlaggedSomewhere,Atk2FlaggedSomewhere,BackupWronglyFlagged\n";
    for (auto const& r : g_results)
    {
        f << r.name << ","
          << r.txPackets << "," << r.rxPackets << ","
          << std::fixed << std::setprecision(2) << r.pdr << ","
          << r.avgDelayMs << ","
          << r.throughputKbps << ","
          << r.nodesDetectingAttacker1 << ","
          << r.nodesDetectingAttacker2 << ","
          << r.nodesDetectingAnyAttacker << ","
          << r.nodesDetectingBothAttackers << ","
          << r.nodesWithFalsePositives << ","
          << r.totalFalsePositives << ","
          << (r.attacker1BlacklistedSomewhere ? 1 : 0) << ","
          << (r.attacker2BlacklistedSomewhere ? 1 : 0) << ","
          << (r.backupBlacklistedSomewhere ? 1 : 0) << "\n";
    }
    f.close();
    std::cout << "[CSV] Results saved to: " << path << std::endl;
}

// =============================================================================
// MAIN
// =============================================================================
int main(int argc, char* argv[])
{
    uint32_t    runNumber = 1;
    std::string csvPath   = "watchdog-validation-results.csv";
    bool        verbose   = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("run",     "RNG run number",                    runNumber);
    cmd.AddValue("csv",     "Output CSV path",                   csvPath);
    cmd.AddValue("verbose", "Enable NS_LOG_INFO on the defense", verbose);
    cmd.Parse(argc, argv);

    if (verbose)
    {
        LogComponentEnable("WatchdogValidation",   LOG_LEVEL_INFO);
        LogComponentEnable("OlsrWatchdogDefense",  LOG_LEVEL_INFO);
    }

    Time::SetResolution(Time::NS);
    RngSeedManager::SetSeed(1);
    RngSeedManager::SetRun(runNumber);

    std::cout << "===========================================\n"
              << "  OLSR Watchdog Defense Validation\n"
              << "  Topology: " << N_LEFT << " senders | "
              << "2 attackers + 1 backup | "
              << N_RIGHT << " receivers (total " << N_TOTAL << ")\n"
              << "  RNG run: " << runNumber << "\n"
              << "===========================================\n\n";

    // --- Nodes ---
    NodeContainer nodes;
    nodes.Create(N_TOTAL);

    // --- WiFi ---
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper wifiPhy;
    wifiPhy.Set("RxGain", DoubleValue(0));

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel",
                                    "MaxRange", DoubleValue(WIFI_MAX_RANGE));
    wifiPhy.SetChannel(wifiChannel.Create());

    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, nodes);

    // --- Mobility (static two-column layout) ---
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < N_LEFT; ++i)
    {
        pos->Add(Vector(300.0, 450.0 + i * 10.0, 0.0));
    }
    for (uint32_t i = 0; i < N_RIGHT; ++i)
    {
        pos->Add(Vector(700.0, 450.0 + i * 10.0, 0.0));
    }
    pos->Add(Vector(500.0, 490.0, 0.0));  // ATTACKER1_IDX = 20
    pos->Add(Vector(500.0, 470.0, 0.0));  // ATTACKER2_IDX = 21
    pos->Add(Vector(500.0, 430.0, 0.0));  // BACKUP_IDX    = 22  (close enough to sniff)
    mobility.SetPositionAllocator(pos);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // --- OLSR ---
    OlsrHelper olsr;
    Ipv4ListRoutingHelper routeList;
    routeList.Add(olsr, 100);

    InternetStackHelper internet;
    internet.SetRoutingHelper(routeList);
    internet.Install(nodes);

    // Install Null defense on every node as the safe default. The real
    // OlsrWatchdogDefense is installed on honest nodes only at t=200.001s.
    for (uint32_t i = 0; i < N_TOTAL; ++i)
    {
        Ptr<olsr::RoutingProtocol> rp = GetOlsrRp(nodes.Get(i));
        if (rp)
        {
            rp->SetAttribute("DefenseStrategy",
                             PointerValue(CreateObject<OlsrDefenseNull>()));
        }
    }

    Ipv4AddressHelper addr;
    addr.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = addr.Assign(devices);

    std::cout << ">> Left column:    " << interfaces.GetAddress(0)
              << " .. " << interfaces.GetAddress(N_LEFT - 1) << "\n";
    std::cout << ">> Right column:   " << interfaces.GetAddress(N_LEFT)
              << " .. " << interfaces.GetAddress(N_LEFT + N_RIGHT - 1) << "\n";
    std::cout << ">> Attacker1 (20): " << interfaces.GetAddress(ATTACKER1_IDX) << "\n";
    std::cout << ">> Attacker2 (21): " << interfaces.GetAddress(ATTACKER2_IDX) << "\n";
    std::cout << ">> Backup    (22): " << interfaces.GetAddress(BACKUP_IDX) << "\n\n";

    // --- Traffic: each left node sends a steady UDP flow to its paired right node ---
    OnOffHelper onoff("ns3::UdpSocketFactory", Address());
    onoff.SetAttribute("OnTime",     StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
    onoff.SetAttribute("OffTime",    StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    onoff.SetAttribute("PacketSize", UintegerValue(UDP_PKT_SIZE));
    onoff.SetAttribute("DataRate",   StringValue(UDP_DATA_RATE));

    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                 InetSocketAddress(Ipv4Address::GetAny(), UDP_PORT));
    for (uint32_t i = 0; i < N_RIGHT; ++i)
    {
        ApplicationContainer sinkApp = sinkHelper.Install(nodes.Get(N_LEFT + i));
        sinkApp.Start(Seconds(0.0));
        sinkApp.Stop(Seconds(SIM_END));
    }
    for (uint32_t i = 0; i < N_LEFT; ++i)
    {
        Ipv4Address destIp = interfaces.GetAddress(N_LEFT + i);
        AddressValue remoteAddress(InetSocketAddress(destIp, UDP_PORT));
        onoff.SetAttribute("Remote", remoteAddress);
        ApplicationContainer app = onoff.Install(nodes.Get(i));
        app.Start(Seconds(TRAFFIC_START_SEC));
        app.Stop(Seconds(SIM_END));
    }

    g_flowMonitor = g_flowHelper.InstallAll();

    // =========================================================================
    // Schedule everything. Triggers (attack/defense toggles) happen at
    // MEAS_END + 1ms so they never collide with an EndMeasurement event.
    // =========================================================================
    Simulator::Schedule(Seconds(BASELINE_MEAS_START - 2.0),
                        &CheckConnectivity, &nodes);

    // Phase 1: BASELINE (nothing enabled)
    Simulator::Schedule(Seconds(BASELINE_MEAS_START),
                        &StartMeasurement, std::string("baseline"));
    Simulator::Schedule(Seconds(BASELINE_MEAS_END),
                        &EndMeasurement, &nodes, std::string("baseline"),
                        &interfaces, MEAS_SECS);

    // Phase 2: ATTACK ONLY
    Simulator::Schedule(Seconds(ATTACK_ENABLE_T), &EnableAttack, &nodes);
    Simulator::Schedule(Seconds(ATTACK_MEAS_START),
                        &StartMeasurement, std::string("attack_only"));
    Simulator::Schedule(Seconds(ATTACK_MEAS_END),
                        &EndMeasurement, &nodes, std::string("attack_only"),
                        &interfaces, MEAS_SECS);

    // Phase 3: DEFENSE ONLY (attack off, defense on)
    Simulator::Schedule(Seconds(DEF_ONLY_TRIGGER_T), &DisableAttack,  &nodes);
    Simulator::Schedule(Seconds(DEF_ONLY_TRIGGER_T), &EnableDefense,  &nodes);
    Simulator::Schedule(Seconds(DEF_ONLY_MEAS_START),
                        &StartMeasurement, std::string("defense_only"));
    Simulator::Schedule(Seconds(DEF_ONLY_MEAS_END),
                        &EndMeasurement, &nodes, std::string("defense_only"),
                        &interfaces, MEAS_SECS);

    // Phase 4: DEFENSE + ATTACK
    Simulator::Schedule(Seconds(DEF_VS_ATK_TRIGGER_T), &EnableAttack, &nodes);
    Simulator::Schedule(Seconds(DEF_VS_ATK_MEAS_START),
                        &StartMeasurement, std::string("defense_vs_attack"));
    Simulator::Schedule(Seconds(DEF_VS_ATK_MEAS_END),
                        &EndMeasurement, &nodes, std::string("defense_vs_attack"),
                        &interfaces, MEAS_SECS);

    // Phase 5 (DIAGNOSTIC): BASELINE_LATE
    // Same conditions as phase 1 (no attack, no defense). If PDR here matches
    // phase 1, baseline was already converged. If PDR here is higher, it
    // means OLSR needed more time to settle - and our original baseline was
    // measuring an unsteady network.
    Simulator::Schedule(Seconds(BASELINE_LATE_TRIGGER_T), &DisableAttack,  &nodes);
    Simulator::Schedule(Seconds(BASELINE_LATE_TRIGGER_T), &DisableDefense, &nodes);
    Simulator::Schedule(Seconds(BASELINE_LATE_MEAS_START),
                        &StartMeasurement, std::string("baseline_late"));
    Simulator::Schedule(Seconds(BASELINE_LATE_MEAS_END),
                        &EndMeasurement, &nodes, std::string("baseline_late"),
                        &interfaces, MEAS_SECS);

    Simulator::Stop(Seconds(SIM_END));
    std::cout << "Running simulation (" << SIM_END << "s)..." << std::endl;
    Simulator::Run();
    Simulator::Destroy();

    PrintFinalSummary();
    SaveCsv(csvPath);
    return 0;
}