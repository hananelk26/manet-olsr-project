/*
 * Copyright (c) 2025 Security Research
 * Implementation of "Cooperative Cross Layer Detection"
 */

#include "olsr-defense-cooperative.h"
#include "olsr-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/wifi-mac-header.h"

#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/arp-cache.h"
#include "ns3/node.h"

namespace ns3 {
namespace olsr {

NS_LOG_COMPONENT_DEFINE("OlsrDefenseCooperative");

NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseCooperative);

TypeId
OlsrDefenseCooperative::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::olsr::OlsrDefenseCooperative")
    .SetParent<OlsrDefenseStrategy>()
    .SetGroupName("Olsr")
    .AddConstructor<OlsrDefenseCooperative>();
  return tid;
}

OlsrDefenseCooperative::OlsrDefenseCooperative()
  : m_protocol(nullptr),
    m_watchdogTimeout(Seconds(0.5)),  // Internal; see m_watchdogCheckInterval below.
    m_noiseThreshold(500),
    m_lastNoiseLevel(0),
    m_myMac(Mac48Address()),
    m_watchdogTimer(Timer::CANCEL_ON_DESTROY),
    m_watchdogCheckInterval(Seconds(0.5))  // Matches m_watchdogTimeout — independent of main defense timer.
{
}

OlsrDefenseCooperative::~OlsrDefenseCooperative() {}

void OlsrDefenseCooperative::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
{
    m_protocol = proto;
    m_mainAddress = nodeAddress;
    
    m_watchdogTimer.Cancel();
    m_watchdogTimer.SetFunction(&OlsrDefenseCooperative::EvaluatePendingPackets, this);
    m_watchdogTimer.Schedule(m_watchdogCheckInterval);
    
    std::cout << ">>> [DEBUG] Setup() called at t=" << Simulator::Now().GetSeconds()
              << "s for node " << nodeAddress << std::endl;
}

void OlsrDefenseCooperative::DoDispose()
{
    m_watchdogTimer.Cancel();
    m_protocol = nullptr;
    m_pendingPackets.clear();
    m_lastRtsTarget.clear();
    m_neighborActivity.clear(); 
}

bool OlsrDefenseCooperative::IsMalicious(Ipv4Address addr)
{
    return m_blacklist.find(addr) != m_blacklist.end();
}

std::set<Ipv4Address> OlsrDefenseCooperative::GetBlacklist() const
{
    return m_blacklist;
}

// --- Data Plane Hooks ---

void OlsrDefenseCooperative::OnDataPacketForwarded(Ptr<const Packet> packet, 
                                                    Ipv4Address nextHop, 
                                                    Ipv4Address finalDest)
{
    if (nextHop == finalDest) {
        return;
    }
    
    uint64_t uid = packet->GetUid();
    
    PendingPacket pp;
    pp.uid = uid;
    pp.nextHopIp = nextHop;
    pp.sendTime = Simulator::Now();
    pp.receivedByNeighbor = true;
    pp.forwardedByNeighbor = false;

    m_pendingPackets[uid] = pp;
    
    // DEBUG: track pendings for attacker specifically
    if (nextHop == Ipv4Address("10.1.1.21")) {
        static thread_local uint32_t cnt = 0;
        if (++cnt % 50 == 1) {
            std::cout << ">>> [PENDING-CREATE] node=" << m_mainAddress
                      << " t=" << Simulator::Now().GetSeconds()
                      << " uid=" << uid
                      << " -> attacker (count=" << cnt << ")" << std::endl;
        }
    }
}

// --- Cross-Layer Hooks (The "Ears") ---

void OlsrDefenseCooperative::OnCtsReceived(Mac48Address receiver)
{
    static thread_local uint32_t ctsHeardCount = 0;
    static thread_local uint32_t ctsMatchedCount = 0;
    static thread_local uint32_t ctsForMeCount = 0;
    static thread_local uint32_t ctsUpdatedPendingCount = 0;
    
    ctsHeardCount++;
    
    auto rtsIt = m_lastRtsTarget.find(receiver);
    if (rtsIt == m_lastRtsTarget.end()) {
        // DEBUG
        if (ctsHeardCount % 500 == 1) {
            std::cout << ">>> [CTS-ORPHAN] node=" << m_mainAddress
                      << " CTS for=" << receiver
                      << " but no matching RTS (heard=" << ctsHeardCount
                      << " matched=" << ctsMatchedCount << ")" << std::endl;
        }
        return;
    }
    ctsMatchedCount++;
    
    Mac48Address ctsSender = rtsIt->second;
    Mac48Address ctsTarget = receiver;
    
    Mac48Address myMac = GetMyMac();
    
    if (myMac != Mac48Address() && ctsTarget == myMac) {
        ctsForMeCount++;
        for (auto& ppEntry : m_pendingPackets) {
            if (!ppEntry.second.receivedByNeighbor) {
                Mac48Address nextHopMac = GetMacForIp(ppEntry.second.nextHopIp);
                if (nextHopMac == ctsSender) {
                    ppEntry.second.receivedByNeighbor = true;
                    ctsUpdatedPendingCount++;
                }
            }
        }
    }
    
    // DEBUG: periodic summary
    if (ctsHeardCount % 500 == 1) {
        std::cout << ">>> [CTS-STATS] node=" << m_mainAddress
                  << " myMac=" << myMac
                  << " heard=" << ctsHeardCount
                  << " matched=" << ctsMatchedCount
                  << " forMe=" << ctsForMeCount
                  << " updatedPending=" << ctsUpdatedPendingCount
                  << std::endl;
    }
    
    auto obsIt = m_macObservations.find(ctsTarget);
    if (obsIt != m_macObservations.end()) {
        auto targetIt = obsIt->second.find(ctsSender);
        if (targetIt != obsIt->second.end()) {
            targetIt->second.hasClearance = true;
            targetIt->second.lastUpdated = Simulator::Now();
        }
    }
    
    m_lastRtsTarget.erase(rtsIt);
}

void OlsrDefenseCooperative::OnRtsReceived(Mac48Address sender, Mac48Address receiver)
{
    MacObservation& obs = m_macObservations[sender][receiver];
    if (obs.rtsCount == 0) {
        obs.firstSeen = Simulator::Now();
        obs.hasClearance = false;
    }
    obs.rtsCount++;
    obs.lastUpdated = Simulator::Now();
    
    m_lastRtsTarget[sender] = receiver;
    
    // DEBUG
    static thread_local uint32_t rtsCount = 0;
    if (++rtsCount % 500 == 1) {
        std::cout << ">>> [RTS] node=" << m_mainAddress
                  << " heard RTS from=" << sender << " to=" << receiver
                  << " (count=" << rtsCount << ")" << std::endl;
    }
}

void OlsrDefenseCooperative::OnNeighborForwardedPacket(Mac48Address transmitter, 
                                                       Mac48Address receiver, Ptr<const Packet> packet)
{
    Mac48Address myMac = GetMyMac();
    if (transmitter == myMac) {
        return;
    }
    
    uint64_t uid = packet->GetUid();
    
    auto it = m_pendingPackets.find(uid);
    if (it != m_pendingPackets.end()) {
        Mac48Address expectedMac = GetMacForIp(it->second.nextHopIp);
        
        // DEBUG: specifically track attacker-related pendings
        if (it->second.nextHopIp == Ipv4Address("10.1.1.21")) {
            static thread_local uint32_t markAttacker = 0;
            markAttacker++;
            if (markAttacker % 20 == 1) {
                std::cout << ">>> [ATTACKER-MARK] node=" << m_mainAddress
                          << " t=" << Simulator::Now().GetSeconds()
                          << " uid=" << uid
                          << " expected=10.1.1.21 expectedMac=" << expectedMac
                          << " heardFrom=" << transmitter
                          << " matches=" << (expectedMac == transmitter ? "YES" : "no")
                          << std::endl;
            }
        }
        
        if (expectedMac != Mac48Address() && transmitter == expectedMac) {
            it->second.forwardedByNeighbor = true;
        }
    }
    
    m_neighborActivity[transmitter]++;
}

void OlsrDefenseCooperative::OnSelfReliabilityReport(uint32_t localDropsCount)
{
    m_lastNoiseLevel = localDropsCount;
}

// --- Periodic Check (The "Brain") ---

// void OlsrDefenseCooperative::PeriodicCheck()
// {
//     Time now = Simulator::Now();
//     std::vector<uint64_t> toRemove;

//     for (auto& item : m_pendingPackets) {
//         PendingPacket& pp = item.second;

//         // Check if enough time has passed to make a judgement (Watchdog Timer)
//         if (now - pp.sendTime > m_watchdogTimeout) {
            
//             // ---------------------------------------------------------
//             // Step 1: Did B (the neighbor) receive the packet from A?
//             // ---------------------------------------------------------
//             if (!pp.receivedByNeighbor) {
//                 // If B didn't send CTS to us, we assume collision or B is dead/unreachable.
//                 // We do NOT classify this as malicious behavior (per summary).
//                 toRemove.push_back(item.first);
//                 continue; 
//             }

//             // ---------------------------------------------------------
//             // Step 2: Did B forward the packet to C? (Network Layer Check)
//             // ---------------------------------------------------------
//             if (pp.forwardedByNeighbor) {
//                 // Packet forwarded successfully. B is behaving correctly.
//                 toRemove.push_back(item.first);
//                 continue;
//             }

//             // --- AT THIS POINT: B received the packet but FAILED to forward it ---
            
//             // ---------------------------------------------------------
//             // Step 3: Algorithm B - Self Reliability Check
//             // ---------------------------------------------------------
//             // Before accusing B, we check if A (us) is in a noisy environment.
//             if (m_lastNoiseLevel > m_noiseThreshold) {
//                 NS_LOG_INFO("Ignoring suspicious event due to high local noise (" << m_lastNoiseLevel << ")");
//                 toRemove.push_back(item.first);
//                 continue;
//             }

//             // ---------------------------------------------------------
//             // Step 4: Algorithm 1 - MAC Layer Investigation
//             // ---------------------------------------------------------
//             // We verify if B tried to send RTS to C, and if C responded.
//             // We need to distinguish between Congestion (Innocent) and Blackhole (Malicious).
            
//             bool isMalicious = true; // Default assumption: Blackhole (Silent Drop)
//             bool foundObservation = false;

//             // Iterate through MAC observations. 
//             // Note: In a real implementation, we would map pp.nextHopIp (B) to a MAC address.
//             // Here we iterate to find observations related to the likely sender.
//             for (auto const& [senderMac, targets] : m_macObservations) {
                
//                 for (auto const& [receiverMac, obs] : targets) {
                     
//                      // We accumulate behavior evidence. 
                     
//                      // Case A: B sent RTS and C sent CTS (Clearance Granted)
//                      if (obs.rtsCount > 0 && obs.hasClearance) {
//                          // Conclusion: MALICIOUS.
//                          // B had permission to send (channel reserved), but didn't send Data.
//                          isMalicious = true;
//                          foundObservation = true;
//                          break; // Strong evidence found
//                      }
                     
//                      // Case B: B sent RTS, but C didn't send CTS (No Clearance / Hidden Terminal)
//                      else if (obs.rtsCount > 0 && !obs.hasClearance) {
//                          // Here we check for Anomalous Behavior vs. Legitimate Congestion.
//                          // Standard IEEE 802.11 Retry Limit is typically 7.
                         
//                          if (obs.rtsCount <= 7) {
//                              // Conclusion: INNOCENT.
//                              // B tried to send, but C was busy or A couldn't hear C's CTS.
//                              // This is likely a collision or hidden terminal scenario.
//                              isMalicious = false;
//                          } else {
//                              // Conclusion: MALICIOUS (Anomaly).
//                              // B sent an excessive amount of RTS frames (>7) without success.
//                              // A real node gives up after retry limit. This looks like 
//                              // "RTS Spamming" to fake an attempt while dropping the packet.
//                              isMalicious = true;
//                          }
//                          foundObservation = true;
//                      }
//                 }
//                 if (foundObservation) break;
//             }

//             // Note: If foundObservation is false, it means RTS count was 0.
//             // In that case, isMalicious remains 'true' (Silent Drop / Passive Blackhole).

//             if (isMalicious) {
//                 ReportMalicious(pp.nextHopIp);
//             }
            
//             toRemove.push_back(item.first);
//         }
//     }

//     // Cleanup processed packets
//     for (uint64_t uid : toRemove) {
//         m_pendingPackets.erase(uid);
//     }
    
//     // Clear observations to keep history fresh for the next cycle
//     m_macObservations.clear();
// }

// In olsr-defense-cooperative.cc



// void OlsrDefenseCooperative::EvaluatePendingPackets ()
// {
//     Time now = Simulator::Now();

//     // DEBUG: prove we're running
//     static thread_local uint32_t callCount = 0;
//     if (++callCount % 10 == 1) {  // every 10th call
//         std::cout << ">>> [DEBUG] EvaluatePendingPackets #" << callCount
//                   << " at t=" << now.GetSeconds() 
//                   << "s for node " << m_mainAddress
//                   << " pending=" << m_pendingPackets.size() << std::endl;
//     }

//     std::vector<uint64_t> toRemove;
//     ApplyDecay();

//     for (auto& item : m_pendingPackets) {
//         PendingPacket& pp = item.second;

//         if (now - pp.sendTime > m_watchdogTimeout) {
            
//             // Step 1: CTS Check
//             if (!pp.receivedByNeighbor) {
//                 toRemove.push_back(item.first);
//                 continue; 
//             }

//             // Step 2: Did the neighbor forward the packet?
//             if (pp.forwardedByNeighbor) {
//                 // REWARD: Reduce suspicion score significantly!
//                 if (m_suspicionScore.count(pp.nextHopIp) && m_suspicionScore[pp.nextHopIp] > 0) {
//                     m_suspicionScore[pp.nextHopIp] -= 5; 
//                     if (m_suspicionScore[pp.nextHopIp] < 0) m_suspicionScore[pp.nextHopIp] = 0;
//                 }
                
//                 toRemove.push_back(item.first);
//                 continue;
//             }

//             // Step 3: Self-Reliability Check
//             if (m_lastNoiseLevel > m_noiseThreshold) {
//                 NS_LOG_INFO("Ignoring suspicious event due to high local noise (" 
//                             << m_lastNoiseLevel << ")");
//                 toRemove.push_back(item.first);
//                 continue;
//             }

//             // Step 4: MAC Layer Investigation (targeted to the suspected neighbor only)
//             bool isMalicious = true; // Default: silent blackhole
//             bool foundObservation = false;
            
//             Mac48Address suspectMac = GetMacForIp(pp.nextHopIp);
            
//             if (suspectMac == Mac48Address())
//             {
//                 // We couldn't resolve the neighbor's MAC address.
//                 // Cannot make a reliable judgment → skip this packet without penalty.
//                 NS_LOG_WARN("Could not resolve MAC for " << pp.nextHopIp 
//                             << ". Skipping this evaluation round.");
//                 toRemove.push_back(item.first);
//                 continue;
//             }
            
//             // Look up observations ONLY for this specific neighbor (B)
//             auto obsIt = m_macObservations.find(suspectMac);
//             if (obsIt != m_macObservations.end())
//             {
//                 // B had some MAC-layer activity. Check what happened between B and its targets (C's).
//                 for (auto const& [receiverMac, obs] : obsIt->second)
//                 {
//                     // Case A: B sent RTS and received CTS (had clearance), but didn't forward data
//                     if (obs.rtsCount > 0 && obs.hasClearance) {
//                         isMalicious = true;
//                         foundObservation = true;
//                         NS_LOG_WARN("Node " << pp.nextHopIp 
//                                     << " had clearance but didn't send. Malicious!");
//                         break; 
//                     }
//                     // Case B: B sent RTS but no CTS received by us
//                     else if (obs.rtsCount > 0 && !obs.hasClearance) {
//                         if (obs.rtsCount <= 7) {
//                             // Normal 802.11 retry behavior → congestion/hidden terminal, NOT malicious
//                             isMalicious = false;
//                             foundObservation = true;
//                             NS_LOG_INFO("Node " << pp.nextHopIp << " attempted " 
//                                         << obs.rtsCount << " RTS without CTS. Legitimate congestion.");
//                         } else {
//                             // RTS spam: exceeded retry limit → suspicious
//                             isMalicious = true;
//                             foundObservation = true;
//                             NS_LOG_WARN("Node " << pp.nextHopIp << " sent " 
//                                         << obs.rtsCount << " RTS (>7). RTS Spam detected!");
//                         }
//                     }
//                 }
//             }

//             // Distinguish true silent drop from observed activity (for logging/debugging)
//             if (!foundObservation) {
//                 NS_LOG_WARN("Node " << pp.nextHopIp 
//                             << " had NO MAC-layer activity (no RTS sent). True silent drop!");
//             }
            
//             // --- Step 5: Congestion Awareness ---
//             // Before accusing B of silent-drop, verify that B is genuinely silent.
//             // If B has been actively forwarding OTHER packets, the most likely
//             // explanation is congestion or a missed observation on our end —
//             // NOT malicious behavior. Be charitable.
//             if (isMalicious && !foundObservation)
//             {
//                 uint32_t activity = 0;
//                 auto actIt = m_neighborActivity.find(suspectMac);
//                 if (actIt != m_neighborActivity.end())
//                 {
//                     activity = actIt->second;
//                 }
                
//                 if (activity >= ACTIVITY_THRESHOLD)
//                 {
//                     // Neighbor is alive and forwarding other traffic.
//                     // This is congestion, not a blackhole. Do not penalize.
//                     NS_LOG_INFO("Node " << pp.nextHopIp 
//                                 << " is busy (activity=" << activity 
//                                 << " forwards observed). Treating as congestion, NOT malicious.");
//                     isMalicious = false;
//                 }
//                 else
//                 {
//                     NS_LOG_WARN("Node " << pp.nextHopIp 
//                                 << " is truly silent (activity=" << activity 
//                                 << "). Confirmed silent blackhole!");
//                 }
//             }

//             // If isMalicious is still true, register suspicion against this neighbor
//             if (isMalicious) {
//                 RegisterSuspicion(pp.nextHopIp);
//             }
            
//             toRemove.push_back(item.first);
//         }
//     }

//     for (uint64_t uid : toRemove) {
//         m_pendingPackets.erase(uid);
//     }
    
//     // Selective cleanup: only remove observations older than 2×watchdogTimeout.
//     // This preserves relevant evidence for pending packets still in-flight,
//     // while preventing unbounded memory growth.
//     Time cutoff = now - (m_watchdogTimeout * 2);
//     for (auto senderIt = m_macObservations.begin(); senderIt != m_macObservations.end(); )
//     {
//         for (auto targetIt = senderIt->second.begin(); targetIt != senderIt->second.end(); )
//         {
//             if (targetIt->second.lastUpdated < cutoff)
//             {
//                 targetIt = senderIt->second.erase(targetIt);
//             }
//             else
//             {
//                 ++targetIt;
//             }
//         }
        
//         // If a sender has no remaining observations, remove its entry entirely
//         if (senderIt->second.empty())
//         {
//             senderIt = m_macObservations.erase(senderIt);
//         }
//         else
//         {
//             ++senderIt;
//         }
//     }
    
//     // Also clean up stale RTS targets (for OnCtsReceived attribution)
//     if (m_lastRtsTarget.size() > 100) {
//         m_lastRtsTarget.clear();
//     }
    
//     // Reset neighbor activity counters for the next evaluation window.
//     // Activity is meaningful only within a short time window — we want to know
//     // "is this neighbor alive RIGHT NOW", not "has it ever transmitted".
//     m_neighborActivity.clear();
    
//     // Reschedule the next internal evaluation.
//     m_watchdogTimer.Schedule(m_watchdogCheckInterval);
// }


void OlsrDefenseCooperative::EvaluatePendingPackets()
{
    Time now = Simulator::Now();
    std::vector<uint64_t> toRemove;
    ApplyDecay();

    // DEBUG: count pendings by next-hop type
    uint32_t pendingToAttacker = 0;
    uint32_t pendingToBackup = 0;
    uint32_t pendingToOther = 0;
    for (auto const& kv : m_pendingPackets) {
        if (kv.second.nextHopIp == Ipv4Address("10.1.1.21")) pendingToAttacker++;
        else if (kv.second.nextHopIp == Ipv4Address("10.1.1.22")) pendingToBackup++;
        else pendingToOther++;
    }
    static thread_local uint32_t evalCallCount = 0;
    if (++evalCallCount % 20 == 1 && (pendingToAttacker + pendingToBackup) > 0) {
        std::cout << ">>> [PENDING-SNAPSHOT] node=" << m_mainAddress
                  << " t=" << now.GetSeconds()
                  << " total=" << m_pendingPackets.size()
                  << " toAttacker=" << pendingToAttacker
                  << " toBackup=" << pendingToBackup
                  << " toOther=" << pendingToOther << std::endl;
    }

    // DEBUG: counters for this evaluation
    uint32_t step1Skip = 0;
    uint32_t step2Skip = 0;
    uint32_t step3Skip = 0;
    uint32_t step4MacNotFound = 0;
    uint32_t step4NoObs = 0;
    uint32_t step5Congestion = 0;
    uint32_t suspicionRegistered = 0;
    uint32_t expired = 0;

    for (auto& item : m_pendingPackets) {
        PendingPacket& pp = item.second;

        if (now - pp.sendTime > m_watchdogTimeout) {
            expired++;
            
            if (!pp.receivedByNeighbor) {
                step1Skip++;
                toRemove.push_back(item.first);
                continue; 
            }

            if (pp.forwardedByNeighbor) {
                step2Skip++;
                if (m_suspicionScore.count(pp.nextHopIp) && m_suspicionScore[pp.nextHopIp] > 0) {
                    m_suspicionScore[pp.nextHopIp] -= 5; 
                    if (m_suspicionScore[pp.nextHopIp] < 0) m_suspicionScore[pp.nextHopIp] = 0;
                }
                toRemove.push_back(item.first);
                continue;
            }

            if (m_lastNoiseLevel > m_noiseThreshold) {
                step3Skip++;
                toRemove.push_back(item.first);
                continue;
            }

            bool isMalicious = true;
            bool foundObservation = false;
            
            Mac48Address suspectMac = GetMacForIp(pp.nextHopIp);
            
            if (suspectMac == Mac48Address()) {
                step4MacNotFound++;
                toRemove.push_back(item.first);
                continue;
            }
            
            auto obsIt = m_macObservations.find(suspectMac);
            if (obsIt != m_macObservations.end()) {
                for (auto const& [receiverMac, obs] : obsIt->second) {
                    if (obs.rtsCount > 0 && obs.hasClearance) {
                        isMalicious = true;
                        foundObservation = true;
                        break; 
                    }
                    else if (obs.rtsCount > 0 && !obs.hasClearance) {
                        if (obs.rtsCount <= 100) {
                            isMalicious = false;
                            foundObservation = true;
                        } else {
                            isMalicious = true;
                            foundObservation = true;
                        }
                    }
                }
            }

            if (!foundObservation) {
                step4NoObs++;
            }
            
            if (isMalicious && !foundObservation) {
                uint32_t activity = 0;
                auto actIt = m_neighborActivity.find(suspectMac);
                if (actIt != m_neighborActivity.end()) {
                    activity = actIt->second;
                }
                
                if (activity >= ACTIVITY_THRESHOLD) {
                    step5Congestion++;
                    isMalicious = false;
                }
            }
            
            if (isMalicious) {
                suspicionRegistered++;
                RegisterSuspicion(pp.nextHopIp);
            }
            
            toRemove.push_back(item.first);
        }
    }

    // DEBUG: report what happened this cycle (only if something interesting)
    if (expired > 0) {
        static thread_local uint32_t evalCount = 0;
        evalCount++;
        if (evalCount % 10 == 1 || suspicionRegistered > 0) {
            std::cout << ">>> [EVAL] node=" << m_mainAddress
                      << " t=" << now.GetSeconds()
                      << " expired=" << expired
                      << " step1(noCts)=" << step1Skip
                      << " step2(forwarded)=" << step2Skip
                      << " step3(noise)=" << step3Skip
                      << " step4(noMac)=" << step4MacNotFound
                      << " step4(noObs)=" << step4NoObs
                      << " step5(congest)=" << step5Congestion
                      << " SUSPECT=" << suspicionRegistered
                      << std::endl;
        }
    }

    for (uint64_t uid : toRemove) {
        m_pendingPackets.erase(uid);
    }
    
    Time cutoff = now - (m_watchdogTimeout * 2);
    for (auto senderIt = m_macObservations.begin(); senderIt != m_macObservations.end(); ) {
        for (auto targetIt = senderIt->second.begin(); targetIt != senderIt->second.end(); ) {
            if (targetIt->second.lastUpdated < cutoff) {
                targetIt = senderIt->second.erase(targetIt);
            } else {
                ++targetIt;
            }
        }
        if (senderIt->second.empty()) {
            senderIt = m_macObservations.erase(senderIt);
        } else {
            ++senderIt;
        }
    }
    
    if (m_lastRtsTarget.size() > 100) {
        m_lastRtsTarget.clear();
    }
    
    m_neighborActivity.clear();
    
    m_watchdogTimer.Schedule(m_watchdogCheckInterval);
}


void OlsrDefenseCooperative::PeriodicCheck()
{
    // Intentionally empty for this strategy.
    //
    // The watchdog evaluation is driven by m_watchdogTimer (private to this strategy,
    // runs at m_watchdogCheckInterval), NOT by the main defense timer. This keeps
    // the 1-second cadence of HandleDefenseTimer — which is shared with other
    // strategies (GCoP etc.) and used for Cross-Layer reports (queue/energy/noise) —
    // decoupled from our faster watchdog cycle.
    //
    // If you want to add slow periodic work (e.g. statistics flushing, trust decay
    // accumulation), put it here and it will run once per second along with the
    // other strategies.
}


void OlsrDefenseCooperative::ReportMalicious(Ipv4Address suspect)
{
    if (m_blacklist.find(suspect) == m_blacklist.end()) {
        std::cout << ">>> [DEFENSE ALERT] Time: " << Simulator::Now().GetSeconds() 
                  << "s | My Node: " << m_mainAddress 
                  << " | DETECTED MALICIOUS NODE: " << suspect 
                  << " -> Adding to Blacklist!" << std::endl;
        
        m_blacklist.insert(suspect);
        
        // Trigger full OLSR eviction: remove from neighbor/link/topology sets
        // and recompute routing table so subsequent traffic bypasses this node.
        if (m_protocol)
        {
            m_protocol->EvictNeighbor(suspect);
        }
    }
}

Mac48Address
OlsrDefenseCooperative::GetMyMac()
{
    // Return cached value if already resolved
    if (m_myMac != Mac48Address()) {
        return m_myMac;
    }
    
    if (!m_protocol) return Mac48Address();
    
    Ptr<Node> node = m_protocol->GetObject<Node>();
    if (!node) return Mac48Address();
    
    // Find the first WifiNetDevice and get its MAC address
    for (uint32_t i = 0; i < node->GetNDevices(); ++i)
    {
        Ptr<NetDevice> dev = node->GetDevice(i);
        if (!dev) continue;
        
        Ptr<WifiNetDevice> wifiDev = DynamicCast<WifiNetDevice>(dev);
        if (!wifiDev) continue;
        
        Address addr = wifiDev->GetAddress();
        if (Mac48Address::IsMatchingType(addr))
        {
            m_myMac = Mac48Address::ConvertFrom(addr);
            return m_myMac;
        }
    }
    
    return Mac48Address();
}

Mac48Address
OlsrDefenseCooperative::GetMacForIp(Ipv4Address ip)
{
    if (!m_protocol) return Mac48Address();
    
    Ptr<Node> node = m_protocol->GetObject<Node>();
    if (!node) return Mac48Address();
    
    Ptr<Ipv4L3Protocol> ipv4 = node->GetObject<Ipv4L3Protocol>();
    if (!ipv4) return Mac48Address();
    
    // Iterate over all interfaces and their ARP caches
    for (uint32_t i = 0; i < ipv4->GetNInterfaces(); ++i)
    {
        Ptr<Ipv4Interface> iface = ipv4->GetInterface(i);
        if (!iface) continue;
        
        Ptr<ArpCache> arpCache = iface->GetArpCache();
        if (!arpCache) continue;
        
        ArpCache::Entry* entry = arpCache->Lookup(ip);
        if (entry && (entry->IsAlive() || entry->IsPermanent()))
        {
            Address addr = entry->GetMacAddress();
            if (Mac48Address::IsMatchingType(addr))
            {
                return Mac48Address::ConvertFrom(addr);
            }
        }
    }

    // DEBUG: log failed lookups for the attacker specifically
    if (ip == Ipv4Address("10.1.1.21")) {
        static thread_local uint32_t failCount = 0;
        if (++failCount % 100 == 1) {
            std::cout << ">>> [MAC-LOOKUP-FAIL] node=" << m_mainAddress
                      << " failed to resolve 10.1.1.21 (count=" << failCount << ")" << std::endl;
        }
    }
    
    return Mac48Address(); // Not found - invalid/empty MAC
}

void OlsrDefenseCooperative::RegisterSuspicion(Ipv4Address suspect)
{
    // If the node is already blacklisted, no further action is needed.
    if (m_blacklist.find(suspect) != m_blacklist.end()) {
        return;
    }

    // Increase the suspicion score
    // שינוי: שימוש ב-Define או בקבוע המעודכן (5 נקודות)
    m_suspicionScore[suspect] += SCORE_PER_BAD_EVENT; 

    // --- DEBUG PRINT: חובה לראות את זה בקונסול ---
    std::cout << ">>> [SUSPICION] Node " << m_mainAddress 
              << " suspects " << suspect 
              << ". Score: " << m_suspicionScore[suspect] 
              << "/" << SUSPICION_THRESHOLD << std::endl;
    // ---------------------------------------------

    // Check if the score has crossed the threshold
    if (m_suspicionScore[suspect] >= SUSPICION_THRESHOLD) {
        std::cout << ">>> [BAN] Node " << suspect << " exceeded threshold! BLOCKING." << std::endl;
        ReportMalicious(suspect); 
    }
}

void OlsrDefenseCooperative::ApplyDecay()
{
    // Iterate over all suspected nodes and reduce their score (Forgiveness Mechanism)
    for (auto it = m_suspicionScore.begin(); it != m_suspicionScore.end(); ) {
        if (it->second > 0) {
            it->second -= DECAY_AMOUNT;
        }
        
        // Optimization: Remove nodes with 0 score to keep the map clean
        if (it->second <= 0) {
            it = m_suspicionScore.erase(it);
        } else {
            ++it;
        }
    }
}

void OlsrDefenseCooperative::OnMacTxFailure(Ipv4Address neighbor, uint32_t count)
{
    static thread_local uint32_t attackerClears = 0;
    static thread_local uint32_t backupClears = 0;
    
    uint32_t erased = 0;
    for (auto it = m_pendingPackets.begin(); it != m_pendingPackets.end(); ) {
        if (it->second.nextHopIp == neighbor) {
            it = m_pendingPackets.erase(it);
            erased++;
        } else {
            ++it;
        }
    }
    
    if (erased > 0) {
        if (neighbor == Ipv4Address("10.1.1.21")) {
            attackerClears++;
            if (attackerClears % 10 == 1) {
                std::cout << ">>> [MAC-FAIL-ATTACKER] node=" << m_mainAddress
                          << " t=" << Simulator::Now().GetSeconds()
                          << " erased=" << erased 
                          << " totalClears=" << attackerClears << std::endl;
            }
        } else if (neighbor == Ipv4Address("10.1.1.22")) {
            backupClears++;
        }
    }
}

// --- Empty implementations for unused hooks ---
void OlsrDefenseCooperative::OnRecvHello(Ipv4Address, Ptr<const Packet>, const MessageHeader&, const MessageHeader::Hello&) {}
void OlsrDefenseCooperative::OnRecvTc(Ipv4Address, Ptr<const Packet>, const MessageHeader&, const MessageHeader::Tc&) {}
void OlsrDefenseCooperative::OnTcGenerated(const MessageHeader::Tc&) {}
void OlsrDefenseCooperative::OnDataPacketReceived(Ptr<const Packet>, Ipv4Address, Ipv4Address, Ipv4Address) {}
void OlsrDefenseCooperative::OnDataPacketDropped(Ptr<const Packet>, Ipv4Address, Ipv4Address, DropReason) {}
void OlsrDefenseCooperative::OnQueueStatusReport(uint32_t, uint32_t) {}
void OlsrDefenseCooperative::OnEnergyStateUpdate(double, double) {}
bool OlsrDefenseCooperative::RequiresFictitiousNode() {
    // Fictitious nodes are not required for the cooperative defense strategy
    return false;
}

} 
}