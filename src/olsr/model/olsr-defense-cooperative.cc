/*
 * Copyright (c) 2025 Security Research
 * Implementation of "Cooperative Cross Layer Detection"
 */

#include "olsr-defense-cooperative.h"
#include "olsr-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/wifi-mac-header.h"

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
    m_watchdogTimeout(Seconds(0.5)), // Adjust based on RTT/Network size
    m_noiseThreshold(5),             // Threshold for Algorithm B (Self-Reliability)
    m_lastNoiseLevel(0)
{
}

OlsrDefenseCooperative::~OlsrDefenseCooperative() {}

void OlsrDefenseCooperative::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
{
    m_protocol = proto;
    m_mainAddress = nodeAddress;
}

void OlsrDefenseCooperative::DoDispose()
{
    m_protocol = nullptr;
    m_pendingPackets.clear();
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
    // A sends packet to B. We register it for monitoring.
    PendingPacket pp;
    pp.uid = packet->GetUid();
    pp.nextHopIp = nextHop;
    pp.sendTime = Simulator::Now();
    pp.receivedByNeighbor = false; // We wait for CTS from B
    pp.forwardedByNeighbor = false;

    m_pendingPackets[packet->GetUid()] = pp;
}

// --- Cross-Layer Hooks (The "Ears") ---

void OlsrDefenseCooperative::OnCtsReceived(Mac48Address receiver)
{
    // NOTE: In CTS frames, the "Receiver" address (Addr1) is the node that sent the RTS.
    // So 'receiver' here is the node getting permission to send.

    // Logic 1: Did B send CTS to Me? (Confirming B received my RTS)
    // Since we don't have easy access to MyMac here, we assume that if we capture a CTS 
    // addressed to 'Me' (implicitly), it means the pending packet exchange started successfully.
    // Simplified Logic: Update all pending packets waiting for CTS.
    for (auto& ppEntry : m_pendingPackets) {
        if (!ppEntry.second.receivedByNeighbor) {
            ppEntry.second.receivedByNeighbor = true; 
        }
    }

    // Logic 2: Did C send CTS to B? (Confirming B has clearance to forward)
    // We update the MAC observations. 'receiver' here is B (the one who wants to send).
    for (auto& targetEntry : m_macObservations[receiver]) {
        targetEntry.second.hasClearance = true;
    }
}

void OlsrDefenseCooperative::OnRtsReceived(Mac48Address sender, Mac48Address receiver)
{
    // B (sender) sends RTS to C (receiver).
    // This counts as an attempt to forward.
    m_macObservations[sender][receiver].rtsCount++;
}

void OlsrDefenseCooperative::OnNeighborForwardedPacket(Mac48Address transmitter, 
                                                       Mac48Address receiver, Ptr<const Packet> packet)
{
    // B (transmitter) actually sent Data to C (receiver).
    // This is the ultimate proof of innocence.
    uint64_t uid = packet->GetUid();
    
    if (m_pendingPackets.find(uid) != m_pendingPackets.end()) {
        m_pendingPackets[uid].forwardedByNeighbor = true;
    }
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

void OlsrDefenseCooperative::PeriodicCheck()
{
    Time now = Simulator::Now();
    std::vector<uint64_t> toRemove;
    ApplyDecay();

    for (auto& item : m_pendingPackets) {
        PendingPacket& pp = item.second;

        if (now - pp.sendTime > m_watchdogTimeout) {
            
            // Step 1: CTS Check
            if (!pp.receivedByNeighbor) {
                toRemove.push_back(item.first);
                continue; 
            }

            // Step 2: Did the neighbor forward the packet?
            if (pp.forwardedByNeighbor) {
                // REWARD: Reduce suspicion score significantly!
                if (m_suspicionScore.count(pp.nextHopIp) && m_suspicionScore[pp.nextHopIp] > 0) {
                    // בונוס כפול: הורד 5 נקודות על כל הצלחה
                    m_suspicionScore[pp.nextHopIp] -= 5; 
                    if (m_suspicionScore[pp.nextHopIp] < 0) m_suspicionScore[pp.nextHopIp] = 0;
                }
                
                toRemove.push_back(item.first);
                continue;
            }

            // Step 3: Self-Reliability Check
            if (m_lastNoiseLevel > m_noiseThreshold) {
                NS_LOG_INFO("Ignoring suspicious event due to high local noise (" 
                            << m_lastNoiseLevel << ")");
                toRemove.push_back(item.first);
                continue;
            }

            // Step 4: MAC Layer Investigation
            bool isMalicious = true; 
            bool foundObservation = false;

            for (auto const& [senderMac, targets] : m_macObservations) {
                for (auto const& [receiverMac, obs] : targets) {
                     
                     // Case A: Clearance Granted but No Data
                     if (obs.rtsCount > 0 && obs.hasClearance) {
                         isMalicious = true;
                         foundObservation = true;
                         NS_LOG_WARN("Node had clearance but didn't send. Malicious!");
                         break; 
                     }
                     
                     // Case B: No Clearance
                     else if (obs.rtsCount > 0 && !obs.hasClearance) {
                         
                         // ✅ תיקון 1: הסרת Lazy Attacker Detection
                         if (obs.rtsCount <= 7) {
                             isMalicious = false;
                             NS_LOG_INFO("Node attempted " << obs.rtsCount 
                                         << " RTS. Legitimate congestion.");
                         } else {
                             isMalicious = true;
                             NS_LOG_WARN("Node sent " << obs.rtsCount 
                                         << " RTS (>7). RTS Spam detected!");
                         }
                         foundObservation = true;
                     }
                }
                if (foundObservation) break;
            }

            // If no observation (Silent Drop) → Malicious
            if (isMalicious) {
                RegisterSuspicion(pp.nextHopIp);
            }
            
            toRemove.push_back(item.first);
        }
    }

    for (uint64_t uid : toRemove) {
        m_pendingPackets.erase(uid);
    }
    
    m_macObservations.clear();
}

void OlsrDefenseCooperative::ReportMalicious(Ipv4Address suspect)
{
    if (m_blacklist.find(suspect) == m_blacklist.end()) {
        // --- ADDED LOGGING HERE ---
        std::cout << ">>> [DEFENSE ALERT] Time: " << Simulator::Now().GetSeconds() 
                  << "s | My Node: " << m_mainAddress 
                  << " | DETECTED MALICIOUS NODE: " << suspect 
                  << " -> Adding to Blacklist!" << std::endl;
        // --------------------------
        
        m_blacklist.insert(suspect);
    }
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

// --- Empty implementations for unused hooks ---
void OlsrDefenseCooperative::OnRecvHello(Ipv4Address, Ptr<const Packet>, const MessageHeader&, const MessageHeader::Hello&) {}
void OlsrDefenseCooperative::OnRecvTc(Ipv4Address, Ptr<const Packet>, const MessageHeader&, const MessageHeader::Tc&) {}
void OlsrDefenseCooperative::OnTcGenerated(const MessageHeader::Tc&) {}
void OlsrDefenseCooperative::OnDataPacketReceived(Ptr<const Packet>, Ipv4Address, Ipv4Address, Ipv4Address) {}
void OlsrDefenseCooperative::OnDataPacketDropped(Ptr<const Packet>, Ipv4Address, Ipv4Address, DropReason) {}
void OlsrDefenseCooperative::OnQueueStatusReport(uint32_t, uint32_t) {}
void OlsrDefenseCooperative::OnEnergyStateUpdate(double, double) {}
void OlsrDefenseCooperative::OnMacTxFailure(Ipv4Address, uint32_t) {}
bool OlsrDefenseCooperative::RequiresFictitiousNode() {
    // Fictitious nodes are not required for the cooperative defense strategy
    return false;
}

} 
}