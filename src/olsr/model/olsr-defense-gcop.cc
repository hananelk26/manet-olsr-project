#include "olsr-defense-gcop.h"
#include "olsr-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include <algorithm>
#include <vector>
#include <list>

namespace ns3 {
namespace olsr {

NS_LOG_COMPONENT_DEFINE("OlsrDefenseGcop");
NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseGcop);

TypeId OlsrDefenseGcop::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::olsr::OlsrDefenseGcop")
        .SetParent<OlsrDefenseStrategy>()
        .SetGroupName("Olsr")
        .AddConstructor<OlsrDefenseGcop>();
    return tid;
}

OlsrDefenseGcop::OlsrDefenseGcop() : m_routingProtocol(nullptr) {
}

OlsrDefenseGcop::~OlsrDefenseGcop() {
}

void OlsrDefenseGcop::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) {
    m_routingProtocol = proto;
    m_mainAddress = nodeAddress;
    m_startTime = Simulator::Now().GetSeconds();
}

void OlsrDefenseGcop::DoDispose() {
    m_suspiciousNodes.clear();
    m_violationCounter.clear();
    m_routingProtocol = nullptr;
}

bool OlsrDefenseGcop::IsMalicious(Ipv4Address addr) {
    // Check if the node is in the suspicious map and the timer hasn't expired
    auto it = m_suspiciousNodes.find(addr);
    if (it != m_suspiciousNodes.end()) {
        if (Simulator::Now() <= it->second) {
            return true; // Node is currently considered malicious
        }
    }
    return false;
}

std::set<Ipv4Address> OlsrDefenseGcop::GetBlacklist() const {
    std::set<Ipv4Address> blacklist;
    Time now = Simulator::Now();
    for (auto const& pair : m_suspiciousNodes) {
        if (now <= pair.second) {
            blacklist.insert(pair.first);
        }
    }
    return blacklist;
}

void OlsrDefenseGcop::PeriodicCheck() {
    // Garbage Collection: Remove nodes from the suspicious list if their penalty time expired
    // (e.g., if a malicious node stops transmitting entirely).
    Time now = Simulator::Now();
    for (auto it = m_suspiciousNodes.begin(); it != m_suspiciousNodes.end(); ) {
        if (now > it->second) {
            NS_LOG_INFO("Node " << it->first << " is no longer suspicious (time expired).");
            it = m_suspiciousNodes.erase(it);
        } else {
            ++it;
        }
    }
}

bool OlsrDefenseGcop::RequiresFictitiousNode() {
    // If GCOP finds that a fictitious node is needed, return true.
    // Otherwise, check if GCOHP (Hexagon pattern) requires it as a fallback.
    if (!RunGcopAlgorithm()) {
        return RunGcohpAlgorithm();
    }
    return true;
}

void OlsrDefenseGcop::OnRecvHello(Ipv4Address senderAddress,
                                  Ptr<const Packet> packet, 
                                  const MessageHeader& msg, 
                                  const MessageHeader::Hello& hello) {
    // Apply C-Rules upon receiving a HELLO message
    EvaluateContradictionRules(senderAddress); 
}

void OlsrDefenseGcop::OnDataPacketReceived(Ptr<const Packet> packet, Ipv4Address source, Ipv4Address destination, Ipv4Address nextHop) {
    // Log if we're about to forward to a node we currently consider malicious.
    // (The actual drop happens in RouteInput via the IMP enforcement check.)
    if (IsMalicious(nextHop)) {
        NS_LOG_INFO("About to forward packet via suspicious next-hop " << nextHop);
    }
}

void OlsrDefenseGcop::OnDataPacketForwarded(Ptr<const Packet> packet, Ipv4Address nextHop, Ipv4Address finalDest) {
    // This hook allows us to log if IMP is actively bypassing or catching a routing attempt
    if (IsMalicious(nextHop)) {
        NS_LOG_WARN("IMP Mechanism triggered! Intercepted attempt to forward packet to malicious Next-Hop " << nextHop);
    }
}

// void OlsrDefenseGcop::EvaluateContradictionRules(Ipv4Address senderAddress) {
//     if (!m_routingProtocol) return;

//     const auto& neighbors = m_routingProtocol->GetNeighbors();
//     const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
//     const auto& topology = m_routingProtocol->GetTopologySet();

//     bool isRisky = false;
        
//     // Calculate our fictitious node address (MainIP + 65536, exactly as in SendHello)
//     Ipv4Address fakeAddress(m_mainAddress.Get() + 65536);

//     // --- C-Rule 1: Topology Contradiction ---
//     for (const auto& twoHop : twoHopNeighbors) {
//         if (twoHop.neighborMainAddr != senderAddress) continue;
        
//         Ipv4Address claimedNeighbor = twoHop.twoHopNeighborAddr;
        
//         bool isMyNeighbor = false;
//         for (const auto& nei : neighbors) {
//             if (nei.neighborMainAddr == claimedNeighbor) {
//                 isMyNeighbor = true;
//                 break;
//             }
//         }

//         if (isMyNeighbor) {
//             // If the claimed neighbor is an actual 1-hop neighbor of ours, verify the symmetric link
//             bool linkVerified = false;
//             for (const auto& verifyTwoHop : twoHopNeighbors) {
//                 if (verifyTwoHop.neighborMainAddr == claimedNeighbor && 
//                     verifyTwoHop.twoHopNeighborAddr == senderAddress) {
//                     linkVerified = true;
//                     break;
//                 }
//             }
            
//             if (!linkVerified) {
//                 NS_LOG_INFO("Rule 1 Violation: Node " << senderAddress << " falsely claims link to real neighbor " << claimedNeighbor);
//                 isRisky = true;
//                 break;
//             }
//         } else {
//             // The bait (fictitious node) check!
//             // If the sender claims to know a node that isn't our neighbor, 
//             // check if it's the fictitious node we injected.
//             if (claimedNeighbor == fakeAddress) {
//                 NS_LOG_INFO("Rule 1 Violation (Bait caught!): Node " << senderAddress << " falsely claims link to our fictitious node " << fakeAddress);
//                 isRisky = true;
//                 break;
//             }
//         }
//     }

//     // --- C-Rule 2: MPR Missing Selection ---
//     if (!isRisky) {
//         std::list<Ipv4Address> groupN; // Sender's neighbors
//         std::list<Ipv4Address> groupZ; // Sender's 2-hop neighbors
//         std::list<Ipv4Address> groupM; // Sender's chosen MPRs
        
//         // Populate N (Sender's 1-hop neighbors from two-hop set)
//         for (const auto& twoHop : twoHopNeighbors) {
//             if (twoHop.neighborMainAddr == senderAddress) {
//                 groupN.push_back(twoHop.twoHopNeighborAddr);
//             }
//         }
//         groupN.sort();
//         groupN.unique();

//         // Populate Z (reachable from N) and M (MPRs chosen by sender) from Topology Set
//         for (const auto& top : topology) {
//             if (std::find(groupN.begin(), groupN.end(), top.lastAddr) != groupN.end()) {
//                 groupZ.push_back(top.destAddr);
//             }
//             if (std::find(groupN.begin(), groupN.end(), top.destAddr) != groupN.end()) {
//                 groupZ.push_back(top.lastAddr);
//             }
            
//             // If the destination is the sender, the lastAddr is the MPR it chose
//             if (top.destAddr == senderAddress) {
//                 groupM.push_back(top.lastAddr);
//             }
//         }
//         groupZ.sort();
//         groupZ.unique();
//         groupM.sort();
//         groupM.unique();

//         // Remove N from Z (Z should only contain strict 2-hop neighbors of the sender)
//         for (const auto& n : groupN) {
//             groupZ.remove(n);
//         }
//         // Remove our own 1-hop neighbors from Z
//         for (const auto& nei : neighbors) {
//             groupZ.remove(nei.neighborMainAddr);
//         }

//         // Verify that every node in Z is covered by at least one MPR in M
//         for (auto zIt = groupZ.begin(); zIt != groupZ.end(); ) {
//             bool isCovered = false;
//             for (const auto& m : groupM) {
//                 // Check if MPR 'm' connects to 'z' in the topology
//                 for (const auto& top : topology) {
//                     if ((top.lastAddr == m && top.destAddr == *zIt) || 
//                         (top.lastAddr == *zIt && top.destAddr == m)) {
//                         isCovered = true;
//                         break;
//                     }
//                 }
//                 if (isCovered) break;
//             }
            
//             if (isCovered) {
//                 zIt = groupZ.erase(zIt); // Covered successfully, remove from Z
//             } else {
//                 ++zIt;
//             }
//         }

//         // If Z is not empty, the sender has 2-hop neighbors it didn't provide an MPR for!
//         if (!groupZ.empty()) {
//             NS_LOG_INFO("Rule 2 Violation: Node " << senderAddress << " failed to select MPRs to cover all its 2-hop neighbors.");
//             isRisky = true;
//         }
//     }

//     // --- C-Rule 3: Over-coverage (Unreachable sets) ---
//     if (!isRisky) {
//         std::list<Ipv4Address> senderReachable;
        
//         // Build the list of nodes the sender claims to reach
//         for (const auto& twoHop : twoHopNeighbors) {
//             if (twoHop.neighborMainAddr == senderAddress && twoHop.twoHopNeighborAddr != m_mainAddress) {
//                 senderReachable.push_back(twoHop.twoHopNeighborAddr);
//             }
//         }
        
//         // Build the list of all valid remote network targets
//         std::list<Ipv4Address> networkTargets;
//         for (const auto& top : topology) {
//             if (top.lastAddr != m_mainAddress) {
//                 networkTargets.push_back(top.destAddr);
//             }
//         }
//         networkTargets.sort();
//         networkTargets.unique();

//         // Remove our direct 1-hop neighbors from the targets
//         for (const auto& nei : neighbors) {
//             networkTargets.remove(nei.neighborMainAddr);
//             senderReachable.remove(nei.neighborMainAddr);
//         }

//         // If the sender claims it can reach everything on its own, flag it!
//         // (Added a safety check 'size > 2' to avoid false positives in tiny networks)
//         if (senderReachable.size() >= networkTargets.size() && !networkTargets.empty() && networkTargets.size() > 2) {
//             NS_LOG_INFO("Rule 3 Violation: Node " << senderAddress << " claims impossibly high coverage.");
//             isRisky = true;
//         }
//     }

//     /* Apply or remove penalty based on the current evaluation */
//     if (isRisky) {
//         /*
//          * Set a short penalty duration just enough to cover the time until 
//          * the next expected HELLO message (e.g., 3.0 seconds). 
//          */
//         Time penaltyDuration = Seconds(3.0);
//         m_suspiciousNodes[senderAddress] = Simulator::Now() + penaltyDuration;
//         NS_LOG_WARN("Node " << senderAddress << " penalized and added to suspicious list!");
//     } else {
//         /*
//          * If the node is no longer risky in this evaluation, remove it from the blacklist.
//          * This mirrors the original algorithm's stateless behavior.
//          */
//         auto it = m_suspiciousNodes.find(senderAddress);
//         if (it != m_suspiciousNodes.end()) {
//             m_suspiciousNodes.erase(it);
//             NS_LOG_INFO("Node " << senderAddress << " passed the checks and is removed from the suspicious list.");
//         }
//     }
// }



void OlsrDefenseGcop::EvaluateContradictionRules(Ipv4Address senderAddress) {
    if (!m_routingProtocol) return;

    // Wait for network convergence before starting to evaluate.
    // OLSR HELLO interval = 2s, TC interval = 5s. 45s gives enough time for
    // routing tables and topology sets to stabilize across the network.
    if (Simulator::Now().GetSeconds() < 45.0)
        return;

    // If sender is already flagged, no need to re-evaluate (preserves the
    // existing penalty window).
    if (IsMalicious(senderAddress))
        return;

    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology        = m_routingProtocol->GetTopologySet();

    bool isRisky = false;
    std::string violationReason;

    // Our injected fictitious node address (matches SendHello in routing-protocol)
    Ipv4Address fakeAddress(m_mainAddress.Get() + 65536);

    // ------------------------------------------------------------------------
    // C-Rule 1: Topology Contradiction + Bait Detection
    // Based solely on HELLO messages - SAFE against ANSN poisoning.
    // ------------------------------------------------------------------------
    for (const auto& twoHop : twoHopNeighbors) {
        if (twoHop.neighborMainAddr != senderAddress) continue;

        const Ipv4Address& claimedNeighbor = twoHop.twoHopNeighborAddr;

        // (a) BAIT CHECK: sender claims to know our fictitious node → attacker
        if (claimedNeighbor == fakeAddress) {
            violationReason = "Rule 1a (Bait): claims link to fictitious node";
            isRisky = true;
            break;
        }

        // (b) SPOOFED IP RANGE CHECK: sender claims to know a node in the
        //     200.0.0.0/8 range (attacker's fake link-spoof range).
        //     Legitimate OLSR networks don't use this range for internal nodes.
        uint32_t claimedIp = claimedNeighbor.Get();
        if ((claimedIp & 0xFF000000) == 0xC8000000) {  // 200.x.x.x
            violationReason = "Rule 1b (Spoofed range): claims link to 200.x.x.x";
            isRisky = true;
            break;
        }

        // (c) SYMMETRY CHECK for real neighbors:
        //     If sender claims a link to a node that IS our direct neighbor,
        //     that node must also advertise sender back (symmetric link).
        bool isMyDirectNeighbor = false;
        for (const auto& nei : neighbors) {
            if (nei.neighborMainAddr == claimedNeighbor &&
                nei.status == NeighborTuple::STATUS_SYM) {
                isMyDirectNeighbor = true;
                break;
            }
        }
        if (isMyDirectNeighbor) {
            bool linkVerified = false;
            for (const auto& verifyTwoHop : twoHopNeighbors) {
                if (verifyTwoHop.neighborMainAddr == claimedNeighbor &&
                    verifyTwoHop.twoHopNeighborAddr == senderAddress) {
                    linkVerified = true;
                    break;
                }
            }
            if (!linkVerified) {
                violationReason = "Rule 1c (Asymmetry): claims link to our "
                                  "neighbor who does not confirm";
                isRisky = true;
                break;
            }
        }
    }

    // ------------------------------------------------------------------------
    // C-Rule 3: Over-Coverage Detection (formerly "claims impossibly high
    //                                     coverage")
    // Based on twoHopNeighbors (HELLO-derived) - SAFE against ANSN poisoning.
    // The topology set IS used here, but only as a LOWER bound on network size.
    // ANSN poisoning may inflate/deflate our view, but Rule 3 only fires when
    // the sender claims MORE neighbors than the entire known network.
    // ------------------------------------------------------------------------
    if (!isRisky) {
        // Count how many DISTINCT nodes the sender claims as its neighbors
        std::set<Ipv4Address> senderClaims;
        for (const auto& twoHop : twoHopNeighbors) {
            if (twoHop.neighborMainAddr == senderAddress &&
                twoHop.twoHopNeighborAddr != m_mainAddress) {
                senderClaims.insert(twoHop.twoHopNeighborAddr);
            }
        }
        // Remove our own direct neighbors from the count (legitimate overlap)
        for (const auto& nei : neighbors) {
            senderClaims.erase(nei.neighborMainAddr);
        }

        // Count total distinct nodes known in the network (from topology set)
        std::set<Ipv4Address> networkNodes;
        for (const auto& top : topology) {
            networkNodes.insert(top.lastAddr);
            networkNodes.insert(top.destAddr);
        }
        for (const auto& nei : neighbors) {
            networkNodes.insert(nei.neighborMainAddr);
        }
        networkNodes.erase(m_mainAddress);

        // Heuristic: if sender claims to know more than ~70% of all known nodes
        // AND claims more than 3 nodes that aren't our direct neighbors,
        // that's suspicious (legitimate nodes rarely dominate like this).
        if (networkNodes.size() > 5 &&
            senderClaims.size() >= 4 &&
            senderClaims.size() * 10 >= networkNodes.size() * 7) {
            violationReason = "Rule 3 (Over-coverage): claims " +
                std::to_string(senderClaims.size()) + " neighbors out of " +
                std::to_string(networkNodes.size()) + " known nodes";
            isRisky = true;
        }
    }

    // ------------------------------------------------------------------------
    // Apply or remove penalty based on evaluation result
    //
    // CONFIRMATION POLICY: A node is added to the blacklist only after 2
    // CONSECUTIVE violations. This filters out one-shot false positives
    // (e.g., a transient MAC-layer asymmetric view due to HELLO packet
    // loss) while still catching real attackers within ~4 seconds.
    //
    // Real attacker behavior:
    //   t=0:   sends malicious HELLO -> violation #1, counter=1, NOT blacklisted
    //   t=2:   sends malicious HELLO -> violation #2, counter=2, BLACKLISTED
    //   t=2-7: blacklist holds (penalty=5s, refreshed by next HELLO)
    //
    // False-positive behavior:
    //   t=0:   transient asymmetry -> violation #1, counter=1, NOT blacklisted
    //   t=2:   normal HELLO -> isRisky=false, counter RESET to 0
    //   No blacklist applied. Legitimate route preserved.
    // ------------------------------------------------------------------------
    if (isRisky) {
        m_violationCounter[senderAddress]++;

        if (m_violationCounter[senderAddress] >= 2) {
            // Confirmed: 2 consecutive violations -> apply penalty.
            // Penalty 5s: long enough to keep a true attacker flagged across
            // HELLO cycles, and gets refreshed every 2s by each new violation.
            m_suspiciousNodes[senderAddress] = Simulator::Now() + Seconds(5.0);
            NS_LOG_WARN("Node " << m_mainAddress << " flagged " << senderAddress
                        << " as MALICIOUS (violation #"
                        << m_violationCounter[senderAddress]
                        << "). Reason: " << violationReason);
        } else {
            // First-time observation: do not blacklist yet, wait for confirmation.
            NS_LOG_INFO("Node " << m_mainAddress << " observed first violation by "
                        << senderAddress << ". Reason: " << violationReason
                        << " (waiting for second violation before blacklisting)");
        }
    } else {
        // Passed all checks: clear blacklist entry AND reset counter.
        // Resetting the counter is the key to filtering false positives:
        // a legitimate node that had one bad HELLO will NOT be blacklisted
        // because its counter resets on the next clean HELLO.
        auto it = m_suspiciousNodes.find(senderAddress);
        if (it != m_suspiciousNodes.end()) {
            m_suspiciousNodes.erase(it);
            NS_LOG_INFO("Node " << senderAddress
                        << " cleared from suspicious list (passed checks).");
        }
        if (m_violationCounter.count(senderAddress)) {
            m_violationCounter[senderAddress] = 0;
        }
    }
}

bool OlsrDefenseGcop::HasKnownMaliciousNeighbor()
{
    const auto& neighbors = m_routingProtocol->GetNeighbors();
    for (const auto& nei : neighbors)
        if (IsMalicious(nei.neighborMainAddr))
            return true;
    return false;
}


// bool OlsrDefenseGcop::RunGcopAlgorithm() {
//     if (!m_routingProtocol) return false;

//     // Retrieve sets from the routing protocol
//     const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
//     const auto& neighbors = m_routingProtocol->GetNeighbors();

//     std::list<Ipv4Address> blues;
//     std::list<Ipv4Address> greens;

//     // Extract blue nodes (2-hop neighbors)
//     for (const auto& it : twoHopNeighbors) {
//         blues.push_back(it.twoHopNeighborAddr);
//     }
//     blues.sort();
//     blues.unique();
//     blues.remove(m_mainAddress);

//     // Extract green nodes (1-hop neighbors) and remove them from blues
//     for (const auto& it : neighbors) {
//         blues.remove(it.neighborMainAddr); 
//         greens.push_back(it.neighborMainAddr);
//     }
//     greens.sort();
//     greens.unique();
//     greens.remove(m_mainAddress);

//     // If there are no blue nodes to cover, no fictitious node is required
//     if (blues.empty()) {
//         return false;
//     }

//     // Build the local graph
//     std::map<Ipv4Address, std::list<Ipv4Address>> graph;
//     for (const auto& it : twoHopNeighbors) {
//         const Ipv4Address& u = it.neighborMainAddr;
//         const Ipv4Address& v = it.twoHopNeighborAddr;
//         graph[u].push_back(v);
//         graph[v].push_back(u); 
//     }

//     // Evaluate coverage: Can one green node cover all blue nodes up to 2 hops?
//     for (const auto& greenAddr : greens) {
//         graph[greenAddr].sort();
//         graph[greenAddr].unique();
//         graph[greenAddr].remove(m_mainAddress);

//         // Check 1-hop coverage
//         if (std::includes(graph[greenAddr].begin(), graph[greenAddr].end(), blues.begin(), blues.end())) {
//             return true; // DANGER: One green node covers all blues! Fictitious node REQUIRED.
//         } else {
//             // Check 2-hop coverage
//             std::list<Ipv4Address> reach2Steps;
//             reach2Steps.insert(reach2Steps.end(), graph[greenAddr].begin(), graph[greenAddr].end());
            
//             for (const auto& neighborOfGreen : graph[greenAddr]) {
//                 reach2Steps.insert(reach2Steps.end(), graph[neighborOfGreen].begin(), graph[neighborOfGreen].end());
//             }
            
//             reach2Steps.sort();
//             reach2Steps.unique();
//             reach2Steps.remove(greenAddr);

//             if (std::includes(reach2Steps.begin(), reach2Steps.end(), blues.begin(), blues.end())) {
//                 return true; // DANGER: One green node covers all blues in 2 hops! Fictitious node REQUIRED.
//             }
//         }
//     }

//     // If no single green node can cover all blue nodes, we are safe.
//     return false;
// }


/**
 * \brief Implements Algorithm 1 (GCOP) from Schweitzer et al. 2024.
 * 
 * Returns TRUE if a fictitious node is required, i.e. if there EXISTS a green
 * node g such that ALL blue nodes are within distance ≤ 2 from g in the subgraph
 * G_2 (which contains only green and blue nodes, and excludes s itself).
 * 
 * Paper's safe condition (Eq. 4):
 *   ∀g ∈ ADJ(s) ∃b ∈ ADJ2(s) : dist(g,b) ≥ 3   (no fictitious needed)
 * Negation (Eq. 6):
 *   ∃g ∀b : dist(g,b) < 3                     (fictitious REQUIRED)
 */
bool OlsrDefenseGcop::RunGcopAlgorithm() {
    if (!m_routingProtocol) return false;

    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();

    // -------------------------------------------------------------------------
    // Step 1: Build the green set (ADJ(s)) and blue set (ADJ2(s))
    // -------------------------------------------------------------------------
    std::set<Ipv4Address> greens;
    for (const auto& nei : neighbors) {
        // Only consider SYMMETRIC neighbors - asymmetric links are not reliable
        if (nei.status == NeighborTuple::STATUS_SYM) {
            greens.insert(nei.neighborMainAddr);
        }
    }
    greens.erase(m_mainAddress);

    std::set<Ipv4Address> blues;
    for (const auto& th : twoHopNeighbors) {
        blues.insert(th.twoHopNeighborAddr);
    }
    // A blue cannot also be 's' itself or one of the greens
    blues.erase(m_mainAddress);
    for (const auto& g : greens) {
        blues.erase(g);
    }

    // No blues → nothing to protect → no fictitious node needed
    if (blues.empty()) {
        return false;
    }

    // -------------------------------------------------------------------------
    // Step 2: Build the subgraph G_2 containing ONLY green+blue nodes.
    // Critically, 's' is NOT in the graph, so paths cannot pass through it.
    // -------------------------------------------------------------------------
    std::set<Ipv4Address> allowedNodes;  // green ∪ blue
    allowedNodes.insert(greens.begin(), greens.end());
    allowedNodes.insert(blues.begin(), blues.end());

    std::map<Ipv4Address, std::set<Ipv4Address>> graph;
    for (const auto& n : allowedNodes) {
        graph[n];  // initialize empty adjacency set
    }

    // Each (neighborMainAddr, twoHopNeighborAddr) entry means:
    // "my green neighbor 'u' advertised in its HELLO that it knows 'v'"
    // This gives edges green↔blue and occasionally green↔green.
    for (const auto& th : twoHopNeighbors) {
        const Ipv4Address& u = th.neighborMainAddr;
        const Ipv4Address& v = th.twoHopNeighborAddr;
        if (allowedNodes.count(u) && allowedNodes.count(v)) {
            graph[u].insert(v);
            graph[v].insert(u);
        }
    }

    // -------------------------------------------------------------------------
    // Step 3: For each green g, run BFS up to depth 2 inside G_2.
    // If ALL blues are reachable within 2 hops from some green g, that green
    // could be impersonated by an attacker using a fake neighbor list →
    // a fictitious node must be injected to defeat it.
    // -------------------------------------------------------------------------
    for (const auto& g : greens) {
        std::set<Ipv4Address> reachable;
        reachable.insert(g);

        // Distance 1 from g within G_2
        const auto& hop1 = graph[g];
        reachable.insert(hop1.begin(), hop1.end());

        // Distance 2 from g within G_2
        for (const auto& h1 : hop1) {
            const auto& hop2 = graph[h1];
            reachable.insert(hop2.begin(), hop2.end());
        }

        // Does 'reachable' cover every blue node?
        if (std::includes(reachable.begin(), reachable.end(),
                          blues.begin(), blues.end())) {
            NS_LOG_INFO("GCOP: Green " << g << " covers all blues in ≤2 hops. "
                        << "Fictitious node REQUIRED for " << m_mainAddress);
            return true;
        }
    }

    NS_LOG_DEBUG("GCOP: No single green covers all blues within ≤2 hops. "
                 "Fictitious node NOT required for " << m_mainAddress);
    return false;
}

// /**
//  * \brief Implements Algorithm 2 (GCOHP) - Hexagon topology check.
//  * \return True if the node is in a hexagon pattern requiring a fictitious node.
//  */
// bool OlsrDefenseGcop::RunGcohpAlgorithm() {
//     if (!m_routingProtocol) return false;

//     const auto& neighbors = m_routingProtocol->GetNeighbors();
//     const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
//     const auto& topology = m_routingProtocol->GetTopologySet();

//     std::set<Ipv4Address> greens;
//     std::set<Ipv4Address> blues;
//     std::map<Ipv4Address, std::set<Ipv4Address>> graph;

//     // Build the 1-hop and 2-hop local graph
//     for (const auto& nei : neighbors) {
//         greens.insert(nei.neighborMainAddr);
//         graph[m_mainAddress].insert(nei.neighborMainAddr);
//         graph[nei.neighborMainAddr].insert(m_mainAddress);
//     }

//     for (const auto& twoHop : twoHopNeighbors) {
//         blues.insert(twoHop.twoHopNeighborAddr);
//         graph[twoHop.neighborMainAddr].insert(twoHop.twoHopNeighborAddr);
//         graph[twoHop.twoHopNeighborAddr].insert(twoHop.neighborMainAddr);
//     }

//     // Include topology TC messages to find the cross-links
//     for (const auto& top : topology) {
//         graph[top.lastAddr].insert(top.destAddr);
//         graph[top.destAddr].insert(top.lastAddr);
//     }

//     blues.erase(m_mainAddress);
//     greens.erase(m_mainAddress);
//     for (const auto& nei : greens) {
//         blues.erase(nei);
//     }

//     // Find edges between Green (1-hop) and Blue (2-hop) nodes
//     std::set<std::pair<Ipv4Address, Ipv4Address>> e3;
//     for (const auto& greenNode : greens) {
//         for (const auto& blueNode : blues) {
//             if (graph[greenNode].count(blueNode) > 0) {
//                 e3.insert({greenNode, blueNode});
//             }
//         }
//     }

//     // Scan the edges to identify a 6-node cycle without chords
//     for (auto it1 = e3.begin(); it1 != e3.end(); ++it1) {
//         auto it2 = it1;
//         ++it2;
//         for (; it2 != e3.end(); ++it2) {
//             const auto& edge1 = *it1;
//             const auto& edge2 = *it2;

//             // Ensure distinct nodes
//             if (edge1.first == edge2.first || edge1.second == edge2.second) continue;

//             // Check if greens are connected or blues are connected (chords in the cycle)
//             if (graph[edge1.first].count(edge2.first) > 0 || graph[edge1.second].count(edge2.second) > 0) continue;
            
//             // Check cross-connections
//             if (graph[edge1.first].count(edge2.second) > 0 || graph[edge2.first].count(edge1.second) > 0) continue;

//             // Find common neighbors between the two blue nodes to close the cycle
//             std::set<Ipv4Address> intersect;
//             std::set_intersection(graph[edge1.second].begin(), graph[edge1.second].end(),
//                                   graph[edge2.second].begin(), graph[edge2.second].end(),
//                                   std::inserter(intersect, intersect.begin()));

//             if (!intersect.empty()) {
//                 // Ensure the closing node is not a green or blue node already in the path
//                 std::set<Ipv4Address> existingPathNodes = blues;
//                 existingPathNodes.insert(greens.begin(), greens.end());
                
//                 std::set<Ipv4Address> result;
//                 std::set_difference(intersect.begin(), intersect.end(),
//                                     existingPathNodes.begin(), existingPathNodes.end(),
//                                     std::inserter(result, result.end()));

//                 if (!result.empty()) {
//                     NS_LOG_INFO("GCOHP: 6-node cycle detected. Fictitious node required.");
//                     return true;
//                 }
//             }

//             for (const auto& blueCloser : blues) {
//                 if (blueCloser == edge1.second || blueCloser == edge2.second) continue;
//                 if (graph[edge1.second].count(blueCloser) &&
//                     graph[edge2.second].count(blueCloser) &&
//                     !graph[edge1.first].count(blueCloser) &&   // (g', b) ∉ E3
//                     !graph[edge2.first].count(blueCloser)) {   // (g'', b) ∉ E3
//                     NS_LOG_INFO("GCOHP: 6-node cycle (blue closing) detected.");
//                     return true;
//                 }
//             }
//         }
//     }
//     return false;
// }

/**
 * \brief Implements Algorithm 2 (GCOHP) from Schweitzer et al. 2024 - Hexagon detection.
 * 
 * Detects the specific "hexagon of nodes" topology where s participates in a 6-node
 * cycle (see paper Fig. 5). In such a topology, GCOP alone would NOT flag the need
 * for a fictitious node, yet an attacker CAN carry out a node isolation attack.
 * 
 * Detection conditions (paper Section 5.2):
 *   1. Two edges (g', b'), (g'', b'') ∈ E_3
 *   2. g' ≠ g'' AND b' ≠ b''
 *   3. No chords: (g', g''), (g', b''), (g'', b'), (b', b'') ∉ E_3
 *   4. Closing node exists: either
 *      a) some yellow y with (b', y), (b'', y) ∈ E_3, OR
 *      b) some third blue b with (b', b), (b'', b) ∈ E_3 AND (g', b), (g'', b) ∉ E_3
 */
bool OlsrDefenseGcop::RunGcohpAlgorithm() {
    if (!m_routingProtocol) return false;

    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology        = m_routingProtocol->GetTopologySet();

    // -------------------------------------------------------------------------
    // Step 1: Build GREEN (ADJ(s)) and BLUE (ADJ2(s)) sets
    // -------------------------------------------------------------------------
    std::set<Ipv4Address> greens;
    for (const auto& nei : neighbors) {
        if (nei.status == NeighborTuple::STATUS_SYM) {
            greens.insert(nei.neighborMainAddr);
        }
    }
    greens.erase(m_mainAddress);

    std::set<Ipv4Address> blues;
    for (const auto& th : twoHopNeighbors) {
        blues.insert(th.twoHopNeighborAddr);
    }
    blues.erase(m_mainAddress);
    for (const auto& g : greens) {
        blues.erase(g);
    }

    // Need at least 2 greens AND 2 blues to form a hexagon
    if (greens.size() < 2 || blues.size() < 2) {
        return false;
    }

    // -------------------------------------------------------------------------
    // Step 2: Build the subgraph G_3 (green+blue+yellow), excluding s
    //
    // Yellow nodes (ADJ3(s)) are inferred from the topology set: a node that
    // appears in TC entries reachable through our blues, but is not a green
    // or a blue, and is not s itself.
    // -------------------------------------------------------------------------
    
    // First, collect candidate yellow nodes from the topology set
    std::set<Ipv4Address> yellows;
    for (const auto& top : topology) {
        // If lastAddr is one of our blues, then destAddr MIGHT be a yellow
        if (blues.count(top.lastAddr)) {
            yellows.insert(top.destAddr);
        }
        if (blues.count(top.destAddr)) {
            yellows.insert(top.lastAddr);
        }
    }
    // Clean up: yellow ≠ s, green, or blue
    yellows.erase(m_mainAddress);
    for (const auto& g : greens) yellows.erase(g);
    for (const auto& b : blues)  yellows.erase(b);

    // Allowed node set for our subgraph
    std::set<Ipv4Address> allowedNodes;
    allowedNodes.insert(greens.begin(), greens.end());
    allowedNodes.insert(blues.begin(),  blues.end());
    allowedNodes.insert(yellows.begin(), yellows.end());

    // -------------------------------------------------------------------------
    // Step 3: Build adjacency graph restricted to allowed nodes, excluding s
    // -------------------------------------------------------------------------
    std::map<Ipv4Address, std::set<Ipv4Address>> graph;
    for (const auto& n : allowedNodes) {
        graph[n];  // initialize empty
    }

    // Edges from two-hop neighbor set (covers green↔green and green↔blue)
    for (const auto& th : twoHopNeighbors) {
        const Ipv4Address& u = th.neighborMainAddr;
        const Ipv4Address& v = th.twoHopNeighborAddr;
        if (allowedNodes.count(u) && allowedNodes.count(v)) {
            graph[u].insert(v);
            graph[v].insert(u);
        }
    }

    // Edges from topology set (covers blue↔yellow, and sometimes blue↔blue)
    for (const auto& top : topology) {
        const Ipv4Address& u = top.lastAddr;
        const Ipv4Address& v = top.destAddr;
        if (allowedNodes.count(u) && allowedNodes.count(v)) {
            graph[u].insert(v);
            graph[v].insert(u);
        }
    }

    // -------------------------------------------------------------------------
    // Step 4: Collect all green↔blue edges into E_gb
    // -------------------------------------------------------------------------
    std::vector<std::pair<Ipv4Address, Ipv4Address>> E_gb;  // (green, blue)
    for (const auto& g : greens) {
        for (const auto& b : blues) {
            if (graph[g].count(b)) {
                E_gb.push_back({g, b});
            }
        }
    }

    // -------------------------------------------------------------------------
    // Step 5: For each pair of distinct green↔blue edges, check hexagon conditions
    // -------------------------------------------------------------------------
    for (size_t i = 0; i < E_gb.size(); ++i) {
        for (size_t j = i + 1; j < E_gb.size(); ++j) {
            const Ipv4Address& gp  = E_gb[i].first;   // g'
            const Ipv4Address& bp  = E_gb[i].second;  // b'
            const Ipv4Address& gpp = E_gb[j].first;   // g''
            const Ipv4Address& bpp = E_gb[j].second;  // b''

            // Condition 2: distinct nodes across the two edges
            if (gp == gpp || bp == bpp) continue;
            if (gp == bpp || gpp == bp) continue;  // sanity (shouldn't happen but safe)

            // Condition 3: no chords
            if (graph[gp].count(gpp))  continue;   // (g', g'') forbidden
            if (graph[bp].count(bpp))  continue;   // (b', b'') forbidden
            if (graph[gp].count(bpp))  continue;   // (g', b'') forbidden
            if (graph[gpp].count(bp))  continue;   // (g'', b') forbidden

            // Condition 4a: closing via a YELLOW node y
            // y must be in yellows, adjacent to both b' and b''
            for (const auto& y : yellows) {
                if (y == gp || y == gpp || y == bp || y == bpp) continue;
                if (graph[bp].count(y) && graph[bpp].count(y)) {
                    NS_LOG_INFO("GCOHP: Hexagon detected (yellow closer=" << y
                                << ") for node " << m_mainAddress
                                << ". Fictitious node REQUIRED.");
                    return true;
                }
            }

            // Condition 4b: closing via a third BLUE node b
            // b ∈ blues, b ≠ b', b ≠ b'', adjacent to b' and b'',
            // NOT adjacent to g' or g''
            for (const auto& b : blues) {
                if (b == bp || b == bpp) continue;
                if (!graph[bp].count(b))  continue;  // need (b', b)
                if (!graph[bpp].count(b)) continue;  // need (b'', b)
                if (graph[gp].count(b))   continue;  // forbid (g', b)
                if (graph[gpp].count(b))  continue;  // forbid (g'', b)

                NS_LOG_INFO("GCOHP: Hexagon detected (blue closer=" << b
                            << ") for node " << m_mainAddress
                            << ". Fictitious node REQUIRED.");
                return true;
            }
        }
    }

    NS_LOG_DEBUG("GCOHP: No hexagon topology detected for " << m_mainAddress);
    return false;
}

} // namespace olsr
} // namespace ns3