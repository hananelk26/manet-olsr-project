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
}

void OlsrDefenseGcop::DoDispose() {
    m_suspiciousNodes.clear();
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

void OlsrDefenseGcop::OnDataPacketReceived(Ptr<const Packet> packet, Ipv4Address source, Ipv4Address destination, Ipv4Address prevHop) {
    // Optional: Log received data packets from suspicious nodes
    if (IsMalicious(prevHop)) {
        NS_LOG_INFO("Warning: Received data packet from a currently suspicious node " << prevHop);
    }
}

void OlsrDefenseGcop::OnDataPacketForwarded(Ptr<const Packet> packet, Ipv4Address source, Ipv4Address nextHop) {
    // This hook allows us to log if IMP is actively bypassing or catching a routing attempt
    if (IsMalicious(nextHop)) {
        NS_LOG_WARN("IMP Mechanism triggered! Intercepted attempt to forward packet to malicious Next-Hop " << nextHop);
    }
}

void OlsrDefenseGcop::EvaluateContradictionRules(Ipv4Address senderAddress) {
    if (!m_routingProtocol) return;

    const auto& neighbors = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology = m_routingProtocol->GetTopologySet();

    bool isRisky = false;
        
    // Calculate our fictitious node address (MainIP + 65536, exactly as in SendHello)
    Ipv4Address fakeAddress(m_mainAddress.Get() + 65536);

    // --- C-Rule 1: Topology Contradiction ---
    for (const auto& twoHop : twoHopNeighbors) {
        if (twoHop.neighborMainAddr != senderAddress) continue;
        
        Ipv4Address claimedNeighbor = twoHop.twoHopNeighborAddr;
        
        bool isMyNeighbor = false;
        for (const auto& nei : neighbors) {
            if (nei.neighborMainAddr == claimedNeighbor) {
                isMyNeighbor = true;
                break;
            }
        }

        if (isMyNeighbor) {
            // If the claimed neighbor is an actual 1-hop neighbor of ours, verify the symmetric link
            bool linkVerified = false;
            for (const auto& verifyTwoHop : twoHopNeighbors) {
                if (verifyTwoHop.neighborMainAddr == claimedNeighbor && 
                    verifyTwoHop.twoHopNeighborAddr == senderAddress) {
                    linkVerified = true;
                    break;
                }
            }
            
            if (!linkVerified) {
                NS_LOG_INFO("Rule 1 Violation: Node " << senderAddress << " falsely claims link to real neighbor " << claimedNeighbor);
                isRisky = true;
                break;
            }
        } else {
            // The bait (fictitious node) check!
            // If the sender claims to know a node that isn't our neighbor, 
            // check if it's the fictitious node we injected.
            if (claimedNeighbor == fakeAddress) {
                NS_LOG_INFO("Rule 1 Violation (Bait caught!): Node " << senderAddress << " falsely claims link to our fictitious node " << fakeAddress);
                isRisky = true;
                break;
            }
        }
    }

    // --- C-Rule 2: MPR Missing Selection ---
    if (!isRisky) {
        std::list<Ipv4Address> groupN; // Sender's neighbors
        std::list<Ipv4Address> groupZ; // Sender's 2-hop neighbors
        std::list<Ipv4Address> groupM; // Sender's chosen MPRs
        
        // Populate N (Sender's 1-hop neighbors from two-hop set)
        for (const auto& twoHop : twoHopNeighbors) {
            if (twoHop.neighborMainAddr == senderAddress) {
                groupN.push_back(twoHop.twoHopNeighborAddr);
            }
        }
        groupN.sort();
        groupN.unique();

        // Populate Z (reachable from N) and M (MPRs chosen by sender) from Topology Set
        for (const auto& top : topology) {
            if (std::find(groupN.begin(), groupN.end(), top.lastAddr) != groupN.end()) {
                groupZ.push_back(top.destAddr);
            }
            if (std::find(groupN.begin(), groupN.end(), top.destAddr) != groupN.end()) {
                groupZ.push_back(top.lastAddr);
            }
            
            // If the destination is the sender, the lastAddr is the MPR it chose
            if (top.destAddr == senderAddress) {
                groupM.push_back(top.lastAddr);
            }
        }
        groupZ.sort();
        groupZ.unique();
        groupM.sort();
        groupM.unique();

        // Remove N from Z (Z should only contain strict 2-hop neighbors of the sender)
        for (const auto& n : groupN) {
            groupZ.remove(n);
        }
        // Remove our own 1-hop neighbors from Z
        for (const auto& nei : neighbors) {
            groupZ.remove(nei.neighborMainAddr);
        }

        // Verify that every node in Z is covered by at least one MPR in M
        for (auto zIt = groupZ.begin(); zIt != groupZ.end(); ) {
            bool isCovered = false;
            for (const auto& m : groupM) {
                // Check if MPR 'm' connects to 'z' in the topology
                for (const auto& top : topology) {
                    if ((top.lastAddr == m && top.destAddr == *zIt) || 
                        (top.lastAddr == *zIt && top.destAddr == m)) {
                        isCovered = true;
                        break;
                    }
                }
                if (isCovered) break;
            }
            
            if (isCovered) {
                zIt = groupZ.erase(zIt); // Covered successfully, remove from Z
            } else {
                ++zIt;
            }
        }

        // If Z is not empty, the sender has 2-hop neighbors it didn't provide an MPR for!
        if (!groupZ.empty()) {
            NS_LOG_INFO("Rule 2 Violation: Node " << senderAddress << " failed to select MPRs to cover all its 2-hop neighbors.");
            isRisky = true;
        }
    }

    // --- C-Rule 3: Over-coverage (Unreachable sets) ---
    if (!isRisky) {
        std::list<Ipv4Address> senderReachable;
        
        // Build the list of nodes the sender claims to reach
        for (const auto& twoHop : twoHopNeighbors) {
            if (twoHop.neighborMainAddr == senderAddress && twoHop.twoHopNeighborAddr != m_mainAddress) {
                senderReachable.push_back(twoHop.twoHopNeighborAddr);
            }
        }
        
        // Build the list of all valid remote network targets
        std::list<Ipv4Address> networkTargets;
        for (const auto& top : topology) {
            if (top.lastAddr != m_mainAddress) {
                networkTargets.push_back(top.destAddr);
            }
        }
        networkTargets.sort();
        networkTargets.unique();

        // Remove our direct 1-hop neighbors from the targets
        for (const auto& nei : neighbors) {
            networkTargets.remove(nei.neighborMainAddr);
            senderReachable.remove(nei.neighborMainAddr);
        }

        // If the sender claims it can reach everything on its own, flag it!
        // (Added a safety check 'size > 2' to avoid false positives in tiny networks)
        if (senderReachable.size() >= networkTargets.size() && !networkTargets.empty() && networkTargets.size() > 2) {
            NS_LOG_INFO("Rule 3 Violation: Node " << senderAddress << " claims impossibly high coverage.");
            isRisky = true;
        }
    }

    /* Apply or remove penalty based on the current evaluation */
    if (isRisky) {
        /*
         * Set a short penalty duration just enough to cover the time until 
         * the next expected HELLO message (e.g., 3.0 seconds). 
         */
        Time penaltyDuration = Seconds(3.0);
        m_suspiciousNodes[senderAddress] = Simulator::Now() + penaltyDuration;
        NS_LOG_WARN("Node " << senderAddress << " penalized and added to suspicious list!");
    } else {
        /*
         * If the node is no longer risky in this evaluation, remove it from the blacklist.
         * This mirrors the original algorithm's stateless behavior.
         */
        auto it = m_suspiciousNodes.find(senderAddress);
        if (it != m_suspiciousNodes.end()) {
            m_suspiciousNodes.erase(it);
            NS_LOG_INFO("Node " << senderAddress << " passed the checks and is removed from the suspicious list.");
        }
    }
}

bool OlsrDefenseGcop::RunGcopAlgorithm() {
    if (!m_routingProtocol) return false;

    // Retrieve sets from the routing protocol
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& neighbors = m_routingProtocol->GetNeighbors();

    std::list<Ipv4Address> blues;
    std::list<Ipv4Address> greens;

    // Extract blue nodes (2-hop neighbors)
    for (const auto& it : twoHopNeighbors) {
        blues.push_back(it.twoHopNeighborAddr);
    }
    blues.sort();
    blues.unique();
    blues.remove(m_mainAddress);

    // Extract green nodes (1-hop neighbors) and remove them from blues
    for (const auto& it : neighbors) {
        blues.remove(it.neighborMainAddr); 
        greens.push_back(it.neighborMainAddr);
    }
    greens.sort();
    greens.unique();
    greens.remove(m_mainAddress);

    // If there are no blue nodes to cover, no fictitious node is required
    if (blues.empty()) {
        return false;
    }

    // Build the local graph
    std::map<Ipv4Address, std::list<Ipv4Address>> graph;
    for (const auto& it : twoHopNeighbors) {
        const Ipv4Address& u = it.neighborMainAddr;
        const Ipv4Address& v = it.twoHopNeighborAddr;
        graph[u].push_back(v);
        graph[v].push_back(u); 
    }

    // Evaluate coverage: Can one green node cover all blue nodes up to 2 hops?
    for (const auto& greenAddr : greens) {
        graph[greenAddr].sort();
        graph[greenAddr].unique();
        graph[greenAddr].remove(m_mainAddress);

        // Check 1-hop coverage
        if (std::includes(graph[greenAddr].begin(), graph[greenAddr].end(), blues.begin(), blues.end())) {
            return true; // DANGER: One green node covers all blues! Fictitious node REQUIRED.
        } else {
            // Check 2-hop coverage
            std::list<Ipv4Address> reach2Steps;
            reach2Steps.insert(reach2Steps.end(), graph[greenAddr].begin(), graph[greenAddr].end());
            
            for (const auto& neighborOfGreen : graph[greenAddr]) {
                reach2Steps.insert(reach2Steps.end(), graph[neighborOfGreen].begin(), graph[neighborOfGreen].end());
            }
            
            reach2Steps.sort();
            reach2Steps.unique();
            reach2Steps.remove(greenAddr);

            if (std::includes(reach2Steps.begin(), reach2Steps.end(), blues.begin(), blues.end())) {
                return true; // DANGER: One green node covers all blues in 2 hops! Fictitious node REQUIRED.
            }
        }
    }

    // If no single green node can cover all blue nodes, we are safe.
    return false;
}

/**
 * \brief Implements Algorithm 2 (GCOHP) - Hexagon topology check.
 * \return True if the node is in a hexagon pattern requiring a fictitious node.
 */
bool OlsrDefenseGcop::RunGcohpAlgorithm() {
    if (!m_routingProtocol) return false;

    const auto& neighbors = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology = m_routingProtocol->GetTopologySet();

    std::set<Ipv4Address> greens;
    std::set<Ipv4Address> blues;
    std::map<Ipv4Address, std::set<Ipv4Address>> graph;

    // Build the 1-hop and 2-hop local graph
    for (const auto& nei : neighbors) {
        greens.insert(nei.neighborMainAddr);
        graph[m_mainAddress].insert(nei.neighborMainAddr);
        graph[nei.neighborMainAddr].insert(m_mainAddress);
    }

    for (const auto& twoHop : twoHopNeighbors) {
        blues.insert(twoHop.twoHopNeighborAddr);
        graph[twoHop.neighborMainAddr].insert(twoHop.twoHopNeighborAddr);
        graph[twoHop.twoHopNeighborAddr].insert(twoHop.neighborMainAddr);
    }

    // Include topology TC messages to find the cross-links
    for (const auto& top : topology) {
        graph[top.lastAddr].insert(top.destAddr);
        graph[top.destAddr].insert(top.lastAddr);
    }

    blues.erase(m_mainAddress);
    greens.erase(m_mainAddress);
    for (const auto& nei : greens) {
        blues.erase(nei);
    }

    // Find edges between Green (1-hop) and Blue (2-hop) nodes
    std::set<std::pair<Ipv4Address, Ipv4Address>> e3;
    for (const auto& greenNode : greens) {
        for (const auto& blueNode : blues) {
            if (graph[greenNode].count(blueNode) > 0) {
                e3.insert({greenNode, blueNode});
            }
        }
    }

    // Scan the edges to identify a 6-node cycle without chords
    for (auto it1 = e3.begin(); it1 != e3.end(); ++it1) {
        auto it2 = it1;
        ++it2;
        for (; it2 != e3.end(); ++it2) {
            const auto& edge1 = *it1;
            const auto& edge2 = *it2;

            // Ensure distinct nodes
            if (edge1.first == edge2.first || edge1.second == edge2.second) continue;

            // Check if greens are connected or blues are connected (chords in the cycle)
            if (graph[edge1.first].count(edge2.first) > 0 || graph[edge1.second].count(edge2.second) > 0) continue;
            
            // Check cross-connections
            if (graph[edge1.first].count(edge2.second) > 0 || graph[edge2.first].count(edge1.second) > 0) continue;

            // Find common neighbors between the two blue nodes to close the cycle
            std::set<Ipv4Address> intersect;
            std::set_intersection(graph[edge1.second].begin(), graph[edge1.second].end(),
                                  graph[edge2.second].begin(), graph[edge2.second].end(),
                                  std::inserter(intersect, intersect.begin()));

            if (!intersect.empty()) {
                // Ensure the closing node is not a green or blue node already in the path
                std::set<Ipv4Address> existingPathNodes = blues;
                existingPathNodes.insert(greens.begin(), greens.end());
                
                std::set<Ipv4Address> result;
                std::set_difference(intersect.begin(), intersect.end(),
                                    existingPathNodes.begin(), existingPathNodes.end(),
                                    std::inserter(result, result.end()));

                if (!result.empty()) {
                    NS_LOG_INFO("GCOHP: 6-node cycle detected. Fictitious node required.");
                    return true;
                }
            }
        }
    }
    return false;
}

} // namespace olsr
} // namespace ns3