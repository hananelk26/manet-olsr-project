#include "olsr-defense-gcop.h"
#include "olsr-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
// HARNESS INTEGRATION: BooleanValue / MakeBooleanAccessor / MakeBooleanChecker
// for the "Enabled" attribute.
#include "ns3/boolean.h"

#include <algorithm>
#include <vector>
#include <list>
#include <sstream>
// PROF PORT: std::distance/std::advance/std::inserter and std::pair for the
// professor's sixNodesArrangedInCircle()-style hexagon search.
#include <iterator>
#include <utility>

namespace ns3 {
namespace olsr {

NS_LOG_COMPONENT_DEFINE("OlsrDefenseGcop");
NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseGcop);

// ============================================================================
// PROF PORT / REFERENCE-DCFM: the detection rules are now byte-faithful to the
// professor's PopulateTwoHopNeighborSet -- single-hit, no warmup, no penalty,
// no uncovered/asymmetry/network-size thresholds, and no topology filtering.
// All former tuning constants were therefore removed; the rules fire exactly
// as the reference does.
// ============================================================================

// ============================================================================
// Type registration and lifecycle
// ============================================================================

TypeId OlsrDefenseGcop::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::olsr::OlsrDefenseGcop")
        .SetParent<OlsrDefenseStrategy>()
        .SetGroupName("Olsr")
        .AddConstructor<OlsrDefenseGcop>()
        // HARNESS INTEGRATION: the ONLY attribute the evaluation harness
        // sets/toggles. Wired through SetEnabled/GetEnabled so BOTH access
        // paths -- SetAttribute("Enabled", ...) at slot transitions and the
        // direct SetEnabled() double-toggle inside the harness's
        // ForceDefenseColdStart() -- run the same symmetric cold-start
        // logic.
        .AddAttribute("Enabled",
                      "Dynamic ON/OFF switch. Every real state transition "
                      "(both directions) performs a full symmetric "
                      "cold-start wipe of all accumulated detection state; "
                      "while false the strategy is fully inert.",
                      BooleanValue(false),
                      MakeBooleanAccessor(&OlsrDefenseGcop::SetEnabled,
                                          &OlsrDefenseGcop::GetEnabled),
                      MakeBooleanChecker())
        // PAPER ALIGNMENT: selects the defense configuration.
        //   true  (default) = full paper mechanism: 3 contradiction rules +
        //                     GCOP/GCOHP fictitious-node injection + Rule-1 bait.
        //   false           = paper "C-Rules": the 3 contradiction rules only,
        //                     no fictitious injection, bait sub-check skipped.
        // The three contradiction rules are UNAFFECTED in both modes.
        .AddAttribute("UseFictitiousNodes",
                      "When true (default) advertise fictitious nodes "
                      "(GCOP/GCOHP) and run the Rule-1 bait sub-check; when "
                      "false run the three contradiction rules only (paper "
                      "C-Rules).",
                      BooleanValue(true),
                      MakeBooleanAccessor(&OlsrDefenseGcop::m_useFictitiousNodes),
                      MakeBooleanChecker());
    return tid;
}

OlsrDefenseGcop::OlsrDefenseGcop()
    : m_routingProtocol(nullptr),
      m_startTime(0.0),
      // HARNESS INTEGRATION: start DISABLED. Both the attribute default and the
      // harness's explicit SetAttribute("Enabled", false) hit the SetEnabled
      // no-op guard by design.
      m_enabled(false),
      m_useFictitiousNodes(true)
{
}

OlsrDefenseGcop::~OlsrDefenseGcop() {
}

void OlsrDefenseGcop::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) {
    m_routingProtocol = proto;
    m_mainAddress = nodeAddress;
    // m_startTime retained for provenance only; reference DCFM has no warmup.
    m_startTime = Simulator::Now().GetSeconds();
}

void OlsrDefenseGcop::DoDispose() {
    m_riskyNodes.clear();
    m_enabled = false;   // HARNESS INTEGRATION: leave the object inert after disposal
    m_routingProtocol = nullptr;
}

// ============================================================================
// Blacklist queries
// ============================================================================

bool OlsrDefenseGcop::IsMalicious(Ipv4Address addr) {
    // HARNESS INTEGRATION (OFF-guard): while disabled, never report anyone
    // as malicious, so a defense-OFF window is indistinguishable from a clean
    // baseline.
    if (!m_enabled) {
        return false;
    }
    // Reference DCFM: flagged iff the sender violated a rule on its latest
    // HELLO (no expiration window).
    return m_riskyNodes.count(addr) > 0;
}

std::set<Ipv4Address> OlsrDefenseGcop::GetBlacklist() const {
    // HARNESS INTEGRATION (OFF-guard): while disabled the truthful answer is
    // "no blacklist".
    if (!m_enabled) {
        return {};
    }
    return m_riskyNodes;
}

bool OlsrDefenseGcop::HasKnownMaliciousNeighbor() {
    if (!m_routingProtocol) return false;
    const auto& neighbors = m_routingProtocol->GetNeighbors();
    for (const auto& nei : neighbors) {
        if (IsMalicious(nei.neighborMainAddr)) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Periodic maintenance and fictitious-node decision
// ============================================================================

void OlsrDefenseGcop::PeriodicCheck() {
    // HARNESS INTEGRATION (OFF-guard): driven unconditionally every 1 s by
    // RoutingProtocol::HandleDefenseTimer; a disabled strategy does nothing.
    if (!m_enabled) {
        return;
    }
    // PROF PORT / REFERENCE-DCFM: nothing to garbage-collect. The risky set is
    // refreshed on every HELLO (a stale entry is overwritten by the sender's
    // next HELLO), so there is no penalty window to expire. Kept as a no-op
    // hook so the RP's periodic timer wiring is unchanged.
}

bool OlsrDefenseGcop::RequiresFictitiousNode() {
    // HARNESS INTEGRATION (CRITICAL OFF-guard): RoutingProtocol queries this
    // on EVERY HELLO and EVERY TC it generates. Without this guard a
    // disabled node would keep injecting fictitious entries into its
    // HELLO/TC messages, making a defense-OFF window observably different
    // from a clean baseline on the air. (When ENABLED, the injection IS the
    // defense's authentic on-air signature and is intentionally not gated
    // by the warmup -- faithful to the original, which had no such gate.)
    if (!m_enabled) {
        return false;
    }
    // PAPER ALIGNMENT (C-Rules): when fictitious nodes are disabled we never
    // advertise one. The three contradiction rules still run; only the
    // GCOP/GCOHP fictitious-node decision is skipped.
    if (!m_useFictitiousNodes) {
        return false;
    }
    // PROF PORT: match the professor's live RequireFake(), whose only active
    // line is `return sixNodesArrangedInCircle();`. His GCOP (Coloring1BFS2 /
    // dcfmReqFake) is present but commented out and NOT wired in. To reproduce
    // his results we therefore run the hexagon (GCOHP) decision ONLY. GCOP is
    // intentionally not consulted here (RunGcopAlgorithm remains available for
    // A/B comparison but is off the live path).
    return RunGcohpAlgorithm();
}

// ============================================================================
// HARNESS INTEGRATION: dynamic ON/OFF switch + symmetric cold start
// ----------------------------------------------------------------------------
// The evaluation harness measures 4 windows back-to-back on the same network
// (baseline / attack / defense / defense+attack) and performs an
// UNCONDITIONAL cold start at every slot transition by toggling Enabled
// twice (SetEnabled(!cur); SetEnabled(cur);). The contract implemented here:
//   * no-op guard      -- a call that does not change the state is a strict
//                         no-op, so a redundant SetAttribute mid-window can
//                         never wipe live state;
//   * symmetric reset  -- every REAL transition, in BOTH directions, clears
//                         ALL accumulated detection state (m_riskyNodes), so
//                         the double toggle always leaves the object
//                         indistinguishable from a freshly loaded one with the
//                         slot's intended ON/OFF value;
//   * scope            -- only defense-owned state is wiped. The Setup()
//                         wiring (m_routingProtocol, m_mainAddress) is
//                         untouched, and no RP/OLSR state is reset from here
//                         (stale MPR/route exclusions and expired tuples
//                         re-converge naturally within the stabilization
//                         window).
// ============================================================================

void OlsrDefenseGcop::SetEnabled(bool enabled) {
    // No-op guard: only a REAL transition resets.
    if (m_enabled == enabled) {
        return;
    }

    // FULL SYMMETRIC COLD START -- both directions wipe all detection state.
    m_riskyNodes.clear();

    m_enabled = enabled;

    NS_LOG_INFO("DCFM defense on " << m_mainAddress << " -> "
                << (m_enabled ? "ENABLED" : "DISABLED")
                << " (cold start: all detection state cleared)");
}

bool OlsrDefenseGcop::GetEnabled() const {
    return m_enabled;
}

OlsrDefenseGcop::DebugStateSizes OlsrDefenseGcop::GetDebugStateSizes() const {
    // RAW container size, deliberately NOT gated on m_enabled: immediately
    // after a cold start this MUST read zero on every node; any non-zero value
    // is direct evidence of a cross-window leak through defense state.
    DebugStateSizes s;
    s.riskyNodes = m_riskyNodes.size();
    return s;
}

// ============================================================================
// Control plane hooks
// ============================================================================

void OlsrDefenseGcop::OnRecvHello(Ipv4Address senderAddress,
                                  Ptr<const Packet> /*packet*/,
                                  const MessageHeader& /*msg*/,
                                  const MessageHeader::Hello& /*hello*/) {
    // HARNESS INTEGRATION (OFF-guard): primary state-mutation entry point,
    // called by RecvOlsr for EVERY received HELLO (before the RP's own
    // filtering). While disabled no strikes / blacklist entries may
    // accumulate.
    if (!m_enabled) {
        return;
    }
    EvaluateContradictionRules(senderAddress);
}

// ============================================================================
// Data plane hooks (logging only - the actual IMP drop happens in
// RoutingProtocol::RouteInput, which queries IsMalicious() on the next-hop)
// ============================================================================

void OlsrDefenseGcop::OnDataPacketReceived(Ptr<const Packet> /*packet*/,
                                           Ipv4Address /*source*/,
                                           Ipv4Address /*destination*/,
                                           Ipv4Address nextHop) {
    // HARNESS INTEGRATION (OFF-guard): log-only hook, but a disabled
    // strategy must do zero work (inertness principle).
    if (!m_enabled) {
        return;
    }
    if (IsMalicious(nextHop)) {
        NS_LOG_INFO("About to forward packet via suspicious next-hop " << nextHop);
    }
}

void OlsrDefenseGcop::OnDataPacketForwarded(Ptr<const Packet> /*packet*/,
                                            Ipv4Address nextHop,
                                            Ipv4Address /*finalDest*/) {
    // HARNESS INTEGRATION (OFF-guard): log-only hook, same rationale.
    if (!m_enabled) {
        return;
    }
    if (IsMalicious(nextHop)) {
        NS_LOG_WARN("IMP Mechanism triggered! Intercepted attempt to forward "
                    "packet to malicious Next-Hop " << nextHop);
    }
}

// ============================================================================
// Contradiction Rule Engine (paper Section 3.5.1)
//
// The three rules below implement DCFM's contradiction detection. Each rule
// is HELLO-derived (Rule 1) or topology-set-derived (Rules 2 and 3); none
// requires anything beyond the standard OLSR state. The reference DCFM/IMP
// implementation evaluates all three rules and marks the sender risky on
// any violation. We follow the same semantics, with the additions noted in
// the tunables block above.
// ============================================================================

void OlsrDefenseGcop::EvaluateContradictionRules(Ipv4Address senderAddress) {
    // HARNESS INTEGRATION (defensive double-guard): OnRecvHello already gates,
    // but this is the ONLY function that writes m_riskyNodes -- guard directly.
    if (!m_enabled) return;
    if (!m_routingProtocol) return;

    // PROF PORT / REFERENCE DCFM: no warmup, no strike counter, no penalty
    // window. The sender's flag is recomputed from scratch on every HELLO
    // (mirroring the professor resetting NeighborTuple::risky=false at the top
    // of PopulateTwoHopNeighborSet and re-deriving it). We therefore do NOT
    // early-out on an already-flagged sender: a node that stops violating must
    // clear on its very next clean HELLO.

    bool isRisky = false;
    std::string violationReason;

    // Short-circuit OR: first rule to fire wins (and labels the reason).
    if (CheckRule1(senderAddress, violationReason)) {
        isRisky = true;
    } else if (CheckRule2(senderAddress, violationReason)) {
        isRisky = true;
    } else if (CheckRule3(senderAddress, violationReason)) {
        isRisky = true;
    }

    if (isRisky) {
        // Flag immediately (single-hit), and (re)assert the flag on every
        // subsequent violating HELLO.
        if (m_riskyNodes.insert(senderAddress).second) {
            NS_LOG_UNCOND("[t=" << Simulator::Now().GetSeconds() << "s] FLAG: "
              << m_mainAddress << " flagged " << senderAddress
              << " as MALICIOUS. Reason: " << violationReason);
        }
    } else {
        // Clean HELLO: clear the flag at once (no lingering penalty window).
        auto it = m_riskyNodes.find(senderAddress);
        if (it != m_riskyNodes.end()) {
            m_riskyNodes.erase(it);
            NS_LOG_INFO("Node " << senderAddress << " cleared (clean HELLO).");
        }
    }
}

// ----------------------------------------------------------------------------
// Rule 1 - direct HELLO contradictions
//
// (a) BAIT:      sender claims to know our own fictitious node F_v. Only we
//                inject F_v, so no honest peer can list it.
//                Maps to: defensive use of our own fictitious-node injection.
//
// (b) ASYMMETRY: sender claims z as a 1-hop neighbor, z is one of our real
//                1-hop neighbors (so we know z's HELLO), yet z never listed
//                the sender back.
//                Maps to paper Rule #1: z in ADJ(x) ∩ ADJ(v) yet x not in ADJ(z).
//
// HELLO-only source -> immune to ANSN poisoning in TC messages.
// ----------------------------------------------------------------------------
bool OlsrDefenseGcop::CheckRule1(Ipv4Address senderAddress, std::string& outReason) {
    // PROF PORT: faithful to the professor's Rule 1 (asymmetry + bait) in
    // PopulateTwoHopNeighborSet. Tests ANY neighbor (his FindNeighborTuple),
    // not symmetric-only; the bait is checked ONLY when the claimed node is not
    // my neighbor, and is ungated (getFakeAddress() is always computed). Fires
    // on the first offending claim.
    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();

    const Ipv4Address fakeAddress(m_mainAddress.Get() + 65536); // getFakeAddress()

    for (const auto& twoHop : twoHopNeighbors) {
        if (twoHop.neighborMainAddr != senderAddress) continue;
        const Ipv4Address nb2hop_addr = twoHop.twoHopNeighborAddr;

        // Is nb2hop_addr a neighbor of mine? (ANY neighbor, per the professor.)
        bool isMyNeighbor = false;
        for (const auto& nei : neighbors) {
            if (nei.neighborMainAddr == nb2hop_addr) { isMyNeighbor = true; break; }
        }

        if (isMyNeighbor) {
            // Asymmetry: my neighbor nb2hop_addr does not confirm the sender
            // back (no 2-hop tuple (nb2hop_addr -> sender)).
            bool linkVerified = false;
            for (const auto& v : twoHopNeighbors) {
                if (v.neighborMainAddr == nb2hop_addr &&
                    v.twoHopNeighborAddr == senderAddress) { linkVerified = true; break; }
            }
            if (!linkVerified) {
                outReason = "Rule 1 (Asymmetry): claimed neighbor does not confirm the link";
                return true;
            }
        } else if (nb2hop_addr == fakeAddress) {
            // Bait: sender claims a link to our fictitious node.
            outReason = "Rule 1 (Bait): claims link to our fictitious node";
            return true;
        }
    }
    return false;
}

// ----------------------------------------------------------------------------
// Rule 2 - MPR-coverage contradiction (paper Rule #2)
//
// Reasoning (paper Section 3.5.1, Fig. 2):
//   The sender x advertises ADJ(x) in its HELLO. Each entry y in ADJ(x)
//   is a candidate 2-hop neighbor for us (we put it in the 2-hop set
//   alongside x). Per OLSR, x must have selected some w in ADJ(x) as an
//   MPR for every z in ADJ2(x). The topology set tells us which w's chose
//   x as MPR (MPR'(x) below) and which z's are in their advertised
//   neighborhood. If some z is in apparent ADJ2(x) but no MPR' of x can
//   reach z in the topology, x is lying about its neighborhood.
//
// Sets, following the reference DCFM "naive" implementation:
//   N = ADJ(x)         -- from our 2-hop set, entries whose 1-hop side is x
//   Z = ADJ2(x)        -- from topology, neighbors-of-N minus N and our 1-hops
//   M = MPR'(x)        -- from topology, advertisers of tuples with destAddr=x
//
// Violation: there exists z in Z that is not adjacent in topology to any
// m in M.
//
// Note on TC poisoning: the user's link-spoofing attacker injects
// (lastAddr=attacker, destAddr=spoof_target) tuples, but those put
// spoof_targets into N (sender's claimed 1-hops), not into M. The
// attacker's actual MPR selectors (M) are the real 1-hop neighbors that
// legitimately selected it. Z therefore contains distant nodes that M
// cannot reach -- exactly what Rule 2 catches.
// ----------------------------------------------------------------------------
bool OlsrDefenseGcop::CheckRule2(Ipv4Address senderAddress, std::string& outReason) {
    // PROF PORT: faithful to the professor's "Naiive implementation for Rule 2".
    // N = sender's claimed 2-hop set; Z = topology-neighbors of N (then minus N
    // and minus our 1-hops; self is NOT removed, per the reference); M =
    // {lastAddr : topology tuple whose destAddr == sender}. A z is covered iff
    // some m in M shares a direct topology edge with z. Any z left uncovered ->
    // contradiction. No MPR-empty short-circuit, no uncovered-count threshold,
    // no topology filtering (all previously-added extras removed).
    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology        = m_routingProtocol->GetTopologySet();

    // N = ADJ(x): sender's claimed 1-hop neighbors (our 2-hop via sender).
    std::set<Ipv4Address> groupN;
    for (const auto& th : twoHopNeighbors) {
        if (th.neighborMainAddr == senderAddress) {
            groupN.insert(th.twoHopNeighborAddr);
        }
    }

    // Undirected topology adjacency == FindTopologyTuple(a,b) || (b,a), which is
    // exactly the per-(z,m) test the professor performs.
    std::map<Ipv4Address, std::set<Ipv4Address>> topoAdj;
    for (const auto& tp : topology) {
        topoAdj[tp.lastAddr].insert(tp.destAddr);
        topoAdj[tp.destAddr].insert(tp.lastAddr);
    }

    // Z = topology-neighbors of N;  M = {lastAddr : destAddr == sender}.
    std::set<Ipv4Address> groupZ;
    std::set<Ipv4Address> groupM;
    for (const auto& tp : topology) {
        if (groupN.count(tp.lastAddr) > 0) groupZ.insert(tp.destAddr);
        if (groupN.count(tp.destAddr) > 0) groupZ.insert(tp.lastAddr);
        if (tp.destAddr == senderAddress)  groupM.insert(tp.lastAddr);
    }

    // Z := Z \ N \ (our 1-hop neighbors).  Self is intentionally NOT removed.
    for (const auto& n : groupN) groupZ.erase(n);
    for (const auto& nei : neighbors) groupZ.erase(nei.neighborMainAddr);

    // Coverage sweep: drop every z that some m in M is topologically linked to.
    for (auto z = groupZ.begin(); z != groupZ.end(); ) {
        bool covered = false;
        auto zAdj = topoAdj.find(*z);
        if (zAdj != topoAdj.end()) {
            for (const auto& m : groupM) {
                if (zAdj->second.count(m) > 0) { covered = true; break; }
            }
        }
        if (covered) z = groupZ.erase(z);
        else ++z;
    }

    if (!groupZ.empty()) {
        outReason = "Rule 2 (MPR-coverage): " + std::to_string(groupZ.size()) +
                    " 2-hop nodes not reachable via the sender's MPR selectors";
        return true;
    }
    return false;
}

// ----------------------------------------------------------------------------
// Rule 3 - over-coverage (paper Rule #3)
//
// Paper condition: {V \ ADJ(v)} subset-of ADJ(x), i.e., the sender claims as
// neighbor essentially every node we know about that is not already our
// 1-hop.
//
// We follow the size-based approximation used in the reference DCFM
// implementation: compute
//      senderReachable = ADJ(x) \ ADJ(v)
//      netTargets      = (destAddrs in topology with lastAddr != us) \ ADJ(v)
// and fire when |senderReachable| >= |netTargets|. The strict ">=" matches
// the reference implementation and the paper's worst-case bound.
//
// A minimum-size guard suppresses the rule on toy topologies where a
// legitimate hub can trivially dominate.
// ----------------------------------------------------------------------------
bool OlsrDefenseGcop::CheckRule3(Ipv4Address senderAddress, std::string& outReason) {
    // PROF PORT: faithful to the professor's Rule 3 (over-coverage).
    // senderReachable = sender's 2-hop set (excluding us); netTargets =
    // {destAddr : topology tuple NOT originated by us}. Remove our 1-hop
    // neighbors from BOTH (this also removes the sender). Fire iff
    // |senderReachable| >= |netTargets|. No minimum-size floor; self is NOT
    // removed from netTargets (matching the reference).
    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology        = m_routingProtocol->GetTopologySet();

    std::set<Ipv4Address> senderReachable;
    for (const auto& th : twoHopNeighbors) {
        if (th.neighborMainAddr == senderAddress &&
            th.twoHopNeighborAddr != m_mainAddress) {
            senderReachable.insert(th.twoHopNeighborAddr);
        }
    }

    std::set<Ipv4Address> netTargets;
    for (const auto& tp : topology) {
        if (tp.lastAddr != m_mainAddress) {
            netTargets.insert(tp.destAddr);
        }
    }

    // Remove our 1-hop neighbors from both sets (this covers the sender too).
    for (const auto& nei : neighbors) {
        netTargets.erase(nei.neighborMainAddr);
        senderReachable.erase(nei.neighborMainAddr);
    }

    if (senderReachable.size() >= netTargets.size()) {
        outReason = "Rule 3 (Over-coverage): claims " +
                    std::to_string(senderReachable.size()) +
                    " non-neighbors out of " +
                    std::to_string(netTargets.size()) + " known";
        return true;
    }
    return false;
}

// ============================================================================
// Algorithm 1 (GCOP) - paper Section 5.1.3
//
// Returns true iff a fictitious node is required, i.e., iff there exists a
// green node g such that all blue nodes are within distance <= 2 from g in
// the subgraph G_2 (which contains only green and blue nodes, and excludes
// s itself).
//
// Paper's "safe" condition (Eq. 4):
//     forall g in ADJ(s): exists b in ADJ2(s): dist(g, b) >= 3
// Negation triggering Rule (Eq. 6):
//     exists g forall b: dist(g, b) < 3
// ============================================================================
bool OlsrDefenseGcop::RunGcopAlgorithm() {
    if (!m_routingProtocol) return false;

    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    // BUGFIX: the topology set is needed to recover blue<->blue (and the
    // remaining green<->green) edges of G_2. The two-hop set only encodes
    // green<->blue and green<->green (1-hop) edges; it NEVER encodes an edge
    // between two blue (2-hop) nodes, because every two-hop tuple has a 1-hop
    // neighbor on one side. Without blue<->blue edges the depth-2 BFS below
    // can only reach a blue at distance 1 from g (a blue reachable solely via
    // g->b'->b would be missed), so Eq. (6) was being under-satisfied and GCOP
    // emitted fewer fictitious nodes than the paper specifies. GCOHP already
    // augments its graph with these topology edges; GCOP must do the same.
    const auto& topology        = m_routingProtocol->GetTopologySet();

    // Step 1: build green (ADJ(s)) and blue (ADJ2(s)) sets ---------------------
    std::set<Ipv4Address> greens;
    for (const auto& nei : neighbors) {
        // Asymmetric links are not reliable -- limit to symmetric only.
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

    if (blues.empty()) {
        // Nothing to protect -- no fictitious node needed.
        return false;
    }

    // Step 2: build the subgraph G_2 over green + blue only --------------------
    // The graph deliberately excludes s, so paths cannot loop through us.
    // Edges come from TWO sources so that all of E_2 (the edges of G restricted
    // to green+blue) is recovered, matching the graph GCOHP builds:
    //   - the two-hop set  -> green<->blue and green<->green edges, and
    //   - the topology set -> blue<->blue (and additional green<->green) edges
    //     that are invisible to the two-hop set.
    std::set<Ipv4Address> allowedNodes;
    allowedNodes.insert(greens.begin(), greens.end());
    allowedNodes.insert(blues.begin(), blues.end());

    std::map<Ipv4Address, std::set<Ipv4Address>> graph;
    for (const auto& n : allowedNodes) {
        graph[n]; // initialize empty adjacency set
    }
    for (const auto& th : twoHopNeighbors) {
        const Ipv4Address& u = th.neighborMainAddr;
        const Ipv4Address& v = th.twoHopNeighborAddr;
        if (allowedNodes.count(u) && allowedNodes.count(v)) {
            graph[u].insert(v);
            graph[v].insert(u);
        }
    }
    // BUGFIX (see note at the top of this function): fold in topology-set edges
    // so that blue<->blue adjacencies contribute to the depth-2 reachability.
    for (const auto& tp : topology) {
        const Ipv4Address& u = tp.lastAddr;
        const Ipv4Address& v = tp.destAddr;
        if (allowedNodes.count(u) && allowedNodes.count(v)) {
            graph[u].insert(v);
            graph[v].insert(u);
        }
    }

    // Step 3: for each green g, BFS to depth 2 inside G_2 ----------------------
    for (const auto& g : greens) {
        std::set<Ipv4Address> reachable;
        reachable.insert(g);
        const auto& hop1 = graph[g];
        reachable.insert(hop1.begin(), hop1.end());
        for (const auto& h1 : hop1) {
            const auto& hop2 = graph[h1];
            reachable.insert(hop2.begin(), hop2.end());
        }

        if (std::includes(reachable.begin(), reachable.end(),
                          blues.begin(), blues.end())) {
            NS_LOG_INFO("GCOP: green " << g << " covers all blues in <=2 hops. "
                        "Fictitious node REQUIRED for " << m_mainAddress);
            return true;
        }
    }

    NS_LOG_DEBUG("GCOP: no single green covers all blues within <=2 hops. "
                 "Fictitious node NOT required for " << m_mainAddress);
    return false;
}

// ============================================================================
// Algorithm 2 (GCOHP) - paper Section 5.2  [PROF PORT]
//
// FAITHFUL PORT of the professor's RoutingProtocol::sixNodesArrangedInCircle().
// This is the ONLY detector wired into RequiresFictitiousNode() now (his live
// RequireFake() returns sixNodesArrangedInCircle() only), so matching it here
// reproduces his fictitious-node injection behavior.
//
// Intentional differences from the previous (paper-literal) version, kept
// because they are exactly what the professor's code does and are the likely
// source of the "weird ML vectors" when they were absent:
//
//   * GREENS = ALL neighbors (the professor commented out the STATUS_SYM
//     filter in his greens loop), not symmetric-only.
//   * GRAPH is NOT restricted to green/blue/yellow: every node seen in the
//     two-hop set and the topology set is a graph vertex, and s itself is
//     included via its symmetric-neighbor edges. A closer may therefore be
//     any node the topology exposes, not only a "yellow adjacent to a blue".
//   * CLOSER is YELLOW-ONLY: the 6th node must lie in (common neighbors of the
//     two blues) \ (blues U greens). The third-blue closer case (paper 4b) is
//     deliberately NOT accepted here -- the professor's version drops it, and
//     that extra 4b branch is the most likely cause of spurious hexagon
//     detections -> spurious fictitious injection -> distorted feature vectors.
//
// Detection (professor's semantics):
//   For every unordered pair of distinct green->blue edges (g',b'), (g'',b''):
//     - g' != g'' and b' != b''                                    (4 nodes)
//     - no green-green edge (g',g''), no blue-blue edge (b',b'')   (opposite sides)
//     - no cross edge (g',b'') and no cross edge (g'',b')          (no 5-cycle chord)
//     - exists c in N(b') ^ N(b'') with c not in (greens U blues)  (yellow closer)
//   => hexagon present => fictitious node required.
// ============================================================================
bool OlsrDefenseGcop::RunGcohpAlgorithm() {
    if (!m_routingProtocol) return false;

    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology        = m_routingProtocol->GetTopologySet();

    // ---- Build the FULL adjacency graph (unrestricted; includes s) ----------
    // Mirrors sixNodesArrangedInCircle(): symmetric-neighbor edges to s, then
    // all two-hop edges, then all topology edges. No allowedNodes gate.
    std::map<Ipv4Address, std::set<Ipv4Address>> graph;

    for (const auto& nei : neighbors) {
        // NOTE: the professor DOES keep the SYM filter when wiring s<->green
        // edges (only the greens-set loop below has it removed).
        if (nei.status == NeighborTuple::STATUS_SYM) {
            graph[m_mainAddress].insert(nei.neighborMainAddr);
            graph[nei.neighborMainAddr].insert(m_mainAddress);
        }
    }
    for (const auto& th : twoHopNeighbors) {
        graph[th.neighborMainAddr].insert(th.twoHopNeighborAddr);
        graph[th.twoHopNeighborAddr].insert(th.neighborMainAddr);
    }
    for (const auto& tp : topology) {
        graph[tp.lastAddr].insert(tp.destAddr);
        graph[tp.destAddr].insert(tp.lastAddr);
    }

    // ---- BLUES = 2-hop addresses, minus s, minus 1-hop neighbors ------------
    std::set<Ipv4Address> blues;
    for (const auto& th : twoHopNeighbors) {
        blues.insert(th.twoHopNeighborAddr);
    }
    blues.erase(m_mainAddress);

    // ---- GREENS = ALL neighbors (professor's SYM filter is commented out) ---
    // Also strips those neighbors out of blues.
    std::set<Ipv4Address> greens;
    for (const auto& nei : neighbors) {
        blues.erase(nei.neighborMainAddr);
        greens.insert(nei.neighborMainAddr);
    }
    greens.erase(m_mainAddress);

    // ---- E3 = green->blue edges present in the graph ------------------------
    std::set<std::pair<Ipv4Address, Ipv4Address>> e3;
    for (const auto& g : greens) {
        for (const auto& b : blues) {
            if (graph[g].count(b) > 0) {
                e3.insert(std::make_pair(g, b));
            }
        }
    }

    // ---- Search unordered pairs of distinct E3 edges for the 6-cycle --------
    for (std::set<std::pair<Ipv4Address, Ipv4Address>>::const_iterator it = e3.begin();
         std::distance(it, e3.end()) > 1; ++it) {
        const std::pair<Ipv4Address, Ipv4Address> firstEdge = *it;
        std::set<std::pair<Ipv4Address, Ipv4Address>>::const_iterator it2 = it;
        std::advance(it2, 1);
        for (; it2 != e3.end(); ++it2) {
            const std::pair<Ipv4Address, Ipv4Address> secondEdge = *it2;

            // 4 distinct nodes: distinct greens AND distinct blues
            if (firstEdge.first == secondEdge.first ||
                firstEdge.second == secondEdge.second) {
                continue;
            }
            // opposite sides must be non-adjacent (no green-green, no blue-blue)
            if (graph[firstEdge.first].count(secondEdge.first) > 0 ||
                graph[secondEdge.first].count(firstEdge.first) > 0 ||
                graph[firstEdge.second].count(secondEdge.second) > 0 ||
                graph[secondEdge.second].count(firstEdge.second) > 0) {
                continue;
            }
            // no cross chord g'<->b'' or g''<->b' (would close a shorter cycle)
            if (graph[firstEdge.first].count(secondEdge.second) > 0 ||
                graph[secondEdge.first].count(firstEdge.second) > 0) {
                continue;
            }

            // closer candidates = common neighbors of the two blues
            std::set<Ipv4Address> intersect;
            std::set_intersection(graph[firstEdge.second].begin(), graph[firstEdge.second].end(),
                                  graph[secondEdge.second].begin(), graph[secondEdge.second].end(),
                                  std::inserter(intersect, intersect.begin()));
            if (intersect.empty()) {
                continue;
            }
            // keep only closers that are NEITHER green NOR blue (i.e. yellow).
            // (Professor drops the paper's third-blue closer case on purpose.)
            std::set<Ipv4Address> bluesAndGreens = blues;
            bluesAndGreens.insert(greens.begin(), greens.end());
            std::set<Ipv4Address> result;
            std::set_difference(intersect.begin(), intersect.end(),
                                bluesAndGreens.begin(), bluesAndGreens.end(),
                                std::inserter(result, result.end()));
            if (!result.empty()) {
                NS_LOG_INFO("GCOHP: hexagon detected (yellow closer) for node "
                            << m_mainAddress << ". Fictitious node REQUIRED.");
                return true;
            }
        }
    }

    NS_LOG_DEBUG("GCOHP: no hexagon topology detected for " << m_mainAddress);
    return false;
}

} // namespace olsr
} // namespace ns3