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

namespace ns3 {
namespace olsr {

NS_LOG_COMPONENT_DEFINE("OlsrDefenseGcop");
NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseGcop);

// ============================================================================
// Tunables
// ----------------------------------------------------------------------------
// These constants control the trade-off between detection speed and the
// false-positive rate. The defaults are calibrated for the simulation
// parameters in the paper (HELLO=2s, TC=5s, 300s simulation, 50-100 nodes).
// ============================================================================

/// Seconds to wait after the defense is (re-)ENABLED before any C-Rule is
/// evaluated. HARNESS INTEGRATION: the check is anchored to m_enableTime
/// (the last OFF->ON transition) rather than to absolute simulation time --
/// see the comment at the warmup check in EvaluateContradictionRules().
/// Required because Rule 2 and Rule 3 read the topology set, which only
/// converges after several TC cycles. HELLO=2s, TC=5s => ~9 TC
/// opportunities in 45s.
/// PAPER-FAITHFUL: the paper evaluates the contradiction rules on every HELLO
/// with no warmup; restored to 0.0 (original calibrated value was 45.0). With a
/// not-yet-converged topology set Rule 2/3 may raise early false positives --
/// the accepted cost of paper fidelity.
static const double WARMUP_SECONDS = 0.0;

/// How long a flagged node remains on the blacklist after the last triggering
/// HELLO. The penalty is refreshed by every subsequent triggering HELLO, so
/// a node under sustained attack stays blacklisted continuously.
static const Time PENALTY_DURATION = Seconds(5.0);

/// Number of consecutive violations required before adding to the blacklist.
/// PAPER-FAITHFUL: the reference DCFM flags on a single contradiction (immediate
/// flag); restored to 1. (Original calibrated value was 2, to filter transient
/// asymmetric-view artifacts from HELLO loss at the cost of ~2s latency.)
static const uint32_t STRIKES_BEFORE_BLACKLIST = 1;

/// Minimum size of (V \ ADJ(v)) required before Rule 3 may fire.
/// PAPER-FAITHFUL: the paper's Rule 3 ({V\ADJ(v)} subset-of ADJ(x)) has no
/// minimum-size floor; restored to 1, which keeps only the degenerate
/// empty-set guard. (Original calibrated value was 6, to suppress toy-topology
/// hubs.)
static const size_t MIN_NETWORK_SIZE_FOR_RULE3 = 1;

/// Minimum number of uncovered 2-hop nodes required to fire Rule 2.
/// Rule 2 has an inherent false-positive tendency in sparse OLSR networks:
/// the topology set only captures MPR-relationship edges, not all physical
/// edges between neighbors. A legitimate sender can therefore appear to
/// have 1-3 uncovered 2-hop nodes purely because some of its MPR-coverage
/// edges happen not to be visible via topology TCs (the nodes involved did
/// not select each other as MPRs). An actual link-spoofing attacker, in
/// contrast, claims N distant nodes that are completely unreachable
/// through any of its legitimate MPRs, producing many uncovered.
static const size_t MIN_UNCOVERED_FOR_RULE2 = 1; // PAPER-FAITHFUL: paper fires on a single uncovered 2-hop node (was 5).

/// Minimum number of asymmetric link claims required to fire Rule 1b.
/// Rule 1b looks for sender X claiming "Z is my neighbor" while Z's HELLO
/// does not list X in return. A single asymmetric claim is common in
/// real wireless networks due to HELLO loss in the MAC layer (~5-10%
/// typical loss). Requiring 2+ asymmetric claims distinguishes a
/// link-spoofing attacker (multiple consistent lies) from a transient
/// HELLO-loss artifact (one isolated discrepancy).
static const size_t MIN_ASYMMETRY_FOR_RULE1B = 1; // PAPER-FAITHFUL: paper Rule 1 fires on a single asymmetry (was 2).

/// Enable filtering of TC tuples from blacklisted originators in Rule 2.
/// When the contradiction rules have low FP rate (e.g., after applying
/// MIN_UNCOVERED_FOR_RULE2 and MIN_ASYMMETRY_FOR_RULE1B), this filter's
/// benefit (cleaning attacker pollution) may be offset by its risk
/// (amplifying rare FP cascades). Disable to compare empirically.
/// PAPER ALIGNMENT: DISABLED. The paper assumes TC cannot be spoofed, so the
/// contradiction rules never filter the topology set in response to a
/// suspicion ("don't touch TC"). Re-enabling improves FP robustness against
/// the link-spoofing attacker, at the cost of paper fidelity.
static const bool ENABLE_TOPOLOGY_FILTER = false;

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
      // HARNESS INTEGRATION: start DISABLED. The attribute system's
      // application of the Enabled default (false) at construction, and the
      // harness's explicit SetAttribute("Enabled", false) at install time,
      // both hit the SetEnabled no-op guard -- by design.
      m_enabled(false),
      m_enableTime(Seconds(0)),
      m_useFictitiousNodes(true)
{
}

OlsrDefenseGcop::~OlsrDefenseGcop() {
}

void OlsrDefenseGcop::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) {
    m_routingProtocol = proto;
    m_mainAddress = nodeAddress;
    // HARNESS INTEGRATION note: m_startTime is retained for provenance /
    // minimal diff only. Since the ON/OFF integration the warmup anchor is
    // m_enableTime (re-armed on every OFF->ON transition in SetEnabled),
    // NOT this value.
    m_startTime = Simulator::Now().GetSeconds();
}

void OlsrDefenseGcop::DoDispose() {
    m_suspiciousNodes.clear();
    m_violationCounter.clear();
    m_enabled = false;   // HARNESS INTEGRATION: leave the object inert after disposal
    m_routingProtocol = nullptr;
}

// ============================================================================
// Blacklist queries
// ============================================================================

bool OlsrDefenseGcop::IsMalicious(Ipv4Address addr) {
    // HARNESS INTEGRATION (OFF-guard): while disabled, never report anyone
    // as malicious. This neutralizes by construction every RP-side consumer
    // (RecvOlsr message filter, MPR exclusion, routing/HNA-table exclusion,
    // IMP next-hop drop) even at transition instants -- a defense-OFF
    // window must be indistinguishable from a clean baseline.
    if (!m_enabled) {
        return false;
    }
    auto it = m_suspiciousNodes.find(addr);
    if (it != m_suspiciousNodes.end() && Simulator::Now() <= it->second) {
        return true;
    }
    return false;
}

std::set<Ipv4Address> OlsrDefenseGcop::GetBlacklist() const {
    std::set<Ipv4Address> blacklist;
    // HARNESS INTEGRATION (OFF-guard): while disabled the truthful answer is
    // "no blacklist". The harness's ObserveAttackerOnPath queries this in
    // EVERY window (including OFF windows); an empty set keeps the oracle
    // trust proxy at 1.0, exactly as in the FPNT/Watchdog harnesses.
    if (!m_enabled) {
        return blacklist;
    }
    Time now = Simulator::Now();
    for (auto const& pair : m_suspiciousNodes) {
        if (now <= pair.second) {
            blacklist.insert(pair.first);
        }
    }
    return blacklist;
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
    // HARNESS INTEGRATION (OFF-guard): this is driven UNCONDITIONALLY every
    // 1 s by RoutingProtocol::HandleDefenseTimer, regardless of the Enabled
    // state. The GC below mutates state (map::erase plus a zero-value
    // operator[] insertion into m_violationCounter), and a disabled
    // strategy must accumulate / mutate nothing.
    if (!m_enabled) {
        return;
    }
    // Garbage collect expired blacklist entries: a previously flagged node
    // that has gone silent (or whose triggering attack has ended) is given
    // a chance to participate again.
    Time now = Simulator::Now();
    for (auto it = m_suspiciousNodes.begin(); it != m_suspiciousNodes.end(); ) {
        if (now > it->second) {
            NS_LOG_INFO("Node " << it->first << " is no longer suspicious "
                        "(penalty expired).");
            // Reset the strike counter too. Without this, the strike count
            // stays at >=STRIKES_BEFORE_BLACKLIST and the very next
            // isRisky=true would instantly re-blacklist, defeating the
            // purpose of the timed cooldown.
            m_violationCounter[it->first] = 0;
            it = m_suspiciousNodes.erase(it);
        } else {
            ++it;
        }
    }
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
    // The paper recommends the GCOP + GCOHP combination: GCOP handles the
    // standard 2-hop-coverage case (Section 5.1) while GCOHP catches the
    // hexagon edge case in which GCOP yields a false negative (Section 5.2).
    if (!RunGcopAlgorithm()) {
        return RunGcohpAlgorithm();
    }
    return true;
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
//                         ALL accumulated detection state, so the double
//                         toggle always leaves the object indistinguishable
//                         from a freshly loaded one with the slot's intended
//                         ON/OFF value;
//   * warmup re-anchor -- the enable leg re-arms m_enableTime so the full
//                         WARMUP_SECONDS run inside the slot's 60 s
//                         stabilization period (option C);
//   * scope            -- only defense-owned state is wiped. The Setup()
//                         wiring (m_routingProtocol, m_mainAddress) is
//                         untouched, and no RP/OLSR state is reset from here
//                         (stale MPR/route exclusions and expired tuples
//                         re-converge naturally within the stabilization
//                         window).
// ============================================================================

void OlsrDefenseGcop::SetEnabled(bool enabled) {
    // No-op guard (aligned with the Watchdog pattern): only a REAL
    // transition resets. The attribute default application at construction
    // (false -> false) and the harness's explicit Enabled=false at install
    // time both land here harmlessly.
    if (m_enabled == enabled) {
        return;
    }

    // FULL SYMMETRIC COLD START -- both directions.
    m_suspiciousNodes.clear();
    m_violationCounter.clear();

    m_enabled = enabled;

    if (m_enabled) {
        // Re-anchor the warmup window: the C-Rules stay silent for
        // WARMUP_SECONDS after EVERY enable, exactly like the original
        // single-activation design in which Setup() at t~0 made the
        // absolute-time check equivalent. Under option C this anchor lands
        // at the slot transition, so the full 45 s warmup completes inside
        // the 60 s stabilization period.
        m_enableTime = Simulator::Now();
    }

    NS_LOG_INFO("DCFM defense on " << m_mainAddress << " -> "
                << (m_enabled ? "ENABLED" : "DISABLED")
                << " (cold start: all detection state cleared)");
}

bool OlsrDefenseGcop::GetEnabled() const {
    return m_enabled;
}

OlsrDefenseGcop::DebugStateSizes OlsrDefenseGcop::GetDebugStateSizes() const {
    // RAW container sizes, deliberately NOT gated on m_enabled: immediately
    // after a cold start these MUST read zero on every node; any non-zero
    // value is direct evidence of a cross-window leak through defense state.
    DebugStateSizes s;
    s.suspiciousNodes  = m_suspiciousNodes.size();
    s.violationCounter = m_violationCounter.size();
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
    // HARNESS INTEGRATION (defensive double-guard): OnRecvHello already
    // gates, but this is the ONLY function that writes m_violationCounter /
    // m_suspiciousNodes -- guard it directly as well.
    if (!m_enabled) return;
    if (!m_routingProtocol) return;

    // Convergence warmup: Rule 2 and Rule 3 depend on a populated topology
    // set, which requires several TC rounds to stabilize.
    //
    // HARNESS INTEGRATION (warmup RE-ANCHOR): the check is anchored to
    // m_enableTime (the last OFF->ON transition) instead of absolute
    // simulation time. In the original single-activation design Setup() ran
    // at t~0, so the absolute check was equivalent; in the 4-window harness
    // every window starts at t>=60 and the absolute check would have been
    // permanently elapsed (the warmup would never run). Anchoring to the
    // enable instant restores the original semantics -- WARMUP_SECONDS of
    // topology-set settling after (re-)activation -- identically in every
    // defense-ON window. The duration is deliberately kept at the FULL
    // original 45 s (not shortened): under option C the anchor lands at the
    // slot transition, so warmup (45 s) + two-strike detection (~4 s) +
    // enforcement and OLSR re-convergence all complete by ~t0+51..56 s,
    // inside the 60 s stabilization period.
    if ((Simulator::Now() - m_enableTime).GetSeconds() < WARMUP_SECONDS) {
        return;
    }

    // Already blacklisted -> keep the existing penalty window intact.
    // We do not re-evaluate, so the penalty cannot be cleared by a single
    // clean HELLO sandwiched between attack HELLOs.
    if (IsMalicious(senderAddress)) {
        return;
    }

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
        m_violationCounter[senderAddress]++;
        if (m_violationCounter[senderAddress] >= STRIKES_BEFORE_BLACKLIST) {
            m_suspiciousNodes[senderAddress] = Simulator::Now() + PENALTY_DURATION;
            NS_LOG_UNCOND("[t=" << Simulator::Now().GetSeconds() << "s] BLACKLIST: "
              << m_mainAddress << " flagged " << senderAddress
              << " as MALICIOUS. Reason: " << violationReason);
        } else {
            NS_LOG_INFO("Node " << m_mainAddress << " observed first strike by "
                        << senderAddress << ". Reason: " << violationReason
                        << " (one more required before blacklist)");
        }
    } else {
        // Clean HELLO: drop both the blacklist entry (if any) and the
        // strike counter. Resetting the counter is the active ingredient
        // for FP filtering -- a legitimate node that triggered a single
        // rule once will not reach the strike threshold because the next
        // clean HELLO clears its count.
        auto it = m_suspiciousNodes.find(senderAddress);
        if (it != m_suspiciousNodes.end()) {
            m_suspiciousNodes.erase(it);
            NS_LOG_INFO("Node " << senderAddress << " cleared from blacklist.");
        }
        if (m_violationCounter.count(senderAddress)) {
            m_violationCounter[senderAddress] = 0;
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
    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();

    Ipv4Address fakeAddress(m_mainAddress.Get() + 65536);

    size_t asymmetricClaims = 0;
    for (const auto& twoHop : twoHopNeighbors) {
        if (twoHop.neighborMainAddr != senderAddress) continue;
        const Ipv4Address& claimedNeighbor = twoHop.twoHopNeighborAddr;

        // (a) Bait detection - fires immediately, no count threshold.
        //     Only meaningful when we actually advertise a fictitious node
        //     (C-Rules mode skips it).
        if (m_useFictitiousNodes && claimedNeighbor == fakeAddress) {
            outReason = "Rule 1a (Bait): claims link to our fictitious node";
            return true;
        }

        // (b) Count asymmetric claims on our real symmetric neighbors
        bool isMyDirectSymNeighbor = false;
        for (const auto& nei : neighbors) {
            if (nei.neighborMainAddr == claimedNeighbor &&
                nei.status == NeighborTuple::STATUS_SYM) {
                isMyDirectSymNeighbor = true;
                break;
            }
        }
        if (isMyDirectSymNeighbor) {
            bool linkVerified = false;
            for (const auto& verifyTwoHop : twoHopNeighbors) {
                if (verifyTwoHop.neighborMainAddr == claimedNeighbor &&
                    verifyTwoHop.twoHopNeighborAddr == senderAddress) {
                    linkVerified = true;
                    break;
                }
            }
            if (!linkVerified) {
                asymmetricClaims++;
            }
        }
    }

    if (asymmetricClaims >= MIN_ASYMMETRY_FOR_RULE1B) {
        outReason = "Rule 1b (Asymmetry): " + std::to_string(asymmetricClaims) +
                    " claimed neighbors do not confirm the link";
        return true;
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
    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology        = m_routingProtocol->GetTopologySet();

    // --- N = ADJ(x) ----------------------------------------------------------
    // Sender's claimed 1-hop neighbors, sourced from our 2-hop set entries
    // where the 1-hop side is the sender.
    std::set<Ipv4Address> groupN;
    for (const auto& th : twoHopNeighbors) {
        if (th.neighborMainAddr == senderAddress) {
            groupN.insert(th.twoHopNeighborAddr);
        }
    }
    if (groupN.empty()) {
        // Sender has not advertised any 1-hop neighbors to us yet;
        // nothing to check.
        return false;
    }

    // --- Pre-build an undirected topology adjacency for fast lookup ---------
    // Each TC tuple (lastAddr, destAddr) is treated as an undirected edge
    // for the purpose of "is m linked to z in topology?".
    //
    // FILTER: tuples whose originator (lastAddr) is already on our
    // blacklist are NOT incorporated. A confirmed link-spoofing attacker
    // pollutes the topology set with (lastAddr=attacker, destAddr=spoof)
    // tuples; if we trusted them, the spoof targets would appear in
    // groupZ when we later evaluate the attacker's legitimate 1-hop
    // neighbors (those neighbors necessarily claim the attacker as a
    // neighbor of theirs, so the attacker's polluted topology bleeds
    // into our evaluation of them), and Rule 2 would falsely fire on
    // those innocent bystanders. Skipping the polluted tuples breaks
    // this collateral-damage cascade.
    std::map<Ipv4Address, std::set<Ipv4Address>> topoAdj;
    size_t filteredTuples = 0;
    size_t totalTuples = 0;
    std::set<Ipv4Address> filteredOriginators;
    for (const auto& tp : topology) {
        totalTuples++;
        if (ENABLE_TOPOLOGY_FILTER && IsMalicious(tp.lastAddr)) {
            filteredTuples++;
            filteredOriginators.insert(tp.lastAddr);
            continue;
        }
        topoAdj[tp.lastAddr].insert(tp.destAddr);
        topoAdj[tp.destAddr].insert(tp.lastAddr);
    }
    if (filteredTuples > 0) {
        std::stringstream originators;
        for (const auto& a : filteredOriginators) originators << a << " ";
        NS_LOG_UNCOND("[t=" << Simulator::Now().GetSeconds() << "s] "
                      << "FILTER: node " << m_mainAddress
                      << " evaluating " << senderAddress
                      << " — skipped " << filteredTuples << "/" << totalTuples
                      << " topology tuples from blacklisted originators: "
                      << originators.str());
    }

    // --- Z = ADJ2(x), and M = MPR'(x) ----------------------------------------
    // Z: candidate 2-hop neighbors of x = topology-neighbors of N.
    // M: MPR'(x) = advertisers of tuples whose destAddr is x.
    //
    // Same FILTER as above: skip tuples originated by blacklisted nodes,
    // so the attacker's polluted state does not feed into Z or M.
    std::set<Ipv4Address> groupZ;
    std::set<Ipv4Address> groupM;
    for (const auto& tp : topology) {
        if (ENABLE_TOPOLOGY_FILTER && IsMalicious(tp.lastAddr)) continue;
        if (groupN.count(tp.lastAddr) > 0) {
            groupZ.insert(tp.destAddr);
        }
        if (groupN.count(tp.destAddr) > 0) {
            groupZ.insert(tp.lastAddr);
        }
        if (tp.destAddr == senderAddress) {
            groupM.insert(tp.lastAddr);
        }
    }

    // Z must be a strict 2-hop of x: remove x's 1-hops (N), our own 1-hops,
    // x itself, and us.
    for (const auto& n : groupN) groupZ.erase(n);
    for (const auto& nei : neighbors) groupZ.erase(nei.neighborMainAddr);
    groupZ.erase(senderAddress);
    groupZ.erase(m_mainAddress);

    if (groupZ.empty()) {
        // No apparent 2-hop neighbors to verify; rule trivially holds.
        return false;
    }

    // --- Coverage sweep ------------------------------------------------------
    // If x has 2-hop neighbors but no MPRs at all, OLSR would not function
    // -- contradiction.
    if (groupM.empty()) {
        outReason = "Rule 2 (No MPRs): claims " + std::to_string(groupZ.size()) +
                    " 2-hop neighbors but no MPR selectors";
        return true;
    }

    // For each z in Z, demand that some m in M is linked to z in topology.
    std::set<Ipv4Address> uncovered;
    for (const auto& z : groupZ) {
        bool covered = false;
        auto zAdj = topoAdj.find(z);
        if (zAdj != topoAdj.end()) {
            for (const auto& m : groupM) {
                if (zAdj->second.count(m) > 0) {
                    covered = true;
                    break;
                }
            }
        }
        if (!covered) {
            uncovered.insert(z);
        }
    }

    if (uncovered.size() >= MIN_UNCOVERED_FOR_RULE2) {
        outReason = "Rule 2 (MPR-coverage): " + std::to_string(uncovered.size()) +
                    " 2-hop nodes claimed by sender are not reachable through "
                    "any of its MPR selectors";
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
    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology        = m_routingProtocol->GetTopologySet();

    // Our own 1-hop set (ADJ(v))
    std::set<Ipv4Address> oneHopSet;
    for (const auto& nei : neighbors) {
        oneHopSet.insert(nei.neighborMainAddr);
    }

    // senderReachable = ADJ(x) \ ADJ(v)
    std::set<Ipv4Address> senderReachable;
    for (const auto& th : twoHopNeighbors) {
        if (th.neighborMainAddr == senderAddress &&
            th.twoHopNeighborAddr != m_mainAddress) {
            senderReachable.insert(th.twoHopNeighborAddr);
        }
    }
    for (const auto& a : oneHopSet) senderReachable.erase(a);

    // netTargets = (V \ {us}) \ ADJ(v), approximated by destAddrs of
    // topology tuples that we did not originate, minus our 1-hops.
    std::set<Ipv4Address> netTargets;
    for (const auto& tp : topology) {
        if (tp.lastAddr != m_mainAddress) {
            netTargets.insert(tp.destAddr);
        }
    }
    for (const auto& a : oneHopSet) netTargets.erase(a);
    netTargets.erase(m_mainAddress);
    netTargets.erase(senderAddress);

    if (netTargets.size() < MIN_NETWORK_SIZE_FOR_RULE3) {
        // Topology too small for this rule to be statistically meaningful.
        return false;
    }

    if (senderReachable.size() >= netTargets.size()) {
        outReason = "Rule 3 (Over-coverage): claims " +
                    std::to_string(senderReachable.size()) +
                    " distinct non-neighbors out of " +
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
// Algorithm 2 (GCOHP) - paper Section 5.2
//
// Detects the hexagon-of-nodes topology that is a false negative for GCOP.
//
// Detection conditions (paper Section 5.2):
//   1. Two green-blue edges (g', b'), (g'', b'') in E_3
//   2. g' != g'' AND b' != b''
//   3. No chords: (g', g''), (b', b''), (g', b''), (g'', b') not in E_3
//   4. A closer exists: either
//      a) some yellow y with (b', y) and (b'', y) in E_3, OR
//      b) some third blue b with (b', b), (b'', b) in E_3
//         AND no edge (g', b), (g'', b) in E_3
// ============================================================================
bool OlsrDefenseGcop::RunGcohpAlgorithm() {
    if (!m_routingProtocol) return false;

    const auto& neighbors       = m_routingProtocol->GetNeighbors();
    const auto& twoHopNeighbors = m_routingProtocol->GetTwoHopNeighbors();
    const auto& topology        = m_routingProtocol->GetTopologySet();

    // Step 1: build GREEN (ADJ(s)) and BLUE (ADJ2(s)) sets --------------------
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

    if (greens.size() < 2 || blues.size() < 2) {
        // Need at least 2 greens and 2 blues to form a hexagon.
        return false;
    }

    // Step 2: derive yellow set (ADJ3(s)) from the topology set ---------------
    // A yellow is a topology node adjacent to one of our blues but not
    // green/blue/us itself.
    std::set<Ipv4Address> yellows;
    for (const auto& tp : topology) {
        if (blues.count(tp.lastAddr)) {
            yellows.insert(tp.destAddr);
        }
        if (blues.count(tp.destAddr)) {
            yellows.insert(tp.lastAddr);
        }
    }
    yellows.erase(m_mainAddress);
    for (const auto& g : greens) yellows.erase(g);
    for (const auto& b : blues)  yellows.erase(b);

    std::set<Ipv4Address> allowedNodes;
    allowedNodes.insert(greens.begin(),  greens.end());
    allowedNodes.insert(blues.begin(),   blues.end());
    allowedNodes.insert(yellows.begin(), yellows.end());

    // Step 3: build the restricted adjacency graph (G_3 minus s) --------------
    std::map<Ipv4Address, std::set<Ipv4Address>> graph;
    for (const auto& n : allowedNodes) {
        graph[n];
    }
    for (const auto& th : twoHopNeighbors) {
        const Ipv4Address& u = th.neighborMainAddr;
        const Ipv4Address& v = th.twoHopNeighborAddr;
        if (allowedNodes.count(u) && allowedNodes.count(v)) {
            graph[u].insert(v);
            graph[v].insert(u);
        }
    }
    for (const auto& tp : topology) {
        const Ipv4Address& u = tp.lastAddr;
        const Ipv4Address& v = tp.destAddr;
        if (allowedNodes.count(u) && allowedNodes.count(v)) {
            graph[u].insert(v);
            graph[v].insert(u);
        }
    }

    // Step 4: enumerate green-blue edges E_gb ---------------------------------
    std::vector<std::pair<Ipv4Address, Ipv4Address>> E_gb; // (green, blue)
    for (const auto& g : greens) {
        for (const auto& b : blues) {
            if (graph[g].count(b)) {
                E_gb.push_back({g, b});
            }
        }
    }

    // Step 5: search pairs of distinct E_gb edges for the hexagon pattern -----
    for (size_t i = 0; i < E_gb.size(); ++i) {
        for (size_t j = i + 1; j < E_gb.size(); ++j) {
            const Ipv4Address& gp  = E_gb[i].first;
            const Ipv4Address& bp  = E_gb[i].second;
            const Ipv4Address& gpp = E_gb[j].first;
            const Ipv4Address& bpp = E_gb[j].second;

            // Condition 2: distinct nodes across the two edges
            if (gp == gpp || bp == bpp) continue;
            if (gp == bpp || gpp == bp) continue;

            // Condition 3: no chords inside the would-be hexagon
            if (graph[gp].count(gpp))  continue;
            if (graph[bp].count(bpp))  continue;
            if (graph[gp].count(bpp))  continue;
            if (graph[gpp].count(bp))  continue;

            // Condition 4a: closing via a yellow node
            for (const auto& y : yellows) {
                if (y == gp || y == gpp || y == bp || y == bpp) continue;
                if (graph[bp].count(y) && graph[bpp].count(y)) {
                    NS_LOG_INFO("GCOHP: hexagon detected (yellow closer=" << y
                                << ") for node " << m_mainAddress
                                << ". Fictitious node REQUIRED.");
                    return true;
                }
            }

            // Condition 4b: closing via a third blue node
            for (const auto& b : blues) {
                if (b == bp || b == bpp) continue;
                if (!graph[bp].count(b))  continue;
                if (!graph[bpp].count(b)) continue;
                if (graph[gp].count(b))   continue;
                if (graph[gpp].count(b))  continue;
                NS_LOG_INFO("GCOHP: hexagon detected (blue closer=" << b
                            << ") for node " << m_mainAddress
                            << ". Fictitious node REQUIRED.");
                return true;
            }
        }
    }

    NS_LOG_DEBUG("GCOHP: no hexagon topology detected for " << m_mainAddress);
    return false;
}

} // namespace olsr
} // namespace ns3