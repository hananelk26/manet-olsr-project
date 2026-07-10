#ifndef OLSR_DEFENSE_GCOP_H
#define OLSR_DEFENSE_GCOP_H

#include "olsr-defense-strategy.h"
#include "ns3/timer.h"
// HARNESS INTEGRATION: explicit includes for the ON/OFF switch additions
// (Time for the warmup anchor, std::size_t for DebugStateSizes).
#include "ns3/nstime.h"

#include <cstddef>
#include <map>
#include <set>
#include <string>

namespace ns3 {
namespace olsr {

class RoutingProtocol;

/**
 * \brief Defense strategy implementing the algorithms from
 *        Schweitzer et al., "Achieving MANET protection without the use of
 *        superfluous fictitious nodes" (Computer Communications, 2024).
 *
 * The strategy combines three mechanisms from the paper, faithful to the
 * reference DCFM / IMP implementation:
 *
 *   1. Three contradiction rules ("C-Rules", paper Section 3.5.1) applied
 *      on every received HELLO message. Each rule independently can mark
 *      the sender as malicious:
 *        - Rule 1: asymmetry on a real neighbor, plus a "bait" extension
 *                  that catches an attacker that swallows our own
 *                  fictitious node.
 *        - Rule 2: MPR-coverage contradiction. The sender claims a 2-hop
 *                  neighborhood that its declared MPR selectors cannot
 *                  cover via the topology set.
 *        - Rule 3: over-coverage. The sender claims to reach essentially
 *                  every non-1-hop node we know about.
 *
 *   2. GCOP (Algorithm 1) - depth-2 BFS fictitious-node decision (paper
 *      Section 5.1).
 *
 *   3. GCOHP (Algorithm 2) - hexagon topology detection (paper Section 5.2),
 *      used as a fallback when GCOP returns false, matching the paper's
 *      recommended "GCOP + GCOHP" combination.
 *
 * Detection results feed into the routing protocol's blacklist, which
 * (a) excludes blacklisted neighbors from MPR computation, and
 * (b) drops data packets whose next-hop is blacklisted (IMP enforcement
 *     against gray-/black-hole forwarding attacks).
 *
 * Local additions on top of the paper, for robustness in simulation:
 *   - Warmup window before any rule is evaluated.
 *   - 2-strike confirmation policy to filter transient false positives.
 *   - Time-windowed blacklist with periodic garbage collection.
 *   - Evaluation-harness integration: a dynamic Enabled switch (ns-3
 *     attribute, default false) performing a FULL SYMMETRIC cold-start
 *     reset on every real ON/OFF transition, with the warmup window
 *     re-anchored to the enable instant, plus a read-only DebugStateSizes
 *     audit. While disabled the strategy is fully inert: it accumulates no
 *     state, reports no node as malicious, returns an empty blacklist and
 *     never requests a fictitious node.
 */
class OlsrDefenseGcop : public OlsrDefenseStrategy {
public:
    static TypeId GetTypeId(void);
    OlsrDefenseGcop();
    virtual ~OlsrDefenseGcop();

    // --- Setup and lifecycle ---
    virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
    virtual void DoDispose() override;

    // --- Blacklist queries ---
    virtual bool IsMalicious(Ipv4Address addr) override;
    virtual std::set<Ipv4Address> GetBlacklist() const override;

    // ======================================================================
    // HARNESS INTEGRATION: dynamic ON/OFF switch + symmetric cold start
    // ======================================================================
    /**
     * \brief Enable/disable the defense at runtime (the "Enabled" attribute).
     *
     * No-op guard: a call that does not change the state returns immediately
     * (so a redundant SetAttribute("Enabled", ...) mid-window cannot wipe
     * live state, and the attribute system's application of the default at
     * construction is harmless).
     *
     * Symmetric cold start: EVERY real transition -- enable->disable AND
     * disable->enable -- wipes all accumulated detection state
     * (m_riskyNodes). The harness's ForceDefenseColdStart() double-toggle
     * therefore always produces exactly two real transitions and a guaranteed
     * full wipe, restoring the slot's intended ON/OFF value.
     *
     * Wipes ONLY defense-owned state; the Setup() wiring
     * (m_routingProtocol, m_mainAddress) is intentionally untouched.
     */
    void SetEnabled(bool enabled);

    /// \return Current ON/OFF state (the "Enabled" attribute getter).
    bool GetEnabled() const;

    /**
     * \brief Raw sizes of every accumulated-state container.
     *
     * Read-only diagnostics for the harness's --debugDefenseState audit.
     * The sizes are RAW container sizes, deliberately NOT gated on
     * m_enabled: a print taken immediately after a cold start must read all
     * zeros, and any non-zero value is direct evidence of a cross-window
     * leak through defense state.
     */
    struct DebugStateSizes
    {
        std::size_t riskyNodes;  //!< |m_riskyNodes| (currently-flagged senders)
    };
    DebugStateSizes GetDebugStateSizes() const;
    // ======================================================================

    // --- Control plane hooks ---
    virtual void OnRecvHello(Ipv4Address senderAddress,
                             Ptr<const Packet> packet,
                             const MessageHeader& msg,
                             const MessageHeader::Hello& hello) override;

    // --- Periodic and fictitious-node decision ---
    virtual void PeriodicCheck() override;
    virtual bool RequiresFictitiousNode() override;

    // --- Data plane hooks (used for logging / IMP audit trail) ---
    virtual void OnDataPacketReceived(Ptr<const Packet> packet, Ipv4Address source,
                                      Ipv4Address destination, Ipv4Address nextHop) override;
    virtual void OnDataPacketForwarded(Ptr<const Packet> packet, Ipv4Address nextHop,
                                       Ipv4Address finalDest) override;

    // --- Unused interface methods (empty implementations) ---
    virtual void OnRecvTc(Ipv4Address, Ptr<const Packet>,
                          const MessageHeader&, const MessageHeader::Tc&) override {}
    virtual void OnTcGenerated(const MessageHeader::Tc&) override {}
    virtual void OnDataPacketDropped(Ptr<const Packet>, Ipv4Address, Ipv4Address,
                                     DropReason) override {}
    virtual void OnNeighborForwardedPacket(Mac48Address, Mac48Address,
                                           Ptr<const Packet>) override {}
    virtual void OnQueueStatusReport(uint32_t, uint32_t) override {}
    virtual void OnEnergyStateUpdate(double, double) override {}
    virtual void OnMacTxFailure(Ipv4Address, uint32_t) override {}
    virtual void OnSelfReliabilityReport(uint32_t) override {}
    virtual void OnRtsReceived(Mac48Address, Mac48Address) override {}
    virtual void OnCtsReceived(Mac48Address) override {}

private:
    // --- Fictitious-node decision (paper Section 5) ---
    /**
     * \brief Algorithm 1 (GCOP) - BFS up to depth 2 inside the subgraph
     *        G_2 of green and blue nodes (excluding s).
     * \return true if a fictitious node is required.
     */
    bool RunGcopAlgorithm();

    /**
     * \brief Algorithm 2 (GCOHP) - hexagon detection in the subgraph
     *        G_3 of green, blue and yellow nodes (excluding s).
     * \return true if the current node is part of a hexagon pattern.
     */
    bool RunGcohpAlgorithm();

    // --- C-Rules (paper Section 3.5.1) ---
    /**
     * \brief Master rule engine. Runs Rule 1, then Rule 2, then Rule 3 on
     *        the given sender; applies the 2-strike / penalty / GC logic.
     */
    void EvaluateContradictionRules(Ipv4Address senderAddress);

    /**
     * \brief Rule 1 - asymmetry on a real neighbor, with bait extension.
     *        Sets outReason if it fires.
     * \return true on rule violation.
     */
    bool CheckRule1(Ipv4Address senderAddress, std::string& outReason);

    /**
     * \brief Rule 2 - MPR-coverage contradiction.
     *        The sender's claimed 2-hop neighborhood must be reachable
     *        through its declared MPR selectors per the topology set.
     * \return true on rule violation.
     */
    bool CheckRule2(Ipv4Address senderAddress, std::string& outReason);

    /**
     * \brief Rule 3 - over-coverage. The sender claims ADJ(x) to be a
     *        superset of V \ ADJ(v).
     * \return true on rule violation.
     */
    bool CheckRule3(Ipv4Address senderAddress, std::string& outReason);

    /**
     * \brief Convenience predicate: do we currently have any blacklisted
     *        1-hop neighbor?  (kept for external callers; the algorithms
     *        do not use it internally.)
     */
    bool HasKnownMaliciousNeighbor();

    // --- State ---
    RoutingProtocol* m_routingProtocol;   //!< Back-reference to the OLSR protocol instance.
    Ipv4Address m_mainAddress;            //!< This node's main OLSR address.
    double m_startTime;                   //!< Sim time at which Setup() was called.

    /**
     * \brief Currently-flagged senders (reference DCFM, instantaneous).
     *
     * PROF PORT: replaces the previous time-windowed blacklist
     * (m_suspiciousNodes) + strike counter (m_violationCounter). Reference
     * DCFM has no penalty window and no strike threshold: a sender is flagged
     * iff it violates a contradiction rule on its LATEST HELLO, and unflagged
     * the moment a clean HELLO arrives. EvaluateContradictionRules() refreshes
     * this set on every HELLO (insert on violation, erase on clean), mirroring
     * the professor's `NeighborTuple::risky` field which is recomputed from
     * scratch on each PopulateTwoHopNeighborSet() call.
     */
    std::set<Ipv4Address> m_riskyNodes;

    // ======================================================================
    // HARNESS INTEGRATION state
    // ======================================================================
    /**
     * \brief Dynamic ON/OFF switch ("Enabled" attribute). Default false.
     *
     * Gates every state-mutating handler (OnRecvHello /
     * EvaluateContradictionRules, PeriodicCheck), every on-air behavior
     * source (RequiresFictitiousNode) and every RP-facing query
     * (IsMalicious, GetBlacklist), so a disabled strategy is fully inert
     * and a defense-OFF window is indistinguishable from a clean baseline.
     */
    bool m_enabled;

    /**
     * \brief Fictitious-node switch ("UseFictitiousNodes" attribute). Default true.
     *
     * true  = full paper mechanism: RequiresFictitiousNode() runs the
     *         GCOP/GCOHP decision and the Rule-1 bait sub-check is active.
     * false = paper "C-Rules": no fictitious node is advertised and the bait
     *         sub-check is skipped. The three contradiction rules run in both
     *         modes; this flag never disables a rule.
     */
    bool m_useFictitiousNodes;
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_DEFENSE_GCOP_H */