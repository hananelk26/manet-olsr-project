#ifndef OLSR_DEFENSE_GCOP_H
#define OLSR_DEFENSE_GCOP_H

#include "olsr-defense-strategy.h"
#include "ns3/timer.h"

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
     * \brief Blacklist: address -> expiration time.
     *        Entries are pruned by PeriodicCheck() once now > expiration.
     */
    std::map<Ipv4Address, Time> m_suspiciousNodes;

    /**
     * \brief Consecutive-violation counter (2-strike policy).
     *
     * Increments on every isRisky=true and resets to 0 on isRisky=false.
     * Blacklist is applied only when the count reaches the configured
     * strike threshold, which filters out one-shot transient violations
     * (e.g., a single asymmetric-view contradiction caused by a HELLO
     * lost over a marginal MAC link).
     */
    std::map<Ipv4Address, uint32_t> m_violationCounter;
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_DEFENSE_GCOP_H */