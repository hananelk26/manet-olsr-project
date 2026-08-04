/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef OLSR_DEFENSE_FPNT_H
#define OLSR_DEFENSE_FPNT_H

#include "olsr-defense-strategy.h"
#include "ns3/nstime.h"
#include "ns3/mac48-address.h"
#include <cstddef>
#include <map>
#include <vector>

namespace ns3 {
namespace olsr {

/**
 * \brief FPNT-OLSR Trust Reasoning Mechanism.
 *
 * Full implementation of the trust based routing mechanism described in:
 *     Tan, Li, Dong (2015). "Trust based routing mechanism for securing
 *     OLSR-based MANET", Ad Hoc Networks 30, pp. 84-98.
 *
 * This class implements:
 *   - The four trust factors (Section 5.1 / Definitions 1-4):
 *       * Load                    (p1 / p2)   -- DoS victim signature
 *       * Packet Forwarding Rate  (p3 / p4)   -- blackhole signature
 *       * Average Forwarding Delay(p5 / p6)   -- jellyfish signature
 *       * Protocol Deviation Flag (p7 / p8)   -- routing-plane signature
 *
 *   - The seven fuzzy rules producing 15 propositions and 11 transitions
 *     (Section 3.2 / Figure 2):
 *       * R1: IF p1 OR p4 OR p5 THEN p9
 *       * R2: IF p2 AND p5 THEN p10
 *       * R3: IF p7 THEN p11
 *       * R4: IF p3 AND p6 AND p2 THEN p12
 *       * R5: IF p8 THEN p13
 *       * R6: IF p9 OR p10 OR p11 THEN p14
 *       * R7: IF p12 AND p13 THEN p15
 *
 *   - The matrix-based reasoning algorithm (Algorithm 1).
 *   - The pairwise L1 slander-filter aggregation (Equations 1-3).
 *   - Equation (4) trust synthesis: T = E_trust + beta * E_uncertain.
 *   - Equation (5) temporal smoothing with correct first-period bootstrap.
 *   - The trust-based routing algorithm (Algorithm 2) is implemented in
 *     RoutingProtocol::RunTrustDijkstra and queries this class via
 *     GetNodeTrust.
 *
 * Architecture note:
 *   This class is passive regarding scheduling. The RoutingProtocol invokes
 *   PeriodicCheck() once per TrustUpdateInterval ('t' in Section 5.1).
 */
class OlsrDefenseFpnt : public OlsrDefenseStrategy
{
public:
  static TypeId GetTypeId (void);

  OlsrDefenseFpnt ();
  virtual ~OlsrDefenseFpnt ();

  // ======================================================================
  // Setup & Lifecycle
  // ======================================================================
  virtual void Setup (RoutingProtocol* proto, Ipv4Address nodeAddress) override;
  virtual void DoDispose () override;

  // ======================================================================
  // Trust Query Methods (Routing Integration)
  // ======================================================================
  virtual bool IsMalicious (Ipv4Address addr) override;
  virtual std::set<Ipv4Address> GetBlacklist () const override;
  virtual std::vector<EvaluationVector> GetEvaluationVectors (
      const std::vector<Ipv4Address> &neighbors) override;
  virtual double GetNodeTrust (Ipv4Address node) override;
  virtual bool IsTrustRoutingEnabled () const override { return m_enabled; }

/**
   * @brief Toggle the defense state with symmetric cold-start semantics.
   *
   * On EVERY state transition (disabled->enabled and enabled->disabled),
   * every piece of accumulated state is wiped so neither phase can carry
   * residue from the other. Hooks fire regardless of m_enabled and
   * PeriodicCheck only clears the per-period containers
   * (m_metrics/m_recommendations/m_pendingArrivals), so without the
   * symmetric wipe an enabled-phase trust table or the longer-lived
   * D1/D2 bookkeeping (m_lastTcTime, m_mprSelectionTime,
   * m_directEvaluationVectors, m_lastSValues) would leak into the
   * subsequent phase. No-op calls (same value passed twice) are skipped.
   */
  void SetEnabled (bool enabled);
  bool GetEnabled () const;

  // ======================================================================
  // Read-only state introspection (harness leak-verification, point 6).
  //
  // Reports the current sizes of every accumulated-state container plus the
  // derived blacklist size. Used ONLY by the evaluation harness to verify,
  // at the start of each measurement window, that the window-boundary cold
  // start emptied the defense state (all fields must be 0 right after the
  // reset). Strictly const and side-effect-free; does not participate in the
  // trust algorithm in any way.
  // ======================================================================
  struct DebugStateSizes
  {
    std::size_t metrics                 = 0;
    std::size_t trustTable              = 0;
    std::size_t directEvaluationVectors = 0;
    std::size_t lastSValues             = 0;
    std::size_t recommendations         = 0;
    std::size_t pendingArrivals         = 0;   // # neighbours with pending arrivals
    std::size_t lastTcTime              = 0;
    std::size_t mprSelectionTime        = 0;
    std::size_t blacklist               = 0;   // derived: nodes below threshold
  };
  DebugStateSizes GetDebugStateSizes () const;

  // ======================================================================
  // Incoming Message Handlers (Trust Propagation, Section 5.2)
  // ======================================================================
  virtual void OnRecvEvaluationVectors (
      Ipv4Address sender,
      const std::vector<Ipv4Address> &advertisedNeighbors,
      const std::vector<EvaluationVector> &vectors) override;

  virtual void OnRecvHello (Ipv4Address senderAddress,
                            Ptr<const Packet> packet,
                            const MessageHeader& msg,
                            const MessageHeader::Hello& hello) override;

  virtual void OnRecvTc (Ipv4Address senderIfaceAddr,
                         Ptr<const Packet> packet,
                         const MessageHeader& msg,
                         const MessageHeader::Tc& tc) override;

  virtual void OnTcGenerated (const MessageHeader::Tc& tc) override;

  // ======================================================================
  // Monitoring & Metric Collection (Section 5.1)
  //
  // Hook wiring summary:
  //   OnDataPacketReceived       -> load accumulation and arrival timestamp
  //                                 recording for delay measurement
  //   OnDataPacketForwarded      -> PFR denominator (Count^j_rcv) and
  //                                 arrival timestamp recording
  //   OnNeighborForwardedPacket  -> PFR numerator (Count^j_fwd) and
  //                                 delay-departure matching
  //   OnRecvTc                   -> deviation-flag D1/D2 monitoring
  //   OnDataPacketDropped, OnQueueStatusReport,
  //   OnEnergyStateUpdate, OnMacTxFailure
  //                              -> out of scope for the paper's model
  // ======================================================================
  virtual void OnDataPacketReceived (Ptr<const Packet> packet,
                                     Ipv4Address source,
                                     Ipv4Address destination,
                                     Ipv4Address nextHop) override;

  virtual void OnDataPacketForwarded (const Ipv4Header &header,
                                      Ptr<const Packet> packet,
                                      Ipv4Address nextHop,
                                      Ipv4Address finalDest) override;

  virtual void OnDataPacketDropped (Ptr<const Packet> packet,
                                    Ipv4Address source,
                                    Ipv4Address destination,
                                    DropReason reason) override;

  virtual void OnNeighborForwardedPacket (Mac48Address transmitter,
                                          Mac48Address receiver,
                                          Ptr<const Packet> packet) override;

  virtual void OnQueueStatusReport (uint32_t size, uint32_t capacity) override;
  virtual void OnEnergyStateUpdate (double remainingEnergyJoules,
                                    double energyFraction) override;
  virtual void OnMacTxFailure (Ipv4Address neighbor, uint32_t count) override;

  /**
   * \brief Execute one full trust reasoning cycle.
   *
   * Performs, in order:
   *   1. Protocol-deviation rule D1 scan (silent MPR detection, Section 5.1.D).
   *   2. Expiration of unmatched delay-measurement arrivals.
   *   3. Fresh direct evaluations from observed metrics for every monitored
   *      neighbor (Algorithm 1).
   *   4. Aggregation of direct evaluation plus received recommendations
   *      via pairwise L1 slander filtering (Equations 1-3).
   *   5. Equation (4) trust synthesis followed by Equation (5) temporal
   *      smoothing (with correct first-period bootstrap).
   *   6. Reactive reroute notification if any neighbor has crossed the
   *      malicious threshold in this period.
   */
  virtual void PeriodicCheck () override;

private:
  RoutingProtocol* m_protocol;

  // ----------------------------------------------------------------------
  // Per-neighbor behavioral counters -- all four factors (Section 5.1).
  // ----------------------------------------------------------------------
  struct NodeBehaviorMetrics
  {
    uint32_t countLoad;   // Bytes of received traffic (Count^j_load).
    uint32_t countRcv;    // Packets V_j is expected to forward (Count^j_rcv).
    uint32_t countFwd;    // Packets observed to be forwarded by V_j (Count^j_fwd).
    uint32_t countRCheat; // Routing-plane deviations (Count^j_rcheat).
    double   totalDelay;  // Sum of forwarding delays (seconds) for matched
                          // packets (accumulator for average forwarding delay).

    NodeBehaviorMetrics ()
      : countLoad (0), countRcv (0), countFwd (0),
        countRCheat (0), totalDelay (0.0) {}
  };

  // Per-period metric counters, one entry per monitored neighbor.
  std::map<Ipv4Address, NodeBehaviorMetrics> m_metrics;

  // Aggregated trust value T(V_j) for every known node in the network.
  std::map<Ipv4Address, double> m_trustTable;

  // Latest direct evaluation vectors (piggybacked onto outgoing TC messages).
  std::map<Ipv4Address, EvaluationVector> m_directEvaluationVectors;

  // Persistence store for S^(0) across periods. Prevents an attacker from
  // resetting its trust by going silent between evaluations.
  std::map<Ipv4Address, std::vector<double>> m_lastSValues;

  std::map<std::pair<Ipv4Address, Ipv4Address>, EvaluationVector> m_recommendations;


  // ----------------------------------------------------------------------
  // Delay-measurement bookkeeping (Definition 3).
  //
  // When we observe a packet arrive at neighbor V_j, we record
  // arrival_time[V_j][uid] = now. When we later observe V_j transmit a
  // packet with the same UID, we compute delay = now - arrival_time and
  // add it to totalDelay[V_j]. Unmatched arrivals are expired during
  // PeriodicCheck to prevent unbounded growth.
  // ----------------------------------------------------------------------
  struct PendingArrival
  {
    Time arrivalTime;
  };
  std::map<Ipv4Address, std::map<uint64_t, PendingArrival>> m_pendingArrivals;

  // ----------------------------------------------------------------------
  // Deviation-flag (D1) bookkeeping: last-seen TC time per originator.
  // D1 fires when an MPR of this node has not emitted a TC within
  // OLSR_TOP_HOLD_TIME = 3 * tcInterval.
  // ----------------------------------------------------------------------
  std::map<Ipv4Address, Time> m_lastTcTime;

  std::map<Ipv4Address, Time> m_mprSelectionTime;

  // Node's own main address, cached from Setup() for D2 self-omission check.
  Ipv4Address m_selfAddress;

  // ----------------------------------------------------------------------
  // Reasoning parameters (all exposed as ns-3 attributes).
  // ----------------------------------------------------------------------
  Time   m_checkInterval;       // Trust update period 't'.
  double m_maliciousThreshold;  // Node is malicious iff T(V_j) < this.
  double m_uncertaintyBeta;     // Eq. (4): T = E_trust + beta * E_uncertain.
  double m_fadingFactor;        // Eq. (5): lambda in temporal smoothing.
  double m_maxLoad;             // NORM normalizer for load, bits/s (Def. 10).
  double m_maxDelay;            // NORM normalizer for avg delay, seconds.
  uint32_t m_cheatThreshold;    // delta in Section 5.1.D.
  bool   m_enabled;             // Runtime toggle: when false the defense
                                // becomes a transparent no-op (every node
                                // reports as non-malicious, trust routing
                                // disabled, PeriodicCheck skipped). Allows
                                // multi-phase scenarios to enable/disable
                                // defense without rebuilding the stack.

  // ----------------------------------------------------------------------
  // Helpers (implementation in .cc).
  // ----------------------------------------------------------------------
  std::vector<double> MetricsToS0 (Ipv4Address addr,
                                   const NodeBehaviorMetrics& metrics);

  EvaluationVector RunFuzzyPetriNet (const std::vector<double>& s0) const;

  /**
   * \brief Apply Equations (1)-(3): pairwise L1 DIF slander filtering.
   *
   * The direct evaluation (when present) is expected to be included as
   * one element of \p evs by the caller. The paper treats direct and
   * indirect evaluations identically during aggregation.
   */
  void AggregateEvaluations (const std::vector<EvaluationVector>& evs,
                             double& outTrust,
                             double& outUncertain) const;

  /**
   * \brief Protocol-deviation Rule D1 scan (Section 5.1.D, silent-MPR case).
   *
   * For every neighbor currently in this node's MPR set, check whether a
   * TC has been received within OLSR_TOP_HOLD_TIME. If not, increment
   * the routing-cheat counter for that MPR.
   */
  void ScanDeviationRuleD1 ();

  /**
   * \brief Expire unmatched delay arrivals older than 2 * trust interval.
   */
  void ExpireStaleArrivals ();

  // Fuzzy Petri Net matrix operators (Definitions 5, 6, 7).
  std::vector<double> MatrixOp_Threshold (
      const std::vector<double>& input,
      const std::vector<double>& threshold) const;

  std::vector<double> MatrixOp_Max (
      const std::vector<double>& a,
      const std::vector<double>& b) const;

  std::vector<double> MatrixOp_WeightedMax (
      const std::vector<std::vector<double>>& U,
      const std::vector<double>& G) const;

  Ipv4Address MacToIpv4 (Mac48Address mac);
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_DEFENSE_FPNT_H */