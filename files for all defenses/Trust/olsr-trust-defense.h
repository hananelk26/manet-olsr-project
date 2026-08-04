/*
 * Trust-based OLSR defense (Adnane, Bidan, de Sousa, Computer Communications 36, 2013)
 *
 * olsr-trust-defense.h -- concrete OlsrDefenseStrategy implementing the paper's
 * black-hole detection (Formula 10) plus complementary consistency checks and
 * the Formula 15 countermeasure. It OWNS and wires four independently toggleable
 * sub-modules and exposes every knob through one config (OlsrTrustDefenseConfig)
 * mirrored as ns-3 TypeId Attributes.
 *
 *   forward_monitor     -> Formula (10)  (black-hole core, priority 1)
 *   trust_state         -> MN_x, Formula (15) verdict / detection log
 *   consistency_rules   -> Formulas (6),(7),(8),(9),(12)
 *   provable_identity   -> Section 6 / Formula (13)  (off by default)
 *
 * Detection (recording a mistrust) is kept separate from response (IsMalicious
 * driving the routing-core countermeasures), so detection can be measured in
 * isolation via the ResponseEnabled=false "detection-only" mode.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_TRUST_DEFENSE_H
#define OLSR_TRUST_DEFENSE_H

#include "olsr-defense-strategy.h"
#include "defense/olsr-trust-config.h"
#include "defense/olsr-forward-monitor.h"   // for ForwardFailureType in the failure callback
#include "defense/olsr-alert-distributor.h" // for ConsistencyProof

#include "ns3/nstime.h"

#include <cstdint>
#include <memory>

namespace ns3
{
namespace olsr
{

class OlsrForwardMonitor;
class OlsrTrustState;
class OlsrConsistencyRules;
class OlsrProvableIdentity;
class OlsrAlertDistributor;

/**
 * \ingroup olsr
 * \brief Trust-based black-hole defense for OLSR (Adnane et al. 2013).
 */
class OlsrTrustDefense : public OlsrDefenseStrategy
{
  public:
    static TypeId GetTypeId();
    OlsrTrustDefense();
    ~OlsrTrustDefense() override;

    /// Programmatic access to the single config location (alternative to attributes).
    void SetConfig(const OlsrTrustDefenseConfig& cfg);
    const OlsrTrustDefenseConfig& GetConfig() const { return m_cfg; }

    /// Detection log access (for precision/recall measurement, independent of response).
    const OlsrTrustState* GetTrustState() const { return m_trust.get(); }

    // ---- OlsrDefenseStrategy interface ----
    void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
    void DoDispose() override;

    bool IsMalicious(Ipv4Address addr) override;
    std::set<Ipv4Address> GetBlacklist() const override;

    void OnRecvHello(Ipv4Address senderAddress,
                     Ptr<const Packet> packet,
                     const MessageHeader& msg,
                     const MessageHeader::Hello& hello) override;
    void OnRecvTc(Ipv4Address senderIfaceAddr,
                  Ptr<const Packet> packet,
                  const MessageHeader& msg,
                  const MessageHeader::Tc& tc) override;
    void OnTcGenerated(const MessageHeader::Tc& tc) override;

    void OnDataPacketReceived(Ptr<const Packet> packet,
                              Ipv4Address source,
                              Ipv4Address destination,
                              Ipv4Address nextHop) override;
    void OnDataPacketForwarded(Ptr<const Packet> packet,
                               Ipv4Address nextHop,
                               Ipv4Address finalDest) override;
    void OnDataPacketDropped(Ptr<const Packet> packet,
                             Ipv4Address source,
                             Ipv4Address destination,
                             DropReason reason) override;

    void OnNeighborForwardedPacket(Mac48Address transmitter,
                                   Mac48Address receiver,
                                   Ptr<const Packet> packet) override;

    // Cross-layer hooks feed OTHER (FPNT/ML) defenses; the trust defense ignores them.
    void OnQueueStatusReport(uint32_t, uint32_t) override {}
    void OnEnergyStateUpdate(double, double) override {}
    void OnMacTxFailure(Ipv4Address, uint32_t) override {}
    void OnSelfReliabilityReport(uint32_t) override {}
    void OnRtsReceived(Mac48Address, Mac48Address) override {}
    void OnCtsReceived(Mac48Address) override {}

    void PeriodicCheck() override;
    bool RequiresFictitiousNode() override { return false; }

  private:
    OlsrTrustDefenseConfig BuildConfig() const;
    /// Internal forward-failure handler -> Formula (10) decision.
    void OnForwardFailure(Ipv4Address mpr, ForwardFailureType type, uint32_t consecutive, Time now);
    /// Consistency-rule mistrust handler (exact or partial); announces if proof is falsifiable.
    void OnConsistencyMistrust(const std::set<Ipv4Address>& group,
                               bool exact,
                               const std::string& formula,
                               const std::string& reason,
                               const ConsistencyProof& proof,
                               Time now);
    /// Accept a (re-verified) alert from the bus -> mistrust the accused.
    void OnAlertReceived(Ipv4Address accused, const std::string& formula, Ipv4Address accuser, Time now);
    /// Whether a consistency formula carries a third-party-verifiable proof (alert set {6,7,8,12}).
    static bool IsAnnounceable(const std::string& formula);

    RoutingProtocol* m_proto;
    Ipv4Address m_self;
    bool m_setupDone;

    OlsrTrustDefenseConfig m_cfg; //!< THE single config (mirrors the attribute members below).

    std::unique_ptr<OlsrForwardMonitor> m_forward;
    std::unique_ptr<OlsrTrustState> m_trust;
    std::unique_ptr<OlsrConsistencyRules> m_consistency;
    std::unique_ptr<OlsrProvableIdentity> m_identity;
    std::unique_ptr<OlsrAlertDistributor> m_alert;

    // one-shot hint: the next OnDataPacketForwarded is a RELAY of this UID, not an origination.
    bool m_relayHintActive;
    uint64_t m_relayHintUid;

    // ---- attribute-backed mirror of OlsrTrustDefenseConfig (defaults match the struct) ----
    Time m_forwardTimeout;
    Time m_checkInterval;
    bool m_monitorData;
    bool m_monitorTc;
    bool m_monitorRelayedData;
    bool m_strictMacAttribution;
    uint32_t m_minForwardFailures;
    bool m_responseEnabled;
    bool m_mistrustPermanent;
    Time m_mistrustDuration;
    bool m_enableForwardMonitor;
    bool m_enableConsistencyRules;
    bool m_enableProvableIdentity;
    bool m_enableAlertDistribution;
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_TRUST_DEFENSE_H */
