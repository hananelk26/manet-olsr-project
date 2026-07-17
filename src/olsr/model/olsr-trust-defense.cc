/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 * olsr-trust-defense.cc
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "olsr-trust-defense.h"

#include "olsr-routing-protocol.h"
#include "defense/olsr-alert-distributor.h"
#include "defense/olsr-consistency-rules.h"
#include "defense/olsr-forward-monitor.h"
#include "defense/olsr-provable-identity.h"
#include "defense/olsr-trust-state.h"

#include "ns3/boolean.h"
#include "ns3/log.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

#include <sstream>

namespace ns3
{
namespace olsr
{

NS_LOG_COMPONENT_DEFINE("OlsrTrustDefense");
NS_OBJECT_ENSURE_REGISTERED(OlsrTrustDefense);

TypeId
OlsrTrustDefense::GetTypeId()
{
    // Defaults below MUST match OlsrTrustDefenseConfig (the canonical config location).
    static TypeId tid =
        TypeId("ns3::olsr::OlsrTrustDefense")
            .SetParent<OlsrDefenseStrategy>()
            .SetGroupName("Olsr")
            .AddConstructor<OlsrTrustDefense>()
            // --- per-sub-module enables ---
            .AddAttribute("EnableForwardMonitor",
                          "Enable the Formula-10 black-hole forward monitor.",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableForwardMonitor),
                          MakeBooleanChecker())
            .AddAttribute("EnableConsistencyRules",
                          "Enable the complementary consistency checks (Formulas 6,7,9b).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableConsistencyRules),
                          MakeBooleanChecker())
            .AddAttribute("EnableProvableIdentity",
                          "Enable SOLSR provable identity (Formula 13, stub, off by default).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableProvableIdentity),
                          MakeBooleanChecker())
            .AddAttribute("EnableAlertDistribution",
                          "Enable §7 trust-alert distribution (idealized bus; propagates falsifiable "
                          "consistency detections 6/7/8/12 network-wide, NOT black-hole Formula 10).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableAlertDistribution),
                          MakeBooleanChecker())
            // --- forward monitor (Formula 10) ---
            .AddAttribute("ForwardTimeout",
                          "Awaiting period to overhear an MPR re-forward a TC/DATA before failure.",
                          TimeValue(Seconds(3.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_forwardTimeout),
                          MakeTimeChecker())
            .AddAttribute("CheckInterval",
                          "Granularity of the forward-failure expiry sweep.",
                          TimeValue(Seconds(0.25)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_checkInterval),
                          MakeTimeChecker())
            .AddAttribute("MonitorData",
                          "Watch DATA forwarding (DATAx branch of Formula 10).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_monitorData),
                          MakeBooleanChecker())
            .AddAttribute("MonitorTc",
                          "Watch TC forwarding (TCx branch of Formula 10).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_monitorTc),
                          MakeBooleanChecker())
            .AddAttribute("MonitorRelayedData",
                          "Also watch data x merely RELAYS (generalized watchdog); default false "
                          "== faithful Formula 10 (only DATAx originated by x).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_monitorRelayedData),
                          MakeBooleanChecker())
            .AddAttribute("StrictMacAttribution",
                          "Only clear a DATA record when the overheard transmitter MAC resolves to "
                          "the expected MPR (default lenient).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_strictMacAttribution),
                          MakeBooleanChecker())
            .AddAttribute("MinForwardFailures",
                          "Consecutive observed forward-failures before mistrust (1 == paper-exact, "
                          "fragile against transient wireless loss).",
                          UintegerValue(3),
                          MakeUintegerAccessor(&OlsrTrustDefense::m_minForwardFailures),
                          MakeUintegerChecker<uint32_t>(1))
            // --- trust state / countermeasures (Formula 15) ---
            .AddAttribute("ResponseEnabled",
                          "If false, DETECTION-ONLY: detect+log but IsMalicious() stays false so the "
                          "topology is never perturbed (measure detection in isolation).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_responseEnabled),
                          MakeBooleanChecker())
            .AddAttribute("MistrustPermanent",
                          "Exact mistrust is permanent; if false it is temporary (rehabilitatable).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_mistrustPermanent),
                          MakeBooleanChecker())
            .AddAttribute("MistrustDuration",
                          "Rehabilitation window for temporary mistrust (MistrustPermanent=false).",
                          TimeValue(Seconds(60.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_mistrustDuration),
                          MakeTimeChecker());
    return tid;
}

OlsrTrustDefense::OlsrTrustDefense()
    : m_proto(nullptr),
      m_setupDone(false),
      m_relayHintActive(false),
      m_relayHintUid(0)
{
    // Initialise the attribute mirror from the canonical struct defaults; the
    // ns-3 attribute system overwrites these with the (matching) AddAttribute
    // defaults or any user override during ConstructSelf().
    OlsrTrustDefenseConfig d;
    m_forwardTimeout = d.forwardTimeout;
    m_checkInterval = d.checkInterval;
    m_monitorData = d.monitorData;
    m_monitorTc = d.monitorTc;
    m_monitorRelayedData = d.monitorRelayedData;
    m_strictMacAttribution = d.strictMacAttribution;
    m_minForwardFailures = d.minForwardFailures;
    m_responseEnabled = d.responseEnabled;
    m_mistrustPermanent = d.mistrustPermanent;
    m_mistrustDuration = d.mistrustDuration;
    m_enableForwardMonitor = d.enableForwardMonitor;
    m_enableConsistencyRules = d.enableConsistencyRules;
    m_enableProvableIdentity = d.enableProvableIdentity;
    m_enableAlertDistribution = d.enableAlertDistribution;
}

OlsrTrustDefense::~OlsrTrustDefense() = default;

OlsrTrustDefenseConfig
OlsrTrustDefense::BuildConfig() const
{
    OlsrTrustDefenseConfig c;
    c.enableForwardMonitor = m_enableForwardMonitor;
    c.enableConsistencyRules = m_enableConsistencyRules;
    c.enableProvableIdentity = m_enableProvableIdentity;
    c.enableAlertDistribution = m_enableAlertDistribution;
    c.forwardTimeout = m_forwardTimeout;
    c.checkInterval = m_checkInterval;
    c.monitorData = m_monitorData;
    c.monitorTc = m_monitorTc;
    c.monitorRelayedData = m_monitorRelayedData;
    c.strictMacAttribution = m_strictMacAttribution;
    c.minForwardFailures = m_minForwardFailures;
    c.responseEnabled = m_responseEnabled;
    c.mistrustPermanent = m_mistrustPermanent;
    c.mistrustDuration = m_mistrustDuration;
    return c;
}

void
OlsrTrustDefense::SetConfig(const OlsrTrustDefenseConfig& cfg)
{
    m_cfg = cfg;
    // keep the attribute mirror in sync so a later Setup() BuildConfig() agrees.
    m_enableForwardMonitor = cfg.enableForwardMonitor;
    m_enableConsistencyRules = cfg.enableConsistencyRules;
    m_enableProvableIdentity = cfg.enableProvableIdentity;
    m_enableAlertDistribution = cfg.enableAlertDistribution;
    m_forwardTimeout = cfg.forwardTimeout;
    m_checkInterval = cfg.checkInterval;
    m_monitorData = cfg.monitorData;
    m_monitorTc = cfg.monitorTc;
    m_monitorRelayedData = cfg.monitorRelayedData;
    m_strictMacAttribution = cfg.strictMacAttribution;
    m_minForwardFailures = cfg.minForwardFailures;
    m_responseEnabled = cfg.responseEnabled;
    m_mistrustPermanent = cfg.mistrustPermanent;
    m_mistrustDuration = cfg.mistrustDuration;
}

void
OlsrTrustDefense::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
{
    m_proto = proto;
    m_self = nodeAddress;
    if (m_setupDone)
    {
        return; // ReactivateDefenseStrategy() may call Setup() again; keep accumulated state.
    }

    m_cfg = BuildConfig();
    NS_LOG_INFO("node " << m_self << " trust defense setup (forwardMonitor="
                        << m_cfg.enableForwardMonitor << " consistency=" << m_cfg.enableConsistencyRules
                        << " response=" << m_cfg.responseEnabled << ")");

    m_trust = std::make_unique<OlsrTrustState>(m_cfg, m_self);
    m_identity = std::make_unique<OlsrProvableIdentity>(m_cfg);

    if (m_cfg.enableForwardMonitor)
    {
        m_forward = std::make_unique<OlsrForwardMonitor>(
            m_cfg, m_proto, m_self,
            [this](Ipv4Address mpr, ForwardFailureType t, uint32_t c, Time now) {
                OnForwardFailure(mpr, t, c, now);
            });
        m_forward->Start();
    }

    if (m_cfg.enableAlertDistribution)
    {
        // Created whenever distribution is on, so this node can RECEIVE alerts even
        // if its own consistency detection is disabled. Announcing still requires a
        // local consistency detection (which needs enableConsistencyRules).
        m_alert = std::make_unique<OlsrAlertDistributor>(
            m_self, [this](Ipv4Address accused, const std::string& f, Ipv4Address accuser, Time now) {
                OnAlertReceived(accused, f, accuser, now);
            });
        m_alert->Start();
    }

    if (m_cfg.enableConsistencyRules)
    {
        m_consistency = std::make_unique<OlsrConsistencyRules>(
            m_cfg, m_proto, m_self,
            [this](const std::set<Ipv4Address>& g, bool e, const std::string& f, const std::string& r,
                   const ConsistencyProof& proof, Time now) {
                OnConsistencyMistrust(g, e, f, r, proof, now);
            });
    }

    m_setupDone = true;
}

void
OlsrTrustDefense::DoDispose()
{
    if (m_forward)
    {
        m_forward->Stop();
    }
    if (m_alert)
    {
        m_alert->Stop(); // unregister from the process-wide bus (critical across runs).
    }
    m_forward.reset();
    m_consistency.reset();
    m_identity.reset();
    m_alert.reset();
    m_trust.reset();
    m_proto = nullptr;
    m_setupDone = false;
}

bool
OlsrTrustDefense::IsMalicious(Ipv4Address addr)
{
    // RESPONSE side: only exact mistrust triggers a countermeasure, and only when
    // response is enabled (detection-only mode returns false here while still logging).
    return m_cfg.responseEnabled && m_trust && m_trust->IsExactMistrusted(addr);
}

std::set<Ipv4Address>
OlsrTrustDefense::GetBlacklist() const
{
    // DETECTION side: always reflects what was detected, regardless of response, so
    // detection performance can be measured independently of the countermeasure.
    return m_trust ? m_trust->GetMistrusted() : std::set<Ipv4Address>{};
}

void
OlsrTrustDefense::OnRecvHello(Ipv4Address,
                              Ptr<const Packet>,
                              const MessageHeader& msg,
                              const MessageHeader::Hello& hello)
{
    if (m_consistency)
    {
        m_consistency->OnRecvHello(msg.GetOriginatorAddress(), hello, Simulator::Now());
    }
}

void
OlsrTrustDefense::OnRecvTc(Ipv4Address,
                           Ptr<const Packet>,
                           const MessageHeader& msg,
                           const MessageHeader::Tc& tc)
{
    if (m_consistency)
    {
        m_consistency->OnRecvTc(msg.GetOriginatorAddress(), tc, Simulator::Now());
    }
}

void
OlsrTrustDefense::OnTcGenerated(const MessageHeader::Tc&)
{
    if (m_forward)
    {
        m_forward->OnTcGenerated(Simulator::Now());
    }
}

void
OlsrTrustDefense::OnDataPacketReceived(Ptr<const Packet> packet,
                                       Ipv4Address,
                                       Ipv4Address,
                                       Ipv4Address)
{
    // RouteInput relay path: the next OnDataPacketForwarded for this UID is a RELAY,
    // not an origination. Tag it so the forward monitor honours the DATAx scope.
    m_relayHintActive = true;
    m_relayHintUid = packet->GetUid();
}

void
OlsrTrustDefense::OnDataPacketForwarded(Ptr<const Packet> packet,
                                        Ipv4Address nextHop,
                                        Ipv4Address finalDest)
{
    bool originatedHere = true;
    if (m_relayHintActive && m_relayHintUid == packet->GetUid())
    {
        originatedHere = false;
    }
    m_relayHintActive = false;
    if (m_forward)
    {
        m_forward->OnDataForward(packet, nextHop, finalDest, originatedHere, Simulator::Now());
    }
}

void
OlsrTrustDefense::OnDataPacketDropped(Ptr<const Packet> packet,
                                      Ipv4Address,
                                      Ipv4Address,
                                      DropReason)
{
    m_relayHintActive = false;
    if (m_forward)
    {
        m_forward->OnLocalDrop(packet); // we dropped it ourselves: do not blame an MPR.
    }
}

void
OlsrTrustDefense::OnNeighborForwardedPacket(Mac48Address transmitter,
                                            Mac48Address receiver,
                                            Ptr<const Packet> packet)
{
    if (m_forward)
    {
        m_forward->OnOverheard(transmitter, receiver, packet, Simulator::Now());
    }
}

void
OlsrTrustDefense::OnForwardFailure(Ipv4Address mpr, ForwardFailureType type, uint32_t, Time now)
{
    // Internal forward-failure (the paper's "x ->8 TC/DATA" event) -> Formula (10).
    const std::string formula = (type == ForwardFailureType::Data) ? "10-DATA" : "10-TC";
    const std::string reason = (type == ForwardFailureType::Data)
                                   ? "selected MPR did not forward DATA I originated within the awaiting period"
                                   : "selected MPR did not re-flood a TC I originated within the awaiting period";
    if (m_trust)
    {
        m_trust->MistrustExact(mpr, formula, reason, now);
    }
}

bool
OlsrTrustDefense::IsAnnounceable(const std::string& formula)
{
    // Only consistency detections with a third-party-verifiable proof (paper §7).
    return formula == "6" || formula == "7" || formula == "8" || formula == "12";
}

void
OlsrTrustDefense::OnConsistencyMistrust(const std::set<Ipv4Address>& group,
                                        bool exact,
                                        const std::string& formula,
                                        const std::string& reason,
                                        const ConsistencyProof& proof,
                                        Time now)
{
    if (!m_trust)
    {
        return;
    }
    if (exact && !group.empty())
    {
        m_trust->MistrustExact(*group.begin(), formula, reason, now);
        // §7: share the falsifiable proof so distant nodes that could not detect
        // locally also mistrust the attacker. Black-hole (Formula 10) is never
        // announced (no provable artifact); 9b is local-only (not third-party verifiable).
        if (m_alert && IsAnnounceable(formula))
        {
            m_alert->Announce(proof, now);
        }
    }
    else
    {
        m_trust->MistrustPartial(group, formula, reason, now);
    }
}

void
OlsrTrustDefense::OnAlertReceived(Ipv4Address accused,
                                  const std::string& formula,
                                  Ipv4Address accuser,
                                  Time now)
{
    if (m_trust)
    {
        std::ostringstream r;
        r << "trust alert (Formula " << formula << ") from " << accuser;
        m_trust->MistrustExact(accused, "ALERT-" + formula, r.str(), now);
    }
}

void
OlsrTrustDefense::PeriodicCheck()
{
    Time now = Simulator::Now();
    if (m_trust)
    {
        m_trust->Expire(now);
    }
    if (m_consistency)
    {
        m_consistency->PeriodicCheck(now);
    }
}

} // namespace olsr
} // namespace ns3
