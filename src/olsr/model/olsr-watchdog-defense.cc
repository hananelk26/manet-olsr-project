/*
 * Cross-Layer Cooperative Watchdog Defense for OLSR - Implementation.
 * See olsr-watchdog-defense.h for design rationale.
 */

#include "olsr-watchdog-defense.h"
#include "olsr-routing-protocol.h"

#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/llc-snap-header.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/node-list.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"
#include "ns3/wifi-mac.h"
#include "ns3/wifi-net-device.h"

#include <algorithm>

namespace ns3 {
namespace olsr {

NS_LOG_COMPONENT_DEFINE("OlsrWatchdogDefense");

NS_OBJECT_ENSURE_REGISTERED(OlsrWatchdogDefense);

// ============================================================================
// TypeId / ctor / dtor
// ============================================================================

TypeId
OlsrWatchdogDefense::GetTypeId()
{
    static TypeId tid = TypeId("ns3::olsr::OlsrWatchdogDefense")
        .SetParent<OlsrDefenseStrategy>()
        .SetGroupName("Olsr")
        .AddConstructor<OlsrWatchdogDefense>()
        .AddAttribute("ForwardTimeout",
                      "Time to wait for a neighbor to retransmit a forwarded "
                      "packet before suspecting misbehavior. Set generously "
                      "to tolerate transient queueing on a busy channel - "
                      "the watchdog already has multiple corroborating "
                      "signals (RTS/CTS, MAC failures) so a longer window "
                      "primarily reduces false positives.",
                      TimeValue(MilliSeconds(500)),
                      MakeTimeAccessor(&OlsrWatchdogDefense::m_forwardTimeout),
                      MakeTimeChecker())
        .AddAttribute("PeriodicInterval",
                      "Interval between PeriodicCheck() invocations.",
                      TimeValue(Seconds(1.0)),
                      MakeTimeAccessor(&OlsrWatchdogDefense::m_periodicInterval),
                      MakeTimeChecker())
        .AddAttribute("WarmupDuration",
                      "Grace period after Setup() during which we observe "
                      "but never accuse. Allows the MAC<->IP map (learned "
                      "from OLSR broadcasts) to populate, and lets in-flight "
                      "packets at activation time drain without producing "
                      "spurious evidence.",
                      TimeValue(Seconds(15.0)),
                      MakeTimeAccessor(&OlsrWatchdogDefense::m_warmupDuration),
                      MakeTimeChecker())
        .AddAttribute("BlacklistThreshold",
                      "Evidence count required to blacklist a neighbor "
                      "(scaled up when self-reliability drops). Each missed "
                      "forward contributes 1 unit; the RTS-without-DATA "
                      "heuristic contributes 2. Higher values trade off "
                      "detection speed for false-positive resistance.",
                      UintegerValue(3),
                      MakeUintegerAccessor(&OlsrWatchdogDefense::m_blacklistThreshold),
                      MakeUintegerChecker<uint32_t>())
        .AddAttribute("RtsToDataRatioThreshold",
                      "RTS:DATA ratio above which a neighbor is considered "
                      "suspicious (heuristic for attackers hidden by receiver "
                      "being out of our range).",
                      DoubleValue(3.0),
                      MakeDoubleAccessor(&OlsrWatchdogDefense::m_rtsToDataRatioThresh),
                      MakeDoubleChecker<double>(0.0))
        .AddAttribute("SelfDropsThreshold",
                      "Local PHY drop count per window above which our own "
                      "observations are considered less reliable.",
                      UintegerValue(5),
                      MakeUintegerAccessor(&OlsrWatchdogDefense::m_selfDropsThreshold),
                      MakeUintegerChecker<uint32_t>())
        .AddAttribute("MacFailureThreshold",
                      "MAC TX failure count above which we suppress blame "
                      "for the neighbor (can't blame what never received).",
                      UintegerValue(3),
                      MakeUintegerAccessor(&OlsrWatchdogDefense::m_macFailureThreshold),
                      MakeUintegerChecker<uint32_t>())
        .AddAttribute("MinRtsForHeuristic",
                      "Minimum RTS count from a neighbor (with no DATA) before "
                      "applying the 'too many RTS = attacker' heuristic.",
                      UintegerValue(5),
                      MakeUintegerAccessor(&OlsrWatchdogDefense::m_minRtsForHeuristic),
                      MakeUintegerChecker<uint32_t>())
        .AddAttribute("MinSelfReliability",
                      "Floor value for self-reliability score; prevents it "
                      "from dropping so low that detection becomes impossible.",
                      DoubleValue(0.6),
                      MakeDoubleAccessor(&OlsrWatchdogDefense::m_minSelfReliability),
                      MakeDoubleChecker<double>(0.01, 1.0))
        .AddAttribute("ProbationDuration",
                      "Once accumulated evidence crosses the blacklist threshold, "
                      "the neighbor enters probation for this duration. Only if "
                      "misbehavior persists beyond probation does blacklisting "
                      "commit. Filters out transient burst losses.",
                      TimeValue(Seconds(2.0)),
                      MakeTimeAccessor(&OlsrWatchdogDefense::m_probationDuration),
                      MakeTimeChecker())
        .AddAttribute("MacFailureRateThreshold",
                      "Fraction of packets to a neighbor that fail at MAC layer "
                      "above which we deem the link itself unhealthy and refuse "
                      "to blacklist. Prevents accusing neighbors when the "
                      "wireless link is just bad. Range [0, 1].",
                      DoubleValue(0.4),
                      MakeDoubleAccessor(&OlsrWatchdogDefense::m_macFailureRateThresh),
                      MakeDoubleChecker<double>(0.0, 1.0))
        .AddAttribute("MinDataObservations",
                      "Minimum number of DATA frames we must have heard from a "
                      "neighbor (via promiscuous sniffer) before considering it "
                      "for blacklisting. Distinguishes 'silent neighbor' "
                      "(may be out of range / link-broken) from 'misbehaving "
                      "neighbor' (forwards some traffic but drops ours).",
                      UintegerValue(2),
                      MakeUintegerAccessor(&OlsrWatchdogDefense::m_minDataObservations),
                      MakeUintegerChecker<uint32_t>())
        .AddAttribute("Enabled",
                      "Master on/off switch. When false the defense is a no-op: "
                      "IsMalicious() always returns false and PeriodicCheck() "
                      "skips evidence aggregation. Allows toggling defenses at "
                      "phase boundaries without swapping the defense pointer. "
                      "Re-enabling resets the warmup window and clears in-flight "
                      "evidence, so packets in transit at toggle time do not "
                      "produce spurious accusations.",
                      BooleanValue(true),
                      MakeBooleanAccessor(&OlsrWatchdogDefense::SetEnabled,
                                          &OlsrWatchdogDefense::IsEnabled),
                      MakeBooleanChecker());
    return tid;
}

OlsrWatchdogDefense::OlsrWatchdogDefense()
    : m_protocol(nullptr),
      m_setupDone(false),
      m_selfDropsWindow(0),
      m_selfReliabilityScore(1.0),
      m_warmupUntil(Seconds(0)),
      m_enabled(true)
{
    NS_LOG_FUNCTION(this);
}

OlsrWatchdogDefense::~OlsrWatchdogDefense()
{
    NS_LOG_FUNCTION(this);
}

// ============================================================================
// Lifecycle
// ============================================================================

void
OlsrWatchdogDefense::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
{
    NS_LOG_FUNCTION(this << nodeAddress);

    if (m_setupDone)
    {
        NS_LOG_DEBUG("Setup called twice on node " << nodeAddress
                     << " - rescheduling timer only.");
    }
    m_protocol = proto;
    m_mainAddress = nodeAddress;

    // Locate our Node so we can hook the WiFi trace sources.
    Ptr<Node> node = FindOwnNode();
    if (!node)
    {
        NS_LOG_WARN("Defense on " << m_mainAddress
                    << ": could not locate own Node; MAC sniffer disabled.");
    }
    else
    {
        AttachWifiTraces(node);
    }

    // Schedule the first periodic check; subsequent ones reschedule themselves.
    if (m_periodicEvent.IsPending())
    {
        Simulator::Cancel(m_periodicEvent);
    }
    m_periodicEvent = Simulator::Schedule(m_periodicInterval,
                                          &OlsrWatchdogDefense::PeriodicCheck,
                                          this);

    // Arm the warmup window. Until Now+m_warmupDuration we will collect
    // observations and learn neighbor MAC<->IP mappings, but will NOT
    // accumulate evidence or blacklist anyone.
    m_warmupUntil = Simulator::Now() + m_warmupDuration;
    NS_LOG_INFO("Defense on " << m_mainAddress
                << ": warmup until t=" << m_warmupUntil.GetSeconds() << "s");

    m_setupDone = true;
    NS_LOG_INFO("OlsrWatchdogDefense active on node " << m_mainAddress);
}

void
OlsrWatchdogDefense::DoDispose()
{
    NS_LOG_FUNCTION(this);

    if (m_periodicEvent.IsPending())
    {
        Simulator::Cancel(m_periodicEvent);
    }

    // Critical: disconnect WiFi PHY traces so callbacks no longer fire
    // into a destroyed object. Safe to call even if AttachWifiTraces
    // was never run (m_attachedPhys is just empty).
    DetachWifiTraces();

    m_pendingByNeighbor.clear();
    m_neighborStats.clear();
    m_macToIp.clear();
    m_blacklist.clear();
    m_protocol = nullptr;
}

Ptr<Node>
OlsrWatchdogDefense::FindOwnNode() const
{
    // First try the aggregation chain of the routing protocol.
    if (m_protocol)
    {
        Ptr<Node> n = m_protocol->GetObject<Node>();
        if (n)
        {
            return n;
        }
    }
    // Fallback: scan NodeList for a node owning m_mainAddress.
    for (uint32_t i = 0; i < NodeList::GetNNodes(); ++i)
    {
        Ptr<Node> candidate = NodeList::GetNode(i);
        Ptr<Ipv4> ipv4 = candidate->GetObject<Ipv4>();
        if (!ipv4)
        {
            continue;
        }
        if (ipv4->GetInterfaceForAddress(m_mainAddress) >= 0)
        {
            return candidate;
        }
    }
    return nullptr;
}

void
OlsrWatchdogDefense::AttachWifiTraces(Ptr<Node> node)
{
    // Defensive: make sure we don't double-attach if someone calls Setup() twice.
    DetachWifiTraces();

    for (uint32_t i = 0; i < node->GetNDevices(); ++i)
    {
        Ptr<WifiNetDevice> wifiDev = DynamicCast<WifiNetDevice>(node->GetDevice(i));
        if (!wifiDev)
        {
            continue;
        }

        // Remember our own MAC so SnifferRxCallback can filter self-originated frames.
        m_myMacAddress = Mac48Address::ConvertFrom(wifiDev->GetAddress());

        Ptr<WifiPhy> phy = wifiDev->GetPhy();
        if (!phy)
        {
            continue;
        }

        phy->TraceConnectWithoutContext(
            "MonitorSnifferRx",
            MakeCallback(&OlsrWatchdogDefense::SnifferRxCallback, this));

        phy->TraceConnectWithoutContext(
            "PhyRxDrop",
            MakeCallback(&OlsrWatchdogDefense::PhyRxDropCallback, this));

        m_attachedPhys.push_back(phy);
    }
}

void
OlsrWatchdogDefense::DetachWifiTraces()
{
    for (Ptr<WifiPhy> phy : m_attachedPhys)
    {
        if (!phy) continue;
        phy->TraceDisconnectWithoutContext(
            "MonitorSnifferRx",
            MakeCallback(&OlsrWatchdogDefense::SnifferRxCallback, this));
        phy->TraceDisconnectWithoutContext(
            "PhyRxDrop",
            MakeCallback(&OlsrWatchdogDefense::PhyRxDropCallback, this));
    }
    m_attachedPhys.clear();
}

// ============================================================================
// Public API consumed by OLSR for enforcement
// ============================================================================

bool
OlsrWatchdogDefense::IsMalicious(Ipv4Address addr)
{
    // When disabled, the defense is a transparent no-op: report nothing.
    if (!m_enabled) return false;
    return m_blacklist.find(addr) != m_blacklist.end();
}

std::set<Ipv4Address>
OlsrWatchdogDefense::GetBlacklist() const
{
    if (!m_enabled) return {};
    return m_blacklist;
}

void
OlsrWatchdogDefense::SetEnabled(bool enabled)
{
    NS_LOG_FUNCTION(this << enabled);

    const bool turningOn = (!m_enabled && enabled);
    m_enabled = enabled;

    if (turningOn)
    {
        // On the false->true transition, restart the observation period from
        // scratch. Otherwise pending packets sent before the toggle would
        // immediately time out and produce evidence based on a period in
        // which we were not even watching.
        m_pendingByNeighbor.clear();
        m_neighborStats.clear();
        m_selfDropsWindow = 0;
        m_selfReliabilityScore = 1.0;
        m_warmupUntil = Simulator::Now() + m_warmupDuration;
        NS_LOG_INFO("Defense on " << m_mainAddress
                    << " ENABLED at t=" << Simulator::Now().GetSeconds()
                    << "s, warmup until t=" << m_warmupUntil.GetSeconds() << "s");
    }
    else if (!enabled)
    {
        NS_LOG_INFO("Defense on " << m_mainAddress
                    << " DISABLED at t=" << Simulator::Now().GetSeconds() << "s");
    }
}

// ============================================================================
// Unused hooks (documented NO-OPs)
// ============================================================================

void OlsrWatchdogDefense::OnRecvHello(Ipv4Address, Ptr<const Packet>,
                                      const MessageHeader&,
                                      const MessageHeader::Hello&) {}
void OlsrWatchdogDefense::OnRecvTc(Ipv4Address, Ptr<const Packet>,
                                   const MessageHeader&,
                                   const MessageHeader::Tc&) {}
void OlsrWatchdogDefense::OnTcGenerated(const MessageHeader::Tc&) {}

// We deliberately ignore OnDataPacketReceived: OLSR fires both
// OnDataPacketReceived AND OnDataPacketForwarded for a forwarded packet,
// so tracking via OnDataPacketForwarded alone avoids double-counting.
void OlsrWatchdogDefense::OnDataPacketReceived(Ptr<const Packet>, Ipv4Address,
                                               Ipv4Address, Ipv4Address) {}

void OlsrWatchdogDefense::OnDataPacketDropped(Ptr<const Packet>, Ipv4Address,
                                              Ipv4Address, DropReason) {}

void OlsrWatchdogDefense::OnQueueStatusReport(uint32_t, uint32_t) {}
void OlsrWatchdogDefense::OnEnergyStateUpdate(double, double) {}
bool OlsrWatchdogDefense::RequiresFictitiousNode() { return false; }

// ============================================================================
// Data plane hooks (core of detection)
// ============================================================================

void
OlsrWatchdogDefense::OnDataPacketForwarded(Ptr<const Packet> packet,
                                            Ipv4Address nextHop,
                                            Ipv4Address finalDest)
{
    NS_LOG_FUNCTION(this << nextHop << finalDest);

    // Skip degenerate cases where there is no forwarder to monitor.
    if (nextHop == m_mainAddress)
    {
        return;
    }
    if (nextHop == finalDest)
    {
        return; // Direct delivery: the neighbor IS the destination.
    }
    if (nextHop == Ipv4Address::GetBroadcast() ||
        nextHop == Ipv4Address::GetAny() ||
        nextHop.IsMulticast())
    {
        return;
    }
    if (IsMalicious(nextHop))
    {
        return; // Already blacklisted; OLSR shouldn't have picked it, but be safe.
    }

    PendingPacket pp;
    pp.packetUid = packet->GetUid();
    pp.finalDest = finalDest;
    pp.sentTime = Simulator::Now();
    m_pendingByNeighbor[nextHop].push_back(pp);

    NeighborStats& s = m_neighborStats[nextHop];
    s.packetsSentTo++;
    s.lastActivityTime = Simulator::Now();
}

void
OlsrWatchdogDefense::OnMacTxFailure(Ipv4Address neighbor, uint32_t count)
{
    NS_LOG_FUNCTION(this << neighbor << count);

    if (neighbor == Ipv4Address() ||
        neighbor == Ipv4Address::GetBroadcast() ||
        neighbor.IsMulticast())
    {
        return;
    }

    NeighborStats& s = m_neighborStats[neighbor];
    s.macTxFailures += count;

    // The neighbor never received the packet -> cannot be blamed for it.
    // Best-effort: drop the oldest pending entry for this neighbor, which
    // is the most likely victim of the TX failure (FIFO heuristic).
    auto it = m_pendingByNeighbor.find(neighbor);
    if (it != m_pendingByNeighbor.end() && !it->second.empty())
    {
        it->second.erase(it->second.begin());
    }
}

// ============================================================================
// MAC promiscuous layer (sniffer callbacks)
// ============================================================================

void
OlsrWatchdogDefense::SnifferRxCallback(Ptr<const Packet> pkt,
                                       uint16_t /*channelFreqMhz*/,
                                       WifiTxVector /*txVector*/,
                                       MpduInfo /*aMpdu*/,
                                       SignalNoiseDbm /*signalNoise*/,
                                       uint16_t /*staId*/)
{
    if (!pkt)
    {
        return;
    }

    Ptr<Packet> copy = pkt->Copy();
    WifiMacHeader hdr;
    if (!copy->PeekHeader(hdr))
    {
        return;
    }

    // Control frames (RTS / CTS) need special handling: we must not try to
    // parse them as data (no LLC / IP payload).
    if (hdr.IsRts())
    {
        Mac48Address tx = hdr.GetAddr2();
        Mac48Address rx = hdr.GetAddr1();
        if (tx == m_myMacAddress)
        {
            return;
        }
        OnRtsReceived(tx, rx);
        return;
    }
    if (hdr.IsCts())
    {
        // In CTS, Addr1 is the node that had sent the matching RTS.
        Mac48Address rx = hdr.GetAddr1();
        OnCtsReceived(rx);
        return;
    }
    if (!hdr.IsData())
    {
        return; // ACK, management, etc. - not interesting here.
    }

    // Data frame: determine sender / receiver.
    Mac48Address txMac = hdr.GetAddr2();
    Mac48Address rxMac = hdr.GetAddr1();
    if (txMac == m_myMacAddress)
    {
        return; // Our own outgoing data sensed by own PHY - ignore.
    }

    // Learn MAC->IP ONLY from broadcast frames (e.g., OLSR HELLO/TC).
    // A UNICAST data frame with Addr2 = X carries an IP source that may be
    // the ORIGINATOR of the flow, not X (X may be forwarding it). Treating
    // unicast Addr2 as matching IP source is the bug that caused the defense
    // to build a wrong MAC<->IP map and blacklist honest bridge nodes.
    //
    // Broadcast frames from a node, on the other hand, are always originated
    // by Addr2 (no forwarding at L2 for broadcast in ad-hoc), so the IP
    // source in the payload is guaranteed to equal Addr2's IP.
    if (rxMac.IsBroadcast())
    {
        Ipv4Address srcIp;
        if (TryExtractIpSource(copy, srcIp) && srcIp != Ipv4Address())
        {
            m_macToIp[txMac] = srcIp;
        }
    }

    OnNeighborForwardedPacket(txMac, rxMac, pkt);
}

bool
OlsrWatchdogDefense::TryExtractIpSource(Ptr<const Packet> rawWifiPkt,
                                         Ipv4Address& outSrc) const
{
    // Caller supplies a packet with a WifiMacHeader still on top.
    Ptr<Packet> p = rawWifiPkt->Copy();
    WifiMacHeader wifi;
    if (p->GetSize() < wifi.GetSerializedSize() ||
        !p->PeekHeader(wifi))
    {
        return false;
    }
    p->RemoveHeader(wifi);

    LlcSnapHeader llc;
    if (p->GetSize() < llc.GetSerializedSize())
    {
        return false;
    }
    p->RemoveHeader(llc);
    if (llc.GetType() != Ipv4L3Protocol::PROT_NUMBER)
    {
        return false;
    }

    Ipv4Header ip;
    if (p->GetSize() < ip.GetSerializedSize())
    {
        return false;
    }
    p->PeekHeader(ip);
    outSrc = ip.GetSource();
    return true;
}

void
OlsrWatchdogDefense::OnNeighborForwardedPacket(Mac48Address transmitter,
                                                Mac48Address /*receiver*/,
                                                Ptr<const Packet> packet)
{
    if (!m_enabled) return;
    if (!packet) return;

    Ipv4Address txIp = LookupIpFromMac(transmitter);
    if (txIp == Ipv4Address())
    {
        return; // Not a known neighbor - can't correlate.
    }

    NeighborStats& s = m_neighborStats[txIp];
    s.dataFromThisNode++;
    s.lastActivityTime = Simulator::Now();

    // Correlate with pending packets we sent to this neighbor.
    auto it = m_pendingByNeighbor.find(txIp);
    if (it == m_pendingByNeighbor.end())
    {
        return;
    }

    const uint64_t uid = packet->GetUid();
    auto& vec = it->second;
    for (auto pp = vec.begin(); pp != vec.end(); ++pp)
    {
        if (pp->packetUid == uid)
        {
            vec.erase(pp);
            s.packetsForwarded++;
            NS_LOG_DEBUG(m_mainAddress << " observed " << txIp
                         << " forward packet uid=" << uid);
            return;
        }
    }
}

void
OlsrWatchdogDefense::OnRtsReceived(Mac48Address sender, Mac48Address /*receiver*/)
{
    Ipv4Address ip = LookupIpFromMac(sender);
    if (ip == Ipv4Address())
    {
        return;
    }
    m_neighborStats[ip].rtsFromThisNode++;
}

void
OlsrWatchdogDefense::OnCtsReceived(Mac48Address /*receiver*/)
{
    // Currently informational only. Reserved for future refinement
    // where we correlate observed CTS-to-B with B's forwarding behavior.
}

void
OlsrWatchdogDefense::PhyRxDropCallback(Ptr<const Packet> /*pkt*/,
                                        WifiPhyRxfailureReason /*reason*/)
{
    // Every PHY drop is a signal that we, the watchdog, might be missing
    // observations. Algorithm B feeds this into m_selfReliabilityScore.
    m_selfDropsWindow++;
}

void
OlsrWatchdogDefense::OnSelfReliabilityReport(uint32_t localDropsCount)
{
    // External push path (e.g., user code reporting drops). Additive with
    // PhyRxDropCallback so both sources count.
    m_selfDropsWindow += localDropsCount;
}

// ============================================================================
// MAC <-> IP resolution
// ============================================================================

Ipv4Address
OlsrWatchdogDefense::LookupIpFromMac(Mac48Address mac) const
{
    // Resolution strategy: we populate m_macToIp in SnifferRxCallback whenever
    // we observe any IPv4 frame from a neighbor (including OLSR HELLO/TC, which
    // travel over WiFi broadcast). Within 1-2 HELLO intervals, every active
    // neighbor is mapped.
    //
    // NS-3's ArpCache::Lookup takes an IPv4 address (forward lookup) and the
    // cache has no public reverse-lookup API, so we do not consult it here.
    auto it = m_macToIp.find(mac);
    if (it != m_macToIp.end())
    {
        return it->second;
    }
    return Ipv4Address();
}

// ============================================================================
// Periodic check and decision logic
// ============================================================================

void
OlsrWatchdogDefense::PeriodicCheck()
{
    NS_LOG_FUNCTION(this);

    // When disabled, just reschedule and return - no observation, no scoring,
    // no blacklisting. Pending packet entries naturally age out via the
    // forward timeout but produce no evidence.
    if (!m_enabled)
    {
        m_periodicEvent = Simulator::Schedule(m_periodicInterval,
                                              &OlsrWatchdogDefense::PeriodicCheck,
                                              this);
        return;
    }

    const Time now = Simulator::Now();

    UpdateSelfReliability();

    // 1. Age out pending packets whose timeout has expired; each expiry is
    //    an observation of "neighbor did not forward".
    for (auto kv = m_pendingByNeighbor.begin(); kv != m_pendingByNeighbor.end();)
    {
        Ipv4Address neighbor = kv->first;
        auto& vec = kv->second;

        auto p = vec.begin();
        while (p != vec.end())
        {
            if (now - p->sentTime > m_forwardTimeout)
            {
                EvaluateMissingForward(neighbor, *p);
                p = vec.erase(p);
            }
            else
            {
                ++p;
            }
        }
        // Garbage-collect empty entries.
        if (vec.empty())
        {
            kv = m_pendingByNeighbor.erase(kv);
        }
        else
        {
            ++kv;
        }
    }

    // 2. For each neighbor we have evidence on, decide whether to blacklist.
    for (const auto& kv : m_neighborStats)
    {
        MaybeBlacklist(kv.first);
    }

    // 3. Reschedule.
    m_periodicEvent = Simulator::Schedule(m_periodicInterval,
                                          &OlsrWatchdogDefense::PeriodicCheck,
                                          this);
}

void
OlsrWatchdogDefense::EvaluateMissingForward(Ipv4Address neighbor,
                                             const PendingPacket& /*pp*/)
{
    // Warmup gate: drop the timed-out entry without scoring. This protects
    // us from (a) packets in flight at activation time, (b) the brief period
    // before our MAC<->IP map is populated by observing OLSR broadcasts.
    if (Simulator::Now() < m_warmupUntil)
    {
        return;
    }

    NeighborStats& s = m_neighborStats[neighbor];

    // (a) If our link to this neighbor was failing at the MAC layer, the
    //     neighbor never received our packet. Cannot blame them.
    if (s.macTxFailures > m_macFailureThreshold)
    {
        NS_LOG_DEBUG(m_mainAddress << ": suppressing evidence vs " << neighbor
                     << " (high MAC TX failures)");
        return;
    }

    // (b) Heuristic from user-summary: if the neighbor has been transmitting
    //     many RTS but almost no DATA, it is likely a blackhole pretending
    //     to try to forward. Attach extra weight.
    const bool manyRts = s.rtsFromThisNode > m_minRtsForHeuristic;
    const bool lowData = s.dataFromThisNode == 0 ||
                         (static_cast<double>(s.rtsFromThisNode) /
                              static_cast<double>(std::max<uint32_t>(1, s.dataFromThisNode))
                          > m_rtsToDataRatioThresh);
    if (manyRts && lowData)
    {
        s.notForwardedEvidence += 2;
        NS_LOG_DEBUG(m_mainAddress << ": +2 evidence vs " << neighbor
                     << " (RTS=" << s.rtsFromThisNode
                     << " DATA=" << s.dataFromThisNode << ")");
        return;
    }

    // (c) Default: one piece of evidence. Will accumulate with repeated drops.
    s.notForwardedEvidence++;
    NS_LOG_DEBUG(m_mainAddress << ": +1 evidence vs " << neighbor
                 << " (total=" << s.notForwardedEvidence << ")");
}

void
OlsrWatchdogDefense::MaybeBlacklist(Ipv4Address neighbor)
{
    if (m_blacklist.count(neighbor))
    {
        return;
    }

    auto it = m_neighborStats.find(neighbor);
    if (it == m_neighborStats.end())
    {
        return;
    }
    NeighborStats& s = it->second;

    // Self-reliability scales the effective threshold: the noisier we are,
    // the more evidence we demand before accusing.
    const double effectiveThreshold =
        static_cast<double>(m_blacklistThreshold) / m_selfReliabilityScore;

    // Not enough evidence yet -> nothing to do.
    if (s.notForwardedEvidence < effectiveThreshold)
    {
        return;
    }

    // === Cautious 3-stage commit gate ===
    // The defense uses a hard blacklist: once a neighbor is flagged, OLSR
    // removes it from every routing computation. In dense or noisy networks
    // this can isolate honest nodes whose links happen to be lossy. To
    // mitigate, we add three cheap sanity checks before committing.

    // GUARD 1: Must have heard some DATA from the neighbor in promiscuous
    // mode. A truly silent neighbor is more likely to be link-broken than
    // malicious. (A genuine blackhole in our forwarding path forwards
    // *other* traffic, just not ours.)
    if (s.dataFromThisNode < m_minDataObservations)
    {
        NS_LOG_DEBUG(m_mainAddress << ": deferring blacklist of " << neighbor
                     << " (only " << s.dataFromThisNode
                     << " DATA observations seen, need "
                     << m_minDataObservations << ")");
        return;
    }

    // GUARD 2: MAC-layer link health must look reasonable. If a large
    // fraction of our unicasts to the neighbor never reach it (RTS retries
    // exhausted), the link itself is unhealthy and we cannot tell whether
    // missed forwards reflect malice or just lost packets.
    if (s.packetsSentTo > 0)
    {
        const double macFailRate =
            static_cast<double>(s.macTxFailures) /
            static_cast<double>(s.packetsSentTo);
        if (macFailRate >= m_macFailureRateThresh)
        {
            NS_LOG_DEBUG(m_mainAddress << ": deferring blacklist of " << neighbor
                         << " (MAC fail-rate " << macFailRate
                         << " exceeds " << m_macFailureRateThresh << ")");
            return;
        }
    }

    // GUARD 3: Probation period. The first time a neighbor crosses the
    // evidence threshold, we don't blacklist - we mark the neighbor as
    // "on probation" and re-check after probationDuration. Only if the
    // neighbor is *still* over threshold AND has accumulated additional
    // evidence during probation do we commit. This filters out burst
    // losses that happen to coincide with the threshold crossing.
    const Time now = Simulator::Now();

    if (!s.onProbation)
    {
        s.onProbation = true;
        s.probationUntil = now + m_probationDuration;
        s.evidenceAtProbationStart = s.notForwardedEvidence;
        NS_LOG_INFO(m_mainAddress << ": " << neighbor
                    << " ENTERED PROBATION (evidence="
                    << s.notForwardedEvidence
                    << ", review at t=" << s.probationUntil.GetSeconds() << "s)");
        return;
    }

    // Still in probation window? Wait it out.
    if (now < s.probationUntil)
    {
        return;
    }

    // Probation window ended. Commit only if misbehavior has actively
    // continued during the window (we got more evidence, not just the same
    // evidence we already had).
    const uint32_t evidenceDuringProbation =
        s.notForwardedEvidence - s.evidenceAtProbationStart;
    const bool persistedMisbehavior =
        evidenceDuringProbation >= m_blacklistThreshold / 2;

    if (!persistedMisbehavior)
    {
        // Probation cleared. Reset and give the neighbor another chance.
        // Halve the existing evidence so old observations decay.
        s.onProbation = false;
        s.probationUntil = Seconds(0);
        s.notForwardedEvidence /= 2;
        s.evidenceAtProbationStart = 0;
        NS_LOG_INFO(m_mainAddress << ": " << neighbor
                    << " CLEARED PROBATION (only "
                    << evidenceDuringProbation
                    << " new evidence during window)");
        return;
    }

    // Persistent misbehavior across probation -> commit.
    m_blacklist.insert(neighbor);
    NS_LOG_WARN("Node " << m_mainAddress
                << " BLACKLISTED " << neighbor
                << " after probation"
                << " (total evidence=" << s.notForwardedEvidence
                << ", new during probation=" << evidenceDuringProbation
                << ", DATA seen=" << s.dataFromThisNode
                << ", selfReliability=" << m_selfReliabilityScore << ")");
}

void
OlsrWatchdogDefense::UpdateSelfReliability()
{
    if (m_selfDropsWindow > m_selfDropsThreshold)
    {
        m_selfReliabilityScore =
            std::max(m_minSelfReliability, m_selfReliabilityScore * 0.9);
    }
    else
    {
        m_selfReliabilityScore =
            std::min(1.0, m_selfReliabilityScore * 1.05);
    }
    m_selfDropsWindow = 0;
}

} // namespace olsr
} // namespace ns3