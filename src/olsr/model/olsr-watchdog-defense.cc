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
                      "INERT. Formerly the RTS:DATA ratio above which a "
                      "neighbor was considered suspicious. That heuristic "
                      "treated RTS activity as incriminating, which inverts "
                      "the cross-layer test of Baiad et al., where RTS/CTS "
                      "evidence is exculpatory. Removed from the decision "
                      "path; the attribute is retained only so that existing "
                      "harness scripts that set it continue to run.",
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
                      "INERT. Formerly the minimum RTS count before applying "
                      "the 'too many RTS = attacker' heuristic. See "
                      "RtsToDataRatioThreshold; retained for harness "
                      "compatibility only.",
                      UintegerValue(5),
                      MakeUintegerAccessor(&OlsrWatchdogDefense::m_minRtsForHeuristic),
                      MakeUintegerChecker<uint32_t>())
        .AddAttribute("RtsCtsDiscrepancyThreshold",
                      "Difference between RTS frames sent by a monitored node "
                      "and CTS frames it was granted, at or above which the "
                      "MAC monitor infers channel contention and voids the "
                      "watchdog report against that node. Baiad et al. state "
                      "only that a difference indicates collision, giving no "
                      "numeric threshold; the default of 1 is that literal "
                      "reading. Raising it to 2 tolerates a single RTS left "
                      "in flight across a window boundary.",
                      UintegerValue(1),
                      MakeUintegerAccessor(&OlsrWatchdogDefense::m_rtsCtsDiscrepancyThresh),
                      MakeUintegerChecker<uint32_t>(1))
        .AddAttribute("MinSelfReliability",
                      "INERT. Formerly the floor of a continuous "
                      "self-reliability score that scaled the blacklist "
                      "threshold. Baiad et al. define the monitor status "
                      "MAC_s as binary (Alg. 4 Part B): a watchdog with "
                      "listening problems is eliminated for the round, not "
                      "merely trusted less. Retained for harness "
                      "compatibility only.",
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
        .AddAttribute("VerifyOnwardHop",
                      "Require that a retransmission observed from a "
                      "monitored node be addressed to a plausible onward hop "
                      "before it counts as a genuine forward. Closes the hole "
                      "Marti et al. describe for hop-by-hop protocols, where "
                      "a node can transmit to a non-existent address and "
                      "appear to have forwarded. Disable to reproduce the "
                      "unverified behaviour.",
                      BooleanValue(true),
                      MakeBooleanAccessor(&OlsrWatchdogDefense::m_verifyOnwardHop),
                      MakeBooleanChecker())
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
      m_selfDropsPrevWindow(0),
      m_verifyOnwardHop(true),
      m_enabled(true),
      m_warmupUntil(Seconds(0))
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

    // No-op skip: a redundant call with the SAME value must not wipe state.
    // The evaluation harness forces an unconditional reset by toggling the
    // value twice (!cur then cur); each of those two calls DOES change the
    // value and therefore DOES reset, so this guard only suppresses true
    // no-ops (e.g. an attribute re-applied to its current value).
    if (m_enabled == enabled)
    {
        return;
    }

    m_enabled = enabled;

    // FULL SYMMETRIC cold-start reset on EVERY enabled-state transition, in
    // BOTH directions (enable->disable and disable->enable). This guarantees
    // that no accumulated detection state can survive a phase boundary: an
    // OFF->ON transition cannot inherit a stale blacklist/evidence built up
    // before the node was disabled, and an ON->OFF transition leaves nothing
    // behind for a later ON to pick up. Combined with the harness's
    // unconditional double-toggle at each slot transition, this makes every
    // measurement window an independent snapshot.
    ResetAccumulatedState();

    NS_LOG_INFO("Defense on " << m_mainAddress
                << (enabled ? " ENABLED" : " DISABLED")
                << " at t=" << Simulator::Now().GetSeconds()
                << "s (full state reset; warmup until t="
                << m_warmupUntil.GetSeconds() << "s)");
}

void
OlsrWatchdogDefense::ResetAccumulatedState()
{
    // The 7 accumulating members (everything that grows/evolves over time):
    m_blacklist.clear();             // 1. committed blacklist verdicts
    m_pendingByNeighbor.clear();     // 2. in-flight forwarded-packet tracking
    m_neighborStats.clear();         // 3. per-neighbor evidence/probation counters
    m_macToIp.clear();               // 4. learned MAC<->IP map (relearned in warmup)
    m_selfDropsWindow = 0;           // 5. local PHY-drop window counter
    m_selfDropsPrevWindow = 0;       // 6. local PHY-drop counter, prev round
    m_warmupUntil = Simulator::Now() + m_warmupDuration; // 7. re-arm warmup

    // Intentionally PRESERVED (these are not accumulated detection state):
    //   m_protocol, m_mainAddress, m_myMacAddress  -- identity / wiring
    //   m_attachedPhys                             -- live WiFi trace handles
    //   m_periodicEvent                            -- self-rescheduling timer
    //   m_setupDone, all configuration attributes  -- lifecycle / config
    //   m_enabled                                  -- set by the caller above
}

OlsrWatchdogDefense::DebugStateSizes
OlsrWatchdogDefense::GetDebugStateSizes() const
{
    DebugStateSizes s;
    s.blacklist        = m_blacklist.size();
    s.pendingNeighbors = m_pendingByNeighbor.size();
    std::size_t total = 0;
    for (const auto& kv : m_pendingByNeighbor)
    {
        total += kv.second.size();
    }
    s.pendingTotal     = total;
    s.neighborStats    = m_neighborStats.size();
    s.macToIp          = m_macToIp.size();
    s.selfDropsWindow  = m_selfDropsWindow;
    s.selfDropsPrev    = m_selfDropsPrevWindow;
    // Reports ACTUAL container sizes irrespective of m_enabled, so a read taken
    // immediately after ResetAccumulatedState() shows all zeros even while
    // disabled -- exactly what the harness's leak check expects.
    return s;
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

    if (!m_enabled) return;   // OFF => fully inert: accumulate nothing.

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

    if (!m_enabled) return;   // OFF => fully inert: accumulate nothing.

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
    if (!m_enabled) return;   // OFF => fully inert: no sniffing, no MAC<->IP learning.
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

bool
OlsrWatchdogDefense::IsKnownNode(Ipv4Address addr) const
{
    if (addr == Ipv4Address() || addr == m_mainAddress)
    {
        return false;
    }
    if (!m_protocol)
    {
        return false;
    }

    for (const auto& n : m_protocol->GetNeighbors())
    {
        if (n.neighborMainAddr == addr)
        {
            return true;
        }
    }
    for (const auto& n2 : m_protocol->GetTwoHopNeighbors())
    {
        if (n2.twoHopNeighborAddr == addr || n2.neighborMainAddr == addr)
        {
            return true;
        }
    }
    for (const auto& t : m_protocol->GetTopologySet())
    {
        if (t.destAddr == addr || t.lastAddr == addr)
        {
            return true;
        }
    }
    return false;
}

bool
OlsrWatchdogDefense::IsPlausibleOnwardHop(Mac48Address receiver,
                                          Ipv4Address forwarder) const
{
    if (!m_verifyOnwardHop)
    {
        return true;
    }

    // A unicast data relay is never broadcast or multicast. Marti et al. name
    // exactly this as the way a node fakes a forward under a hop-by-hop
    // protocol.
    if (receiver == Mac48Address::GetBroadcast() || receiver.IsGroup())
    {
        return false;
    }

    // Sending it back to us is not forwarding it onward.
    if (receiver == m_myMacAddress)
    {
        return false;
    }

    Ipv4Address rxIp = LookupIpFromMac(receiver);
    if (rxIp == Ipv4Address())
    {
        // Unresolved. We cannot show the hop is bogus, so we do not treat it
        // as such: the watchdog never accuses on absence of information.
        return true;
    }
    if (rxIp == m_mainAddress || rxIp == forwarder)
    {
        return false;
    }

    // The target must be a node we have actually heard of. A fabricated
    // address appears nowhere in the link-state view.
    return IsKnownNode(rxIp);
}

void
OlsrWatchdogDefense::OnNeighborForwardedPacket(Mac48Address transmitter,
                                                Mac48Address receiver,
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
            if (!IsPlausibleOnwardHop(receiver, txIp))
            {
                // The frame carries our packet but is addressed nowhere real.
                // Leave the entry pending so that it ages out and is scored:
                // an unverifiable relay is not a relay.
                NS_LOG_DEBUG(m_mainAddress << ": " << txIp
                             << " retransmitted uid=" << uid
                             << " to an implausible hop " << receiver
                             << "; not crediting the forward");
                return;
            }
            vec.erase(pp);
            s.packetsForwarded++;
            NS_LOG_DEBUG(m_mainAddress << " observed " << txIp
                         << " forward packet uid=" << uid
                         << " to " << receiver);
            return;
        }
    }
}

void
OlsrWatchdogDefense::OnRtsReceived(Mac48Address sender, Mac48Address /*receiver*/)
{
    if (!m_enabled) return;   // OFF => fully inert.
    if (sender == m_myMacAddress)
    {
        return; // Our own RTS; says nothing about a monitored node.
    }
    Ipv4Address ip = LookupIpFromMac(sender);
    if (ip == Ipv4Address())
    {
        return;
    }
    NeighborStats& s = m_neighborStats[ip];
    s.rtsFromThisNode++;   // cumulative, retained for logging
    s.rtsInWindow++;       // per-round, feeds the collision test
}

void
OlsrWatchdogDefense::OnCtsReceived(Mac48Address rtsSender)
{
    // An 802.11 CTS carries a single address field (Addr1/RA) holding the
    // address of the station whose RTS is being cleared. Overhearing it
    // therefore tells us that THAT station won the medium, so the frame is
    // credited to it, and is what the RTS count is compared against.
    if (!m_enabled) return;   // OFF => fully inert.
    if (rtsSender == m_myMacAddress)
    {
        return; // Clears one of our own RTS frames, not a monitored node's.
    }
    Ipv4Address ip = LookupIpFromMac(rtsSender);
    if (ip == Ipv4Address())
    {
        return;
    }
    m_neighborStats[ip].ctsInWindow++;
}

bool
OlsrWatchdogDefense::CollisionSuspectedFor(const NeighborStats& s) const
{
    // Sum the current and previous rounds so that the test spans the whole
    // lifetime of a pending packet (see B2 in DESIGN_DECISIONS.md).
    const uint32_t rts = s.rtsInWindow + s.rtsPrevWindow;
    const uint32_t cts = s.ctsInWindow + s.ctsPrevWindow;

    // Guard against unsigned wraparound. CTS may legitimately exceed RTS when
    // the node's RTS was transmitted out of our hearing but the CTS answering
    // it was not; that is evidence of a clear medium, never of contention.
    if (cts >= rts)
    {
        return false;
    }
    return (rts - cts) >= m_rtsCtsDiscrepancyThresh;
}

void
OlsrWatchdogDefense::RotateMacWindows()
{
    for (auto& kv : m_neighborStats)
    {
        NeighborStats& s = kv.second;
        s.rtsPrevWindow = s.rtsInWindow;
        s.ctsPrevWindow = s.ctsInWindow;
        s.rtsInWindow = 0;
        s.ctsInWindow = 0;
    }
    m_selfDropsPrevWindow = m_selfDropsWindow;
    m_selfDropsWindow = 0;
}

void
OlsrWatchdogDefense::PhyRxDropCallback(Ptr<const Packet> /*pkt*/,
                                        WifiPhyRxfailureReason /*reason*/)
{
    if (!m_enabled) return;   // OFF => fully inert.
    // Every PHY drop is a signal that we, the watchdog, might be missing
    // observations. Feeds MAC_s (Alg. 4 Part B) via LocalMacStatus().
    m_selfDropsWindow++;
}

void
OlsrWatchdogDefense::OnSelfReliabilityReport(uint32_t localDropsCount)
{
    if (!m_enabled) return;   // OFF => fully inert.
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

    // 3. Advance the MAC observation window. Deliberately AFTER steps 1 and 2:
    //    the collision test in EvaluateMissingForward must see the counts that
    //    were accumulating while the packet in question was in flight.
    RotateMacWindows();

    // 4. Reschedule.
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

    // (a) MAC_s GATE (Baiad et al., Alg. 4 Part B). If this watchdog was
    //     itself colliding while listening, it is eliminated from this round
    //     rather than accusing on evidence it could not reliably gather.
    //     Checked before any per-neighbour reasoning: the disqualification is
    //     a property of the monitor, not of the monitored node.
    if (!LocalMacStatus())
    {
        NS_LOG_DEBUG(m_mainAddress << ": MAC_s=0 (local drops="
                     << (m_selfDropsWindow + m_selfDropsPrevWindow)
                     << "), abstaining this round");
        return;
    }

    NeighborStats& s = m_neighborStats[neighbor];

    // (b) If our link to this neighbor was failing at the MAC layer, the
    //     neighbor never received our packet. Cannot blame them.
    if (s.macTxFailures > m_macFailureThreshold)
    {
        NS_LOG_DEBUG(m_mainAddress << ": suppressing evidence vs " << neighbor
                     << " (high MAC TX failures)");
        return;
    }

    // (c) CROSS-LAYER TEST (Baiad et al. [B14] §IV-B, [B16] §3.2, Alg. 4 Part A).
    //     The MAC monitor compares the number of RTS frames the node sent
    //     against the number of CTS frames it was granted. A shortfall means
    //     the node was contending for a channel it did not win, so the missing
    //     forward is attributable to collision rather than to an intentional
    //     drop, and the watchdog report is voided (`wd_report(i) = 0`).
    //
    //     This is the exculpatory direction the papers specify. An earlier
    //     revision used RTS activity to INCRIMINATE, which inverted the
    //     premise of the cross-layer design — the mechanism exists precisely
    //     to suppress collision-induced false positives.
    if (CollisionSuspectedFor(s))
    {
        NS_LOG_DEBUG(m_mainAddress << ": voiding report vs " << neighbor
                     << " (MAC contention: RTS="
                     << (s.rtsInWindow + s.rtsPrevWindow)
                     << " CTS=" << (s.ctsInWindow + s.ctsPrevWindow) << ")");
        return;
    }

    // (d) Default: one piece of evidence. Will accumulate with repeated drops.
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

    // Fixed threshold. Monitor reliability is handled upstream in
    // EvaluateMissingForward, where a round in which this watchdog was itself
    // colliding contributes no evidence at all (MAC_s = 0). Scaling the
    // threshold by a continuous confidence score, as an earlier revision did,
    // has no counterpart in Baiad et al. or in Marti et al.
    if (s.notForwardedEvidence < m_blacklistThreshold)
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
                << ", DATA seen=" << s.dataFromThisNode << ")");
}

bool
OlsrWatchdogDefense::LocalMacStatus() const
{
    // MAC_s = 0 when this watchdog was itself losing frames to collisions
    // over the observation window; in that case it cannot distinguish "the
    // neighbour did not forward" from "I did not hear the neighbour forward",
    // and the papers eliminate such a watchdog from the round entirely.
    // Summed over two rounds for the same reason as the RTS/CTS counts, and
    // compared against twice the threshold so that SelfDropsThreshold keeps
    // its original meaning of "tolerated drops per round". Comparing a
    // two-round sum against a one-round threshold would silently halve the
    // configured tolerance and mute a watchdog sitting exactly at it.
    return (m_selfDropsWindow + m_selfDropsPrevWindow) <= (2 * m_selfDropsThreshold);
}

} // namespace olsr
} // namespace ns3