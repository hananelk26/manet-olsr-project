/*
 * Cross-Layer Cooperative Watchdog Defense for OLSR
 *
 * Based on:
 *   R. Baiad, H. Otrok, S. Muhaidat, J. Bentahar,
 *   "Cooperative Cross Layer Detection for Blackhole Attack in VANET-OLSR",
 *   IEEE IWCMC 2014.
 *
 * Adapted for NS-3 with the following design decisions:
 *   - Per-node independent detection (no inter-node cooperation messages).
 *   - Local blacklist enforced by OLSR via the existing IsMalicious() hook.
 *   - Emergent isolation: when multiple neighbors independently blacklist an
 *     attacker, it is practically isolated from the network.
 *
 * Implements the OlsrDefenseStrategy interface.
 */

#ifndef OLSR_WATCHDOG_DEFENSE_H
#define OLSR_WATCHDOG_DEFENSE_H

#include "olsr-defense-strategy.h"

#include "ns3/event-id.h"
#include "ns3/mac48-address.h"
#include "ns3/nstime.h"
#include "ns3/wifi-phy.h"
#include "ns3/wifi-mac-header.h"

#include <map>
#include <set>
#include <vector>

namespace ns3 {
namespace olsr {

/**
 * \brief Cross-layer cooperative watchdog defense against Blackhole attacks.
 *
 * Each node runs an independent watchdog that:
 *   1. Records packets it forwarded to each direct neighbor.
 *   2. Promiscuously listens for that neighbor retransmitting the packet.
 *   3. If the neighbor does not retransmit within a timeout, examines MAC
 *      layer evidence (RTS/CTS of that neighbor to the next hop) to
 *      distinguish an intentional drop from a legitimate collision.
 *   4. Blacklists the neighbor after enough independent evidences accumulate.
 *
 * The blacklist is local; OLSR calls IsMalicious() during MPR computation and
 * routing table construction, which results in the attacker being excluded
 * from all routing paths computed by this node.
 */
class OlsrWatchdogDefense : public OlsrDefenseStrategy
{
public:
    static TypeId GetTypeId();

    OlsrWatchdogDefense();
    ~OlsrWatchdogDefense() override;

    // === OlsrDefenseStrategy interface ===

    void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
    void DoDispose() override;

    bool IsMalicious(Ipv4Address addr) override;
    std::set<Ipv4Address> GetBlacklist() const override;

    // Control plane (unused - not relevant for pure blackhole detection)
    void OnRecvHello(Ipv4Address senderAddress,
                     Ptr<const Packet> packet,
                     const MessageHeader& msg,
                     const MessageHeader::Hello& hello) override;
    void OnRecvTc(Ipv4Address senderIfaceAddr,
                  Ptr<const Packet> packet,
                  const MessageHeader& msg,
                  const MessageHeader::Tc& tc) override;
    void OnTcGenerated(const MessageHeader::Tc& tc) override;

    // Data plane (core of detection)
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

    // Promiscuous / cross-layer (core of detection)
    void OnNeighborForwardedPacket(Mac48Address transmitter,
                                   Mac48Address receiver,
                                   Ptr<const Packet> packet) override;
    void OnRtsReceived(Mac48Address sender, Mac48Address receiver) override;
    void OnCtsReceived(Mac48Address receiver) override;
    void OnMacTxFailure(Ipv4Address neighbor, uint32_t count) override;
    void OnSelfReliabilityReport(uint32_t localDropsCount) override;

    // Unused
    void OnQueueStatusReport(uint32_t size, uint32_t capacity) override;
    void OnEnergyStateUpdate(double remainingEnergyJoules,
                             double energyFraction) override;
    bool RequiresFictitiousNode() override;

    // Periodic aggregation and decision logic
    void PeriodicCheck() override;

private:
    // ----- Internal data structures -----

    /** Packet we forwarded to a neighbor and expect them to forward onward. */
    struct PendingPacket
    {
        uint64_t packetUid;     //!< Preserved across hops in NS-3.
        Ipv4Address finalDest;  //!< Ultimate destination (for context only).
        Time sentTime;          //!< When we forwarded it.
    };

    /** Per-neighbor observation counters. */
    struct NeighborStats
    {
        uint32_t packetsSentTo = 0;        //!< # packets we forwarded via this neighbor
        uint32_t packetsForwarded = 0;     //!< # we observed being retransmitted
        uint32_t notForwardedEvidence = 0; //!< Aggregate evidence of blackhole behavior
        uint32_t macTxFailures = 0;        //!< # times our RTS to them timed out
        uint32_t rtsFromThisNode = 0;      //!< # RTS frames observed with them as sender
        uint32_t dataFromThisNode = 0;     //!< # DATA frames observed with them as sender
        Time lastActivityTime = Seconds(0);
    };

    // ----- Members -----

    RoutingProtocol* m_protocol;   //!< Owning OLSR instance (raw ptr: no lifetime issue).
    Ipv4Address m_mainAddress;     //!< Our OLSR main address.
    Mac48Address m_myMacAddress;   //!< Our WiFi MAC (to filter out own traffic in sniffer).
    bool m_setupDone;

    std::set<Ipv4Address> m_blacklist;
    std::map<Ipv4Address, std::vector<PendingPacket>> m_pendingByNeighbor;
    std::map<Ipv4Address, NeighborStats> m_neighborStats;
    std::map<Mac48Address, Ipv4Address> m_macToIp;

    // Algorithm B: self-reliability (lowers watchdog confidence when itself is noisy)
    uint32_t m_selfDropsWindow;        //!< Local PHY drops accumulated this window.
    double m_selfReliabilityScore;     //!< In [m_minSelfReliability, 1.0].

    // Periodic timer
    EventId m_periodicEvent;

    // PHYs we have attached our sniffer/PhyRxDrop callbacks to. We hold
    // smart pointers so we can disconnect cleanly in DetachWifiTraces().
    std::vector<Ptr<WifiPhy>> m_attachedPhys;

    // ----- Configuration (NS-3 Attributes) -----
    Time m_forwardTimeout;
    Time m_periodicInterval;
    Time m_warmupDuration;
    uint32_t m_blacklistThreshold;
    double m_rtsToDataRatioThresh;
    uint32_t m_selfDropsThreshold;
    uint32_t m_macFailureThreshold;
    uint32_t m_minRtsForHeuristic;
    double m_minSelfReliability;

    // ----- Runtime state for warmup -----
    /** Absolute time after which evidence accumulation is allowed.
     *  Set to (Now + m_warmupDuration) at every Setup() invocation.
     *  Before this time, EvaluateMissingForward returns without scoring,
     *  so the defense can quietly observe the network and learn MAC<->IP
     *  mappings (mostly via OLSR HELLO/TC broadcasts) without producing
     *  false positives from packets in flight at activation time. */
    Time m_warmupUntil;

    // ----- Helpers -----

    /** Connects MonitorSnifferRx and PhyRxDrop callbacks on all WiFi devices. */
    void AttachWifiTraces(Ptr<Node> node);

    /** Disconnects callbacks installed by AttachWifiTraces. Idempotent.
     *  Crucial for safety: if the strategy gets replaced via SetAttribute
     *  but no one calls DoDispose on the old instance, the WiFi PHY traces
     *  would still hold a callback into a soon-to-be-destroyed object. */
    void DetachWifiTraces();

    /** Locates our own Node by searching NodeList for our main address. */
    Ptr<Node> FindOwnNode() const;

    /** Called for every WiFi frame this node overhears. */
    void SnifferRxCallback(Ptr<const Packet> pkt,
                           uint16_t channelFreqMhz,
                           WifiTxVector txVector,
                           MpduInfo aMpdu,
                           SignalNoiseDbm signalNoise,
                           uint16_t staId);

    /** Called when our own PHY drops a received frame (collision, CRC, etc). */
    void PhyRxDropCallback(Ptr<const Packet> pkt, WifiPhyRxfailureReason reason);

    /** Tries MAC->IP mapping from our learned table, then ARP caches. */
    Ipv4Address LookupIpFromMac(Mac48Address mac) const;

    /** Decision tree from the paper + user-summary when a pending packet
     *  timed out without observing a retransmission. */
    void EvaluateMissingForward(Ipv4Address neighbor, const PendingPacket& pp);

    /** Checks whether accumulated evidence warrants blacklisting. */
    void MaybeBlacklist(Ipv4Address neighbor);

    /** Adjusts self-reliability based on local drop window count. */
    void UpdateSelfReliability();

    /** Attempt to read IPv4 source from a raw WiFi data MPDU. Returns false on failure. */
    bool TryExtractIpSource(Ptr<const Packet> rawWifiPkt, Ipv4Address& outSrc) const;
};

} // namespace olsr
} // namespace ns3

#endif // OLSR_WATCHDOG_DEFENSE_H