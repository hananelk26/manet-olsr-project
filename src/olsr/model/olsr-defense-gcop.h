#ifndef OLSR_DEFENSE_GCOP_H
#define OLSR_DEFENSE_GCOP_H

#include "olsr-defense-strategy.h"
#include "ns3/timer.h"
#include <map>
#include <set>

namespace ns3 {
namespace olsr {

class RoutingProtocol;

/**
 * \brief Defense strategy implementing GCOP and GCOHP algorithms
 * to mitigate node isolation and black/gray hole attacks in OLSR.
 */
class OlsrDefenseGcop : public OlsrDefenseStrategy {
public:
    static TypeId GetTypeId(void);
    OlsrDefenseGcop();
    virtual ~OlsrDefenseGcop();

    // Overridden setup and core methods from OlsrDefenseStrategy
    virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
    virtual void DoDispose() override;

    virtual bool IsMalicious(Ipv4Address addr) override;
    virtual std::set<Ipv4Address> GetBlacklist() const override;

    // --- Control Plane Hooks ---
    virtual void OnRecvHello(Ipv4Address senderAddress,
                             Ptr<const Packet> packet, 
                             const MessageHeader& msg, 
                             const MessageHeader::Hello& hello) override;

    // Overridden periodic and state checks
    virtual void PeriodicCheck() override;
    virtual bool RequiresFictitiousNode() override;

    // --- Data Plane Hooks ---
    virtual void OnDataPacketReceived(Ptr<const Packet> packet, Ipv4Address source, Ipv4Address destination, Ipv4Address prevHop) override;
    virtual void OnDataPacketForwarded(Ptr<const Packet> packet, Ipv4Address source, Ipv4Address nextHop) override;

    // --- Unused Interface Methods (Empty Implementations) ---
    virtual void OnRecvTc(Ipv4Address senderIfaceAddr, Ptr<const Packet> packet, const MessageHeader& msg, const MessageHeader::Tc& tc) override {}
    virtual void OnTcGenerated(const MessageHeader::Tc& tc) override {}
    virtual void OnDataPacketDropped(Ptr<const Packet> packet, Ipv4Address src, Ipv4Address dst, DropReason reason) override {}
    virtual void OnNeighborForwardedPacket(Mac48Address transmitter, Mac48Address receiver, Ptr<const Packet> packet) override {}
    virtual void OnQueueStatusReport(uint32_t size, uint32_t capacity) override {}
    virtual void OnEnergyStateUpdate(double remainingEnergyJoules, double energyFraction) override {}
    virtual void OnMacTxFailure(Ipv4Address neighbor, uint32_t count) override {}
    virtual void OnSelfReliabilityReport(uint32_t localDropsCount) override {}
    virtual void OnRtsReceived(Mac48Address sender, Mac48Address receiver) override {}
    virtual void OnCtsReceived(Mac48Address receiver) override {}

private:
    /**
     * \brief Implements Algorithm 1 (GCOP) - BFS checking for depth 2.
     * Evaluates whether a fictitious node is needed based on green and blue nodes.
     * \return True if a fictitious node is required, false otherwise.
     */
    bool RunGcopAlgorithm();

    /**
     * \brief Implements Algorithm 2 (GCOHP) - Hexagon topology check.
     * Evaluates if the current node is part of a vulnerable 6-node cycle.
     * \return True if the node is in a hexagon pattern requiring a fictitious node.
     */
    bool RunGcohpAlgorithm();

    /**
     * \brief Evaluates the Contradiction Rules (C-Rules) against a specific sender.
     * \param senderAddress The IPv4 address of the node sending the control message.
     */
    void EvaluateContradictionRules(Ipv4Address senderAddress);

    RoutingProtocol* m_routingProtocol;        //!< Pointer to the core OLSR routing protocol.
    Ipv4Address m_mainAddress;                 //!< Main IPv4 address of this node.

    double m_startTime; 

    bool HasKnownMaliciousNeighbor();
    
    /**
     * \brief Data structure to track suspicious nodes.
     * Maps an IPv4 address to the timestamp indicating until when it is considered suspicious.
     */
    std::map<Ipv4Address, Time> m_suspiciousNodes; 
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_DEFENSE_GCOP_H */