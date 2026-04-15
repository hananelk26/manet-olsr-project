#ifndef OLSR_DEFENSE_STRATEGY_H
#define OLSR_DEFENSE_STRATEGY_H

#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/ipv4-address.h"
#include "ns3/mac48-address.h" 
#include "olsr-header.h"
#include <set>

namespace ns3 {
namespace olsr {

class RoutingProtocol;

enum DropReason : uint8_t {
    DROP_NO_ROUTE = 0,
    DROP_TTL_EXPIRED = 1,
    DROP_QUEUE_FULL = 2
};

class OlsrDefenseStrategy : public Object
{
public:
  static TypeId GetTypeId(void);
  virtual ~OlsrDefenseStrategy() {}

  virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) = 0;
  virtual void DoDispose() = 0;

  virtual bool IsMalicious(Ipv4Address addr) = 0;
  virtual std::set<Ipv4Address> GetBlacklist() const = 0;

  // --- Control Plane Hooks ---
  virtual void OnRecvHello(Ipv4Address senderAddress,
                           Ptr<const Packet> packet, 
                           const MessageHeader& msg, 
                           const MessageHeader::Hello& hello) = 0;

  virtual void OnRecvTc (Ipv4Address senderIfaceAddr, 
                         Ptr<const Packet> packet, 
                         const MessageHeader& msg, 
                         const MessageHeader::Tc& tc) = 0;

  virtual void OnTcGenerated(const MessageHeader::Tc& tc) = 0;

  // --- Data Plane Hooks ---
  virtual void OnDataPacketReceived(Ptr<const Packet> packet,
                                     Ipv4Address source,
                                     Ipv4Address destination,
                                     Ipv4Address nextHop) = 0;

  virtual void OnDataPacketForwarded(Ptr<const Packet> packet, 
                                      Ipv4Address nextHop,
                                      Ipv4Address finalDest) = 0;

  virtual void OnDataPacketDropped(Ptr<const Packet> packet, 
                                    Ipv4Address source,
                                    Ipv4Address destination,
                                    DropReason reason) = 0;

  // --- Sniffer / Promiscuous Hooks ---
  virtual void OnNeighborForwardedPacket(Mac48Address transmitter,
                                         Mac48Address receiver, Ptr<const Packet> packet) = 0;

  // --- Cross Layer & Physical Metrics ---
  virtual void OnQueueStatusReport(uint32_t size, uint32_t capacity) = 0;
  virtual void OnEnergyStateUpdate(double remainingEnergyJoules, double energyFraction) = 0;
  virtual void OnMacTxFailure(Ipv4Address neighbor, uint32_t count) = 0;

  // --- NEW: Cooperative Detection Extensions (Cross-Layer) ---
  // Reports local physical layer drops (noise/interference) to assess self-reliability
  virtual void OnSelfReliabilityReport(uint32_t localDropsCount) = 0;
  
  // Reports RTS frames seen by the sniffer (Algorithm 1)
  virtual void OnRtsReceived(Mac48Address sender, Mac48Address receiver) = 0;
  
  // Reports CTS frames seen by the sniffer (Algorithm 1)
  virtual void OnCtsReceived(Mac48Address receiver) = 0;

  virtual void PeriodicCheck() = 0;

  // Determines whether the current topology requires injecting a fictitious node
  // Returns true if a fictitious node should be added to HELLO/TC messages
  virtual bool RequiresFictitiousNode() = 0;
};

// --- Null Implementation (Default) ---
class OlsrDefenseNull : public OlsrDefenseStrategy
{
public:
  static TypeId GetTypeId(void);

  virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override {}
  virtual void DoDispose() override {}
  virtual bool IsMalicious(Ipv4Address addr) override { return false; }
  virtual std::set<Ipv4Address> GetBlacklist() const override { return {}; }

  virtual void OnRecvHello(Ipv4Address, Ptr<const Packet>, const MessageHeader&, 
                           const MessageHeader::Hello&) override {}
  virtual void OnRecvTc(Ipv4Address, Ptr<const Packet>, 
                        const MessageHeader&, const MessageHeader::Tc&) override {}
  virtual void OnTcGenerated(const MessageHeader::Tc&) override {}

  virtual void OnDataPacketReceived(Ptr<const Packet>, Ipv4Address, Ipv4Address, 
                                     Ipv4Address) override {}
  virtual void OnDataPacketForwarded(Ptr<const Packet>, Ipv4Address, Ipv4Address) override {}
  
  virtual void OnDataPacketDropped(Ptr<const Packet>, Ipv4Address, Ipv4Address, DropReason) override {}

  virtual void OnNeighborForwardedPacket(Mac48Address, Mac48Address, Ptr<const Packet>) override {}
  virtual void OnQueueStatusReport(uint32_t, uint32_t) override {}
  virtual void OnEnergyStateUpdate(double, double) override {}
  virtual void OnMacTxFailure(Ipv4Address, uint32_t) override {}
  
  // New empty implementations for the null strategy
  virtual void OnSelfReliabilityReport(uint32_t) override {}
  virtual void OnRtsReceived(Mac48Address, Mac48Address) override {}
  virtual void OnCtsReceived(Mac48Address) override {}

  virtual void PeriodicCheck() override {}

  virtual bool RequiresFictitiousNode() override { return false; }
};

} 
} 

#endif