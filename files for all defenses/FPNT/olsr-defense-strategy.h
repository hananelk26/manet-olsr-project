#ifndef OLSR_DEFENSE_STRATEGY_H
#define OLSR_DEFENSE_STRATEGY_H

#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/ipv4-address.h"
#include "olsr-header.h"
#include <set>
#include <vector>
#include "ns3/ipv4-header.h"

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
  virtual void DoDispose() override;

  virtual bool IsMalicious(Ipv4Address addr) = 0;
  virtual std::set<Ipv4Address> GetBlacklist() const = 0;

  virtual std::vector<EvaluationVector> GetEvaluationVectors (
      const std::vector<Ipv4Address> &neighbors) = 0;

  virtual void OnRecvEvaluationVectors (
      Ipv4Address sender,
      const std::vector<Ipv4Address> &advertisedNeighbors,
      const std::vector<EvaluationVector> &vectors) = 0;

  virtual double GetNodeTrust (Ipv4Address node) = 0;

  virtual bool IsTrustRoutingEnabled () const = 0;

  virtual void OnRecvHello(Ipv4Address senderAddress,
                           Ptr<const Packet> packet, 
                           const MessageHeader& msg, 
                           const MessageHeader::Hello& hello) = 0;

  virtual void OnRecvTc (Ipv4Address senderIfaceAddr, 
                         Ptr<const Packet> packet, 
                         const MessageHeader& msg, 
                         const MessageHeader::Tc& tc) = 0;

  virtual void OnTcGenerated(const MessageHeader::Tc& tc) = 0;

  virtual void OnDataPacketReceived(Ptr<const Packet> packet,
                                    Ipv4Address source,
                                    Ipv4Address destination,
                                    Ipv4Address nextHop) = 0;

  virtual void OnDataPacketForwarded(const Ipv4Header &header, 
                                    Ptr<const Packet> packet, 
                                    Ipv4Address nextHop, 
                                    Ipv4Address finalDest) = 0;

  virtual void OnDataPacketDropped(Ptr<const Packet> packet, 
                                   Ipv4Address source,
                                   Ipv4Address destination,
                                   DropReason reason) = 0;

  virtual void OnNeighborForwardedPacket(Mac48Address transmitter,
                                         Mac48Address receiver, Ptr<const Packet> packet) = 0;

  virtual void OnQueueStatusReport(uint32_t size, uint32_t capacity) = 0;
  virtual void OnEnergyStateUpdate(double remainingEnergyJoules, double energyFraction) = 0;
  virtual void OnMacTxFailure(Ipv4Address neighbor, uint32_t count) = 0;

  virtual void PeriodicCheck() = 0;
};

class OlsrDefenseNull : public OlsrDefenseStrategy
{
public:
  static TypeId GetTypeId(void);

  virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override {}
  virtual void DoDispose() override {}
  virtual bool IsMalicious(Ipv4Address addr) override { return false; }
  virtual std::set<Ipv4Address> GetBlacklist() const override { return {}; }

  virtual std::vector<EvaluationVector> GetEvaluationVectors (
      const std::vector<Ipv4Address> &neighbors) override 
  {
      return {}; 
  }

  virtual void OnRecvEvaluationVectors (
      Ipv4Address sender,
      const std::vector<Ipv4Address> &advertisedNeighbors,
      const std::vector<EvaluationVector> &vectors) override {}

  virtual double GetNodeTrust (Ipv4Address node) override { return 1.0; }
  virtual bool IsTrustRoutingEnabled () const override { return false; }

  virtual void OnRecvHello(Ipv4Address, Ptr<const Packet>, const MessageHeader&, 
                           const MessageHeader::Hello&) override {}
  virtual void OnRecvTc(Ipv4Address senderIfaceAddr, Ptr<const Packet> packet, 
                        const MessageHeader& msg, const MessageHeader::Tc& tc) override {}
  virtual void OnTcGenerated(const MessageHeader::Tc&) override {}

  virtual void OnDataPacketReceived(Ptr<const Packet>, Ipv4Address, Ipv4Address, 
                                    Ipv4Address) override {}
  virtual void OnDataPacketForwarded(const Ipv4Header &header, Ptr<const Packet> packet, Ipv4Address nextHop, Ipv4Address finalDest) override {}
  
  virtual void OnDataPacketDropped(Ptr<const Packet>, Ipv4Address, Ipv4Address, DropReason) override {}

  virtual void OnNeighborForwardedPacket(Mac48Address transmitter, Mac48Address receiver, Ptr<const Packet> packet) override {}
  virtual void OnQueueStatusReport(uint32_t size, uint32_t capacity) override {}
  virtual void OnEnergyStateUpdate(double remainingEnergyJoules, double energyFraction) override {}
  virtual void OnMacTxFailure(Ipv4Address, uint32_t) override {}
  
  virtual void PeriodicCheck() override {}
};

} 
} 

#endif