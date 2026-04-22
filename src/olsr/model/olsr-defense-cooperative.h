#ifndef OLSR_DEFENSE_COOPERATIVE_H
#define OLSR_DEFENSE_COOPERATIVE_H

#include "olsr-defense-strategy.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
#include "ns3/timer.h" 
#include <map>
#include <vector>


namespace ns3 {
namespace olsr {

/**
 * \brief Cooperative Cross Layer Detection Strategy.
 * * Implements a sophisticated Watchdog mechanism that verifies:
 * 1. Did the neighbor actually receive the packet? (CTS check)
 * 2. Did the neighbor try to forward it? (RTS check)
 * 3. Was the neighbor blocked by congestion? (Clearance check)
 * 4. Is the local node reliable enough to judge? (Noise check)
 */
class OlsrDefenseCooperative : public OlsrDefenseStrategy
{
public:
  static TypeId GetTypeId(void);
  OlsrDefenseCooperative();
  virtual ~OlsrDefenseCooperative();

  // --- Implementation of Interface ---
  virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
  virtual void DoDispose() override;

  virtual bool IsMalicious(Ipv4Address addr) override;
  virtual std::set<Ipv4Address> GetBlacklist() const override;

  // Protocol hooks (Unused for detection in this specific algo, but required)
  virtual void OnRecvHello(Ipv4Address senderAddress, Ptr<const Packet> packet, 
                           const MessageHeader& msg, const MessageHeader::Hello& hello) override;
  virtual void OnRecvTc(Ipv4Address senderIfaceAddr, Ptr<const Packet> packet, 
                        const MessageHeader& msg, const MessageHeader::Tc& tc) override;
  virtual void OnTcGenerated(const MessageHeader::Tc& tc) override;

  // Data Plane hooks
  virtual void OnDataPacketReceived(Ptr<const Packet> packet, Ipv4Address source, 
                                     Ipv4Address destination, Ipv4Address nextHop) override;
  virtual void OnDataPacketForwarded(Ptr<const Packet> packet, 
                                      Ipv4Address nextHop, Ipv4Address finalDest) override;
  virtual void OnDataPacketDropped(Ptr<const Packet> packet, Ipv4Address source, 
                                    Ipv4Address destination, DropReason reason) override;

  // Sniffer hooks
  virtual void OnNeighborForwardedPacket(Mac48Address transmitter, 
                                         Mac48Address receiver, Ptr<const Packet> packet) override;

  // Cross Layer hooks
  virtual void OnQueueStatusReport(uint32_t size, uint32_t capacity) override;
  virtual void OnEnergyStateUpdate(double remainingEnergyJoules, double energyFraction) override;
  virtual void OnMacTxFailure(Ipv4Address neighbor, uint32_t count) override;

  // --- COOPERATIVE SPECIFIC ---
  virtual void OnSelfReliabilityReport(uint32_t localDropsCount) override;
  virtual void OnRtsReceived(Mac48Address sender, Mac48Address receiver) override;
  virtual void OnCtsReceived(Mac48Address receiver) override;

  virtual void PeriodicCheck() override;

  // Determines if a fictitious node is required by this defense strategy
    virtual bool RequiresFictitiousNode() override;

private:
  RoutingProtocol* m_protocol;
  Ipv4Address m_mainAddress;
  std::set<Ipv4Address> m_blacklist;

  // Configuration
  Time m_watchdogTimeout;
  uint32_t m_noiseThreshold; // Algorithm B threshold

  // --- Internal Structures ---

  struct PendingPacket {
      uint64_t uid;               // Packet UID
      Ipv4Address nextHopIp;      // B (The Neighbor)
      Time sendTime;
      
      // State Machine Flags
      bool receivedByNeighbor;    // Did B send CTS to Me (A)?
      bool forwardedByNeighbor;   // Did B send Data to C?
  };

  struct MacObservation {
      uint32_t rtsCount;          // How many RTS B sent to C
      bool hasClearance;          // Did C send CTS to B?
      Time firstSeen;             // Time of first observation in the current window
      Time lastUpdated;            // Time of the most recent update
  };

  // Map: PacketUID -> Packet Info (A -> B)
  std::map<uint64_t, PendingPacket> m_pendingPackets;

  // Map: Sender(MAC) -> Receiver(MAC) -> Observation
  // Keeps track of interaction between neighbors (B->C) to detect maliciousness
  std::map<Mac48Address, std::map<Mac48Address, MacObservation>> m_macObservations;

  // Local Reliability (Noise level)
  uint32_t m_lastNoiseLevel;

  // Helpers
  void ReportMalicious(Ipv4Address suspect);

  // --- REPUTATION SYSTEM EXTENSION ---
  
  /**
   * \brief Map storing the suspicion score for each node.
   * Key: Node IPv4 Address
   * Value: Current Suspicion Score (0 to Threshold)
   */
  std::map<Ipv4Address, int> m_suspicionScore;
  
  // --- Tuning Constants ---
  static const int SUSPICION_THRESHOLD = 25; // Number of bad events required to trigger a ban
  static const int SCORE_PER_BAD_EVENT = 5;  // Penalty points for dropping a packet
  static const int DECAY_AMOUNT = 1;         // Points forgiven per check cycle (Forgiveness mechanism)
  
  /**
   * \brief Increases the suspicion score for a specific node.
   * If the score exceeds the threshold, the node is reported as malicious.
   * \param suspect The address of the suspicious node.
   */
  void RegisterSuspicion(Ipv4Address suspect);

  /**
   * \brief Applies the decay mechanism to all tracked nodes.
   * Decreases suspicion scores over time to forgive temporary congestion issues.
   */
  void ApplyDecay();

  /**
   * \brief Tracks the most recent RTS target for each sender.
   * Used to correctly attribute CTS frames (which only carry Addr1=sender of RTS).
   * Key: sender MAC (who sent RTS) → Value: receiver MAC (to whom RTS was sent)
   */
  std::map<Mac48Address, Mac48Address> m_lastRtsTarget;
  
  /**
   * \brief Cached MAC address of this node (resolved lazily).
   */
  Mac48Address m_myMac;

  /**
   * \brief Helper to resolve this node's own MAC address (lazy initialization).
   */
  Mac48Address GetMyMac();

  /**
   * \brief Resolves the MAC address of a neighbor given its IP address.
   * Searches through all Ipv4Interface ARP caches on this node.
   * \param ip The IPv4 address of the neighbor.
   * \return The Mac48Address if found, or a default-constructed (invalid) one otherwise.
   */
  Mac48Address GetMacForIp(Ipv4Address ip);

  /**
   * \brief Private timer for fast watchdog evaluation.
   * Runs independently of the main defense timer (which stays at 1s),
   * allowing this strategy to evaluate pending packets at its own pace.
   */
  Timer m_watchdogTimer;
  
  /**
   * \brief Interval between internal watchdog evaluations.
   * Should be ≤ m_watchdogTimeout for timely pending-packet checks.
   */
  Time m_watchdogCheckInterval;
  
  /**
   * \brief Internal evaluator — the logic that used to live in PeriodicCheck.
   * Called by m_watchdogTimer on its own schedule.
   */
  void EvaluatePendingPackets();

  /**
   * \brief Tracks forwarding activity for each neighbor (by MAC address).
   * Used to distinguish a true silent blackhole (activity=0) from a
   * congested-but-honest node (activity>0). 
   * 
   * Key: neighbor MAC address
   * Value: number of data packets we overheard this neighbor transmit
   *        in the current observation window.
   */
  std::map<Mac48Address, uint32_t> m_neighborActivity;
  
  /**
   * \brief Minimum activity count required to consider a neighbor "alive/busy"
   * rather than silently dropping. If activity >= this threshold, silent-drop
   * classification is suppressed (charitable interpretation: congestion).
   */
  static const uint32_t ACTIVITY_THRESHOLD = 2;

};

} 
} 

#endif