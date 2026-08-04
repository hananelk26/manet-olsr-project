#ifndef OLSR_WINDOW_FEATURES_H
#define OLSR_WINDOW_FEATURES_H

#include "ns3/core-module.h"
#include "ns3/ipv4-address.h"
#include "ns3/olsr-module.h"
#include "ns3/mac48-address.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <numeric>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ns3 {
namespace olsreval {

// ---------------------------------------------------------------------------
// Small numeric helpers (unchanged from the original).
// ---------------------------------------------------------------------------
inline double Mean (const std::vector<double>& v)
{
  if (v.empty ()) return 0.0;
  double s = 0.0; for (double x : v) s += x;
  return s / v.size ();
}

inline double Std (const std::vector<double>& v)
{
  if (v.size () < 2) return 0.0;
  const double m = Mean (v);
  double s = 0.0;
  for (double x : v) { const double d = x - m; s += d * d; }
  return std::sqrt (s / v.size ());
}

inline double Percentile (std::vector<double> v, double p /* 0..1 */)
{
  if (v.empty ()) return 0.0;
  std::sort (v.begin (), v.end ());
  const double idx = p * (v.size () - 1);
  const size_t lo = static_cast<size_t> (std::floor (idx));
  const size_t hi = static_cast<size_t> (std::ceil  (idx));
  if (lo == hi) return v[lo];
  const double frac = idx - lo;
  return v[lo] * (1.0 - frac) + v[hi] * frac;
}

inline double Skewness (const std::vector<double>& v)
{
  if (v.size () < 3) return 0.0;
  const double m = Mean (v);
  const double s = Std  (v);
  if (s == 0.0) return 0.0;
  double num = 0.0;
  for (double x : v) { const double d = (x - m) / s; num += d * d * d; }
  return num / v.size ();
}

inline double Kurtosis (const std::vector<double>& v)
{
  if (v.size () < 4) return 0.0;
  const double m = Mean (v);
  const double s = Std  (v);
  if (s == 0.0) return 0.0;
  double num = 0.0;
  for (double x : v) { const double d = (x - m) / s; num += d * d * d * d; }
  return (num / v.size ()) - 3.0;       // excess kurtosis
}

inline double Gini (std::vector<double> v)
{
  if (v.empty ()) return 0.0;
  std::sort (v.begin (), v.end ());
  double cum = 0.0, total = 0.0;
  for (size_t i = 0; i < v.size (); ++i)
    {
      cum   += (i + 1.0) * v[i];
      total += v[i];
    }
  if (total == 0.0) return 0.0;
  const double n = static_cast<double> (v.size ());
  return (2.0 * cum) / (n * total) - (n + 1.0) / n;
}

inline double ShannonEntropy (const std::vector<uint64_t>& counts)
{
  uint64_t total = 0; for (uint64_t c : counts) total += c;
  if (total == 0) return 0.0;
  double h = 0.0;
  for (uint64_t c : counts)
    {
      if (c == 0) continue;
      const double p = static_cast<double> (c) / total;
      h -= p * std::log2 (p);
    }
  return h;
}

inline double ByteEntropy (const std::vector<uint8_t>& bytes)
{
  if (bytes.empty ()) return 0.0;
  std::vector<uint64_t> hist (256, 0);
  for (uint8_t b : bytes) hist[b]++;
  return ShannonEntropy (hist);
}

// Hurst exponent via simple rescaled-range (R/S). Marked exploratory.
inline double HurstRS (const std::vector<double>& x)
{
  const size_t n = x.size ();
  if (n < 10) return 0.5;
  const double m = Mean (x);
  std::vector<double> Y (n);
  double cum = 0.0;
  for (size_t i = 0; i < n; ++i) { cum += x[i] - m; Y[i] = cum; }
  double mx = *std::max_element (Y.begin (), Y.end ());
  double mn = *std::min_element (Y.begin (), Y.end ());
  const double R = mx - mn;
  const double S = Std (x);
  if (S == 0.0 || R == 0.0) return 0.5;
  return std::log (R / S) / std::log (static_cast<double> (n));
}

// ---------------------------------------------------------------------------
// FeatureCollector
// ---------------------------------------------------------------------------
class FeatureCollector
{
public:
  // ----------------------- Output mode selection ---------------------------
  // Selects which feature block(s) EmitFeatureCsv()/FeatureCsvHeader() output.
  //   Core      : groups A-K only  (DEFAULT; the v2 parity group is ignored).
  //   V2Only    : only the strict_observable_v2 parity group (L).
  //   CoreAndV2 : everything -- groups A-K followed by the parity group (L).
  // Header and row stay in lock-step as long as the SAME mode value is passed
  // to both FeatureCsvHeader() and EmitFeatureCsv().
  enum class FeatureMode { Core, V2Only, CoreAndV2 };

  // ------------------------- Per-window reset ------------------------------
  void Reset (double tStart)
  {
    m_winStart = tStart;
    m_winEnd   = tStart;

    m_tcCount = m_midCount = m_hnaCount = 0;
    m_tcBytes = m_midBytes = m_hnaBytes = 0;
    m_dataPackets = 0;
    m_dataBytes   = 0;
    m_dataDeliveredBytes = 0;       // for ThroughputBitsPerSecond (OBS-006)

    m_tcBySender.clear ();
    m_tcBytesBySender.clear ();
    m_tcSizes.clear ();
    m_advertisedLinksPerTc.clear ();
    m_tcVtimes.clear ();
    m_lastAnsnBySender.clear ();
    m_ansnIncrements.clear ();
    m_ansnSkipCount = 0;
    m_tcContentKeys.clear ();
    m_tcPayloadBytes.clear ();
    m_tcAdvertisedAddrCounts.clear ();
    m_tcSenderAddrCounts.clear ();
    m_addressesSeenInTcPayload.clear ();
    m_addressesEverSentTc.clear ();
    m_addressesEverSentData.clear ();
    m_addressesFirstSeen.clear ();
    m_addressesLastSeen.clear ();
    m_observedDirectedEdges.clear ();
    m_mprSelectorsByTcSender.clear ();
    m_mprSelectorsHistoryBySender.clear ();
    m_mprChurnEvents = 0;
    m_distinctMprSetsBySender.clear ();
    m_hopCounts.clear ();
    m_sourceDestPairs.clear ();

    // E-group: first-hop-MAC churn (BUG-004 observable replacement).
    m_firstHopMacsPerSrc.clear ();
    m_pathChangeEventsPerSrc.clear ();
    m_lastFirstHopMacPerSrc.clear ();

    // MAC-frame counters (PHY-trace driven; suppressed if PHY unavailable).
    m_macRetxCount = 0;
    m_busyIntervals.clear ();
    m_interFrameSpacing.clear ();
    m_lastMacTxEnd = -1.0;
    m_dataFramesObservedOnAir = 0;  // MIS-001 denominator

    m_dataLatencies.clear ();
    m_dataSentByFlow.clear ();
    m_dataDeliveredByFlow.clear ();
    m_jitterSamples.clear ();
    m_lastArrivalPerFlow.clear ();

    // L-group (strict_observable_v2 parity): per-flow accumulators.
    m_flowFirstTxTime.clear ();
    m_flowLastTxTime.clear ();
    m_flowTxBytes.clear ();
    m_flowDelays.clear ();
    m_flowJitters.clear ();

    m_tcInterArrivalsPerSender.clear ();
    m_lastTcTimeBySender.clear ();
    m_controlMessageTimes.clear ();
    m_packetSizes.clear ();
    m_advertisedEdgesAllTime.clear ();
    m_edgeFirstSeen.clear ();
    m_edgeLastSeen.clear ();

    // BUG-002/003: within-window edge split (replaces cross-window state).
    m_edgesFirstHalf.clear ();
    m_edgesLastHalf.clear ();

    // FEAT-008 (schema v4): clear defense-detection breadth accumulators.
    m_tcSeqByOriginator.clear ();
    m_tcRelayMacsByOriginator.clear ();
    m_tcMaxHopByOriginator.clear ();
    m_distinctForwarderNextHopPairs.clear ();
    m_lastNextHopByForwarderDst.clear ();
    m_forwardersThatChangedNextHop.clear ();
  }

  // -------------------------- Phy availability ----------------------------
  // Set once at start of simulation. When false, all F-group features
  // emit 0 (per DEG-003).
  void SetPhyAvailable (bool ok) { m_phyAvailable = ok; }

  // -------------------------- Observations ---------------------------------

  void ObserveTc (Ipv4Address senderIfaceAddr,
                  Ipv4Address originator,
                  const olsr::MessageHeader& msg,
                  const olsr::MessageHeader::Tc& tc,
                  uint32_t messageSerializedSize)
  {
    const double now = Simulator::Now ().GetSeconds ();
    (void) senderIfaceAddr;
    m_tcCount++;
    m_tcBytes += messageSerializedSize;
    m_tcBySender[originator]++;
    m_tcBytesBySender[originator] += messageSerializedSize;
    m_tcSizes.push_back (messageSerializedSize);
    m_advertisedLinksPerTc.push_back (tc.neighborAddresses.size ());
    m_tcVtimes.push_back (msg.GetVTime ().GetSeconds ());

    // BUG-001: ANSN delta with modular-16-bit arithmetic. The subtraction
    // is performed in uint16_t (wraps cleanly), then reinterpreted as int16_t
    // to get the shortest signed distance (RFC 1982 serial-number style).
    auto itAnsn = m_lastAnsnBySender.find (originator);
    if (itAnsn != m_lastAnsnBySender.end ())
      {
        const uint16_t prev = itAnsn->second;
        const uint16_t cur  = tc.ansn;
        const int16_t signedDelta =
            static_cast<int16_t> (static_cast<uint16_t> (cur - prev));
        m_ansnIncrements.push_back (signedDelta);
        if (signedDelta > 1 || signedDelta < 0) m_ansnSkipCount++;
      }
    m_lastAnsnBySender[originator] = tc.ansn;

    // Canonical key over sorted neighbour addresses (content entropy).
    std::vector<uint32_t> addrs;
    addrs.reserve (tc.neighborAddresses.size ());
    for (const auto& a : tc.neighborAddresses) addrs.push_back (a.Get ());
    std::sort (addrs.begin (), addrs.end ());
    std::string key;
    key.reserve (addrs.size () * 4);
    for (uint32_t a : addrs) {
      key.append (reinterpret_cast<const char*> (&a), sizeof (a));
    }
    m_tcContentKeys[key]++;

    m_tcSenderAddrCounts[originator]++;
    m_addressesEverSentTc.insert (originator);
    m_addressesFirstSeen.emplace (originator, now);
    m_addressesLastSeen[originator] = now;

    // BUG-002/003: split edge observation by window half. The within-window
    // dynamic replaces the broken cross-window diff.
    const double halfPoint = m_winStart + (m_winEnd > m_winStart
                                           ? (m_winEnd - m_winStart) * 0.5
                                           : 20.0);  // updated at Snapshot
    // Note: m_winEnd may not be set yet at Observe-time; we use a deferred
    // half-point computed in EmitFeatureCsv() instead. See Snapshot logic.

    for (const auto& adv : tc.neighborAddresses)
      {
        m_addressesSeenInTcPayload.insert (adv);
        m_tcAdvertisedAddrCounts[adv]++;
        m_addressesFirstSeen.emplace (adv, now);
        m_addressesLastSeen[adv] = now;
        m_observedDirectedEdges.emplace (originator, adv);

        Edge e {originator, adv};
        if (e.a > e.b) std::swap (e.a, e.b);
        auto efIt = m_edgeFirstSeen.find (e);
        if (efIt == m_edgeFirstSeen.end ())
          {
            m_edgeFirstSeen[e] = now;
          }
        m_edgeLastSeen[e] = now;
        m_advertisedEdgesAllTime.insert (e);

        // DEG-002: push only the last octet of the IP. The /8 prefix is
        // constant across all 10.0.0.0/8 nodes, so emitting all four bytes
        // destroyed the byte-entropy column's variance.
        const uint32_t raw = adv.Get ();
        m_tcPayloadBytes.push_back (static_cast<uint8_t> (raw & 0xff));
      }

    // Record edge observation time for the within-window half split.
    // We re-bucket at EmitFeatureCsv based on m_edgeFirstSeen/m_edgeLastSeen.
    (void) halfPoint;

    std::set<Ipv4Address> mprSet (tc.neighborAddresses.begin (),
                                  tc.neighborAddresses.end ());
    m_mprSelectorsByTcSender[originator].push_back (mprSet.size ());

    auto& history = m_mprSelectorsHistoryBySender[originator];
    if (!history.empty () && history.back () != mprSet) m_mprChurnEvents++;
    history.push_back (mprSet);
    m_distinctMprSetsBySender[originator].insert (
        SetToCanonicalKey (mprSet));

    auto itLast = m_lastTcTimeBySender.find (originator);
    if (itLast != m_lastTcTimeBySender.end ())
      {
        m_tcInterArrivalsPerSender[originator].push_back (now - itLast->second);
      }
    m_lastTcTimeBySender[originator] = now;
    m_controlMessageTimes.push_back (now);
    m_packetSizes.push_back (messageSerializedSize);
  }

  void ObserveMid (Ipv4Address originator, uint32_t messageSerializedSize)
  {
    (void) originator;
    m_midCount++;
    m_midBytes += messageSerializedSize;
    m_controlMessageTimes.push_back (Simulator::Now ().GetSeconds ());
    m_packetSizes.push_back (messageSerializedSize);
  }

  void ObserveHna (Ipv4Address originator, uint32_t messageSerializedSize)
  {
    (void) originator;
    m_hnaCount++;
    m_hnaBytes += messageSerializedSize;
    m_controlMessageTimes.push_back (Simulator::Now ().GetSeconds ());
    m_packetSizes.push_back (messageSerializedSize);
  }

  // OBS-004/005: data-flow observations from on-air capture. Callers
  // (in the .cc) parse the MSDU at MacTx time, HELLO-filter, and call
  // these. The "Sent" event is the first appearance of an IP-id on the
  // medium (sender's transmission); the "Delivered" event is the
  // last-hop transmission addressed to the victim.
  void ObserveDataSentOnAir (Ipv4Address src, Ipv4Address dst,
                             uint32_t bytes, double now)
  {
    m_dataPackets++;
    m_dataBytes += bytes;
    m_addressesEverSentData.insert (src);
    m_addressesFirstSeen.emplace (src, now);
    m_addressesLastSeen[src] = now;
    m_sourceDestPairs.emplace (src, dst);
    m_dataSentByFlow[{src, dst}]++;
    m_packetSizes.push_back (bytes);

    // L-group: per-flow tx accumulators (first/last tx time, tx bytes).
    const std::pair<Ipv4Address, Ipv4Address> fk (src, dst);
    if (m_flowFirstTxTime.find (fk) == m_flowFirstTxTime.end ())
      m_flowFirstTxTime[fk] = now;
    m_flowLastTxTime[fk] = now;
    m_flowTxBytes[fk] += bytes;
  }

  void ObserveDataDeliveredOnAir (Ipv4Address src, Ipv4Address dst,
                                  uint8_t ttlAtLastForwarder,
                                  double latencySec,
                                  Mac48Address firstHopMac, double now)
  {
    // BUG-004 fix (hops formula): at the LAST forwarder's MacTx, ttl =
    // 65 - hops (initial TTL=64, each forwarder decrements before TX).
    // So hops = 65 - ttlAtLastForwarder. For a 1-hop path (source TXes
    // directly), the source itself is the "last forwarder" and ttl=64
    // -> hops=1. Verified for 2-hop and 3-hop paths.
    if (ttlAtLastForwarder > 0 && ttlAtLastForwarder <= 65)
      {
        const int hops = 65 - ttlAtLastForwarder;
        if (hops >= 1 && hops < 65) m_hopCounts.push_back (hops);
      }
    m_dataDeliveredByFlow[{src, dst}]++;
    // NOTE: m_dataDeliveredBytes is credited via AddDeliveredBytes() by
    // the caller (single source of truth for the bytes count).
    m_dataLatencies.push_back (latencySec);

    auto key = std::make_pair (src, dst);
    auto itLast = m_lastArrivalPerFlow.find (key);
    if (itLast != m_lastArrivalPerFlow.end ())
      {
        const double jitterSample = std::abs (latencySec - itLast->second);
        m_jitterSamples.push_back (jitterSample);
        m_flowJitters[key].push_back (jitterSample);   // L-group per-flow jitter
      }
    m_lastArrivalPerFlow[key] = latencySec;
    m_flowDelays[key].push_back (latencySec);           // L-group per-flow delay

    // BUG-004: first-hop MAC tracking. The caller passes the MAC of the
    // first relay (the second on-air transmitter of the same IP-id).
    if (firstHopMac != Mac48Address ())
      {
        m_firstHopMacsPerSrc[src].insert (firstHopMac);
        auto itPrev = m_lastFirstHopMacPerSrc.find (src);
        if (itPrev != m_lastFirstHopMacPerSrc.end ()
            && itPrev->second != firstHopMac)
          {
            m_pathChangeEventsPerSrc[src]++;
          }
        m_lastFirstHopMacPerSrc[src] = firstHopMac;
      }
    (void) now;
  }

  // OBS-006: caller passes delivered bytes; credited exactly once per
  // ipId-delivery (the caller dedupes via the IP-id correlation map).
  void AddDeliveredBytes (uint64_t bytes) { m_dataDeliveredBytes += bytes; }

  // OBS-002(b) / DEG-003: PHY-trace driven MAC frame observation.
  // The caller MUST already have filtered out HELLO (OBS-001) and the
  // 1-hop RTS/CTS/ACK control frames (OBS-007) before calling this.
  // durationSec is from WifiMacHeader::GetDuration() (NAV) -- approximates
  // medium-busy time for this frame's exchange (DATA + SIFS + ACK); the
  // Duration field is read from the observable data frame's own header.
  void ObserveMacFrame (double now, double durationSec, bool isData,
                        bool isRetry)
  {
    if (!m_phyAvailable) return;
    if (durationSec > 0.0)
      m_busyIntervals.emplace_back (now, now + durationSec);
    if (m_lastMacTxEnd >= 0.0)
      m_interFrameSpacing.push_back (now - m_lastMacTxEnd);
    m_lastMacTxEnd = now;
    if (isData)
      {
        m_dataFramesObservedOnAir++;            // MIS-001 denominator
        if (isRetry) m_macRetxCount++;
      }
  }

  // ----- FEAT-008 (schema v4): defense-detection breadth observers --------
  // Fed from the on-air PHY sniffer only. transmitterMac is MAC Addr2 of the
  // frame carrying a copy of `originator`'s TC; a copy is deduplicated by
  // (originator, msgSeq). hopCount is the OLSR message-header hop-count.
  void ObserveTcRelayOnAir (Ipv4Address originator,
                            uint16_t msgSeq,
                            uint8_t hopCount,
                            Mac48Address transmitterMac)
  {
    m_tcSeqByOriginator[originator].insert (msgSeq);
    if (transmitterMac != Mac48Address ())
      m_tcRelayMacsByOriginator[originator].insert (transmitterMac);
    const uint32_t h = static_cast<uint32_t> (hopCount);
    auto it = m_tcMaxHopByOriginator.find (originator);
    if (it == m_tcMaxHopByOriginator.end () || h > it->second)
      m_tcMaxHopByOriginator[originator] = h;
  }

  // Fed from the on-air PHY sniffer only. forwarderMac is MAC Addr2 (the node
  // retransmitting a DATA frame), nextHopMac is MAC Addr1 (its chosen L2
  // next-hop), dst is the IP destination of the frame. With a static topology
  // any change in the next-hop a forwarder uses for a destination is a
  // defense-induced reroute.
  void ObserveDataForwardOnAir (Mac48Address forwarderMac,
                                Mac48Address nextHopMac,
                                Ipv4Address dst)
  {
    if (forwarderMac == Mac48Address () || nextHopMac == Mac48Address ())
      return;
    m_distinctForwarderNextHopPairs.emplace (forwarderMac, nextHopMac);
    const std::pair<Mac48Address, Ipv4Address> fdKey (forwarderMac, dst);
    auto it = m_lastNextHopByForwarderDst.find (fdKey);
    if (it == m_lastNextHopByForwarderDst.end ())
      {
        m_lastNextHopByForwarderDst[fdKey] = nextHopMac;
      }
    else if (it->second != nextHopMac)
      {
        it->second = nextHopMac;
        m_forwardersThatChangedNextHop.insert (forwarderMac);
      }
  }

  // -------------------------- Snapshot -------------------------------------
  static std::string CoreFeatureCsvHeader ()
  {
    return
      // A. Control traffic volume (11)
      "TcPacketRate,MidPacketRate,HnaPacketRate,"
      "TcBytesPerSecond,MidBytesPerSecond,HnaBytesPerSecond,"
      "DataPacketRate,DataBytesPerSecond,"
      "PerNodeTcRateStd,PerNodeTcBytesStd,PerNodeTcBytesGini,"
      // B. TC structure (14)
      "TcMessageSizeMean,TcMessageSizeStd,TcMessageSizeP95,TcMessageSizeMax,"
      "AdvertisedLinksPerTcMean,AdvertisedLinksPerTcStd,"
      "AdvertisedLinksPerTcP95,AdvertisedLinksPerTcMax,"
      "TcAnsnIncrementMean,TcAnsnSkipCount,"
      "NumDistinctTcSenderNodesPerWindow,"
      "TcMessageContentEntropy,TcVtimeMean,TcVtimeStd,"
      // C. Address sets (5; C3 removed per DEG-001)
      "NumDistinctAddressesInTcAdvertisements,NumDistinctTcSenderAddresses,"
      "NumPhantomAddresses,NumAsymmetricAdvertisements,NumEphemeralAddresses,"
      // D. MPR (4)
      "MprSelectorCountPerTcMean,MprSelectorCountPerTcStd,"
      "NumberOfMprChurnEvents,NumDistinctMprSetsObserved,"
      // E. Paths & forwarding (5; E3, E5, E6 removed)
      "ObservedHopCountMean,ObservedHopCountStd,ObservedHopCountMax,"
      "NumPathChangesPerFlow,NumDistinctNextHopsPerSource,"
      // F. MAC (3; F11, F12, F8 InterFrameSpacingStd removed; OBS-007:
      //    RtsRateLocal, CtsRateLocal, AckRateLocal, AckDelayMean,
      //    AckDelayStd removed)
      "Layer2RetransmissionRate,ChannelBusyTimeFraction,"
      "InterFrameSpacingMean,"
      // G. Performance (6; G5, G7 JitterStd, G9 removed)
      "PacketsDeliveredCount,PacketsSentCount,"
      "EndToEndLatencyMean,EndToEndLatencyStd,"
      "JitterMean,ThroughputBitsPerSecond,"
      // H. Time & periodicity (6)
      "TcInterArrivalMean,TcInterArrivalStd,TcInterArrivalP95,"
      "TcBurstinessHurst,"
      "ControlMessageInterArrivalSkew,ControlMessageInterArrivalKurtosis,"
      // I. Entropy & stats (5; I3, I6 removed)
      "TcSenderAddressEntropy,TcAdvertisedAddressEntropy,"
      "PacketSizeDistributionSkew,PacketSizeDistributionKurtosis,"
      "TcPayloadByteDistributionEntropy,"
      // J. Topology graph (22)
      "AdvertisedAverageDegree,AdvertisedDegreeStd,AdvertisedDegreeSkew,"
      "AdvertisedDegreeKurtosis,NumberOfDegreeOneNodes,"
      "AdvertisedClusteringCoefficient,NumberOfTrianglesInAdvertisedGraph,"
      "AdvertisedConnectivityComponents,AdvertisedDiameter,AdvertisedRadius,"
      "AdvertisedGraphDensity,"
      "BetweennessCentralityMean,BetweennessCentralityStd,BetweennessCentralityMax,"
      "ClosenessCentralityMean,ClosenessCentralityStd,"
      "EdgePersistenceMean,EdgeEmergenceWithinWindowRate,EdgeChurnWithinWindowRate,"
      "NumberOfHexagonalCycles,NumberOfShortCycles,AdvertisedSpectralRadius,"
      // K. Defense-detection breadth (FEAT-008, schema v4) (14)
      "TcOriginationCountMin,TcOriginationCountMean,TcOriginationCountStd,TcOriginationCountMax,"
      "TcRelayerBreadthMin,TcRelayerBreadthMean,TcRelayerBreadthStd,TcRelayerBreadthMax,"
      "TcMaxHopReachMin,TcMaxHopReachMean,TcMaxHopReachStd,TcMaxHopReachMax,"
      "DistinctForwardersChangingNextHop,NumDistinctNextHopsObservedNetworkwide";
  }

  // ----- strict_observable_v2 parity group (L): 33 columns. ----------------
  // Names and order match defense_detection_v2.py's METRICS list so the
  // existing v2 ML pipeline can consume these columns directly.
  static std::string V2FeatureCsvHeader ()
  {
    return
      "TcMessageRate,MidMessageRate,HnaMessageRate,"
      "AverageAdvertisedLinksPerTCMessage,"
      "NormalizedRoutingLoad,RoutingOverheadRatio,RoutingOverheadBytesRatio,"
      "PacketDeliveryRatio,PacketLossRatio,AverageEndToEndDelay,AverageJitter,"
      "Throughput,AverageHopCount,DataPacketRate,RxTxPacketRatio,"
      "FlowCount,AvgFlowDuration,FlowDurationStd,AvgFlowThroughput,"
      "AvgFlowDelay,AvgFlowJitter,AvgFlowLossRate,"
      "FlowThroughputStd,FlowDelayStd,FlowJitterStd,FlowLossRateStd,"
      "AvgTxBytesPerFlow,AvgRxBytesPerFlow,AvgTxPacketsPerFlow,AvgRxPacketsPerFlow,"
      "AvgTxPacketSize,AvgRxPacketSize,AverageMprCount";
  }

  // Mode-aware header. Defaults to FeatureMode::Core, so existing callers that
  // call FeatureCsvHeader() keep emitting groups A-K unchanged.
  static std::string FeatureCsvHeader (FeatureMode mode = FeatureMode::Core)
  {
    switch (mode)
      {
      case FeatureMode::V2Only:    return V2FeatureCsvHeader ();
      case FeatureMode::CoreAndV2: return CoreFeatureCsvHeader () + "," + V2FeatureCsvHeader ();
      case FeatureMode::Core:
      default:                     return CoreFeatureCsvHeader ();
      }
  }

  std::string EmitFeatureCsv (double tEnd, FeatureMode mode = FeatureMode::Core)
  {
    m_winEnd = tEnd;
    const double dur = std::max (1e-6, m_winEnd - m_winStart);
    const double halfPoint = m_winStart + dur * 0.5;

    // BUG-002/003: bucket edges into first-half / last-half based on
    // m_edgeFirstSeen and m_edgeLastSeen.
    m_edgesFirstHalf.clear ();
    m_edgesLastHalf.clear ();
    for (const auto& e : m_advertisedEdgesAllTime)
      {
        auto itF = m_edgeFirstSeen.find (e);
        auto itL = m_edgeLastSeen.find (e);
        if (itF == m_edgeFirstSeen.end () || itL == m_edgeLastSeen.end ())
          continue;
        if (itF->second < halfPoint) m_edgesFirstHalf.insert (e);
        if (itL->second >= halfPoint) m_edgesLastHalf.insert (e);
      }
    // Emergence = present in late half, absent from early half.
    // Churn    = present in early half, absent from late half.
    uint64_t emerged = 0, churned = 0;
    for (const auto& e : m_edgesLastHalf)
      if (m_edgesFirstHalf.find (e) == m_edgesFirstHalf.end ())
        emerged++;
    for (const auto& e : m_edgesFirstHalf)
      if (m_edgesLastHalf.find (e) == m_edgesLastHalf.end ())
        churned++;
    const double edgeEmergenceRate = emerged / dur;
    const double edgeChurnRate     = churned / dur;

    // === A. Control traffic volume =======================================
    const double tcRate    = m_tcCount    / dur;
    const double midRate   = m_midCount   / dur;
    const double hnaRate   = m_hnaCount   / dur;
    const double tcBps     = m_tcBytes    / dur;
    const double midBps    = m_midBytes   / dur;
    const double hnaBps    = m_hnaBytes   / dur;
    const double dataPRate = m_dataPackets / dur;
    const double dataBps   = m_dataBytes   / dur;

    std::vector<double> perNodeTcRates, perNodeTcBytes;
    for (auto& kv : m_tcBySender)      perNodeTcRates.push_back (kv.second / dur);
    for (auto& kv : m_tcBytesBySender) perNodeTcBytes.push_back (kv.second / dur);
    const double perNodeTcRateStd   = Std (perNodeTcRates);
    const double perNodeTcBytesStd  = Std (perNodeTcBytes);
    const double perNodeTcBytesGini = Gini (perNodeTcBytes);

    // === B. TC structure ==================================================
    const double tcMsgMean = Mean (m_tcSizes);
    const double tcMsgStd  = Std  (m_tcSizes);
    const double tcMsgP95  = Percentile (m_tcSizes, 0.95);
    const double tcMsgMax  = m_tcSizes.empty () ? 0.0
                          : *std::max_element (m_tcSizes.begin (), m_tcSizes.end ());
    const double advLnkMean = Mean (m_advertisedLinksPerTc);
    const double advLnkStd  = Std  (m_advertisedLinksPerTc);
    const double advLnkP95  = Percentile (m_advertisedLinksPerTc, 0.95);
    const double advLnkMax  = m_advertisedLinksPerTc.empty () ? 0.0
        : *std::max_element (m_advertisedLinksPerTc.begin (),
                             m_advertisedLinksPerTc.end ());
    const double ansnMean   = Mean (m_ansnIncrements);
    const uint64_t ansnSkip = m_ansnSkipCount;
    const uint64_t distSenders = m_tcBySender.size ();
    std::vector<uint64_t> contentHist;
    contentHist.reserve (m_tcContentKeys.size ());
    for (auto& kv : m_tcContentKeys) contentHist.push_back (kv.second);
    const double tcContentEntropy = ShannonEntropy (contentHist);
    const double tcVtMean = Mean (m_tcVtimes);
    const double tcVtStd  = Std  (m_tcVtimes);

    // === C. Address sets ==================================================
    const uint64_t numAddrInTc       = m_addressesSeenInTcPayload.size ();
    const uint64_t numDistinctTcSend = m_addressesEverSentTc.size ();
    // C3 (NumDistinctDataSenderAddresses) removed per DEG-001.

    uint64_t numPhantom = 0;
    for (const auto& a : m_addressesSeenInTcPayload)
      {
        if (m_addressesEverSentTc.find (a) == m_addressesEverSentTc.end ()
            && m_addressesEverSentData.find (a) == m_addressesEverSentData.end ())
          numPhantom++;
      }

    uint64_t numAsym = 0;
    for (const auto& pr : m_observedDirectedEdges)
      {
        if (m_observedDirectedEdges.find ({pr.second, pr.first})
            == m_observedDirectedEdges.end ())
          numAsym++;
      }

    uint64_t numEphemeral = 0;
    const double halfDur = dur * 0.5;
    for (auto& kv : m_addressesFirstSeen)
      {
        auto itLast = m_addressesLastSeen.find (kv.first);
        if (itLast == m_addressesLastSeen.end ()) continue;
        if ((itLast->second - kv.second) < halfDur) numEphemeral++;
      }

    // === D. MPR selection ================================================
    std::vector<double> allSelectorCounts;
    for (auto& kv : m_mprSelectorsByTcSender)
      for (auto c : kv.second) allSelectorCounts.push_back (c);
    const double mprSelMean = Mean (allSelectorCounts);
    const double mprSelStd  = Std  (allSelectorCounts);
    const uint64_t mprChurn = m_mprChurnEvents;
    uint64_t totalDistinctMprSets = 0;
    for (auto& kv : m_distinctMprSetsBySender)
      totalDistinctMprSets += kv.second.size ();

    // === E. Paths & forwarding ============================================
    const double hopMean = Mean (m_hopCounts);
    const double hopStd  = Std  (m_hopCounts);
    // E3 (P95) and E5/E6 removed per DEG-001/DEG-004.
    const double hopMax  = m_hopCounts.empty () ? 0.0
        : *std::max_element (m_hopCounts.begin (), m_hopCounts.end ());

    // BUG-004: prev-hop-MAC churn replaces the broken next-hop bookkeeping.
    uint64_t sumPathChanges = 0;
    for (auto& kv : m_pathChangeEventsPerSrc) sumPathChanges += kv.second;
    const double pathChangesPerFlow =
        (m_firstHopMacsPerSrc.empty ())
        ? 0.0
        : (static_cast<double> (sumPathChanges)
           / m_firstHopMacsPerSrc.size ());
    double sumDistinctNextHops = 0.0;
    for (auto& kv : m_firstHopMacsPerSrc) sumDistinctNextHops += kv.second.size ();
    const double distinctNextHopsPerSrc =
        (m_firstHopMacsPerSrc.empty ())
        ? 0.0
        : (sumDistinctNextHops / m_firstHopMacsPerSrc.size ());

    // === F. MAC layer (DEG-003: gated on PHY availability) ================
    double l2RetxRate = 0.0;
    double busyFrac = 0.0;
    double ifsMean = 0.0;
    if (m_phyAvailable)
      {
        // MIS-001: denominator is total non-HELLO data frames observed on
        // the medium during this window. Numerator is the retry-bit count.
        l2RetxRate = (m_dataFramesObservedOnAir > 0)
            ? (static_cast<double> (m_macRetxCount)
               / static_cast<double> (m_dataFramesObservedOnAir))
            : 0.0;
        // BUG-006 fix: union-of-intervals channel busy fraction.
        busyFrac = ComputeBusyFraction (m_busyIntervals,
                                        m_winStart, m_winEnd);
        ifsMean = Mean (m_interFrameSpacing);
      }

    // === G. Performance ==================================================
    uint64_t pktsDelivered = 0, pktsSent = 0;
    for (auto& kv : m_dataDeliveredByFlow) pktsDelivered += kv.second;
    for (auto& kv : m_dataSentByFlow)      pktsSent      += kv.second;
    const double e2eMean = Mean (m_dataLatencies);
    const double e2eStd  = Std  (m_dataLatencies);
    // G5 (P95), G7 (JitterStd), G9 removed per DEG-001/DEG-004.
    const double jMean   = Mean (m_jitterSamples);
    // OBS-006: throughput = delivered bytes on air * 8 / dur.
    const double throughputBps = (m_dataDeliveredBytes * 8.0) / dur;

    // === H. Time & periodicity ============================================
    std::vector<double> allTcGaps;
    for (auto& kv : m_tcInterArrivalsPerSender)
      for (double g : kv.second) allTcGaps.push_back (g);
    const double tcGapMean = Mean (allTcGaps);
    const double tcGapStd  = Std  (allTcGaps);
    const double tcGapP95  = Percentile (allTcGaps, 0.95);
    std::vector<double> tcPerSlot;
    if (m_tcCount > 0)
      {
        const int nslots = static_cast<int> (std::ceil (dur));
        tcPerSlot.assign (nslots > 0 ? nslots : 1, 0.0);
        for (double t : m_controlMessageTimes)
          {
            const int s = static_cast<int> (t - m_winStart);
            if (s >= 0 && s < static_cast<int> (tcPerSlot.size ()))
              tcPerSlot[s] += 1.0;
          }
      }
    const double tcHurst = HurstRS (tcPerSlot);
    std::vector<double> ctrlGaps;
    if (m_controlMessageTimes.size () >= 2)
      {
        std::vector<double> t = m_controlMessageTimes;
        std::sort (t.begin (), t.end ());
        for (size_t i = 1; i < t.size (); ++i) ctrlGaps.push_back (t[i] - t[i-1]);
      }
    const double ctrlSkew = Skewness (ctrlGaps);
    const double ctrlKurt = Kurtosis (ctrlGaps);

    // === I. Entropy & stats ==============================================
    std::vector<uint64_t> hSender, hAdv;
    for (auto& kv : m_tcSenderAddrCounts)    hSender.push_back (kv.second);
    for (auto& kv : m_tcAdvertisedAddrCounts) hAdv.push_back (kv.second);
    const double tcSenderEnt = ShannonEntropy (hSender);
    const double tcAdvEnt    = ShannonEntropy (hAdv);
    // I3 (DataSenderAddressEntropy) removed per DEG-001.
    std::vector<double> sizesD;
    sizesD.reserve (m_packetSizes.size ());
    for (auto s : m_packetSizes) sizesD.push_back (s);
    const double pktSkew = Skewness (sizesD);
    const double pktKurt = Kurtosis (sizesD);
    // I6 (Compressibility) removed per DEG-002.
    const double byteEnt = ByteEntropy (m_tcPayloadBytes);

    // === J. Topology graph features ======================================
    std::map<Ipv4Address, uint32_t> idx;
    auto getIdx = [&] (Ipv4Address a) -> uint32_t {
      auto it = idx.find (a);
      if (it != idx.end ()) return it->second;
      const uint32_t v = idx.size ();
      idx[a] = v;
      return v;
    };
    for (const auto& e : m_advertisedEdgesAllTime)
      {
        getIdx (e.a);
        getIdx (e.b);
      }
    const uint32_t N = idx.size ();
    std::vector<std::vector<uint32_t>> adj (N);
    for (const auto& e : m_advertisedEdgesAllTime)
      {
        const uint32_t u = idx[e.a];
        const uint32_t v = idx[e.b];
        if (u == v) continue;
        adj[u].push_back (v);
        adj[v].push_back (u);
      }
    for (auto& nb : adj)
      {
        std::sort (nb.begin (), nb.end ());
        nb.erase (std::unique (nb.begin (), nb.end ()), nb.end ());
      }

    std::vector<double> degrees (N);
    for (uint32_t i = 0; i < N; ++i) degrees[i] = adj[i].size ();
    const double degMean = Mean (degrees);
    const double degStd  = Std  (degrees);
    const double degSkew = Skewness (degrees);
    const double degKurt = Kurtosis (degrees);
    uint64_t degOne = 0;
    for (double d : degrees) if (static_cast<int> (d) == 1) degOne++;

    double clusterSum = 0.0;
    uint64_t triangles3 = 0;
    for (uint32_t v = 0; v < N; ++v)
      {
        const auto& nbv = adj[v];
        if (nbv.size () < 2) continue;
        uint64_t edgesAmongNb = 0;
        for (size_t i = 0; i < nbv.size (); ++i)
          for (size_t j = i + 1; j < nbv.size (); ++j)
            {
              const uint32_t a = nbv[i], b = nbv[j];
              if (std::binary_search (adj[a].begin (), adj[a].end (), b))
                edgesAmongNb++;
            }
        const double k = nbv.size ();
        clusterSum += (2.0 * edgesAmongNb) / (k * (k - 1));
        triangles3 += edgesAmongNb;
      }
    const double clustering = (N > 0) ? (clusterSum / N) : 0.0;
    const uint64_t triangles = triangles3 / 3;

    // Connected components.
    std::vector<int> componentId (N, -1);
    uint32_t numComponents = 0;
    for (uint32_t s = 0; s < N; ++s)
      {
        if (componentId[s] != -1) continue;
        numComponents++;
        std::queue<uint32_t> q;
        q.push (s);
        componentId[s] = static_cast<int> (numComponents);
        while (!q.empty ())
          {
            const uint32_t u = q.front (); q.pop ();
            for (uint32_t v : adj[u])
              {
                if (componentId[v] == -1)
                  {
                    componentId[v] = static_cast<int> (numComponents);
                    q.push (v);
                  }
              }
          }
      }

    // Eccentricity, diameter, radius.
    std::vector<int> eccentricity (N, 0);
    int diameterFinal = 0;
    for (uint32_t s = 0; s < N; ++s)
      {
        std::vector<int> dist (N, -1);
        std::queue<uint32_t> bq;
        bq.push (s);
        dist[s] = 0;
        int best = 0;
        while (!bq.empty ())
          {
            const uint32_t u = bq.front (); bq.pop ();
            for (uint32_t w : adj[u])
              {
                if (dist[w] < 0)
                  {
                    dist[w] = dist[u] + 1;
                    bq.push (w);
                    if (dist[w] > best) best = dist[w];
                  }
              }
          }
        eccentricity[s] = best;
        if (best > diameterFinal) diameterFinal = best;
      }
    const int diameter = diameterFinal;
    // BUG-005: initialize radius with int-max and take min over positive
    // eccentricities. Collapse to 0 only if no positive eccentricity exists.
    int radius = std::numeric_limits<int>::max ();
    for (uint32_t i = 0; i < N; ++i)
      if (eccentricity[i] > 0 && eccentricity[i] < radius)
        radius = eccentricity[i];
    if (radius == std::numeric_limits<int>::max ()) radius = 0;

    const double density = (N >= 2)
        ? (2.0 * m_advertisedEdgesAllTime.size () / (N * (N - 1.0)))
        : 0.0;

    // Betweenness & closeness (Brandes' algorithm).
    std::vector<double> betweenness (N, 0.0);
    std::vector<double> closenessV  (N, 0.0);
    for (uint32_t s = 0; s < N; ++s)
      {
        std::vector<std::vector<uint32_t>> P (N);
        std::vector<int> sigma (N, 0); sigma[s] = 1;
        std::vector<int> dist  (N, -1); dist[s]  = 0;
        std::queue<uint32_t> bfsq; bfsq.push (s);
        std::vector<uint32_t> stk;
        while (!bfsq.empty ())
          {
            const uint32_t v = bfsq.front (); bfsq.pop ();
            stk.push_back (v);
            for (uint32_t w : adj[v])
              {
                if (dist[w] < 0) { dist[w] = dist[v] + 1; bfsq.push (w); }
                if (dist[w] == dist[v] + 1)
                  {
                    sigma[w] += sigma[v];
                    P[w].push_back (v);
                  }
              }
          }
        double sumDist = 0; int reach = 0;
        for (uint32_t i = 0; i < N; ++i)
          if (i != s && dist[i] > 0) { sumDist += dist[i]; reach++; }
        if (sumDist > 0)
          closenessV[s] = static_cast<double> (reach) / sumDist;

        std::vector<double> delta (N, 0.0);
        while (!stk.empty ())
          {
            const uint32_t w = stk.back (); stk.pop_back ();
            for (uint32_t v : P[w])
              {
                if (sigma[w] == 0) continue;
                delta[v] += (static_cast<double> (sigma[v]) / sigma[w])
                            * (1.0 + delta[w]);
              }
            if (w != s) betweenness[w] += delta[w];
          }
      }
    for (double& b : betweenness) b /= 2.0;

    const double btwMean = Mean (betweenness);
    const double btwStd  = Std  (betweenness);
    const double btwMax  = betweenness.empty () ? 0.0
        : *std::max_element (betweenness.begin (), betweenness.end ());
    const double closMean = Mean (closenessV);
    const double closStd  = Std  (closenessV);

    // Edge persistence (within-window).
    double sumPersistence = 0.0;
    for (const auto& e : m_advertisedEdgesAllTime)
      sumPersistence += (m_edgeLastSeen[e] - m_edgeFirstSeen[e]);
    const double edgePersistMean =
        m_advertisedEdgesAllTime.empty () ? 0.0
        : (sumPersistence / m_advertisedEdgesAllTime.size ());

    // Cycle counts (BUG-007 fix: dead code removed in CountCyclesOfLength).
    const uint64_t hexCycles    = CountCyclesOfLength (adj, 6);
    const uint64_t shortCycles  = CountCyclesOfLength (adj, 3)
                                 + CountCyclesOfLength (adj, 4)
                                 + CountCyclesOfLength (adj, 5);

    const double spectralRadius = PowerIterationLargestEigen (adj);

    // ---- FEAT-008 (schema v4): defense-detection breadth ----------------
    // Group A: per-originator vectors, then distribution stats across nodes.
    std::vector<double> tcOrigCounts;
    std::vector<double> tcRelayBreadths;
    std::vector<double> tcMaxHops;
    tcOrigCounts.reserve (m_tcSeqByOriginator.size ());
    for (const auto& kv : m_tcSeqByOriginator)
      tcOrigCounts.push_back (static_cast<double> (kv.second.size ()));
    tcRelayBreadths.reserve (m_tcRelayMacsByOriginator.size ());
    for (const auto& kv : m_tcRelayMacsByOriginator)
      tcRelayBreadths.push_back (static_cast<double> (kv.second.size ()));
    tcMaxHops.reserve (m_tcMaxHopByOriginator.size ());
    for (const auto& kv : m_tcMaxHopByOriginator)
      tcMaxHops.push_back (static_cast<double> (kv.second));

    auto vecMin = [] (const std::vector<double>& v) -> double {
      if (v.empty ()) return 0.0;
      double mn = v.front ();
      for (double x : v) if (x < mn) mn = x;
      return mn;
    };
    auto vecMax = [] (const std::vector<double>& v) -> double {
      if (v.empty ()) return 0.0;
      double mx = v.front ();
      for (double x : v) if (x > mx) mx = x;
      return mx;
    };

    const double tcOrigMin  = vecMin (tcOrigCounts);
    const double tcOrigMean = Mean   (tcOrigCounts);
    const double tcOrigStd  = Std    (tcOrigCounts);
    const double tcOrigMax  = vecMax (tcOrigCounts);

    const double tcRelMin   = vecMin (tcRelayBreadths);
    const double tcRelMean  = Mean   (tcRelayBreadths);
    const double tcRelStd   = Std    (tcRelayBreadths);
    const double tcRelMax   = vecMax (tcRelayBreadths);

    const double tcHopMin   = vecMin (tcMaxHops);
    const double tcHopMean  = Mean   (tcMaxHops);
    const double tcHopStd   = Std    (tcMaxHops);
    const double tcHopMax   = vecMax (tcMaxHops);

    // Group B: single raw values.
    const uint64_t distinctForwardersChangingNextHop =
        static_cast<uint64_t> (m_forwardersThatChangedNextHop.size ());
    const uint64_t numDistinctNextHopsNetworkwide =
        static_cast<uint64_t> (m_distinctForwarderNextHopPairs.size ());

    // ---- Emit row -------------------------------------------------------
    std::ostringstream r;
    r << std::fixed << std::setprecision (6);
    // A (11)
    r << tcRate << "," << midRate << "," << hnaRate << ","
      << tcBps  << "," << midBps  << "," << hnaBps  << ","
      << dataPRate << "," << dataBps << ","
      << perNodeTcRateStd << "," << perNodeTcBytesStd << "," << perNodeTcBytesGini << ",";
    // B (14)
    r << tcMsgMean << "," << tcMsgStd << "," << tcMsgP95 << "," << tcMsgMax << ","
      << advLnkMean << "," << advLnkStd << "," << advLnkP95 << "," << advLnkMax << ","
      << ansnMean << "," << ansnSkip << ","
      << distSenders << ","
      << tcContentEntropy << "," << tcVtMean << "," << tcVtStd << ",";
    // C (5)
    r << numAddrInTc << "," << numDistinctTcSend << ","
      << numPhantom << "," << numAsym << "," << numEphemeral << ",";
    // D (4)
    r << mprSelMean << "," << mprSelStd << ","
      << mprChurn << "," << totalDistinctMprSets << ",";
    // E (5)
    r << hopMean << "," << hopStd << "," << hopMax << ","
      << pathChangesPerFlow << "," << distinctNextHopsPerSrc << ",";
    // F (3)
    r << l2RetxRate << "," << busyFrac << ","
      << ifsMean << ",";
    // G (6)
    r << pktsDelivered << "," << pktsSent << ","
      << e2eMean << "," << e2eStd << ","
      << jMean << "," << throughputBps << ",";
    // H (6)
    r << tcGapMean << "," << tcGapStd << "," << tcGapP95 << ","
      << tcHurst << ","
      << ctrlSkew << "," << ctrlKurt << ",";
    // I (5)
    r << tcSenderEnt << "," << tcAdvEnt << ","
      << pktSkew << "," << pktKurt << ","
      << byteEnt << ",";
    // J (22)
    r << degMean << "," << degStd << "," << degSkew << "," << degKurt << ","
      << degOne << ","
      << clustering << "," << triangles << ","
      << numComponents << "," << diameter << "," << radius << ","
      << density << ","
      << btwMean << "," << btwStd << "," << btwMax << ","
      << closMean << "," << closStd << ","
      << edgePersistMean << "," << edgeEmergenceRate << "," << edgeChurnRate << ","
      << hexCycles << "," << shortCycles << "," << spectralRadius;
    // K (14): FEAT-008 defense-detection breadth
    r << "," << tcOrigMin  << "," << tcOrigMean << "," << tcOrigStd  << "," << tcOrigMax
      << "," << tcRelMin   << "," << tcRelMean  << "," << tcRelStd   << "," << tcRelMax
      << "," << tcHopMin   << "," << tcHopMean  << "," << tcHopStd   << "," << tcHopMax
      << "," << distinctForwardersChangingNextHop
      << "," << numDistinctNextHopsNetworkwide;

    // ----- Mode Core: emit groups A-K exactly as before. -----------------
    if (mode == FeatureMode::Core)
      return r.str ();

    // === L. strict_observable_v2 parity features (33) ====================
    // Re-implements the metric set consumed by defense_detection_v2.py,
    // adapted to this strictly-passive collector. Metrics that originally
    // read node-internal state use an on-air observable analog (noted):
    //   - NormalizedRoutingLoad / RoutingOverhead* : HELLO is excluded (not
    //     observable); routing traffic = TC+MID+HNA only.
    //   - AverageMprCount : mean in-degree of advertised nodes in the directed
    //     TC graph (node X chose sender S as MPR iff X in adv(S)).
    //   - AvgRxBytesPerFlow : delivered-packets * mean sent packet size of the
    //     flow (per-flow delivered bytes are not separately observable).
    const double L_routingMsgs  = static_cast<double> (m_tcCount + m_midCount + m_hnaCount);
    const double L_routingBytes = static_cast<double> (m_tcBytes + m_midBytes + m_hnaBytes);
    const double L_dataPkts     = static_cast<double> (m_dataPackets);
    const double L_dataBytes    = static_cast<double> (m_dataBytes);

    const double L_pdr = (pktsSent > 0)
        ? static_cast<double> (pktsDelivered) / static_cast<double> (pktsSent) : 0.0;
    const double L_nrl = (pktsDelivered > 0)
        ? L_routingMsgs / static_cast<double> (pktsDelivered) : 0.0;
    const double L_overheadRatio = (L_routingMsgs + L_dataPkts > 0.0)
        ? L_routingMsgs / (L_routingMsgs + L_dataPkts) : 0.0;
    const double L_overheadBytesRatio = (L_routingBytes + L_dataBytes > 0.0)
        ? L_routingBytes / (L_routingBytes + L_dataBytes) : 0.0;

    // Per-flow distributions (keyed by observed (src,dst)).
    std::vector<double> fDur, fThr, fDelay, fJit, fLoss, fTxB, fRxB, fTxP, fRxP;
    for (const auto& kv : m_dataSentByFlow)
      {
        const auto& fkey = kv.first;
        const double txPk = static_cast<double> (kv.second);
        fTxP.push_back (txPk);
        auto itRx = m_dataDeliveredByFlow.find (fkey);
        const double rxPk = (itRx != m_dataDeliveredByFlow.end ())
            ? static_cast<double> (itRx->second) : 0.0;
        fRxP.push_back (rxPk);
        auto itB = m_flowTxBytes.find (fkey);
        const double txB = (itB != m_flowTxBytes.end ())
            ? static_cast<double> (itB->second) : 0.0;
        fTxB.push_back (txB);
        const double meanPkt = (txPk > 0.0) ? txB / txPk : 0.0;
        fRxB.push_back (rxPk * meanPkt);
        double fd = 0.0;
        auto itF = m_flowFirstTxTime.find (fkey);
        auto itL = m_flowLastTxTime.find (fkey);
        if (itF != m_flowFirstTxTime.end () && itL != m_flowLastTxTime.end ())
          fd = std::max (0.0, itL->second - itF->second);
        fDur.push_back (fd);
        fThr.push_back ((fd > 0.0) ? (txB * 8.0) / fd : 0.0);
        auto itD = m_flowDelays.find (fkey);
        fDelay.push_back ((itD != m_flowDelays.end ()) ? Mean (itD->second) : 0.0);
        auto itJ = m_flowJitters.find (fkey);
        fJit.push_back ((itJ != m_flowJitters.end ()) ? Mean (itJ->second) : 0.0);
        fLoss.push_back ((txPk > 0.0) ? std::max (0.0, 1.0 - rxPk / txPk) : 0.0);
      }

    const double L_avgMprCount = (!m_addressesSeenInTcPayload.empty ())
        ? static_cast<double> (m_observedDirectedEdges.size ())
          / static_cast<double> (m_addressesSeenInTcPayload.size ()) : 0.0;

    std::ostringstream rl;
    rl << std::fixed << std::setprecision (6);
    rl << tcRate << "," << midRate << "," << hnaRate << ","
       << advLnkMean << ","
       << L_nrl << "," << L_overheadRatio << "," << L_overheadBytesRatio << ","
       << L_pdr << "," << (1.0 - L_pdr) << "," << e2eMean << "," << jMean << ","
       << throughputBps << "," << hopMean << "," << dataPRate << "," << L_pdr << ","
       << static_cast<double> (m_dataSentByFlow.size ()) << ","
       << Mean (fDur) << "," << Std (fDur) << "," << Mean (fThr) << ","
       << Mean (fDelay) << "," << Mean (fJit) << "," << Mean (fLoss) << ","
       << Std (fThr) << "," << Std (fDelay) << "," << Std (fJit) << "," << Std (fLoss) << ","
       << Mean (fTxB) << "," << Mean (fRxB) << "," << Mean (fTxP) << "," << Mean (fRxP) << ","
       << ((m_dataPackets > 0) ? L_dataBytes / L_dataPkts : 0.0) << ","
       << ((pktsDelivered > 0) ? static_cast<double> (m_dataDeliveredBytes)
                                 / static_cast<double> (pktsDelivered) : 0.0) << ","
       << L_avgMprCount;

    if (mode == FeatureMode::V2Only)
      return rl.str ();
    // CoreAndV2: groups A-K, then the parity group.
    return r.str () + "," + rl.str ();
  }

  // ----- Public test hooks (used by harness --self-test) -------------------
  // Run the cycle counter against a known small graph passed as adjacency.
  static uint64_t TestCountCyclesOfLength (
      const std::vector<std::vector<uint32_t>>& adj, uint32_t k)
  {
    return CountCyclesOfLength (adj, k);
  }

private:
  // ------------- raw observation state ------------------------------------
  double m_winStart = 0.0, m_winEnd = 0.0;

  uint64_t m_tcCount = 0, m_midCount = 0, m_hnaCount = 0;
  uint64_t m_tcBytes = 0, m_midBytes = 0, m_hnaBytes = 0;
  uint64_t m_dataPackets = 0;
  uint64_t m_dataBytes   = 0;
  uint64_t m_dataDeliveredBytes = 0;     // OBS-006

  std::map<Ipv4Address, uint64_t> m_tcBySender;
  std::map<Ipv4Address, uint64_t> m_tcBytesBySender;
  std::vector<double>             m_tcSizes;
  std::vector<double>             m_advertisedLinksPerTc;
  std::vector<double>             m_tcVtimes;
  std::map<Ipv4Address, uint16_t> m_lastAnsnBySender;
  std::vector<double>             m_ansnIncrements;
  uint64_t                        m_ansnSkipCount = 0;
  std::map<std::string, uint64_t> m_tcContentKeys;
  std::vector<uint8_t>            m_tcPayloadBytes;

  std::map<Ipv4Address, uint64_t> m_tcSenderAddrCounts;
  std::map<Ipv4Address, uint64_t> m_tcAdvertisedAddrCounts;
  std::set<Ipv4Address>           m_addressesSeenInTcPayload;
  std::set<Ipv4Address>           m_addressesEverSentTc;
  std::set<Ipv4Address>           m_addressesEverSentData;
  std::map<Ipv4Address, double>   m_addressesFirstSeen;
  std::map<Ipv4Address, double>   m_addressesLastSeen;
  std::set<std::pair<Ipv4Address, Ipv4Address>> m_observedDirectedEdges;

  std::map<Ipv4Address, std::vector<double>>              m_mprSelectorsByTcSender;
  std::map<Ipv4Address, std::vector<std::set<Ipv4Address>>> m_mprSelectorsHistoryBySender;
  uint64_t                                                m_mprChurnEvents = 0;
  std::map<Ipv4Address, std::set<std::string>>            m_distinctMprSetsBySender;

  std::vector<double> m_hopCounts;
  std::set<std::pair<Ipv4Address, Ipv4Address>> m_sourceDestPairs;
  std::map<std::pair<Ipv4Address, Ipv4Address>, uint64_t> m_dataSentByFlow;
  std::map<std::pair<Ipv4Address, Ipv4Address>, uint64_t> m_dataDeliveredByFlow;
  std::map<std::pair<Ipv4Address, Ipv4Address>, double>   m_lastArrivalPerFlow;
  std::vector<double> m_dataLatencies;
  std::vector<double> m_jitterSamples;

  // L-group (strict_observable_v2 parity): per-flow accumulators.
  std::map<std::pair<Ipv4Address, Ipv4Address>, double>   m_flowFirstTxTime;
  std::map<std::pair<Ipv4Address, Ipv4Address>, double>   m_flowLastTxTime;
  std::map<std::pair<Ipv4Address, Ipv4Address>, uint64_t> m_flowTxBytes;
  std::map<std::pair<Ipv4Address, Ipv4Address>, std::vector<double>> m_flowDelays;
  std::map<std::pair<Ipv4Address, Ipv4Address>, std::vector<double>> m_flowJitters;

  // BUG-004: first-hop-MAC-churn observable replacement for next-hop.
  std::map<Ipv4Address, std::set<Mac48Address>> m_firstHopMacsPerSrc;
  std::map<Ipv4Address, uint64_t>               m_pathChangeEventsPerSrc;
  std::map<Ipv4Address, Mac48Address>           m_lastFirstHopMacPerSrc;

  // PHY-trace driven MAC layer state.
  bool     m_phyAvailable = false;
  uint64_t m_macRetxCount = 0;
  uint64_t m_dataFramesObservedOnAir = 0;
  std::vector<std::pair<double,double>> m_busyIntervals;
  std::vector<double> m_interFrameSpacing;
  double   m_lastMacTxEnd = -1.0;

  std::map<Ipv4Address, std::vector<double>> m_tcInterArrivalsPerSender;
  std::map<Ipv4Address, double>              m_lastTcTimeBySender;
  std::vector<double>                        m_controlMessageTimes;
  std::vector<uint32_t>                      m_packetSizes;

  // Graph state.
  struct Edge
  {
    Ipv4Address a, b;
    bool operator< (const Edge& o) const
    { return a < o.a || (a == o.a && b < o.b); }
    bool operator== (const Edge& o) const
    { return a == o.a && b == o.b; }
  };
  std::set<Edge>                    m_advertisedEdgesAllTime;
  std::map<Edge, double>            m_edgeFirstSeen;
  std::map<Edge, double>            m_edgeLastSeen;
  // BUG-002/003: within-window split (re-computed at EmitFeatureCsv).
  std::set<Edge>                    m_edgesFirstHalf;
  std::set<Edge>                    m_edgesLastHalf;

  // FEAT-008 (schema v4): passively-observable defense-detection breadth.
  // Group A -- TC propagation suppression, keyed per TC originator. A copy
  // is deduplicated by (originator, message-sequence); breadth counts the
  // distinct on-air transmitters (MAC Addr2) of that originator's TC, and
  // max-hop tracks the largest hop-count its TC reached.
  std::map<Ipv4Address, std::set<uint16_t>>       m_tcSeqByOriginator;
  std::map<Ipv4Address, std::set<Mac48Address>>   m_tcRelayMacsByOriginator;
  std::map<Ipv4Address, uint32_t>                 m_tcMaxHopByOriginator;
  // Group B -- DATA-side isolation breadth. Distinct (forwarder -> next-hop)
  // MAC pairs networkwide, plus the set of forwarders observed changing the
  // next-hop they use for a given destination within the window (static
  // topology => such a change is a defense-induced reroute).
  std::set<std::pair<Mac48Address, Mac48Address>> m_distinctForwarderNextHopPairs;
  std::map<std::pair<Mac48Address, Ipv4Address>, Mac48Address>
                                                  m_lastNextHopByForwarderDst;
  std::set<Mac48Address>                          m_forwardersThatChangedNextHop;

  // --------------- internal helpers ---------------------------------------
  static std::string SetToCanonicalKey (const std::set<Ipv4Address>& s)
  {
    std::string k; k.reserve (s.size () * 4);
    for (const auto& a : s)
      {
        uint32_t raw = a.Get ();
        k.append (reinterpret_cast<const char*> (&raw), sizeof (raw));
      }
    return k;
  }

  // BUG-006: union of busy intervals (replaces sum-of-NAVs).
  static double ComputeBusyFraction (std::vector<std::pair<double,double>> v,
                                     double winStart, double winEnd)
  {
    if (v.empty ()) return 0.0;
    const double dur = std::max (1e-6, winEnd - winStart);
    // Clamp to window.
    for (auto& p : v)
      {
        if (p.first  < winStart) p.first  = winStart;
        if (p.second > winEnd)   p.second = winEnd;
      }
    std::sort (v.begin (), v.end (),
               [] (const std::pair<double,double>& a,
                   const std::pair<double,double>& b)
               { return a.first < b.first; });
    double total = 0.0;
    double curS = v[0].first;
    double curE = v[0].second;
    for (size_t i = 1; i < v.size (); ++i)
      {
        if (v[i].first <= curE)
          {
            if (v[i].second > curE) curE = v[i].second;
          }
        else
          {
            total += std::max (0.0, curE - curS);
            curS = v[i].first;
            curE = v[i].second;
          }
      }
    total += std::max (0.0, curE - curS);
    return std::min (1.0, total / dur);
  }

  // BUG-007: dead `depth==1 && w < path[1]` branch removed. The DFS is
  // entered at depth=2 from the outer loop, so the branch was unreachable.
  // Correctness of the final /2 is covered by --self-test (K3, K4, C6, K3,3).
  static uint64_t
  CountCyclesOfLength (const std::vector<std::vector<uint32_t>>& adj,
                       uint32_t k)
  {
    if (k < 3) return 0;
    uint64_t total = 0;
    const uint32_t N = adj.size ();
    std::vector<uint32_t> path; path.reserve (k);
    std::vector<bool>     visited (N, false);

    std::function<void (uint32_t, uint32_t, uint32_t)> dfs =
      [&] (uint32_t start, uint32_t v, uint32_t depth) {
        if (depth == k)
          {
            for (uint32_t w : adj[v])
              if (w == start) { total++; break; }
            return;
          }
        for (uint32_t w : adj[v])
          {
            if (visited[w]) continue;
            if (w < start) continue;            // rotation pruning
            visited[w] = true;
            path.push_back (w);
            dfs (start, w, depth + 1);
            path.pop_back ();
            visited[w] = false;
          }
      };
    for (uint32_t s = 0; s < N; ++s)
      {
        visited[s] = true;
        path.push_back (s);
        for (uint32_t w : adj[s])
          {
            if (w <= s) continue;
            visited[w] = true;
            path.push_back (w);
            dfs (s, w, 2);
            path.pop_back ();
            visited[w] = false;
          }
        path.pop_back ();
        visited[s] = false;
      }
    return total / 2;
  }

  static double
  PowerIterationLargestEigen (const std::vector<std::vector<uint32_t>>& adj)
  {
    const uint32_t N = adj.size ();
    if (N == 0) return 0.0;
    std::vector<double> v (N, 1.0 / std::sqrt (static_cast<double> (N)));
    std::vector<double> next (N, 0.0);
    double lambda = 0.0;
    for (int iter = 0; iter < 100; ++iter)
      {
        std::fill (next.begin (), next.end (), 0.0);
        for (uint32_t i = 0; i < N; ++i)
          for (uint32_t j : adj[i])
            next[i] += v[j];
        double norm = 0.0;
        for (double x : next) norm += x * x;
        norm = std::sqrt (norm);
        if (norm < 1e-12) return 0.0;
        double newLambda = 0.0;
        for (uint32_t i = 0; i < N; ++i) 
          newLambda += v[i] * next[i];
      // Now normalize next for the next iteration.
      for (uint32_t i = 0; i < N; ++i) next[i] /= norm;
        v.swap (next);
        if (std::abs (newLambda - lambda) < 1e-8) { lambda = newLambda; break; }
        lambda = newLambda;
      }
    return std::abs (lambda);
  }
};

} // namespace olsreval
} // namespace ns3

#endif // OLSR_WINDOW_FEATURES_H