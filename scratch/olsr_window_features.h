#ifndef OLSR_WINDOW_FEATURES_H
#define OLSR_WINDOW_FEATURES_H

// ---------------------------------------------------------------------------
// Single-listener (LISTENER) window feature collector -- schema v6.
//
// PARITY TARGET
//   This file is a deliberate re-implementation of the reference harness
//   iolsr-tests-corrected.cc, specifically:
//     * SniffFrameInto()      (accumulation; ~line 498)
//     * SaveObserverMetrics() (derivation;   ~line 1834)
//   Every counter name below matches a field of that file's ObserverCounters,
//   and every formula matches the corresponding expression in
//   SaveObserverMetrics. Where the reference is surprising, the surprise is
//   reproduced on purpose and flagged in a comment -- divergence would make
//   our rows incomparable to observer_metrics-<id>.csv.
//
// SCOPE
//   Every value is computable by ONE node with a radio in promiscuous mode.
//   Nothing reads another node's internal state.
//
// THE 17 COLUMNS (emit order = the order the spec listed them)
//
//   Control plane -- OLSR
//     1  TcMessageRate                       tcUniqueCount / Duration
//     2  AverageAdvertisedLinksPerTCMessage  tcRows / tcCount
//     3  AverageMprCount                     SumAdvertisedLinks / |addrsSeen|
//     4  AverageHopCount                     tcHopSum / tcCount
//     5  MidMessageRate                      midCount / Duration
//     6  HnaMessageRate                      hnaCount / Duration
//
//   Load & overhead
//     7  RoutingOverheadBytesRatio           olsrBytes / dataBytes
//     8  NormalizedRoutingLoad               olsrFrames / dataFrames
//
//   Data plane
//     9  DataPacketRate                      frames / Duration
//    10  Throughput                          dataBytes * 8 / Duration
//    11  AvgTxPacketSize                     bytes / frames
//
//   Per perceived source
//    12  AvgFlowDuration                     mean over sources of (last - first)
//    13  FlowDurationStd                     population std of the same
//    14  AvgFlowThroughput                   (dataBytes / nSrc) * 8 / Duration
//    15  FlowThroughputStd                   population std of per-source bit rates
//    16  AvgTxBytesPerFlow                   dataBytes / nSrc
//    17  AvgTxPacketsPerFlow                 dataFrames / nSrc
//
// SIX PROPERTIES OF THE REFERENCE THAT ARE EASY TO GET WRONG
//
//   (a) HELLO IS COUNTED. A frame is added to frames/bytes before any
//       filtering, and any UDP/698 frame -- HELLO included -- lands in
//       olsrFrames/olsrBytes. Only the per-message switch distinguishes
//       HELLO, and it uses break, never return, so later messages in the
//       same OLSR packet are still parsed.
//
//   (b) RTS/CTS/ACK ARE COUNTED in frames/bytes. They are added before the
//       IsData() test. So feature 9 is a MAC frame rate, and feature 11 is
//       pulled down by tiny control frames.
//
//   (c) "SOURCE" IS THE IPv4 SOURCE ADDRESS OF EVERY IPv4 FRAME, INCLUDING
//       OLSR BROADCASTS. Since every node broadcasts HELLO/TC under its own
//       address, every audible neighbour is a distinct source. Features
//       12-17 therefore measure neighbour visibility, not application flows.
//
//   (d) dataBytes/dataFrames COUNT ALL IPv4 TRAFFIC, OLSR INCLUDED. Feature
//       10 is named "Throughput" but is really the IP-layer air bitrate, and
//       in a typical window it is dominated by control traffic.
//
//   (e) FEATURES 2 AND 4 ARE NOT DE-DUPLICATED, FEATURE 1 IS. tcRows, tcCount
//       and tcHopSum accumulate over every heard copy of every TC; only
//       tcUniqueCount/tcUniqueRows dedupe by (originator, msgSeq). The
//       reference exposes a deduplicated ObsAvgAdvLinksPerUniqueTc as well,
//       but the spec maps feature 2 to the NON-deduplicated AvgAdvertisedLinksPerTC.
//
//   (f) SumAdvertisedLinks IS NOT tcRows. It is the sum, over each originator
//       heard, of the advertised-link count of that originator's MOST RECENT
//       TC. advByOriginator[orig] is overwritten on every TC, then summed at
//       emit time.
//
//   (g) FEATURE 8 IS A SHARE, NOT A RATIO. arm_spec.py was corrected on
//       28/8/2026: NormalizedRoutingLoad is now ObsOlsrFrames/SniffedDataFrames
//       -- OLSR frames as a fraction of ALL IPv4-carrying frames heard -- and
//       NOT the old ObsOlsrFrames/ObsNonOlsrDataFrames. The old denominator
//       (dataFrames - olsrFrames) is zero whenever the vantage point heard no
//       non-OLSR data frame, which the reference measured at 64.3% of static
//       and 51.1% of mobile observer rows; the pipeline caught the
//       ZeroDivisionError and stored 0.0, so "all control, no data" (an
//       effectively infinite ratio) became indistinguishable from its exact
//       opposite. The share form is bounded in [0,1] and strictly monotone in
//       the old ratio (s = r/(1+r)), so the ordering of every previously
//       defined row is preserved and the collapsed rows now take 1.0.
//       Undefined only when the listener heard nothing at all.
// ---------------------------------------------------------------------------

#include "ns3/core-module.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-header.h"
#include "ns3/llc-snap-header.h"
#include "ns3/olsr-module.h"
#include "ns3/packet.h"
#include "ns3/udp-header.h"
#include "ns3/wifi-mac-header.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace ns3 {
namespace olsreval {

// Population mean / standard deviation. Matches ComputeMean / ComputeStdDev in
// the reference (both return 0.0 on an empty vector; the divisor is n, not
// n-1). A single-element vector yields std 0.0 in both implementations.
inline double Mean (const std::vector<double>& v)
{
  if (v.empty ()) return 0.0;
  double s = 0.0;
  for (double x : v) s += x;
  return s / static_cast<double> (v.size ());
}

inline double Std (const std::vector<double>& v)
{
  if (v.empty ()) return 0.0;
  const double m = Mean (v);
  double s = 0.0;
  for (double x : v) { const double d = x - m; s += d * d; }
  return std::sqrt (s / static_cast<double> (v.size ()));
}

class FeatureCollector
{
public:
  static constexpr uint32_t kNumFeatures = 17;

  // Feature 8 is undefined only when the listener heard no IPv4-carrying frame
  // at all in the window. arm_spec.py's _eval_obs was corrected on 28/8/2026 to
  // return NaN there rather than 0.0, precisely because 0.0 is a legal value of
  // the metric and an undefined quantity must not be storable as a measured
  // one. We match that: NaN, never a filled-in number.
  //
  // These rows are meant to be DROPPED in analysis, not imputed. The reference
  // measured them at 0.000% of static and 0.068% of mobile observer rows.
  // HeardAnyIpFrame() below lets the caller count them without parsing the CSV.
  static constexpr double kNrlUndefinedValue =
      std::numeric_limits<double>::quiet_NaN ();

  void Reset (double tStart)
  {
    m_winStart = tStart;
    m_winEnd   = tStart;

    m_frames     = 0;
    m_bytes      = 0;
    m_dataFrames = 0;
    m_dataBytes  = 0;
    m_olsrFrames = 0;
    m_olsrBytes  = 0;

    m_tcCount       = 0;
    m_tcRows        = 0;
    m_tcHopSum      = 0;
    m_tcSeen.clear ();
    m_tcUniqueCount = 0;
    m_tcUniqueRows  = 0;

    m_helloCount = 0;
    m_midCount   = 0;
    m_hnaCount   = 0;

    m_advByOriginator.clear ();
    m_addrsSeen.clear ();

    m_bytesBySource.clear ();
    m_framesBySource.clear ();
    m_firstSeenBySource.clear ();
    m_lastSeenBySource.clear ();
  }

  // ------------------------------------------------------------------------
  // The ONLY observation entry point. Feed it the raw PSDU from
  // Phy/MonitorSnifferRx on the listener node, once per frame.
  //
  // The collector parses the frame itself, in the same order as the
  // reference's SniffFrameInto, so the caller cannot introduce a divergence by
  // filtering or by counting bytes at a different layer. In particular the
  // caller must NOT drop RTS/CTS/ACK and must NOT drop HELLO -- see notes (a)
  // and (b) at the top of this file.
  // ------------------------------------------------------------------------
  void ObserveSniffedFrame (Ptr<const Packet> packet)
  {
    if (!packet) return;

    // (b) Every frame, control frames included, before any filtering.
    m_frames += 1;
    m_bytes  += packet->GetSize ();

    const uint32_t frameBytes = packet->GetSize ();
    Ptr<Packet> p = packet->Copy ();

    WifiMacHeader macHdr;
    if (p->GetSize () < macHdr.GetSerializedSize ()) return;
    p->RemoveHeader (macHdr);
    if (!macHdr.IsData ()) return;      // control/management carry no IP

    LlcSnapHeader llc;
    if (p->GetSize () < llc.GetSerializedSize ()) return;
    p->RemoveHeader (llc);
    if (llc.GetType () != 0x0800) return;   // not IPv4

    Ipv4Header ipHeader;
    if (p->GetSize () < ipHeader.GetSerializedSize ()) return;
    p->RemoveHeader (ipHeader);

    // (d) All IPv4 traffic, OLSR included.
    m_dataFrames += 1;
    m_dataBytes  += frameBytes;

    // (c) Attribute to the IPv4 source, full 32-bit key. Reached for OLSR
    // broadcasts too, so every audible neighbour becomes a source.
    const uint32_t srcKey = ipHeader.GetSource ().Get ();
    m_bytesBySource[srcKey]  += frameBytes;
    m_framesBySource[srcKey] += 1;

    const double nowS = Simulator::Now ().GetSeconds ();
    m_firstSeenBySource.emplace (srcKey, nowS);
    m_lastSeenBySource[srcKey] = nowS;

    if (ipHeader.GetProtocol () != 17) return;     // not UDP

    UdpHeader udpHeader;
    if (p->GetSize () < udpHeader.GetSerializedSize ()) return;
    p->RemoveHeader (udpHeader);
    if (udpHeader.GetDestinationPort () != 698) return;   // not OLSR control

    // (a) Reached by HELLO as well as TC/MID/HNA.
    m_olsrFrames += 1;
    m_olsrBytes  += frameBytes;

    olsr::PacketHeader olsrHeader;
    if (p->GetSize () < olsrHeader.GetSerializedSize ()) return;
    p->RemoveHeader (olsrHeader);

    // A sniffed 802.11 frame may carry padding past the end of the OLSR
    // packet, so the message loop is bounded by the length field rather than
    // by the remaining buffer.
    uint32_t remaining = 0;
    if (olsrHeader.GetPacketLength () > olsrHeader.GetSerializedSize ())
      remaining = olsrHeader.GetPacketLength ()
                  - olsrHeader.GetSerializedSize ();
    if (remaining > p->GetSize ()) remaining = p->GetSize ();

    while (remaining > 0)
      {
        // Validate the message-type byte before RemoveHeader. The reference
        // omits this; ns-3's MessageHeader::Deserialize trips an assertion on
        // an out-of-range type, and this guard only fires where the reference
        // would abort, so it cannot change any value on well-formed input.
        uint8_t firstByte = 0;
        if (p->CopyData (&firstByte, 1) != 1) break;
        if (firstByte < 1 || firstByte > 4) break;

        olsr::MessageHeader msg;
        const uint32_t before = p->GetSize ();
        p->RemoveHeader (msg);
        const uint32_t after = p->GetSize ();
        const uint32_t consumed = (before >= after) ? (before - after) : 0;
        if (consumed == 0 || consumed > remaining) break;
        remaining -= consumed;

        switch (msg.GetMessageType ())
          {
          case olsr::MessageHeader::HELLO_MESSAGE:
            // (a) break, NOT return: a later TC in this same packet must
            // still be parsed.
            ++m_helloCount;
            break;

          case olsr::MessageHeader::TC_MESSAGE:
            {
              // Statement order below mirrors the reference's TC_MESSAGE case
              // exactly. The accumulators are independent, so the order does
              // not affect any value -- it is kept aligned so that a future
              // diff against SniffFrameInto stays a one-to-one comparison.
              ++m_tcCount;
              const uint32_t adv =
                  static_cast<uint32_t> (msg.GetTc ().neighborAddresses.size ());
              // (e) Accumulated over every heard COPY.
              m_tcRows += adv;

              const uint32_t orig = msg.GetOriginatorAddress ().Get ();
              // (f) Overwrite: only the most recent advertisement survives.
              m_advByOriginator[orig] = adv;
              m_addrsSeen.insert (orig);

              m_tcHopSum += msg.GetHopCount ();

              const uint64_t key =
                  (static_cast<uint64_t> (orig) << 16)
                  | static_cast<uint64_t> (msg.GetMessageSequenceNumber ());
              if (m_tcSeen.insert (key).second)
                {
                  ++m_tcUniqueCount;
                  m_tcUniqueRows += adv;
                }

              for (const auto& a : msg.GetTc ().neighborAddresses)
                m_addrsSeen.insert (a.Get ());
            }
            break;

          case olsr::MessageHeader::MID_MESSAGE:
            ++m_midCount;
            break;

          case olsr::MessageHeader::HNA_MESSAGE:
            ++m_hnaCount;
            break;

          default:
            break;
          }
      }
  }

  // ------------------------------------------------------------------------
  // Emit
  // ------------------------------------------------------------------------
  static std::string FeatureCsvHeader ()
  {
    return
      "TcMessageRate,AverageAdvertisedLinksPerTCMessage,AverageMprCount,"
      "AverageHopCount,MidMessageRate,HnaMessageRate,"
      "RoutingOverheadBytesRatio,NormalizedRoutingLoad,"
      "DataPacketRate,Throughput,AvgTxPacketSize,"
      "AvgFlowDuration,FlowDurationStd,AvgFlowThroughput,FlowThroughputStd,"
      "AvgTxBytesPerFlow,AvgTxPacketsPerFlow";
  }

  std::string EmitFeatureCsv (double tEnd)
  {
    m_winEnd = tEnd;
    const double dur = std::max (1e-6, m_winEnd - m_winStart);

    // === 1. Unique TC messages per second (ObsTcGenerationRate) ===========
    const double tcMessageRate =
        static_cast<double> (m_tcUniqueCount) / dur;

    // === 2. Advertised links per heard TC COPY (AvgAdvertisedLinksPerTC) ==
    const double avgAdvLinksPerTc =
        (m_tcCount > 0)
        ? (static_cast<double> (m_tcRows) / static_cast<double> (m_tcCount))
        : 0.0;

    // === 3. Perceived MPR count ===========================================
    // (f) numerator: sum of each originator's most recent advertisement.
    // denominator: every address seen on the air, originators and advertised
    // alike, so fictitious addresses enter both terms.
    double sumAdvertisedLinks = 0.0;
    for (const auto& kv : m_advByOriginator)
      sumAdvertisedLinks += static_cast<double> (kv.second);
    const double avgMprCount =
        (!m_addrsSeen.empty ())
        ? (sumAdvertisedLinks / static_cast<double> (m_addrsSeen.size ()))
        : 0.0;

    // === 4. Mean TC hop count over heard COPIES (ObsAvgTcHopCount) ========
    const double avgHopCount =
        (m_tcCount > 0)
        ? (static_cast<double> (m_tcHopSum) / static_cast<double> (m_tcCount))
        : 0.0;

    // === 5, 6. Expected to be identically zero; kept as health check ======
    const double midMessageRate = static_cast<double> (m_midCount) / dur;
    const double hnaMessageRate = static_cast<double> (m_hnaCount) / dur;

    // === 7. Control byte share (ObsControlBytesRatio) =====================
    // Denominator is dataBytes -- IPv4 frames only -- NOT total sniffed
    // bytes. 802.11 control-frame bytes are excluded from both terms.
    const double routingOverheadBytesRatio =
        (m_dataBytes > 0)
        ? (static_cast<double> (m_olsrBytes)
           / static_cast<double> (m_dataBytes))
        : 0.0;

    // === 8. Observable NRL, SHARE form (arm_spec.py, corrected 28/8/2026) ==
    // ObsOlsrFrames / SniffedDataFrames. m_dataFrames IS SniffedDataFrames:
    // every IPv4-carrying frame heard, OLSR included, so olsrFrames is a subset
    // of it and the result is bounded in [0,1]. Zero only when no IPv4 frame
    // was heard at all -- see kNrlUndefinedValue.
    const double normalizedRoutingLoad =
        (m_dataFrames > 0)
        ? (static_cast<double> (m_olsrFrames)
           / static_cast<double> (m_dataFrames))
        : kNrlUndefinedValue;

    // === 9. All sniffed frames per second (SniffedFrameRate) ==============
    const double dataPacketRate = static_cast<double> (m_frames) / dur;

    // === 10. IP-layer air bitrate, control traffic included ===============
    const double throughput =
        (static_cast<double> (m_dataBytes) * 8.0) / dur;

    // === 11. Mean sniffed frame size ======================================
    const double avgTxPacketSize =
        (m_frames > 0)
        ? (static_cast<double> (m_bytes) / static_cast<double> (m_frames))
        : 0.0;

    // === 12-17. Per perceived source ======================================
    std::vector<double> srcDurations, srcRates;
    srcDurations.reserve (m_firstSeenBySource.size ());
    srcRates.reserve (m_bytesBySource.size ());

    for (const auto& kv : m_firstSeenBySource)
      {
        auto la = m_lastSeenBySource.find (kv.first);
        if (la != m_lastSeenBySource.end ())
          srcDurations.push_back (la->second - kv.second);
      }
    for (const auto& kv : m_bytesBySource)
      srcRates.push_back ((static_cast<double> (kv.second) * 8.0) / dur);

    const double avgFlowDuration = Mean (srcDurations);   // 12
    const double flowDurationStd = Std  (srcDurations);   // 13
    const double flowThroughputStd = Std (srcRates);      // 15

    // 16, 17: totals over the number of distinct sources. Equivalent to the
    // per-source means, since the per-source maps partition the totals.
    const double avgTxBytesPerFlow =
        (!m_bytesBySource.empty ())
        ? (static_cast<double> (m_dataBytes)
           / static_cast<double> (m_bytesBySource.size ()))
        : 0.0;
    const double avgTxPktsPerFlow =
        (!m_framesBySource.empty ())
        ? (static_cast<double> (m_dataFrames)
           / static_cast<double> (m_framesBySource.size ()))
        : 0.0;

    // 14 is 16 rescaled; kept as its own column for spec parity.
    const double avgFlowThroughput = (avgTxBytesPerFlow * 8.0) / dur;

    std::ostringstream r;
    r << std::fixed << std::setprecision (6);
    r << tcMessageRate             << ","
      << avgAdvLinksPerTc          << ","
      << avgMprCount               << ","
      << avgHopCount               << ","
      << midMessageRate            << ","
      << hnaMessageRate            << ","
      << routingOverheadBytesRatio << ","
      << normalizedRoutingLoad     << ","
      << dataPacketRate            << ","
      << throughput                << ","
      << avgTxPacketSize           << ","
      << avgFlowDuration           << ","
      << flowDurationStd           << ","
      << avgFlowThroughput         << ","
      << flowThroughputStd         << ","
      << avgTxBytesPerFlow         << ","
      << avgTxPktsPerFlow;
    return r.str ();
  }

  // ----------------------- Introspection hooks ----------------------------
  // For sanity-checking a window before writing it. A window with almost no
  // observations emits a row of near-zeros that reads like a quiet network.
  // HeardAnyIpFrame() == false is exactly the case where feature 8 emits NaN
  // and the row should be dropped in analysis.
  uint64_t SniffedFrames ()          const { return m_frames; }
  uint64_t HeardTcCopies ()          const { return m_tcCount; }
  uint64_t HeardUniqueTcs ()         const { return m_tcUniqueCount; }
  uint64_t HeardHellos ()            const { return m_helloCount; }
  uint64_t PerceivedSources ()       const { return m_bytesBySource.size (); }
  bool     HeardAnyIpFrame ()        const { return m_dataFrames > 0; }
  uint64_t HeardIpFrames ()          const { return m_dataFrames; }
  uint64_t HeardNonOlsrDataFrames () const
  { return (m_dataFrames >= m_olsrFrames) ? (m_dataFrames - m_olsrFrames) : 0; }

private:
  double m_winStart = 0.0;
  double m_winEnd   = 0.0;

  // Frame-level totals.
  uint64_t m_frames     = 0;   // every frame, control frames included
  uint64_t m_bytes      = 0;
  uint64_t m_dataFrames = 0;   // subset carrying an IPv4 payload
  uint64_t m_dataBytes  = 0;
  uint64_t m_olsrFrames = 0;   // subset of those carrying UDP/698
  uint64_t m_olsrBytes  = 0;

  // TC accumulation over heard copies, plus flood-copy de-duplication.
  uint64_t           m_tcCount       = 0;
  uint64_t           m_tcRows        = 0;
  uint64_t           m_tcHopSum      = 0;
  std::set<uint64_t> m_tcSeen;
  uint64_t           m_tcUniqueCount = 0;
  uint64_t           m_tcUniqueRows  = 0;   // parity field; unused by the 17

  uint64_t m_helloCount = 0;   // parity field; unused by the 17
  uint64_t m_midCount   = 0;
  uint64_t m_hnaCount   = 0;

  // originator -> most recently advertised link count.
  std::map<uint32_t, uint32_t> m_advByOriginator;
  // every address seen as an originator or as an advertised link.
  std::set<uint32_t> m_addrsSeen;

  // Per IPv4 source address.
  std::map<uint32_t, uint64_t> m_bytesBySource;
  std::map<uint32_t, uint64_t> m_framesBySource;
  std::map<uint32_t, double>   m_firstSeenBySource;
  std::map<uint32_t, double>   m_lastSeenBySource;
};

} // namespace olsreval
} // namespace ns3

#endif // OLSR_WINDOW_FEATURES_H
