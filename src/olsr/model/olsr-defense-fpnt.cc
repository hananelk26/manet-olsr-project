/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "olsr-defense-fpnt.h"
#include "ns3/log.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/uinteger.h"
#include "ns3/boolean.h"
#include "ns3/olsr-routing-protocol.h"
#include "ns3/olsr-repositories.h"
#include "ns3/node.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/arp-cache.h"
#include "ns3/node-list.h"
#include "ns3/wifi-net-device.h"
#include <algorithm>
#include <cmath>
#include <set>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OlsrDefenseFpnt");

namespace olsr {

NS_OBJECT_ENSURE_REGISTERED (OlsrDefenseFpnt);

// ============================================================================
// Fuzzy Petri Net -- static structure (Figure 2 of the paper)
// ----------------------------------------------------------------------------
// Place indices (15 places):
//    0  p1   "load is high"                       (evidence)
//    1  p2   "load is low"                        (evidence)
//    2  p3   "PFR is high"                        (evidence)
//    3  p4   "PFR is low"                         (evidence)
//    4  p5   "avg forwarding delay is high"       (evidence)
//    5  p6   "avg forwarding delay is low"        (evidence)
//    6  p7   "routing deviation observed"         (evidence)
//    7  p8   "routing normal"                     (evidence)
//    8  p9   "compromised/serious attacker"       (intermediate)
//    9  p10  "lightly malicious (jellyfish-like)" (intermediate)
//   10  p11  "routing integrity attacker"         (intermediate)
//   11  p12  "data plane normal"                  (intermediate)
//   12  p13  "routing plane normal"               (intermediate)
//   13  p14  "node cannot be trusted"             (verdict: distrust)
//   14  p15  "node can be trusted"                (verdict: trust)
//
// Transition indices (11 transitions). OR rules (R1 and R6) use one
// transition per branch because Type-2 competitive semantics require
// independent threshold tests on each input place.
//
//    0  R1-a  p1 -> p9   tau=0.4, omega=1.0, mu=0.9
//    1  R1-b  p4 -> p9   tau=0.4, omega=1.0, mu=0.9
//    2  R1-c  p5 -> p9   tau=0.5, omega=1.0, mu=0.6
//    3  R2    p2,p5 -> p10  tau=0.5, omega=(0.6,0.4), mu=0.8
//    4  R3    p7 -> p11  tau=0.5, omega=1.0, mu=0.9
//    5  R4    p3,p6,p2 -> p12  tau=0.7, omega=(0.6,0.3,0.1), mu=0.9
//    6  R5    p8 -> p13  tau=0.8, omega=1.0, mu=1.0
//    7  R6-a  p9 -> p14  tau=0.4, omega=1.0, mu=0.9
//    8  R6-b  p10 -> p14 tau=0.4, omega=1.0, mu=0.7
//    9  R6-c  p11 -> p14 tau=0.4, omega=1.0, mu=0.9
//   10  R7    p12,p13 -> p15  tau=0.6, omega=(0.5,0.5), mu=0.9
// ============================================================================

namespace {

// Place indices.
constexpr int P1_LOAD_HIGH      = 0;
constexpr int P2_LOAD_LOW       = 1;
constexpr int P3_FWD_HIGH       = 2;
constexpr int P4_FWD_LOW        = 3;
constexpr int P5_DELAY_HIGH     = 4;
constexpr int P6_DELAY_LOW      = 5;
constexpr int P7_ROUTE_BAD      = 6;
constexpr int P8_ROUTE_OK       = 7;
constexpr int P9_SERIOUS_ATTACK = 8;
constexpr int P10_JELLYFISH     = 9;
constexpr int P11_ROUTE_ATTACK  = 10;
constexpr int P12_DATA_OK       = 11;
constexpr int P13_ROUTE_OK      = 12;
constexpr int P14_DISTRUST      = 13;
constexpr int P15_TRUST         = 14;

constexpr int NUM_PLACES      = 15;
constexpr int NUM_TRANSITIONS = 11;

// Transition firing thresholds (Algorithm 1, Step 2).
// Order: R1a, R1b, R1c, R2, R3, R4, R5, R6a, R6b, R6c, R7.
const std::vector<double> TH = { 0.4, 0.4, 0.5, 0.5, 0.5, 0.7, 0.8, 0.4, 0.4, 0.4, 0.6 };

// Input incidence matrix W^T (transitions x places).
// Row r lists the weighted inputs (omega) to transition r.
const std::vector<std::vector<double>> W_T = {
    // p1   p2   p3   p4   p5   p6   p7   p8   p9   p10  p11  p12  p13  p14  p15
    {  1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R1a: p1
    {  0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R1b: p4
    {  0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R1c: p5
    {  0.0, 0.6, 0.0, 0.0, 0.4, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R2 : p2,p5
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R3 : p7
    {  0.0, 0.1, 0.6, 0.0, 0.0, 0.3, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R4 : p3,p6,p2
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R5 : p8
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R6a: p9
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // R6b: p10
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0 }, // R6c: p11
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0 }, // R7 : p12,p13
};

// Output incidence matrix U (places x transitions).
// U[p][r] = weight of the arc from transition r to place p (the mu value).
const std::vector<std::vector<double>> U_MAT = {
    //  R1a  R1b  R1c  R2   R3   R4   R5   R6a  R6b  R6c  R7
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p1   (input only)
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p2   (input only)
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p3   (input only)
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p4   (input only)
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p5   (input only)
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p6   (input only)
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p7   (input only)
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p8   (input only)
    {  0.9, 0.9, 0.6, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p9   <- R1a,R1b,R1c
    {  0.0, 0.0, 0.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p10  <- R2
    {  0.0, 0.0, 0.0, 0.0, 0.9, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p11  <- R3
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.9, 0.0, 0.0, 0.0, 0.0, 0.0 }, // p12  <- R4
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0 }, // p13  <- R5
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9, 0.7, 0.9, 0.0 }, // p14  <- R6a,R6b,R6c
    {  0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.9 }, // p15  <- R7
};

// Maximum iterations of the fuzzy reasoning loop (Algorithm 1, Step 5).
// The longest causal chain in the FPN is two hops (evidence -> intermediate
// -> verdict), so convergence is guaranteed in at most 2 iterations under
// monotonic updates. The bound of 10 is a conservative safety guard.
constexpr int MAX_FPN_ITERATIONS = 10;

// Tolerance for detecting the "all recommendations identical" case in the
// pairwise L1 DIF computation.
constexpr double DIF_EPS = 1e-9;

// OLSR defines OLSR_TOP_HOLD_TIME = 3 * tcInterval. D1 fires when the most
// recent TC from an MPR is older than this holding window.
constexpr double D1_HOLD_MULTIPLIER = 3.0;


inline uint64_t
HashIpv4Header (const Ipv4Header& h)
{
  uint64_t v = (uint64_t (h.GetSource ().Get ()) << 32)
             | uint64_t (h.GetDestination ().Get ());
  v ^= (uint64_t (h.GetIdentification ()) << 16) | uint64_t (h.GetPayloadSize ());
  v = (v ^ (v >> 30)) * 0xbf58476d1ce4e5b9ULL;
  v = (v ^ (v >> 27)) * 0x94d049bb133111ebULL;
  v = v ^ (v >> 31);
  return v;
}

} // anonymous namespace

// ============================================================================
// TypeId & Construction
// ============================================================================

TypeId
OlsrDefenseFpnt::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::olsr::OlsrDefenseFpnt")
    .SetParent<OlsrDefenseStrategy> ()
    .SetGroupName ("Olsr")
    .AddConstructor<OlsrDefenseFpnt> ()
    .AddAttribute ("TrustUpdateInterval",
                   "Trust evaluation period 't' used for metric normalization.",
                   TimeValue (Seconds (5.0)),
                   MakeTimeAccessor (&OlsrDefenseFpnt::m_checkInterval),
                   MakeTimeChecker ())
    .AddAttribute ("MaliciousThreshold",
                   "Node is flagged malicious when its trust value T falls "
                   "below this threshold.",
                   DoubleValue (0.2),
                   MakeDoubleAccessor (&OlsrDefenseFpnt::m_maliciousThreshold),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("UncertaintyBeta",
                   "Beta factor in Equation (4): "
                   "T = E_trust + beta * E_uncertain.",
                   DoubleValue (0.6),
                   MakeDoubleAccessor (&OlsrDefenseFpnt::m_uncertaintyBeta),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("HistoryFadingFactor",
                   "Lambda factor in Equation (5): "
                   "T = (1-lambda)*T_current + lambda*T_previous.",
                   DoubleValue (0.7),
                   MakeDoubleAccessor (&OlsrDefenseFpnt::m_fadingFactor),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("MaxLoad",
                   "Load normalization constant X (bits/second) used in "
                   "Definition 10's NORM operator for the load factor. Load "
                   "values at or above this are mapped to truth degree 1.",
                   DoubleValue (1.0e6),
                   MakeDoubleAccessor (&OlsrDefenseFpnt::m_maxLoad),
                   MakeDoubleChecker<double> (1.0))
    .AddAttribute ("MaxDelay",
                   "Delay normalization constant (seconds) for Definition 10's "
                   "NORM operator applied to average forwarding delay.",
                   DoubleValue (0.5),
                   MakeDoubleAccessor (&OlsrDefenseFpnt::m_maxDelay),
                   MakeDoubleChecker<double> (0.001))
    .AddAttribute ("CheatThreshold",
                   "delta in Section 5.1.D: minimum number of routing-plane "
                   "deviations observed in a single period before the "
                   "protocol-deviation flag (p7) is raised. Prevents false "
                   "positives from transient wireless losses.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&OlsrDefenseFpnt::m_cheatThreshold),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Enabled",
                   "Runtime toggle for the defense. When false, IsMalicious "
                   "returns false for every node, GetBlacklist is empty, "
                   "IsTrustRoutingEnabled is false, and PeriodicCheck is a "
                   "no-op. Transitioning from false to true triggers a full "
                   "state reset (metrics, trust table, recommendations, "
                   "pending arrivals, direct evaluations, D1/D2 bookkeeping) "
                   "so the defense never carries evidence across a "
                   "disabled period.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&OlsrDefenseFpnt::SetEnabled,
                                        &OlsrDefenseFpnt::GetEnabled),
                   MakeBooleanChecker ())
  ;
  return tid;
}

OlsrDefenseFpnt::OlsrDefenseFpnt ()
  : m_protocol (nullptr),
    m_selfAddress (),
    m_checkInterval (Seconds (5.0)),
    m_maliciousThreshold (0.2),
    m_uncertaintyBeta (0.6),
    m_fadingFactor (0.7),
    m_maxLoad (1.0e6),
    m_maxDelay (0.5),
    m_cheatThreshold (2),
    m_enabled (true)
{
  NS_LOG_FUNCTION (this);
}

OlsrDefenseFpnt::~OlsrDefenseFpnt ()
{
  NS_LOG_FUNCTION (this);
}

void
OlsrDefenseFpnt::Setup (RoutingProtocol* proto, Ipv4Address nodeAddress)
{
  NS_LOG_FUNCTION (this << nodeAddress);
  m_protocol = proto;
  m_selfAddress = nodeAddress;
  NS_LOG_INFO ("FPNT-OLSR initialized for node " << nodeAddress);
}

void
OlsrDefenseFpnt::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_metrics.clear ();
  m_trustTable.clear ();
  m_directEvaluationVectors.clear ();
  m_lastSValues.clear ();
  m_recommendations.clear ();
  m_pendingArrivals.clear ();
  m_lastTcTime.clear ();
  m_protocol = nullptr;
  OlsrDefenseStrategy::DoDispose ();
}

void
OlsrDefenseFpnt::SetEnabled (bool enabled)
{
  NS_LOG_FUNCTION (this << enabled);

  const bool wasEnabled = m_enabled;
  m_enabled = enabled;

// Cold-start reset on EVERY state transition (symmetric semantics).
  // Both directions wipe accumulated state so neither phase can carry
  // residue from the other: an attack -> defense transition cannot
  // contaminate the first FPN evaluation with pre-enable metrics, and
  // a defense -> off -> on cycle cannot accumulate state across phases.
  // No-op calls (same value passed twice) are skipped.
  if (wasEnabled == enabled)
    {
      return;
    }

  NS_LOG_INFO ("FPNT-OLSR " << (enabled ? "enabled" : "disabled")
               << " on " << m_selfAddress
               << " - clearing all accumulated state for cold start");

  // Per-period metric counters and matched-arrival bookkeeping.
  m_metrics.clear ();
  m_pendingArrivals.clear ();

  // Inbound recommendations from TC piggyback.
  m_recommendations.clear ();

  // Direct evaluation cache (persists across periods normally).
  m_directEvaluationVectors.clear ();
  m_lastSValues.clear ();

  // Trust table - the actual verdicts that drive routing.
  m_trustTable.clear ();

  // D1/D2 bookkeeping. Without clearing m_lastTcTime, a long disabled
  // window followed by an enable would make every MPR look silent
  // (last TC seen "long ago") and trip D1 immediately.
  m_lastTcTime.clear ();
  m_mprSelectionTime.clear ();

  // Force an immediate routing-table recompute on the now-empty trust
  // state. Without this, the routing table carries pre-enable routes
  // until the next OLSR event (HELLO, TC, link update) triggers a
  // recompute on its own.
  if (m_protocol)
    {
      m_protocol->RunTrustDijkstra ();
    }
}

bool
OlsrDefenseFpnt::GetEnabled () const
{
  return m_enabled;
}

// ============================================================================
// Trust Query Methods
// ============================================================================

bool
OlsrDefenseFpnt::IsMalicious (Ipv4Address addr)
{
  if (!m_enabled)
    {
      return false;   // Defense disabled: no node is ever flagged.
    }
  auto it = m_trustTable.find (addr);
  if (it == m_trustTable.end ())
    {
      // Unknown nodes receive no verdict until either direct traffic or
      // recommendations produce an entry in m_trustTable.
      return false;
    }
  return (it->second < m_maliciousThreshold);
}

std::set<Ipv4Address>
OlsrDefenseFpnt::GetBlacklist () const
{
  std::set<Ipv4Address> blacklist;
  if (!m_enabled)
    {
      return blacklist;   // Defense disabled: blacklist is empty.
    }
  for (const auto& [addr, trust] : m_trustTable)
    {
      if (trust < m_maliciousThreshold)
        {
          blacklist.insert (addr);
        }
    }
  return blacklist;
}

std::vector<EvaluationVector>
OlsrDefenseFpnt::GetEvaluationVectors (const std::vector<Ipv4Address>& neighbors)
{
  NS_LOG_FUNCTION (this);
  if (!m_enabled)
    {
      return {};
    }
  // Section 5.2: Piggyback direct evaluation vectors onto the locally
  // generated TC message.
  std::vector<EvaluationVector> vectors;
  vectors.reserve (neighbors.size ());

  for (const auto& addr : neighbors)
    {
      EvaluationVector ev;   // default-constructed: (0, 0, 0)

      auto it = m_directEvaluationVectors.find (addr);
      if (it != m_directEvaluationVectors.end ())
        {
          ev = it->second;
        }
      else
        {
          // No direct observation yet -- encode maximum uncertainty
          // (E_trust = 0, E_distrust = 0, E_uncertain = 1).
          ev.trust     = 0;
          ev.distrust  = 0;
          ev.uncertain = 255;
        }

      vectors.push_back (ev);
    }

  return vectors;
}

double
OlsrDefenseFpnt::GetNodeTrust (Ipv4Address node)
{
  if (!m_enabled)
    {
      return m_uncertaintyBeta;
    }
  auto it = m_trustTable.find (node);
  if (it != m_trustTable.end ())
    {
      return it->second;
    }

  if (m_protocol != nullptr)
    {
      bool seenInRealState = false;
      for (const auto& nb : m_protocol->GetNeighbors ())
        {
          if (nb.neighborMainAddr == node) { seenInRealState = true; break; }
        }
      if (!seenInRealState)
        {
          for (const auto& nb2 : m_protocol->GetTwoHopNeighbors ())
            {
              if (nb2.twoHopNeighborAddr == node ||
                  nb2.neighborMainAddr   == node) { seenInRealState = true; break; }
            }
        }
      if (!seenInRealState)
        {
          // Reachable only via a single advertisement -- demote.
          // Value chosen above the malicious threshold (so we still route
          // through if no alternative exists) but below beta (so any real
          // node with even one observation is preferred).
          const double demoted = std::max (m_maliciousThreshold + 0.01,
                                           m_uncertaintyBeta * 0.5);
          return demoted;
        }
    }

  return m_uncertaintyBeta;
}

// ----------------------------------------------------------------------------
// Read-only state introspection (point 6). Reports the live sizes of every
// accumulated-state container. After SetEnabled() performs its symmetric
// cold-start wipe (which the harness triggers at every measurement-window
// boundary), all of these must read zero. const / no side effects.
// ----------------------------------------------------------------------------
OlsrDefenseFpnt::DebugStateSizes
OlsrDefenseFpnt::GetDebugStateSizes () const
{
  DebugStateSizes s;
  s.metrics                 = m_metrics.size ();
  s.trustTable              = m_trustTable.size ();
  s.directEvaluationVectors = m_directEvaluationVectors.size ();
  s.lastSValues             = m_lastSValues.size ();
  s.recommendations         = m_recommendations.size ();
  s.pendingArrivals         = m_pendingArrivals.size ();
  s.lastTcTime              = m_lastTcTime.size ();
  s.mprSelectionTime        = m_mprSelectionTime.size ();
  s.blacklist               = GetBlacklist ().size ();
  return s;
}

// ============================================================================
// Recommendation Intake & Deviation-Flag Rule D2 (TC-omission check)
// ============================================================================

void
OlsrDefenseFpnt::OnRecvEvaluationVectors (
    Ipv4Address sender,
    const std::vector<Ipv4Address>& advertisedNeighbors,
    const std::vector<EvaluationVector>& vectors)
{
  NS_LOG_FUNCTION (this << sender);

  if (advertisedNeighbors.size () != vectors.size ())
    {
      NS_LOG_WARN ("Malformed TC from " << sender << ": size mismatch ("
                   << advertisedNeighbors.size () << " vs "
                   << vectors.size () << ")");
      return;
    }

  for (size_t i = 0; i < advertisedNeighbors.size (); ++i)
    {
      const Ipv4Address target = advertisedNeighbors[i];
      // Keyed by (sender, target): a later TC from the same sender about
      // the same target overwrites the previous one. Without this, a
      // chatty MPR sending multiple TCs per trust period would be
      // counted multiple times by AggregateEvaluations.
      m_recommendations[{sender, target}] = vectors[i];

      NS_LOG_DEBUG ("Recommendation from " << sender << " about " << target
                    << ": T=" << static_cast<int> (vectors[i].trust)
                    << " D=" << static_cast<int> (vectors[i].distrust)
                    << " U=" << static_cast<int> (vectors[i].uncertain));
    }
}

void
OlsrDefenseFpnt::OnRecvHello (Ipv4Address, Ptr<const Packet>,
                              const MessageHeader&, const MessageHeader::Hello&)
{
  // Not used by the paper's model.
}

void
OlsrDefenseFpnt::OnRecvTc (Ipv4Address senderIfaceAddr, Ptr<const Packet>,
                           const MessageHeader& msg, const MessageHeader::Tc& tc)
{
  NS_LOG_FUNCTION (this << senderIfaceAddr);

  const Ipv4Address originator = msg.GetOriginatorAddress ();
  const Time now = Simulator::Now ();

  // D1 bookkeeping: record the most recent TC time per originator.
  m_lastTcTime[originator] = now;

  if (m_protocol == nullptr)
    {
      return;
    }

  const MprSet mprs = m_protocol->GetMprSet ();
  if (mprs.find (originator) == mprs.end ())
    {
      // Originator is not our MPR — they are not required to advertise us.
      return;
    }

  // Maintain the shared first-observation map so D1 and D2 share a single
  // grace-window definition.
  auto sit = m_mprSelectionTime.find (originator);
  if (sit == m_mprSelectionTime.end ())
    {
      m_mprSelectionTime[originator] = now;
      return;  // first time we see them as our MPR — grant grace.
    }

  // D2 is suppressed during the grace window: they may not have learned
  // we exist yet (HELLO exchange in progress).
  TimeValue tcIntervalValue;
  m_protocol->GetAttribute ("TcInterval", tcIntervalValue);
  const Time graceWindow = tcIntervalValue.Get () * D1_HOLD_MULTIPLIER;
  if (now - sit->second < graceWindow)
    {
      return;
    }

  const auto& advertised = tc.neighborAddresses;
  const bool selfIsAdvertised =
      std::find (advertised.begin (), advertised.end (), m_selfAddress)
      != advertised.end ();

  if (!selfIsAdvertised)
    {
      auto& metrics = m_metrics[originator];
      metrics.countRCheat++;
      NS_LOG_LOGIC ("Deviation D2: MPR " << originator
                    << " omitted us from TC");
    }
}

void
OlsrDefenseFpnt::OnTcGenerated (const MessageHeader::Tc&)
{
  // Not used by the paper's model.
}

// ============================================================================
// Metric Collection Hooks -- all four factors (Section 5.1)
// ============================================================================

void
OlsrDefenseFpnt::OnDataPacketReceived (Ptr<const Packet> /*packet*/,
                                       Ipv4Address /*source*/,
                                       Ipv4Address /*destination*/,
                                       Ipv4Address /*nextHop*/)
{
  // This hook fires on an intermediate node (us) when we are about to
  // forward a packet. It is redundant with OnDataPacketForwarded, which
  // fires at the same moment in both the relay path (RouteInput) and
  // the source path (RouteOutput) -- so we accumulate load and record
  // arrival timestamps there instead. Leaving this as a no-op keeps
  // the base-class contract satisfied.
}

void
OlsrDefenseFpnt::OnDataPacketForwarded (const Ipv4Header& header,
                                        Ptr<const Packet> packet,
                                        Ipv4Address nextHop,
                                        Ipv4Address finalDest)
{
  // Paper Section 5.1, paragraph 2:
  //   "Only MPRs are responsible for monitoring and evaluating their
  //    selectors."
  //
  // We are this node's defense; we monitor V_j only if V_j is in OUR
  // MPR Selector Set (i.e., V_j selected US as one of its MPRs). This
  // is the relationship under which the paper claims aggregation across
  // multiple MPRs yields objective recommendations.
  //
  // Note: GetMprSelectors() — not GetMprSet(). The two are directional
  // opposites:
  //   GetMprSet()       = nodes I chose as my MPRs (upstream).
  //   GetMprSelectors() = nodes that chose me as their MPR (downstream).
  // The paper's monitoring rule applies in the second direction.
  if (nextHop.IsBroadcast ()) return;
  if (nextHop.IsAny ())       return;
  if (m_protocol == nullptr)  return;

  const MprSelectorSet& selectors = m_protocol->GetMprSelectors ();
  bool isOurSelector = false;
  for (const auto& sel : selectors)
    {
      if (sel.mainAddr == nextHop) { isOurSelector = true; break; }
    }
  if (!isOurSelector)
    {
      return;   // V_j did not select us as its MPR -- not in our scope.
    }

auto& metrics = m_metrics[nextHop];
  metrics.countLoad += packet->GetSize ();

  if (nextHop != finalDest)
    {
      metrics.countRcv++;

      auto& pending = m_pendingArrivals[nextHop];

      const uint64_t key = HashIpv4Header (header);
      if (pending.find (key) == pending.end ())
        {
          pending[key] = { Simulator::Now () };
        }
    }
}

void
OlsrDefenseFpnt::OnDataPacketDropped (Ptr<const Packet>, Ipv4Address,
                                      Ipv4Address, DropReason)
{
  // Drops are observed implicitly through the ratio countFwd/countRcv.
  // No explicit hook action is required.
}

void
OlsrDefenseFpnt::OnNeighborForwardedPacket (Mac48Address transmitter,
                                            Mac48Address receiver,
                                            Ptr<const Packet> packet)
{
  if (m_protocol == nullptr)
    {
      return;
    }

  // Peek the IP header once -- both arms below need it.
  Ipv4Header ipHeader;
  if (packet->PeekHeader (ipHeader) == 0)
    {
      return;   // Not an IPv4 packet -- out of scope.
    }
  const uint64_t fingerprint = HashIpv4Header (ipHeader);

  const MprSelectorSet& selectors = m_protocol->GetMprSelectors ();
  auto isOurSelector = [&selectors] (const Ipv4Address& addr) {
    for (const auto& sel : selectors)
      {
        if (sel.mainAddr == addr) return true;
      }
    return false;
  };

  // ====================================================================
  // Transmitter-side observation:  V_j --(DATA)--> *
  //   Paper Sec. 5.1.B numerator: "If V_j --(DATA)_j--> *, Count^j_fwd++".
  //   Also drives Definition 3 (average forwarding delay) via the
  //   matched arrival timestamp.
  // ====================================================================
  const Ipv4Address txAddr = MacToIpv4 (transmitter);
  if (txAddr != Ipv4Address::GetAny () && isOurSelector (txAddr))
    {
      auto& pending = m_pendingArrivals[txAddr];
      auto it = pending.find (fingerprint);
      if (it != pending.end ())
        {
          auto& metrics = m_metrics[txAddr];
          metrics.countFwd++;
          const double delay =
              (Simulator::Now () - it->second.arrivalTime).GetSeconds ();
          if (delay >= 0.0)
            {
              metrics.totalDelay += delay;
            }
          pending.erase (it);
          NS_LOG_LOGIC ("Observed " << txAddr << " forwarding packet (fingerprint "
                        << std::hex << fingerprint << std::dec << ")");
        }
    }

  // ====================================================================
  // Receiver-side observation:  * --DATA--> V_j
  //   Paper Sec. 5.1.A (Load) and Sec. 5.1.B (PFR denominator): the '*'
  //   is ANY transmitter, not just us. Without this arm, only traffic
  //   our own routing layer feeds into V_j ever increments the
  //   denominator, so a blackhole sitting on a path no monitoring MPR
  //   happens to feed yields PFR = 0/0 (no evidence) and is never
  //   flagged.
  //
  //   When we are the transmitter, MonitorSnifferRx in the routing
  //   protocol short-circuits before invoking this callback, so the
  //   receiver-side bump is correctly skipped for self-sourced traffic
  //   -- that case is already handled by OnDataPacketForwarded.
  // ====================================================================
  if (receiver.IsGroup ())
    {
      // Multicast bit set (includes broadcast). Not directed at a
      // specific V_j -- skip.
      return;
    }

  const Ipv4Address rxAddr = MacToIpv4 (receiver);
  if (rxAddr == Ipv4Address::GetAny ())
    {
      // Receiver MAC didn't resolve to a known 1-hop neighbor (ARP cache
      // not yet populated, or the receiver isn't one of our neighbors).
      return;
    }
  if (!isOurSelector (rxAddr))
    {
      // Paper Sec. 5.1 limits monitoring scope to our MPR Selectors.
      return;
    }

  auto& rxMetrics = m_metrics[rxAddr];

  // Definition 1 (Load): every packet V_j receives, regardless of whether
  // V_j is the final destination. Paper Sec. 5.1.A states the rule with
  // no dest gating: "If * --packet--> V_j, Count^j_load += LENGTH(packet)".
  rxMetrics.countLoad += packet->GetSize ();

  // Definition 2 (PFR denominator): only packets V_j is expected to
  // forward, per the paper's "DATA.dest != V_j" clause. The arrival seed
  // lives under the same gate -- matching to a future retransmission is
  // only meaningful for forwardable packets.
  if (ipHeader.GetDestination () != rxAddr)
    {
      rxMetrics.countRcv++;

      auto& pending = m_pendingArrivals[rxAddr];
      // Don't overwrite an existing seed -- a duplicate sniff of the
      // same hop must not reset the arrival timestamp, or delay
      // measurement against the eventual retransmission would be biased
      // toward zero.
      if (pending.find (fingerprint) == pending.end ())
        {
          pending[fingerprint] = { Simulator::Now () };
        }

      NS_LOG_LOGIC ("Observed packet --> " << rxAddr
                    << " (fingerprint " << std::hex << fingerprint
                    << std::dec << ")");
    }
}

// ----------------------------------------------------------------------------
// Hooks outside the paper's model: intentional no-ops.
// ----------------------------------------------------------------------------

void OlsrDefenseFpnt::OnQueueStatusReport (uint32_t, uint32_t)          {}
void OlsrDefenseFpnt::OnEnergyStateUpdate (double, double)              {}
void
OlsrDefenseFpnt::OnMacTxFailure (Ipv4Address neighbor, uint32_t count)
{
  // OnDataPacketForwarded fires at "intent to send" (before the MAC layer
  // processes the packet), so countRcv was already incremented for V_j.
  // If the MAC layer hits the retry limit, the packet never actually
  // reached V_j -- we should roll back the denominator to avoid
  // penalizing V_j for our own link failure (false-low PFR).
  if (!m_enabled) return;
  if (neighbor == Ipv4Address::GetAny ()) return;
  if (neighbor.IsBroadcast ())            return;

  auto it = m_metrics.find (neighbor);
  if (it == m_metrics.end ())
    {
      return;
    }

  // Roll back countRcv. We do not roll back countLoad because the MAC
  // failure callback does not give us the packet size, and the bias is
  // small enough that it does not affect the load factor's coarse NORM.
  if (it->second.countRcv >= count)
    {
      it->second.countRcv -= count;
    }
  else
    {
      it->second.countRcv = 0;
    }
}

// ============================================================================
// Trust Reasoning Cycle -- Algorithm 1 + Equations (1)-(5)
// ============================================================================

void
OlsrDefenseFpnt::PeriodicCheck ()
{
  NS_LOG_FUNCTION (this);

  if (!m_enabled)
    {
      // Defense is disabled. Drain any state that has accumulated from
      // hook callbacks (which fire regardless of the flag, because the
      // routing protocol does not gate them) so that a subsequent
      // enable does not act on stale evidence.
      m_metrics.clear ();
      m_recommendations.clear ();
      m_pendingArrivals.clear ();
      return;
    }
  if (m_protocol != nullptr)
    {
      const MprSelectorSet& selectors = m_protocol->GetMprSelectors ();
      std::set<Ipv4Address> currentSelectors;
      for (const auto& s : selectors) currentSelectors.insert (s.mainAddr);

      for (auto it = m_metrics.begin (); it != m_metrics.end (); )
        {
          if (currentSelectors.find (it->first) == currentSelectors.end ())
            {
              m_pendingArrivals.erase (it->first);
              m_directEvaluationVectors.erase (it->first);  
              m_lastSValues.erase (it->first); 
              it = m_metrics.erase (it);
            }
          else
            {
              ++it;
            }
        }
    }
  // ----- Step 0: Protocol-deviation D1 scan (silent MPRs) and arrival
  //               cleanup. Both may add counters / evict state before the
  //               per-neighbor evaluation runs.
  ScanDeviationRuleD1 ();
  ExpireStaleArrivals ();

  bool needsReactiveUpdate = false;

  // ----- Step 1: Refresh direct evaluations for every observed neighbor.
  for (auto& [addr, metrics] : m_metrics)
    {
      const std::vector<double> s0 = MetricsToS0 (addr, metrics);
      m_lastSValues[addr] = s0;
      m_directEvaluationVectors[addr] = RunFuzzyPetriNet (s0);
    }

  // ----- Step 2: Build the union of targets that need a trust update.
  // A target qualifies if we have a direct evaluation for it, or if at
  // least one recommendation about it was received this period, or both.
  std::set<Ipv4Address> targets;
  for (const auto& [addr, ev]      : m_directEvaluationVectors) targets.insert (addr);
  for (const auto& [key, ev]       : m_recommendations)         targets.insert (key.second);

  // ----- Step 3: Unified aggregation + Equations (4)-(5) for every target.
  for (const Ipv4Address& addr : targets)
    {
      // Assemble the evidence set: direct EV (if any) + all received
      // recommendations. The paper treats both as equally weighted inputs
      // to the slander-filtering aggregation.
      std::vector<EvaluationVector> evs;

      auto itDirect = m_directEvaluationVectors.find (addr);
      if (itDirect != m_directEvaluationVectors.end ())
        {
          evs.push_back (itDirect->second);
        }

      for (const auto& [key, ev] : m_recommendations)
        {
          if (key.second == addr)
            {
              evs.push_back (ev);
            }
        }

      if (evs.empty ())
        {
          continue;   // No evidence of any kind for this target.
        }

      // Equations (1)-(3): pairwise L1 DIF aggregation with slander filter.
      double aggTrust     = 0.0;
      double aggUncertain = 0.0;
      AggregateEvaluations (evs, aggTrust, aggUncertain);

      // Equation (4): current-period trust value.
      double Tc = aggTrust + m_uncertaintyBeta * aggUncertain;
      Tc = std::clamp (Tc, 0.0, 1.0);

      // Equation (5): temporal smoothing with correct first-period bootstrap.
      double finalTrust;
      auto itOld = m_trustTable.find (addr);
      const bool hasHistory = (itOld != m_trustTable.end ());
      if (hasHistory)
        {
          finalTrust = (1.0 - m_fadingFactor) * Tc
                     + m_fadingFactor       * itOld->second;
        }
      else
        {
          // No previous value exists; Equation (5) reduces to T = T_c.
          // Blending with a fictitious old value would distort the
          // first-period verdict.
          finalTrust = Tc;
        }

      const bool wasMalicious = hasHistory
                              && (itOld->second < m_maliciousThreshold);
      const bool isMalicious  = (finalTrust < m_maliciousThreshold);
      if (wasMalicious != isMalicious)
        {
          if (isMalicious)
            {
              NS_LOG_WARN ("Node " << addr
                           << " flagged MALICIOUS (T = " << finalTrust << ")");
            }
          else
            {
              NS_LOG_INFO ("Node " << addr
                           << " RECOVERED to trusted (T = " << finalTrust << ")");
            }
          needsReactiveUpdate = true;
        }

      m_trustTable[addr] = finalTrust;
    }

  // ----- Step 4: Clean per-period state.
  m_metrics.clear ();
  m_recommendations.clear ();
  // m_directEvaluationVectors and m_lastSValues persist across periods;
  // they are overwritten only when fresh data for the same neighbor arrives.
  // m_pendingArrivals is managed by ExpireStaleArrivals.

  // ----- Step 5: Notify the routing layer if any verdict flipped.
  if (needsReactiveUpdate && m_protocol)
    {
      m_protocol->RunTrustDijkstra ();
    }
}

// ============================================================================
// Deviation-Flag Rule D1 (silent-MPR detection)
// ============================================================================

void
OlsrDefenseFpnt::ScanDeviationRuleD1 ()
{
  if (m_protocol == nullptr)
    {
      return;
    }

  TimeValue tcIntervalValue;
  m_protocol->GetAttribute ("TcInterval", tcIntervalValue);
  const Time tcInterval = tcIntervalValue.Get ();
  const Time holdTime = tcInterval * D1_HOLD_MULTIPLIER;

  const MprSet mprs = m_protocol->GetMprSet ();
  const Time now = Simulator::Now ();

  // Reap selection-time entries for nodes that are no longer our MPRs.
  for (auto it = m_mprSelectionTime.begin (); it != m_mprSelectionTime.end (); )
    {
      if (mprs.find (it->first) == mprs.end ())
        {
          it = m_mprSelectionTime.erase (it);
        }
      else
        {
          ++it;
        }
    }

  for (const Ipv4Address& mpr : mprs)
    {
      // Record first observation. New MPRs receive a holdTime grace
      // window before D1 can fire against them — otherwise a freshly
      // selected MPR is guaranteed to be flagged on the very next scan
      // because it has not had time to emit a TC yet.
      auto sit = m_mprSelectionTime.find (mpr);
      if (sit == m_mprSelectionTime.end ())
        {
          m_mprSelectionTime[mpr] = now;
          continue;  // first observation — no D1 evaluation this period.
        }
      const Time selectedSince = sit->second;
      if (now - selectedSince < holdTime)
        {
          continue;  // still inside grace window.
        }

      // Past the grace window: apply the silence test.
      auto it = m_lastTcTime.find (mpr);
      Time age;
      if (it == m_lastTcTime.end ())
        {
          // Never seen a TC. Measure age from when we selected them as
          // our MPR, NOT from simulation start.
          age = now - selectedSince;
        }
      else
        {
          age = now - it->second;
        }

      if (age > holdTime)
        {
          auto& metrics = m_metrics[mpr];
          metrics.countRCheat++;
          NS_LOG_LOGIC ("Deviation D1: MPR " << mpr
                        << " silent for " << age.GetSeconds () << " s");
        }
    }
}

void
OlsrDefenseFpnt::ExpireStaleArrivals ()
{
  // Remove pending arrival timestamps older than 2 * trust interval.
  // These correspond to packets that entered a neighbor but were never
  // observed to leave -- either because the neighbor dropped them (which
  // is captured by the PFR factor independently) or because our
  // promiscuous sniffing missed the transmission. Expiring them prevents
  // unbounded memory growth.
  const Time cutoff = Simulator::Now () - m_checkInterval * 2;

  for (auto& [neighbor, pending] : m_pendingArrivals)
    {
      for (auto it = pending.begin (); it != pending.end (); )
        {
          if (it->second.arrivalTime < cutoff)
            {
              it = pending.erase (it);
            }
          else
            {
              ++it;
            }
        }
    }
}

// ============================================================================
// Metric Normalization -- all four factors (Section 5.1)
// ============================================================================

std::vector<double>
OlsrDefenseFpnt::MetricsToS0 (Ipv4Address addr,
                              const NodeBehaviorMetrics& metrics)
{
  // Reduced S^(0) over 15 places. Only indices p1..p8 receive evidence;
  // p9..p15 are intermediate / verdict places populated by the FPN.
  std::vector<double> S (NUM_PLACES, 0.0);

  const bool hasHistory = (m_lastSValues.find (addr) != m_lastSValues.end ());
  const std::vector<double>& last =
      hasHistory ? m_lastSValues.at (addr)
                 : std::vector<double> (NUM_PLACES, 0.0);

  const double t = m_checkInterval.GetSeconds ();
  const double tSafe = (t > 0.0) ? t : 1.0;

  // ---- Factor 1: Load (Definition 1) ----
  // Units: countLoad is bytes. Paper defines load in bps. Convert and
  // apply NORM against m_maxLoad (also in bits/s).
  if (metrics.countLoad > 0)
    {
      const double loadBps = (metrics.countLoad * 8.0) / tSafe;
      const double s1 = std::clamp (loadBps / m_maxLoad, 0.0, 1.0);
      S[P1_LOAD_HIGH] = s1;
      S[P2_LOAD_LOW]  = 1.0 - s1;
    }
  else if (hasHistory)
    {
      S[P1_LOAD_HIGH] = last[P1_LOAD_HIGH];
      S[P2_LOAD_LOW]  = last[P2_LOAD_LOW];
    }
  // else: no evidence -> leave at (0, 0). This produces E_uncertain weight
  // in the downstream reasoning, which is the correct semantics for a
  // neighbor we have not yet observed.

  // ---- Factor 2: Packet Forwarding Rate (Definition 2) ----
  if (metrics.countRcv > 0)
    {
      // PFR = countFwd / countRcv, clamped to [0, 1]. Clamping is needed
      // because promiscuous countFwd may incidentally include
      // retransmissions of control packets that slip the IP-header check.
      double pfr = static_cast<double> (metrics.countFwd)
                 / static_cast<double> (metrics.countRcv);
      pfr = std::clamp (pfr, 0.0, 1.0);
      S[P3_FWD_HIGH] = pfr;
      S[P4_FWD_LOW]  = 1.0 - pfr;
    }
  else if (hasHistory)
    {
      S[P3_FWD_HIGH] = last[P3_FWD_HIGH];
      S[P4_FWD_LOW]  = last[P4_FWD_LOW];
    }

  // ---- Factor 3: Average Forwarding Delay (Definition 3) ----
  if (metrics.countFwd > 0 && metrics.totalDelay > 0.0)
    {
      const double avgDelay = metrics.totalDelay
                            / static_cast<double> (metrics.countFwd);
      const double s5 = std::clamp (avgDelay / m_maxDelay, 0.0, 1.0);
      S[P5_DELAY_HIGH] = s5;
      S[P6_DELAY_LOW]  = 1.0 - s5;
    }
  else if (hasHistory)
    {
      S[P5_DELAY_HIGH] = last[P5_DELAY_HIGH];
      S[P6_DELAY_LOW]  = last[P6_DELAY_LOW];
    }
  // Note: if countFwd > 0 but totalDelay == 0 (no matched packets), we
  // also fall through to history / zero, reflecting genuine lack of
  // delay evidence rather than reporting spuriously perfect delay.

  // ---- Factor 4: Protocol Deviation Flag (Definition 4) ----
  // p7 (deviation) is 1 iff countRCheat > delta; p8 is the complement.
  //
  // Unlike the other three factors, deviation is a fresh per-period
  // assessment rather than a smoothed observation: the paper's
  // Definition 4 states the flag is 1 only "when routing related
  // abnormal behaviors" are observed, implicitly in the current window.
  // We therefore always evaluate against the current period's
  // countRCheat, with the default (0) meaning "routing normal".
  //
  // This also matches Section 5.1.D which describes the threshold
  // delta as suppressing false detections within a single period --
  // a notion that only makes sense if each period is evaluated on
  // its own observations.
  const bool deviates = (metrics.countRCheat > m_cheatThreshold);
  S[P7_ROUTE_BAD] = deviates ? 1.0 : 0.0;
  S[P8_ROUTE_OK]  = deviates ? 0.0 : 1.0;

  return S;
}

// ============================================================================
// Fuzzy Petri Net Core -- Algorithm 1
// ============================================================================

EvaluationVector
OlsrDefenseFpnt::RunFuzzyPetriNet (const std::vector<double>& s0) const
{
  NS_ASSERT (s0.size () == static_cast<size_t> (NUM_PLACES));

  std::vector<double> S = s0;

  for (int k = 0; k < MAX_FPN_ITERATIONS; ++k)
    {
      // Step 1: I = W^T * S  (equivalent input to each transition).
      std::vector<double> I (NUM_TRANSITIONS, 0.0);
      for (int r = 0; r < NUM_TRANSITIONS; ++r)
        {
          for (int p = 0; p < NUM_PLACES; ++p)
            {
              I[r] += W_T[r][p] * S[p];
            }
        }

      // Step 2: G = I (x) TH          (Definition 5, circled asterisk).
      const std::vector<double> G = MatrixOp_Threshold (I, TH);

      // Step 3: S_calc = U (x) G      (Definition 7, circled cross).
      const std::vector<double> S_calc = MatrixOp_WeightedMax (U_MAT, G);

      // Step 4: S_next = S (.) S_calc (Definition 6, circled dot).
      std::vector<double> S_next = MatrixOp_Max (S, S_calc);

      // Step 5: convergence check.
      if (S_next == S)
        {
          break;
        }
      S = std::move (S_next);
    }

  // Step 6: extract the evaluation triple.
  const double sTrust    = S[P15_TRUST];
  const double sDistrust = S[P14_DISTRUST];

  double eTrust, eDistrust, eUncertain;
  if (sTrust + sDistrust < 1.0)
    {
      eTrust     = sTrust;
      eDistrust  = sDistrust;
      eUncertain = 1.0 - sTrust - sDistrust;
    }
  else
    {
      // Overflow branch (paper Algorithm 1, Step 6, else clause).
      eTrust     = sTrust;
      eDistrust  = 1.0 - sTrust;
      eUncertain = 0.0;
    }

  EvaluationVector ev;
  ev.trust     = static_cast<uint8_t> (std::round (eTrust     * 255.0));
  ev.distrust  = static_cast<uint8_t> (std::round (eDistrust  * 255.0));
  ev.uncertain = static_cast<uint8_t> (std::round (eUncertain * 255.0));
  return ev;
}

// ============================================================================
// Slander-Filter Aggregation -- Equations (1)-(3)
// ============================================================================

void
OlsrDefenseFpnt::AggregateEvaluations (const std::vector<EvaluationVector>& evs,
                                       double& outTrust,
                                       double& outUncertain) const
{
  const size_t n = evs.size ();
  NS_ASSERT_MSG (n > 0, "AggregateEvaluations requires at least one vector");

  // Pre-decode each EV to [0, 1].
  std::vector<double> t (n), d (n), u (n);
  for (size_t k = 0; k < n; ++k)
    {
      t[k] = evs[k].trust     / 255.0;
      d[k] = evs[k].distrust  / 255.0;
      u[k] = evs[k].uncertain / 255.0;
    }

  // Equation (1): DIF_k = sum over (type, v) of |E^type_k - E^type_v|,
  // where type ranges over {trust, distrust, uncertain} and v ranges over
  // every recommendation index (including k itself, which contributes 0).
  std::vector<double> dif (n, 0.0);
  for (size_t k = 0; k < n; ++k)
    {
      for (size_t v = 0; v < n; ++v)
        {
          dif[k] += std::abs (t[k] - t[v])
                  + std::abs (d[k] - d[v])
                  + std::abs (u[k] - u[v]);
        }
    }

  // In the pairwise L1 formulation, dif[k] = 0 for some k implies all
  // recommendations are mutually identical (so dif is uniformly 0).
  const double maxDif = *std::max_element (dif.begin (), dif.end ());

  std::vector<double> alpha (n);
  if (maxDif < DIF_EPS)
    {
      // All recommendations are indistinguishable -> equal weights.
      std::fill (alpha.begin (), alpha.end (),
                 1.0 / static_cast<double> (n));
    }
  else
    {
      // Equation (2): alpha_k = (1/dif_k) / sum_i (1/dif_i).
      double sumInvDif = 0.0;
      for (size_t k = 0; k < n; ++k)
        {
          sumInvDif += 1.0 / dif[k];
        }
      for (size_t k = 0; k < n; ++k)
        {
          alpha[k] = (1.0 / dif[k]) / sumInvDif;
        }
    }

  // Equation (3): weighted aggregation.
  // The distrust component is not needed downstream; Equation (4) uses only
  // E_trust and E_uncertain.
  outTrust     = 0.0;
  outUncertain = 0.0;
  for (size_t k = 0; k < n; ++k)
    {
      outTrust     += alpha[k] * t[k];
      outUncertain += alpha[k] * u[k];
    }

  // Guard against floating-point drift. Downstream Eq. (4) and Eq. (5)
  // assume both components lie in [0, 1].
  outTrust     = std::clamp (outTrust,     0.0, 1.0);
  outUncertain = std::clamp (outUncertain, 0.0, 1.0);
}

// ============================================================================
// Matrix Operators -- Definitions 5, 6, 7
// ============================================================================

std::vector<double>
OlsrDefenseFpnt::MatrixOp_Threshold (const std::vector<double>& input,
                                     const std::vector<double>& threshold) const
{
  // Definition 5 ("circled asterisk"): c_i = a_i if a_i >= b_i else 0.
  NS_ASSERT (input.size () == threshold.size ());
  std::vector<double> result (input.size (), 0.0);
  for (size_t i = 0; i < input.size (); ++i)
    {
      result[i] = (input[i] > threshold[i]) ? input[i] : 0.0;
    }
  return result;
}

std::vector<double>
OlsrDefenseFpnt::MatrixOp_Max (const std::vector<double>& a,
                               const std::vector<double>& b) const
{
  // Definition 6 ("circled dot"): c_i = max(a_i, b_i).
  NS_ASSERT (a.size () == b.size ());
  std::vector<double> result (a.size ());
  for (size_t i = 0; i < a.size (); ++i)
    {
      result[i] = std::max (a[i], b[i]);
    }
  return result;
}

std::vector<double>
OlsrDefenseFpnt::MatrixOp_WeightedMax (
    const std::vector<std::vector<double>>& Umat,
    const std::vector<double>& G) const
{
  // Definition 7 ("circled cross"): c_p = max_r { U[p][r] * G[r] }.
  std::vector<double> result (NUM_PLACES, 0.0);
  for (int p = 0; p < NUM_PLACES; ++p)
    {
      double maxVal = 0.0;
      for (int r = 0; r < NUM_TRANSITIONS; ++r)
        {
          const double val = Umat[p][r] * G[r];
          if (val > maxVal)
            {
              maxVal = val;
            }
        }
      result[p] = maxVal;
    }
  return result;
}

// ============================================================================
// MAC -> IPv4 resolution (for promiscuous monitoring)
//
// Two-tier lookup:
//   1) ARP cache (fast, but only populated for IPs we have sent unicast to).
//   2) Global NodeList scan, anchored by our OLSR neighbor / 2-hop set
//      (slower, but works regardless of unicast history).
//
// The fallback exists because trust monitoring is fundamentally a passive
// promiscuous-listen operation. The MPRs of node B never send unicast to B
// (B chose them, not the other way round), so their ARP cache never has
// an entry for B. Without the fallback, every promiscuous observation of
// B by its own MPRs is silently discarded, m_metrics[B] stays empty,
// PeriodicCheck never produces a direct evaluation for B, m_trustTable
// never gets an entry, GetNodeTrust(B) always returns the default beta,
// and the routing layer behaves as if no trust evidence exists. Symptom
// in the logs: trust(BH) stuck at the beta default forever, PDR with
// defense ON no better (or worse) than with defense OFF.
// ============================================================================

Ipv4Address
OlsrDefenseFpnt::MacToIpv4 (Mac48Address mac)
{
  if (!m_protocol) return Ipv4Address::GetAny ();

  Ptr<Node> myNode = m_protocol->GetObject<Node> ();
  if (!myNode) return Ipv4Address::GetAny ();

  // ---------- Tier 1: ARP cache (fast path).
  Ptr<Ipv4L3Protocol> l3 = myNode->GetObject<Ipv4L3Protocol> ();
  if (l3)
    {
      const NeighborSet& neighbors = m_protocol->GetNeighbors ();
      for (uint32_t i = 0; i < l3->GetNInterfaces (); ++i)
        {
          Ptr<Ipv4Interface> interface = l3->GetInterface (i);
          Ptr<ArpCache> arp = interface->GetArpCache ();
          if (!arp) continue;

          for (const auto& nb : neighbors)
            {
              ArpCache::Entry* entry = arp->Lookup (nb.neighborMainAddr);
              if (entry && entry->IsAlive () &&
                  entry->GetMacAddress () == mac)
                {
                  return nb.neighborMainAddr;
                }
            }
        }
    }

  // ---------- Tier 2: NodeList scan anchored by OLSR state.
  // Build a quick lookup of IPs we are willing to recognise (1-hop and
  // 2-hop neighbours, plus addresses in our topology set).
  std::set<Ipv4Address> recognised;
  for (const auto& nb : m_protocol->GetNeighbors ())
    {
      recognised.insert (nb.neighborMainAddr);
    }
  for (const auto& nb2 : m_protocol->GetTwoHopNeighbors ())
    {
      recognised.insert (nb2.neighborMainAddr);
      recognised.insert (nb2.twoHopNeighborAddr);
    }

  for (auto it = NodeList::Begin (); it != NodeList::End (); ++it)
    {
      Ptr<Node> other = *it;
      if (other == myNode) continue;

      // Does this node own a WifiNetDevice with the matching MAC?
      bool macHere = false;
      for (uint32_t d = 0; d < other->GetNDevices (); ++d)
        {
          Ptr<WifiNetDevice> wifi =
              DynamicCast<WifiNetDevice> (other->GetDevice (d));
          if (!wifi) continue;
          if (Mac48Address::ConvertFrom (wifi->GetAddress ()) == mac)
            {
              macHere = true;
              break;
            }
        }
      if (!macHere) continue;

      // Yes -- return one of the node's IPs, preferring an IP that we
      // already recognise from OLSR state. Without that preference we
      // could feed observations into the defense for nodes the routing
      // layer does not believe in.
      Ptr<Ipv4> ipv4 = other->GetObject<Ipv4> ();
      if (!ipv4) continue;
      Ipv4Address fallback = Ipv4Address::GetAny ();
      for (uint32_t i = 1; i < ipv4->GetNInterfaces (); ++i)
        {
          for (uint32_t a = 0; a < ipv4->GetNAddresses (i); ++a)
            {
              Ipv4Address addr = ipv4->GetAddress (i, a).GetLocal ();
              if (recognised.count (addr)) return addr;
              if (fallback == Ipv4Address::GetAny ()) fallback = addr;
            }
        }
      return fallback;   // MAC matched but IP not in our OLSR view yet.
    }

  return Ipv4Address::GetAny ();
}

} // namespace olsr
} // namespace ns3