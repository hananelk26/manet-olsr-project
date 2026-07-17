/*
 * OLSR Blackhole Attack Simulation - FORCED TOPOLOGY
 * Description: Implements a "Bridge" topology where traffic MUST go through Node 0.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/olsr-helper.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-flow-classifier.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("OlsrBlackholeAttackSim");

// Function updated to accept spoof count
void
SetMaliciousNode (Ptr<Node> node, uint32_t spoofCount) // <--- Updated signature to accept spoof count
{
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
  Ptr<Ipv4RoutingProtocol> proto = ipv4->GetRoutingProtocol ();
  Ptr<Ipv4ListRouting> listProto = DynamicCast<Ipv4ListRouting> (proto);

  if (listProto)
    {
      for (uint32_t i = 0; i < listProto->GetNRoutingProtocols (); i++)
        {
          int16_t priority;
          Ptr<Ipv4RoutingProtocol> child = listProto->GetRoutingProtocol (i, priority);
          if (child->GetInstanceTypeId ().GetName () == "ns3::olsr::RoutingProtocol")
            {
              child->SetAttribute ("IsMalicious", BooleanValue (true));
              child->SetAttribute ("SpoofedLinksCount", UintegerValue (spoofCount)); // <--- Setting the Phantom Nodes count
              return;
            }
        }
    }
}

int
main (int argc, char *argv[])
{
  bool enableBlackhole = false;
  uint32_t nNodes = 21; // 10 left, 10 right, 1 middle
  uint32_t simTime = 100;
  uint32_t spoofedLinks = 15; 

  CommandLine cmd;
  cmd.AddValue ("enableBlackhole", "Enable/Disable Malicious Node", enableBlackhole);
  cmd.AddValue ("spoofedLinks", "Number of Phantom Neighbors", spoofedLinks); 
  cmd.Parse (argc, argv);

  NodeContainer allNodes;
  allNodes.Create (nNodes);

  // Node grouping
  Ptr<Node> maliciousNode = allNodes.Get (0);
  NodeContainer leftNodes;
  NodeContainer rightNodes;
  
  for (uint32_t i = 1; i <= 10; ++i) leftNodes.Add (allNodes.Get (i));
  for (uint32_t i = 11; i <= 20; ++i) rightNodes.Add (allNodes.Get (i));

  // --- WiFi Setup ---
  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211b);

  YansWifiPhyHelper wifiPhy;
  wifiPhy.Set ("RxGain", DoubleValue (0));
  wifiPhy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);

  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  // Range ~250m
  wifiChannel.AddPropagationLoss ("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (250.0));
  wifiPhy.SetChannel (wifiChannel.Create ());

  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");
  
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, allNodes);

  // --- Mobility - Critical Topology ---
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();

  // 1. Blackhole at center (Bridge)
  positionAlloc->Add (Vector (500.0, 500.0, 0.0)); // Node 0

  // 2. Left Cluster (Sources)
  for (int i = 0; i < 10; i++) {
      positionAlloc->Add (Vector (300.0, 450.0 + (i * 10), 0.0)); 
  }

  // 3. Right Cluster (Destinations)
  for (int i = 0; i < 10; i++) {
      positionAlloc->Add (Vector (700.0, 450.0 + (i * 10), 0.0)); 
  }

  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (allNodes);

  // --- OLSR Routing ---
  OlsrHelper olsr;
  Ipv4ListRoutingHelper list;
  list.Add (olsr, 100);

  InternetStackHelper internet;
  internet.SetRoutingHelper (list);
  internet.Install (allNodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign (devices);

  // Enable malicious mode if requested
  if (enableBlackhole)
    {
      SetMaliciousNode (maliciousNode, spoofedLinks); // <--- Passing the 15 phantom nodes variable
    }

  // --- Applications ---
  // Sending from Left nodes to corresponding Right nodes
  OnOffHelper onoff ("ns3::UdpSocketFactory", Address ());
  onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
  onoff.SetAttribute ("PacketSize", UintegerValue (512));
  onoff.SetAttribute ("DataRate", StringValue ("20kbps")); 

  for (uint32_t i = 0; i < 10; ++i)
    {
      // Left Node (i+1) sends to Right Node (i+11)
      // IP address index matches node index in 'interfaces' container
      AddressValue remoteAddress (InetSocketAddress (interfaces.GetAddress (i + 11), 9));
      onoff.SetAttribute ("Remote", remoteAddress);
      
      ApplicationContainer app = onoff.Install (allNodes.Get (i + 1)); // Source is Left Node
      app.Start (Seconds (10.0 + i)); // Stagger start times
      app.Stop (Seconds (simTime - 10.0));
    }

  // --- Flow Monitor ---
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();

  // --- Results Analysis ---
  uint32_t txPacketsSum = 0;
  uint32_t rxPacketsSum = 0;

  monitor->CheckForLostPackets ();
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();

  for (auto i = stats.begin (); i != stats.end (); ++i)
    {
      txPacketsSum += i->second.txPackets;
      rxPacketsSum += i->second.rxPackets;
    }

  double pdr = 0;
  if (txPacketsSum > 0)
    {
      pdr = (double)rxPacketsSum / txPacketsSum * 100;
    }

  std::cout << "\n=======================================================" << std::endl;
  std::cout << "         OLSR Blackhole Attack - BRIDGE TOPOLOGY         " << std::endl;
  std::cout << "=======================================================" << std::endl;
  std::cout << " Attack Status : " << (enableBlackhole ? "ENABLED" : "DISABLED") << std::endl;
  std::cout << " Spoofed Links : " << (enableBlackhole ? spoofedLinks : 0) << std::endl; // <--- Added print for verification
  std::cout << " Total Tx      : " << txPacketsSum << std::endl;
  std::cout << " Total Rx      : " << rxPacketsSum << std::endl;
  std::cout << " PDR (%)       : " << pdr << " %" << std::endl;
  std::cout << "=======================================================\n" << std::endl;

  Simulator::Destroy ();
  return 0;
}