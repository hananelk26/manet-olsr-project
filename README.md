# ML-Based Classification of MANET Defense Mechanisms Against Blackhole Attacks

## 📌 Project Overview
This project focuses on the identification and classification of defense mechanisms in Mobile Ad-hoc Networks (MANETs), specifically targeting the **OLSR protocol** under **Blackhole routing attacks**. 

The ultimate goal is to develop a **Machine Learning (Neural Network) model** capable of analyzing a given OLSR network's state (via extracted feature vectors) in real-time. The model will determine:
1. Whether a defense mechanism against Blackhole attacks is currently active.
2. If active, specifically *which* class of defense strategy is being utilized.

This repository contains the C++ implementation of the attack vectors, the defense strategies, and the extensive simulation environment built on top of the **NS-3 Network Simulator**, which generates the datasets required for training the ML classifier.

---

## ⚖️ NS-3 License Notice
**Compliance with GPLv2:** This project is built as an extension of the official NS-3 network simulator. In accordance with the GNU General Public License v2.0 (GPLv2), the original `LICENSE` and `COPYING` files of the NS-3 project remain completely intact and must not be deleted or modified. This repository strictly adheres to open-source principles, and any derivative work herein is subject to the same licensing terms.

---

## 🏗️ System Architecture & Code Design

### Modified Protocol (`olsr-routing-protocol`)
We modified the core `olsr-routing-protocol` in NS-3 to act as the foundation for both our attacks and defenses. Key additions to the `RoutingProtocol` class include:
* `m_isMalicious`: A boolean flag determining if a node is an attacker.
* `m_spoofedLinksCount`: Defines how many fake neighbors an attacker will broadcast.
* `m_localRxDrops`: A counter tracking locally dropped packets.
* **The Defense Interface Pointer (`m_defenseStrategy`)**: An instance pointer of type `OlsrDefenseStrategy`. Every node possesses this pointer, allowing us to dynamically assign different defense mechanisms to different nodes.

### Interface Integration
Instead of hardcoding defenses, we created a unified interface: `OlsrDefenseStrategy`. 
We strategically placed hooks throughout the `RoutingProtocol` functions. If `m_defenseStrategy` is not `NULL`, the protocol triggers corresponding interface functions. For example:
* **Packet Forwarding:** Hooked to trigger `OnDataPacketForwarded`.
* **Promiscuous Listening:** Implemented `SetupPromiscuousMonitor` and `MonitorSnifferRx` to eavesdrop on neighbors' traffic (crucial for Watchdog mechanisms).
* **Timers & State:** Added `HandleDefenseTimer` (called every second) which triggers the defense's `PeriodicCheck`, providing the defense algorithm with the node's current queue load and battery state (to prevent false positives caused by congestion).

---

## 🛑 Attack Mechanisms (Blackhole & Poisoning)
The implementation utilizes four distinct techniques to compromise the network topology and disrupt data delivery:

1. **Willingness Manipulation (Control Plane):** The attacker overrides its default willingness, setting it to `WILL_ALWAYS` (7) in outgoing HELLO messages. According to RFC 3626, neighbors are forced to prioritize this node as a Multi-Point Relay (MPR), ensuring the attacker is included in nearly all routing paths.
2. **Topology Poisoning via ANSN (Control Plane):** In the `SendTc` function, the attacker increments the Advertised Neighbor Sequence Number (ANSN) by a large offset (+200). Neighbors perceive this as significantly newer topology info, overwriting valid routing tables.
3. **Link Spoofing (Control Plane):** The node advertises symmetric links with non-existent (phantom) neighbors by generating HELLO messages with fake IP addresses (starting from `200.0.0.1`), artificially inflating its connectivity degree to attract traffic.
4. **Silent Packet Drop / Blackhole (Data Plane):** Within the `RouteInput` function, the malicious node intercepts unicast packets. It returns `true` (signaling success) but intentionally drops the packet without invoking the `UnicastForwardCallback`, silently destroying traffic.

*⚠️ Research Disclaimer: This implementation is strictly for academic research and IDS evaluation.*

---

## 🛡️ Implemented Defense Strategies

We have implemented three distinct defense classes that inherit from the `OlsrDefenseStrategy` interface:

### Defense 1: Cooperative Cross-Layer Watchdog
*Based on: Baiad, R., et al. (2014).*
* **Mechanism:** Every node acts as a Watchdog over its neighbors. We modified NS-3 to force RTS/CTS handshakes even for small packets.
* **Logic:** If node A asks B to forward to C, A monitors B. If B doesn't send an RTS, it's marked malicious. If B sends an RTS but gets no CTS from C (collision), A forgives B. However, to catch smart attackers who spoof RTS, excessive RTS requests without CTS also trigger suspicion.
* **Enhancements:** Added a **Reputation System with Decay**. Instead of binary classification, nodes gain points for forwarding and lose points for dropping. This, combined with queue-load monitoring, solves the issue of falsely accusing congested nodes of being attackers.

### Defense 2: Trust-Based Routing (Petri Net)
*Based on: Tan, S., et al. (2015).*
* **Mechanism:** Nodes monitor neighbors and use a Petri Net (a state-machine/flowchart algorithm) to calculate a continuous "Trust Score" for each neighbor.
* **Sharing:** These trust scores are piggybacked onto standard TC (Topology Control) messages, allowing trust data to propagate network-wide.
* **Routing:** Instead of standard shortest-path Dijkstra, nodes calculate routes where the bottleneck (minimum) trust score of the path is maximized compared to alternative routes (MAX-MIN routing).

### Defense 3: Contradiction Rules & Fictitious Nodes (DCFM / GCOP)
*Based on: Schweitzer, N., et al. (2025).*
* **Mechanism:** A highly formalized logic system. Nodes evaluate neighbors based on 3 Contradiction Rules (e.g., Node X claims Y is a neighbor, but Y's HELLO message doesn't list X). 
* **Fictitious Node Injection:** To force attackers to reveal themselves via contradictions, nodes occasionally broadcast a fictitious neighbor. The decision to deploy a fictitious node is calculated using the **GCOP** (and fallback **GCOHP**) algorithms. These algorithms perform localized BFS searches (to depths of 2 and 3) to analyze hex-shaped network topologies and determine if a trap is necessary.
* **Integration:** Hooked into the protocol so that every time a node prepares to send a HELLO message, it evaluates the GCOP algorithm.

---

## 🧠 Machine Learning Pipeline & Data Generation
To train the neural network classifier, we are generating vast amounts of network traffic data using NS-3 simulations located in the `scratch` directory (e.g., `bridge_attack.cc`, `olsr-watchdog-defense.cc`).

**The Data Generation Matrix:**
Each simulation topology is run through 4 distinct phases to extract feature vectors:
1. Normal Network (No Attack, No Defense).
2. Network Under Attack (Blackhole active).
3. Network Under Attack + Defense Active.
4. Normal Network + Defense Active (To evaluate overhead/false positives).

The extracted statistical feature vectors will be fed into a deep neural network, allowing it to predict the exact state of a live network environment and classify the underlying defense logic autonomously.

---

## 📚 References
1. Baiad, Raghad, et al. *"Cooperative cross layer detection for blackhole attack in VANET-OLSR."* 2014 International Wireless Communications and Mobile Computing Conference (IWCMC). IEEE, 2014.
2. Tan, Shuaishuai, Xiaoping Li, and Qingkuan Dong. *"Trust based routing mechanism for securing OSLR-based MANET."* Ad Hoc Networks 30 (2015): 84-98.
3. Schweitzer, Nadav, et al. *"Achieving manet protection without the use of superfluous fictitious nodes."* Computer Communications 229 (2025): 107978.