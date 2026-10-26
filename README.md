# 🛡️ LANGuard – Real-Time LAN Network Intrusion Detection & Traffic Anomaly Monitoring System

LANGuard is a real-time network monitoring and intrusion detection system designed to analyze Local Area Network (LAN) traffic, extract multi-layer protocol metadata, detect malicious activity using both rule-based signatures and statistical anomaly algorithms, and visualize network telemetry on an interactive web dashboard.

Built using **Python**, **Scapy**, **Streamlit**, and **SQLite**, LANGuard applies foundational **Computer Networks (CN)** principles across the OSI and TCP/IP protocol suites without requiring expensive dedicated hardware.

---

## 🌟 Key Features

1. **Multi-Layer Protocol Dissection (OSI Layers 2 – 7)**
   - **Layer 2 (Data Link):** Ethernet II frame parsing, MAC address mapping, ARP resolution (RFC 826).
   - **Layer 3 (Network):** IPv4 header inspection (TTL, Protocol numbers 1/6/17, IP addresses), IPv6, ICMP.
   - **Layer 4 (Transport):** TCP flag decoding (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), sequence/acknowledgment numbers, UDP datagrams, port resolution (0–65535).
   - **Layer 7 (Application):** DNS query and answer parsing (RFC 1035), HTTP, Telnet, FTP, DHCP, NTP.

2. **Hybrid Passive & Active Reverse DNS Resolution**
   - Automatically resolves raw IP addresses to real domain names (e.g. `142.250.x.x` $\rightarrow$ `google.com`).
   - Uses **Passive DNS Snooping** by inspecting live DNS Type 1 (A Record) responses with zero overhead, supplemented by an asynchronous background reverse PTR worker pool.

3. **Rule-Based Intrusion Detection System (IDS)**
   - **Vertical Port Scans:** Probing multiple ports on a single target host.
   - **Horizontal Port Sweeps:** Probing a single service port across multiple network endpoints.
   - **TCP SYN Flood (DoS):** Detection of embryonic half-open TCP connections exceeding thresholds.
   - **ICMP Ping Flood:** Rapid bursts of ICMP Echo Requests (Type 8).
   - **Stealth Scans:** Xmas Tree (`FIN+PSH+URG`), NULL Scan (`0x00`), and illegal `SYN+FIN` state violations.
   - **ARP Poisoning / Spoofing:** Detecting conflicting IP-to-MAC associations (Layer 2 MitM).
   - **Cleartext Protocol Warnings:** Flags unencrypted protocols carrying plaintext credentials (Telnet 23, FTP 21).

4. **Statistical Traffic Anomaly Detection**
   - Dynamically calculates the moving baseline average ($\mu$) and sample standard deviation ($\sigma$) of packet rates and byte throughput.
   - Computes real-time **Z-Scores** ($Z = \frac{x - \mu}{\sigma}$); triggers alerts when traffic spikes exceed the $3\sigma$ threshold (99.7% confidence interval) or exceed burst multipliers.

5. **Interactive Real-Time Dashboard (Streamlit & Plotly)**
   - **Live Packet Stream:** Live auto-refreshing table with protocol filters and header inspector.
   - **Protocol & Traffic Analytics:** Donut charts for protocol distribution, packet size histograms, and time-series throughput charts.
   - **IDS Alert Center:** Categorized alerts by severity (CRITICAL, HIGH, MEDIUM, LOW) with defensive mitigation strategies.
   - **Anomaly Monitor:** Dynamic Gaussian curve showing baseline mean vs. observed traffic.
   - **LAN Host Inventory:** Top Talkers bar chart and discovered endpoint matrix.
   - **Built-in Attack Simulator:** Single-click benign traffic generators for live lab demonstrations.
   - **Computer Networks Viva Guide:** Built-in tab explaining all networking code for oral examinations.

6. **Thread-Safe SQLite Database Storage**
   - Stores packets, security alerts, host states, and aggregated time-series metrics.
   - Runs with Write-Ahead Logging (`WAL` mode) for concurrent sniffer writes and Streamlit dashboard reads.

---

## 🏗️ Architecture Diagram

```
                        [ Network Interface (Wi-Fi / Ethernet) ]
                                          │
                                 (Promiscuous Mode)
                                          ▼
                                  [ Scapy Sniffer ]
                                          │
                                          ▼
                                [ Concurrent Queue ]
                                          │
                                          ▼
                             [ Packet Dissector Worker ]
             ┌────────────────────────────┼───────────────────────────┐
             ▼                            ▼                           ▼
  [ Protocol Decoders ]          [ Passive DNS Snooper ]      [ Host Profiler ]
  - Layer 2: Ethernet / ARP      - Extract DNS A Records      - IP-to-MAC Map
  - Layer 3: IPv4 / ICMP         - Background PTR Worker      - Byte / Pkt Counters
  - Layer 4: TCP / UDP           - Domain <-> IP Mapping      - Active Status
             │                            │                           │
             └────────────────────────────┼───────────────────────────┘
                                          │
                                          ▼
                   ┌─────────────────────────────────────────┐
                   │        Security Analysis Engines        │
                   ├────────────────────┬────────────────────┤
                   │ Rule-Based IDS     │ Statistical        │
                   │ - Port Scans       │ Anomaly Engine     │
                   │ - SYN Flood        │ - Moving Avg (μ)   │
                   │ - ICMP Ping Flood  │ - StdDev (σ)       │
                   │ - Stealth Scans    │ - Z-Score > 3.0    │
                   │ - ARP Spoofing     │ - Burst Ratios     │
                   └────────────────────┴────────────────────┘
                                          │
                                          ▼
                            [ SQLite Database (WAL) ]
                                          │
                                          ▼
                       [ Streamlit Interactive Dashboard ]
```

---

## 📂 Project Structure

```
d:\Educational Contents\CN\
├── config.py                 # System thresholds, DB path, and capture settings
├── core\
│   ├── __init__.py           # Package exports
│   ├── protocols.py          # Layer 2-7 Protocol Dissectors, TCP flags, Port constants
│   ├── dns_resolver.py       # Hybrid Passive/Active Reverse DNS Resolution Engine
│   ├── sniffer.py            # Asynchronous multi-threaded packet capture coordinator
│   ├── ids_engine.py         # Rule-based Intrusion Detection System
│   ├── anomaly_engine.py     # Statistical Moving Average & Z-Score Anomaly Detector
│   ├── database.py           # Thread-safe SQLite manager (WAL mode)
│   └── utils.py              # Bandwidth formatters, IP classification & styling
├── attack_simulator.py       # Benign network attack generator for live demos
├── run_sniffer.py            # Standalone headless sniffer console application
├── app.py                    # Main Streamlit web dashboard
├── CN_EXPLANATION_GUIDE.md   # Detailed Viva / Lab exam explanation guide for Mam
├── requirements.txt          # Python library dependencies
└── README.md                 # Project documentation
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+
- **Npcap** (Windows packet capture driver). If not installed, download from [npcap.com](https://npcap.com/) (installed with *"WinPcap API-compatible mode"* checked).

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Dashboard
```bash
streamlit run app.py
```
The browser will automatically open at `http://localhost:8501`.

### 4. Start Packet Capture
- In the sidebar on the left, select your network adapter (e.g., `Wi-Fi` or `Loopback Pseudo-Interface 1`).
- Click **▶️ Start Capture**.
- Live packets and traffic statistics will appear immediately.

---

## 🧪 Testing Attacks with the Simulator

LANGuard includes a built-in attack simulator (`attack_simulator.py`) that can be executed directly from **Tab 6 (Attack & Demo Simulator)** in the web UI, or from the terminal:

```bash
# 1. Simulate a Vertical Port Scan (Ports 20 - 45)
python attack_simulator.py --attack scan --target 127.0.0.1

# 2. Simulate a TCP SYN Flood (DoS)
python attack_simulator.py --attack syn_flood --target 127.0.0.1

# 3. Simulate an ICMP Ping Flood
python attack_simulator.py --attack ping_flood --target 127.0.0.1

# 4. Simulate Stealth Scans (Xmas Tree, NULL Scan, SYN-FIN)
python attack_simulator.py --attack stealth --target 127.0.0.1

# 5. Generate DNS traffic for Passive Domain Snooping
python attack_simulator.py --attack dns

# 6. Simulate a High-Rate Traffic Burst (Z-score spike)
python attack_simulator.py --attack burst --target 127.0.0.1

# 7. Run the Full Automated Demonstration Suite
python attack_simulator.py --demo-all
```

---

## 🎓 Viva & Computer Networks Code Explanation

If your teacher or examiner (**"Mam"**) asks you to open and explain the Computer Networks code:
- Open [`CN_EXPLANATION_GUIDE.md`](CN_EXPLANATION_GUIDE.md) in your editor.
- Or open **Tab 7 ("🎓 Computer Networks Code & Viva Guide")** directly in the running web application!
- It gives you the exact line-by-line explanation for:
  - How TCP 3-way handshake is tracked via flags (`SYN`, `ACK`).
  - How port numbers and protocol fields demultiplex incoming frames.
  - How ARP spoofing is detected at Layer 2.
  - How DNS A-records are snooped at Layer 7.
  - How Z-scores statistically model traffic bursts.
