"""
LANGuard - Configuration & Detection Thresholds
===============================================
Central configuration parameters for network packet capture,
rule-based IDS thresholds, statistical anomaly detection,
reverse DNS lookup, and SQLite database storage.
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = os.path.join(BASE_DIR, "languard.db")

# Sniffer & Network Interface Settings
DEFAULT_INTERFACE = None          # None = Scapy auto-detects default working interface
SNIFFER_PROMISCUOUS = True        # Promiscuous mode to capture all LAN packets
SNIFFER_BUFFER_SIZE = 10000       # Maximum packets in memory ring-buffer
PACKET_QUEUE_MAX_SIZE = 5000      # Queue size between sniffer and analyzer thread
DB_BATCH_INSERT_SIZE = 50         # Batch size for bulk SQLite writes
DB_FLUSH_INTERVAL = 1.0           # Seconds before flushing pending packets to SQLite

# DNS Resolution Settings
DNS_CACHE_TTL = 3600              # Cache DNS entries for 1 hour
DNS_REVERSE_LOOKUP_TIMEOUT = 1.5  # Timeout in seconds for active PTR lookups
DNS_MAX_WORKER_THREADS = 4        # Concurrent threads for reverse DNS resolution

# Rule-Based Intrusion Detection System (IDS) Thresholds
IDS_RULES = {
    # Port Scan Detection
    "PORT_SCAN_VERTICAL_THRESHOLD": 15,      # >15 distinct ports on 1 target within time window
    "PORT_SCAN_HORIZONTAL_THRESHOLD": 10,    # >10 distinct target hosts on same port within window
    "PORT_SCAN_WINDOW_SECONDS": 10.0,        # Time window for port scan correlation
    
    # DoS / Flooding Detection
    "SYN_FLOOD_THRESHOLD": 40,               # >40 TCP SYN packets without completion in window
    "SYN_FLOOD_WINDOW_SECONDS": 5.0,         # Window for SYN flood
    "ICMP_FLOOD_THRESHOLD": 30,              # >30 ICMP Echo Requests in window
    "ICMP_FLOOD_WINDOW_SECONDS": 5.0,        # Window for Ping flood
    "UDP_FLOOD_THRESHOLD": 60,               # >60 UDP packets to closed/uncommon ports in window
    "UDP_FLOOD_WINDOW_SECONDS": 5.0,         # Window for UDP flood
    
    # TCP Anomaly / Stealth Scans
    "DETECT_XMAS_SCAN": True,                # Alert if FIN, PSH, URG flags are simultaneously set
    "DETECT_NULL_SCAN": True,                # Alert if TCP flags are completely empty (0x00)
    "DETECT_SYN_FIN_SCAN": True,             # Alert if SYN and FIN are set simultaneously (invalid state)
    
    # Local Area Network (LAN) Specific Attacks
    "DETECT_ARP_SPOOF": True,                # Detect conflicting IP-to-MAC associations (ARP Cache Poisoning)
    "DETECT_CLEARTEXT_SERVICES": True,       # Flag insecure cleartext protocols (Telnet=23, FTP=21, HTTP=80)
}

# Statistical Anomaly Detection Thresholds (Z-Score & Moving Baseline)
ANOMALY_CONFIG = {
    "BASELINE_WINDOW_SIZE": 30,              # Number of historical 1-second intervals for baseline
    "Z_SCORE_THRESHOLD": 3.0,                # Number of standard deviations above mean to trigger anomaly
    "MIN_SAMPLES_FOR_BASELINE": 10,          # Minimum samples required before triggering anomalies
    "PACKET_RATE_BURST_RATIO": 3.5,          # Instantaneous rate > 3.5x average triggers burst anomaly
    "BYTE_RATE_BURST_RATIO": 4.0,            # Instantaneous byte volume > 4x average triggers burst anomaly
}

# UI Dashboard Settings
DASHBOARD_REFRESH_RATE = 2                   # Seconds between auto-refreshes in Streamlit
TOP_TALKERS_LIMIT = 10                       # Number of top IP hosts to display
RECENT_PACKETS_DISPLAY_LIMIT = 100           # Number of live packets in the table
RECENT_ALERTS_DISPLAY_LIMIT = 50             # Number of recent alerts to show
