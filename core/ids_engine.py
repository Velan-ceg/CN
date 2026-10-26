"""
LANGuard - Rule-Based Intrusion Detection System (IDS) Engine
=============================================================
Computer Networks (CN) Security Detection Module
-------------------------------------------------------------
This module evaluates every parsed network frame against stateful
and signature-based detection rules defined in `config.py`.

Monitored CN Attack Vectors:
1. Transport Layer Port Scanning:
   - Vertical Scan: Single source probing multiple ports on one destination.
   - Horizontal Sweep: Single source probing one service port across multiple hosts.
   - TCP Stealth Scans: Xmas Tree Scan (FIN+PSH+URG), NULL Scan (No flags), SYN+FIN Scan.
2. Denial-of-Service (DoS) / Flooding:
   - TCP SYN Flood (RFC 793 half-open queue exhaustion).
   - ICMP Ping Flood (RFC 792 Echo Request bandwidth exhaustion).
   - UDP High-Rate Flood (RFC 768 port exhaustion).
3. Data Link Layer (LAN) Attacks:
   - ARP Cache Poisoning / Spoofing (RFC 826 IP-MAC mapping conflict / MitM).
4. Application Layer Security Policies:
   - Detection of unencrypted cleartext credentials (Telnet 23, FTP 21).
"""

import time
import threading
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Set, Tuple

from config import IDS_RULES
from core.database import db_manager
from core.dns_resolver import dns_resolver


class RuleBasedIDSEngine:
    """Stateful Rule-Based Intrusion Detection Engine."""

    def __init__(self):
        self._lock = threading.Lock()
        
        # Sliding-window trackers for rate-based analysis:
        # Structure: src_ip -> deque of (timestamp, dst_port, dst_ip)
        self._tcp_syn_history: Dict[str, deque] = defaultdict(deque)
        self._icmp_echo_history: Dict[str, deque] = defaultdict(deque)
        self._udp_history: Dict[str, deque] = defaultdict(deque)
        
        # Port scan trackers:
        # (src_ip, dst_ip) -> deque of (timestamp, dst_port)
        self._vertical_scan_tracker: Dict[Tuple[str, str], deque] = defaultdict(deque)
        # (src_ip, dst_port) -> deque of (timestamp, dst_ip)
        self._horizontal_scan_tracker: Dict[Tuple[str, int], deque] = defaultdict(deque)
        
        # ARP IP-to-MAC mapping table for ARP Poisoning detection
        # ip -> (mac_address, first_seen_timestamp)
        self._arp_table: Dict[str, Tuple[str, float]] = {}
        
        # Alert cooldown cache to prevent log flooding (signature_key -> last_alert_time)
        self._alert_cooldowns: Dict[str, float] = {}
        self.cooldown_period = 4.0  # seconds between repeated alerts for identical event

    def process_packet(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate a single dissected packet against all IDS rules.
        Returns a list of generated alert dictionaries (if any).
        """
        alerts: List[Dict[str, Any]] = []
        now = packet_data.get("timestamp", time.time())
        src_ip = packet_data.get("src_ip", "N/A")
        dst_ip = packet_data.get("dst_ip", "N/A")
        src_port = packet_data.get("src_port")
        dst_port = packet_data.get("dst_port")
        l3_proto = packet_data.get("layer3_proto")
        l4_proto = packet_data.get("layer4_proto")
        flag_map = packet_data.get("tcp_flag_map", {})
        
        # Skip loopback non-threatening internal noise unless targeted
        is_loopback = (src_ip == "127.0.0.1" and dst_ip == "127.0.0.1")

        with self._lock:
            # -------------------------------------------------------------
            # RULE 1: TCP STEALTH SCANS (Xmas, NULL, SYN-FIN)
            # -------------------------------------------------------------
            if l4_proto == "TCP":
                # 1a. Xmas Tree Scan: FIN + PSH + URG simultaneously set
                if IDS_RULES.get("DETECT_XMAS_SCAN"):
                    if flag_map.get("FIN") and flag_map.get("PSH") and flag_map.get("URG"):
                        alert = self._create_alert(
                            severity="HIGH",
                            alert_type="Stealth Port Scan (Xmas Tree)",
                            src_ip=src_ip, dst_ip=dst_ip,
                            signature="IDS-XMAS-03",
                            description=f"TCP Xmas Scan detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}. "
                                        f"Flags [FIN, PSH, URG] are set, violating standard TCP RFC 793 state machines.",
                            mitigation="Drop packets with invalid flag combinations at border firewall; block source IP."
                        )
                        if alert: alerts.append(alert)

                # 1b. NULL Scan: No TCP flags set (Flags == 0x00)
                if IDS_RULES.get("DETECT_NULL_SCAN"):
                    if flag_map and not any(flag_map.values()):
                        alert = self._create_alert(
                            severity="MEDIUM",
                            alert_type="Stealth Port Scan (NULL Scan)",
                            src_ip=src_ip, dst_ip=dst_ip,
                            signature="IDS-NULL-04",
                            description=f"TCP NULL Scan detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}. "
                                        f"No control flags are set, an indicator of stealth reconnaissance.",
                            mitigation="Configure firewall to reject TCP packets with flag sequence 0x00."
                        )
                        if alert: alerts.append(alert)

                # 1c. SYN-FIN Scan: Both SYN and FIN are set simultaneously
                if IDS_RULES.get("DETECT_SYN_FIN_SCAN"):
                    if flag_map.get("SYN") and flag_map.get("FIN"):
                        alert = self._create_alert(
                            severity="HIGH",
                            alert_type="Malformed TCP State (SYN-FIN Scan)",
                            src_ip=src_ip, dst_ip=dst_ip,
                            signature="IDS-SYNFIN-05",
                            description=f"Illegal TCP state from {src_ip} -> {dst_ip}. "
                                        f"Both SYN (open) and FIN (close) bits set simultaneously.",
                            mitigation="Enforce strict stateful packet inspection (SPI) at firewall."
                        )
                        if alert: alerts.append(alert)

            # -------------------------------------------------------------
            # RULE 2: VERTICAL PORT SCANNING
            # -------------------------------------------------------------
            # Probing multiple destination ports on a single host
            if l4_proto in ("TCP", "UDP") and dst_port is not None and src_ip != "N/A" and dst_ip != "N/A":
                # We specifically inspect TCP SYN packets or UDP connection attempts
                is_scan_candidate = (l4_proto == "TCP" and flag_map.get("SYN") and not flag_map.get("ACK")) or (l4_proto == "UDP")
                if is_scan_candidate:
                    key = (src_ip, dst_ip)
                    v_history = self._vertical_scan_tracker[key]
                    v_history.append((now, dst_port))
                    
                    # Evict entries older than window
                    window = IDS_RULES.get("PORT_SCAN_WINDOW_SECONDS", 10.0)
                    while v_history and now - v_history[0][0] > window:
                        v_history.popleft()
                        
                    unique_ports = {entry[1] for entry in v_history}
                    thresh = IDS_RULES.get("PORT_SCAN_VERTICAL_THRESHOLD", 15)
                    if len(unique_ports) >= thresh:
                        alert = self._create_alert(
                            severity="HIGH",
                            alert_type="Vertical Port Scan",
                            src_ip=src_ip, dst_ip=dst_ip,
                            signature="IDS-SCAN-01",
                            description=f"Host {src_ip} probed {len(unique_ports)} distinct ports on {dst_ip} "
                                        f"within {window:.1f}s (Threshold: {thresh}). Example ports: {sorted(list(unique_ports))[:6]}...",
                            mitigation="Block scanner source IP using iptables/Firewall; hide internal topology using port knocking or honey-ports."
                        )
                        if alert: alerts.append(alert)

            # -------------------------------------------------------------
            # RULE 3: HORIZONTAL PORT SWEEP
            # -------------------------------------------------------------
            # Probing the same destination port across multiple hosts on the network
            if l4_proto in ("TCP", "UDP") and dst_port is not None and src_ip != "N/A" and dst_ip != "N/A":
                is_scan_candidate = (l4_proto == "TCP" and flag_map.get("SYN") and not flag_map.get("ACK")) or (l4_proto == "UDP")
                if is_scan_candidate:
                    h_key = (src_ip, dst_port)
                    h_history = self._horizontal_scan_tracker[h_key]
                    h_history.append((now, dst_ip))
                    
                    window = IDS_RULES.get("PORT_SCAN_WINDOW_SECONDS", 10.0)
                    while h_history and now - h_history[0][0] > window:
                        h_history.popleft()
                        
                    unique_targets = {entry[1] for entry in h_history}
                    thresh = IDS_RULES.get("PORT_SCAN_HORIZONTAL_THRESHOLD", 10)
                    if len(unique_targets) >= thresh:
                        alert = self._create_alert(
                            severity="HIGH",
                            alert_type="Horizontal Network Sweep",
                            src_ip=src_ip, dst_ip=dst_ip,
                            signature="IDS-SWEEP-02",
                            description=f"Host {src_ip} sweeping port {dst_port} across {len(unique_targets)} "
                                        f"hosts within {window:.1f}s (Threshold: {thresh}).",
                            mitigation="Isolate scanning machine from LAN; apply subnet ACLs to restrict lateral traversal."
                        )
                        if alert: alerts.append(alert)

            # -------------------------------------------------------------
            # RULE 4: TCP SYN FLOOD (Denial of Service - DoS)
            # -------------------------------------------------------------
            if l4_proto == "TCP" and flag_map.get("SYN") and not flag_map.get("ACK"):
                syn_q = self._tcp_syn_history[src_ip]
                syn_q.append(now)
                
                win = IDS_RULES.get("SYN_FLOOD_WINDOW_SECONDS", 5.0)
                while syn_q and now - syn_q[0] > win:
                    syn_q.popleft()
                    
                thresh = IDS_RULES.get("SYN_FLOOD_THRESHOLD", 40)
                if len(syn_q) >= thresh:
                    alert = self._create_alert(
                        severity="CRITICAL",
                        alert_type="TCP SYN Flood (DoS)",
                        src_ip=src_ip, dst_ip=dst_ip,
                        signature="IDS-DOS-SYN-06",
                        description=f"SYN Flood DoS attack detected from {src_ip}: {len(syn_q)} TCP SYN "
                                    f"packets in {win:.1f}s without connection completion (Threshold: {thresh}).",
                        mitigation="Enable SYN Cookies (sysctl -w net.ipv4.tcp_syncookies=1); throttle embryonic connections."
                    )
                    if alert: alerts.append(alert)

            # -------------------------------------------------------------
            # RULE 5: ICMP PING FLOOD (Ping of Death / Flood)
            # -------------------------------------------------------------
            if l4_proto == "ICMP" and packet_data.get("icmp_type") == 8:  # 8 = Echo Request
                icmp_q = self._icmp_echo_history[src_ip]
                icmp_q.append(now)
                
                win = IDS_RULES.get("ICMP_FLOOD_WINDOW_SECONDS", 5.0)
                while icmp_q and now - icmp_q[0] > win:
                    icmp_q.popleft()
                    
                thresh = IDS_RULES.get("ICMP_FLOOD_THRESHOLD", 30)
                if len(icmp_q) >= thresh:
                    alert = self._create_alert(
                        severity="HIGH",
                        alert_type="ICMP Ping Flood (DoS)",
                        src_ip=src_ip, dst_ip=dst_ip,
                        signature="IDS-DOS-ICMP-07",
                        description=f"ICMP Echo Request flooding detected from {src_ip}: "
                                    f"{len(icmp_q)} ping packets in {win:.1f}s (Threshold: {thresh}).",
                        mitigation="Rate-limit ICMP Echo packets at the firewall or router interface; disable ICMP replies if unnecessary."
                    )
                    if alert: alerts.append(alert)

            # -------------------------------------------------------------
            # RULE 6: UDP FLOOD ATTACK
            # -------------------------------------------------------------
            if l4_proto == "UDP" and dst_port not in (53, 67, 68, 123, 5353):  # Ignore normal DNS/DHCP/NTP/mDNS
                udp_q = self._udp_history[src_ip]
                udp_q.append(now)
                
                win = IDS_RULES.get("UDP_FLOOD_WINDOW_SECONDS", 5.0)
                while udp_q and now - udp_q[0] > win:
                    udp_q.popleft()
                    
                thresh = IDS_RULES.get("UDP_FLOOD_THRESHOLD", 60)
                if len(udp_q) >= thresh:
                    alert = self._create_alert(
                        severity="HIGH",
                        alert_type="UDP Packet Flood (DoS)",
                        src_ip=src_ip, dst_ip=dst_ip,
                        signature="IDS-DOS-UDP-08",
                        description=f"High-rate UDP flooding from {src_ip}: {len(udp_q)} datagrams "
                                    f"in {win:.1f}s targeting unreserved ports.",
                        mitigation="Apply UDP policing and per-IP rate limiting on switch ports."
                    )
                    if alert: alerts.append(alert)

            # -------------------------------------------------------------
            # RULE 7: ARP CACHE POISONING / SPOOFING (Layer 2 MitM)
            # -------------------------------------------------------------
            if l3_proto == "ARP" and IDS_RULES.get("DETECT_ARP_SPOOF"):
                arp_op = packet_data.get("arp_opcode")
                src_mac = packet_data.get("src_mac")
                # When a host replies or sends ARP (opcode 2 = reply, opcode 1 = request)
                if src_ip and src_mac and src_ip != "0.0.0.0":
                    if src_ip in self._arp_table:
                        recorded_mac, recorded_time = self._arp_table[src_ip]
                        if recorded_mac.lower() != src_mac.lower():
                            alert = self._create_alert(
                                severity="CRITICAL",
                                alert_type="ARP Spoofing / Cache Poisoning",
                                src_ip=src_ip, dst_ip=dst_ip,
                                signature="IDS-LAN-ARP-09",
                                description=f"Conflicting MAC address for IP {src_ip}! "
                                            f"Known MAC: {recorded_mac}, New Claimed MAC: {src_mac}. "
                                            f"Potential Man-in-the-Middle (MitM) ARP Poisoning attack on LAN.",
                                mitigation="Enable Dynamic ARP Inspection (DAI) on switch; implement static ARP tables or 802.1X NAC."
                            )
                            if alert: alerts.append(alert)
                    else:
                        self._arp_table[src_ip] = (src_mac, now)

            # -------------------------------------------------------------
            # RULE 8: INSECURE CLEARTEXT SERVICES (Policy Violation)
            # -------------------------------------------------------------
            if IDS_RULES.get("DETECT_CLEARTEXT_SERVICES") and dst_port in (21, 23):
                service_name = "Telnet" if dst_port == 23 else "FTP"
                alert = self._create_alert(
                    severity="LOW",
                    alert_type="Insecure Cleartext Protocol Used",
                    src_ip=src_ip, dst_ip=dst_ip,
                    signature="IDS-POLICY-CLEARTEXT-10",
                    description=f"Detected unencrypted {service_name} traffic to {dst_ip}:{dst_port}. "
                                f"Credentials and commands pass across the LAN in cleartext.",
                    mitigation=f"Migrate immediately to secure alternatives: use SSH instead of Telnet, and SFTP instead of FTP."
                )
                if alert: alerts.append(alert)

        # Dispatch generated alerts to SQLite database
        for alert in alerts:
            db_manager.insert_alert(alert)

        return alerts

    def _create_alert(self, severity: str, alert_type: str, src_ip: str, dst_ip: str,
                      signature: str, description: str, mitigation: str) -> Optional[Dict[str, Any]]:
        """Constructs an alert dictionary if not currently within the alert cooldown."""
        cooldown_key = f"{signature}:{src_ip}:{dst_ip}"
        now = time.time()
        
        last_alert = self._alert_cooldowns.get(cooldown_key, 0.0)
        if now - last_alert < self.cooldown_period:
            return None  # Suppress duplicate alerts during active flood
            
        self._alert_cooldowns[cooldown_key] = now
        
        # Enrich with resolved domain names / hostnames
        src_host = dns_resolver.get_display_name(src_ip)
        dst_host = dns_resolver.get_display_name(dst_ip)
        
        return {
            "timestamp": now,
            "severity": severity,
            "alert_type": alert_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_host": src_host,
            "dst_host": dst_host,
            "signature": signature,
            "description": description,
            "mitigation": mitigation
        }


# Global singleton IDS engine instance
ids_engine = RuleBasedIDSEngine()
