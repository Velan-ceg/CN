"""
LANGuard - Real-Time Packet Sniffing & Processing Engine
========================================================
Computer Networks (CN) Packet Capture & Processing Module
--------------------------------------------------------
Implements asynchronous, multi-threaded packet capture on local network
interfaces using Scapy and Npcap.

Architectural Pipeline:
  [ Network Interface (Wi-Fi / Ethernet) ]
                     │  (Promiscuous Mode / BPF Filter)
                     ▼
             [ Sniffer Thread ]
                     │  (scapy.sniff with store=False)
                     ▼
           [ Concurrent Queue ]
                     │  (Buffered to prevent packet drops)
                     ▼
           [ Processing Worker ]
        ┌────────────┼─────────────┬─────────────┐
        ▼            ▼             ▼             ▼
  [Dissection]   [Passive DNS]  [IDS Engine]  [Anomaly Engine]
        │            │             │             │
        └────────────┴─────────────┴─────────────┘
                     ▼
       [ SQLite Database (WAL Mode) ]
"""

import time
import queue
import threading
from typing import Dict, Any, List, Optional
from scapy.all import sniff, get_working_ifaces, conf, Packet

from config import (
    DEFAULT_INTERFACE,
    PACKET_QUEUE_MAX_SIZE,
    DB_BATCH_INSERT_SIZE,
    DB_FLUSH_INTERVAL
)
from core.protocols import dissect_packet
from core.dns_resolver import dns_resolver
from core.ids_engine import ids_engine
from core.anomaly_engine import anomaly_engine
from core.database import db_manager


class NetworkSniffer:
    """Threaded network packet sniffer and pipeline coordinator."""

    def __init__(self, interface: Optional[str] = DEFAULT_INTERFACE):
        self.interface = interface
        self._packet_queue: queue.Queue = queue.Queue(maxsize=PACKET_QUEUE_MAX_SIZE)
        
        self.is_running = False
        self._sniffer_thread: Optional[threading.Thread] = None
        self._processor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Telemetry counters
        self.total_captured = 0
        self.total_bytes = 0
        self.dropped_packets = 0
        self.start_time: Optional[float] = None

    @staticmethod
    def get_available_interfaces() -> List[Dict[str, str]]:
        """List active network interfaces with IP and friendly descriptions, prioritizing active internet adapters."""
        ifaces = []
        try:
            for iface in get_working_ifaces():
                ip = iface.ip or ""
                # Prioritize active LAN/Wi-Fi adapters with valid routable IP (10., 192.168., 172.)
                score = 0
                if ip and not ip.startswith("169.254") and not ip.startswith("127."):
                    score = 10
                elif ip.startswith("127."):
                    score = 2
                elif ip:
                    score = 1

                ifaces.append({
                    "name": iface.name,
                    "description": iface.description,
                    "ip": ip or "0.0.0.0",
                    "mac": iface.mac or "00:00:00:00:00:00",
                    "score": score
                })
            # Sort highest score first so Wi-Fi / Ethernet is automatically the default
            ifaces.sort(key=lambda x: x["score"], reverse=True)
        except Exception:
            pass
        return ifaces

    def start(self, bpf_filter: str = "") -> bool:
        """Start packet sniffer and processing workers in background threads."""
        if self.is_running:
            return True

        self.is_running = True
        self._stop_event.clear()
        self.start_time = time.time()
        self.total_captured = 0
        self.total_bytes = 0
        self.dropped_packets = 0

        # Start consumer/processor thread first
        self._processor_thread = threading.Thread(
            target=self._process_queue_worker,
            name="LANGuard-Processor",
            daemon=True
        )
        self._processor_thread.start()

        # Start packet sniffer thread
        self._sniffer_thread = threading.Thread(
            target=self._sniff_worker,
            args=(bpf_filter,),
            name="LANGuard-Sniffer",
            daemon=True
        )
        self._sniffer_thread.start()

        return True

    def stop(self) -> None:
        """Gracefully stop capturing and wait for queue drainage."""
        if not self.is_running:
            return

        self.is_running = False
        self._stop_event.set()

        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=1.5)
        if self._processor_thread and self._processor_thread.is_alive():
            self._processor_thread.join(timeout=1.5)

    def _packet_callback(self, packet: Packet) -> None:
        """Callback invoked by Scapy for every captured frame."""
        if not self.is_running:
            return
            
        self.total_captured += 1
        self.total_bytes += len(packet)

        try:
            # Place packet into processing queue non-blocking
            self._packet_queue.put_nowait(packet)
        except queue.Full:
            self.dropped_packets += 1

    def _sniff_worker(self, bpf_filter: str) -> None:
        """Target for sniffer thread executing Scapy sniff."""
        try:
            # If interface is specified, use it; otherwise let Scapy pick default
            kwargs: Dict[str, Any] = {
                "prn": self._packet_callback,
                "store": False,
                "stop_filter": lambda _: self._stop_event.is_set(),
            }
            if self.interface:
                kwargs["iface"] = self.interface
            if bpf_filter:
                kwargs["filter"] = bpf_filter

            sniff(**kwargs)
        except Exception as e:
            print(f"[LANGuard Sniffer Error]: {e}")
        finally:
            self.is_running = False

    def _process_queue_worker(self) -> None:
        """Consumer worker that dissects packets, runs IDS, updates DB & DNS."""
        batch_packets: List[Dict[str, Any]] = []
        host_updates: Dict[str, Dict[str, Any]] = {}
        
        last_flush_time = time.time()
        last_interval_second = int(time.time())
        interval_packets = 0
        interval_bytes = 0
        interval_proto_counts = {"tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "other": 0}

        while self.is_running or not self._packet_queue.empty():
            try:
                packet = self._packet_queue.get(timeout=0.2)
            except queue.Empty:
                packet = None

            now = time.time()
            current_second = int(now)

            # Check if 1-second interval has elapsed for traffic metric recording
            if current_second > last_interval_second:
                metric_record = {
                    "timestamp": float(last_interval_second),
                    "packet_count": interval_packets,
                    "byte_count": interval_bytes,
                    "tcp_count": interval_proto_counts["tcp"],
                    "udp_count": interval_proto_counts["udp"],
                    "icmp_count": interval_proto_counts["icmp"],
                    "arp_count": interval_proto_counts["arp"],
                    "other_count": interval_proto_counts["other"],
                }
                db_manager.insert_traffic_metric(metric_record)
                
                # Check for statistical traffic anomalies
                anomaly_engine.record_interval_metric(
                    timestamp=float(last_interval_second),
                    packet_count=interval_packets,
                    byte_count=interval_bytes
                )

                # Reset 1-second interval accumulators
                last_interval_second = current_second
                interval_packets = 0
                interval_bytes = 0
                interval_proto_counts = {"tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "other": 0}

            if packet is not None:
                # 1. Computer Networks Dissection
                data = dissect_packet(packet)
                if data:
                    src_ip = data.get("src_ip", "N/A")
                    dst_ip = data.get("dst_ip", "N/A")
                    pkt_len = data.get("packet_length", 0)
                    l4 = data.get("layer4_proto", "None")
                    l3 = data.get("layer3_proto", "Other")

                    # Update interval counters
                    interval_packets += 1
                    interval_bytes += pkt_len
                    if l3 == "ARP":
                        interval_proto_counts["arp"] += 1
                    elif l4 == "TCP":
                        interval_proto_counts["tcp"] += 1
                    elif l4 == "UDP":
                        interval_proto_counts["udp"] += 1
                    elif l4 == "ICMP":
                        interval_proto_counts["icmp"] += 1
                    else:
                        interval_proto_counts["other"] += 1

                    # 2. Passive DNS & TLS SNI Snooping (Extracts website names like w3schools.com)
                    for rdata_ip, qname in data.get("dns_answers", []):
                        dns_resolver.learn_dns_mapping(rdata_ip, qname, is_passive=True)

                    # Extract from TLS Client Hello SNI (RFC 6066 - works even when DNS is cached or DoH is used!)
                    if data.get("tls_sni"):
                        dns_resolver.learn_dns_mapping(dst_ip, data["tls_sni"], is_passive=True)
                    elif data.get("http_host"):
                        dns_resolver.learn_dns_mapping(dst_ip, data["http_host"], is_passive=True)

                    # Enrich with domain / hostnames
                    data["src_host"] = dns_resolver.get_display_name(src_ip)
                    data["dst_host"] = dns_resolver.get_display_name(dst_ip)

                    # 3. Rule-Based Intrusion Detection System
                    ids_engine.process_packet(data)

                    # 4. Host Inventory Aggregation
                    if src_ip != "N/A":
                        if src_ip not in host_updates:
                            host_updates[src_ip] = {
                                "ip": src_ip,
                                "mac": data.get("src_mac", ""),
                                "hostname": data["src_host"],
                                "timestamp": now,
                                "sent_packets": 0, "recv_packets": 0,
                                "sent_bytes": 0, "recv_bytes": 0
                            }
                        host_updates[src_ip]["sent_packets"] += 1
                        host_updates[src_ip]["sent_bytes"] += pkt_len
                        host_updates[src_ip]["timestamp"] = now

                    if dst_ip != "N/A":
                        if dst_ip not in host_updates:
                            host_updates[dst_ip] = {
                                "ip": dst_ip,
                                "mac": data.get("dst_mac", ""),
                                "hostname": data["dst_host"],
                                "timestamp": now,
                                "sent_packets": 0, "recv_packets": 0,
                                "sent_bytes": 0, "recv_bytes": 0
                            }
                        host_updates[dst_ip]["recv_packets"] += 1
                        host_updates[dst_ip]["recv_bytes"] += pkt_len
                        host_updates[dst_ip]["timestamp"] = now

                    batch_packets.append(data)

            # Flush to database when batch limit reached or timeout passed
            if (len(batch_packets) >= DB_BATCH_INSERT_SIZE) or (now - last_flush_time > DB_FLUSH_INTERVAL and batch_packets):
                db_manager.insert_packets_batch(batch_packets)
                db_manager.update_host_inventory(list(host_updates.values()))
                batch_packets.clear()
                host_updates.clear()
                last_flush_time = now

        # Final flush on worker exit
        if batch_packets:
            db_manager.insert_packets_batch(batch_packets)
        if host_updates:
            db_manager.update_host_inventory(list(host_updates.values()))


# Global sniffer controller
sniffer = NetworkSniffer()
