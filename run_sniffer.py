"""
LANGuard - Standalone Network Sniffer Console Runner
===================================================
Computer Networks (CN) Headless Capture CLI
---------------------------------------------------
Runs the packet sniffer and IDS engine directly in terminal mode,
writing all events and metrics to SQLite database (`languard.db`).

Usage:
  python run_sniffer.py
  python run_sniffer.py --interface "Wi-Fi"
  python run_sniffer.py --filter "tcp or udp"
"""

import sys
import time
import argparse
from core.sniffer import sniffer
from core.database import db_manager
from core.utils import format_bytes, format_bps, format_timestamp


def main():
    parser = argparse.ArgumentParser(description="LANGuard Headless Packet Sniffer")
    parser.add_argument("--interface", "-i", default=None, help="Network interface name (e.g. Wi-Fi, Ethernet)")
    parser.add_argument("--filter", "-f", default="", help="BPF packet capture filter (e.g. 'ip', 'tcp or udp')")
    args = parser.parse_args()

    print("==================================================================")
    print(" LANGuard - Real-Time Network Sniffer & Intrusion Detection System")
    print("==================================================================")
    
    # List available interfaces
    ifaces = sniffer.get_available_interfaces()
    print("\n[*] Detected Working Network Interfaces:")
    for idx, iface in enumerate(ifaces):
        print(f"  [{idx}] {iface['name']} | IP: {iface['ip']} | {iface['description']}")

    target_iface = args.interface
    if target_iface:
        print(f"\n[*] Binding to specified interface: '{target_iface}'")
        sniffer.interface = target_iface
    else:
        print(f"\n[*] Auto-binding to default active interface...")

    if args.filter:
        print(f"[*] Applying BPF Filter: '{args.filter}'")

    print("\n[+] Starting packet capture worker threads...")
    sniffer.start(bpf_filter=args.filter)
    print("[+] LANGuard is now sniffing and monitoring live traffic.")
    print("[!] Press Ctrl+C to stop capture.\n")

    try:
        last_captured = 0
        last_bytes = 0
        while sniffer.is_running:
            time.sleep(2.0)
            stats = db_manager.get_summary_stats()
            delta_pkts = sniffer.total_captured - last_captured
            delta_bytes = sniffer.total_bytes - last_bytes
            pps = delta_pkts / 2.0
            bps = (delta_bytes / 2.0) * 8
            
            print(f"[{format_timestamp(time.time())}] Packets Captured: {sniffer.total_captured:,} | "
                  f"Throughput: {format_bps(delta_bytes/2.0)} ({pps:.1f} pps) | "
                  f"DB Packets: {stats['total_packets']:,} | Alerts: {stats['total_alerts']} | "
                  f"Active Hosts: {stats['total_hosts']}")
            
            last_captured = sniffer.total_captured
            last_bytes = sniffer.total_bytes

    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer gracefully...")
        sniffer.stop()
        print("[+] Sniffer stopped. All packets saved to languard.db.")


if __name__ == "__main__":
    main()
