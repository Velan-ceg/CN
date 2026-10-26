"""
LANGuard - Network Attack & Traffic Simulation Tool
===================================================
Computer Networks (CN) Educational Test & Demo Suite
---------------------------------------------------
This tool safely generates specific network traffic patterns to test and
demonstrate LANGuard's Intrusion Detection System (IDS) and Statistical
Anomaly Detection Engine during lab evaluations and project presentations.

Simulations Available:
  1. Vertical Port Scan (Probes multiple ports on a target IP)
  2. TCP SYN Flood (Rapid burst of SYN packets without ACK)
  3. ICMP Ping Flood (Rapid burst of ICMP Echo Requests)
  4. Stealth Scans (Xmas Tree, NULL Scan, SYN-FIN scan)
  5. DNS Query Traffic (Generates DNS queries to test Passive DNS snooping)
  6. Statistical Traffic Burst (Triggers Z-score anomaly detector)

Usage (CLI):
  python attack_simulator.py --attack scan --target 127.0.0.1
  python attack_simulator.py --attack syn_flood --target 127.0.0.1
  python attack_simulator.py --attack ping_flood --target 127.0.0.1
  python attack_simulator.py --attack stealth --target 127.0.0.1
  python attack_simulator.py --attack burst --target 127.0.0.1
  python attack_simulator.py --attack dns
  python attack_simulator.py --demo-all
"""

import sys
import time
import socket
import argparse
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, send, sendp, conf


def simulate_vertical_port_scan(target_ip: str = "127.0.0.1", start_port: int = 20, end_port: int = 45) -> str:
    """
    Simulates a Vertical Port Scan (Reconnaissance Phase).
    Sends TCP SYN packets to sequential destination ports on the target host.
    """
    print(f"[*] Starting Vertical Port Scan simulation on {target_ip} (Ports {start_port}-{end_port})...")
    packets_sent = 0
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=target_ip)/TCP(dport=port, sport=44444, flags="S")
        send(pkt, verbose=False)
        packets_sent += 1
        time.sleep(0.04)  # Rapid scan within time window
    msg = f"[+] Vertical Port Scan completed: Sent {packets_sent} TCP SYN packets to {target_ip}."
    print(msg)
    return msg


def simulate_syn_flood(target_ip: str = "127.0.0.1", target_port: int = 80, count: int = 55) -> str:
    """
    Simulates a TCP SYN Flood (Denial of Service - DoS).
    Rapidly transmits SYN packets without completing the 3-way handshake.
    """
    print(f"[*] Starting TCP SYN Flood simulation on {target_ip}:{target_port} ({count} packets)...")
    for i in range(count):
        # Varying source ports to simulate multiple embryonic TCP sessions
        pkt = IP(dst=target_ip)/TCP(dport=target_port, sport=10000 + i, flags="S", seq=1000 + i)
        send(pkt, verbose=False)
        time.sleep(0.02)
    msg = f"[+] SYN Flood completed: Sent {count} SYN packets to {target_ip}:{target_port}."
    print(msg)
    return msg


def simulate_icmp_ping_flood(target_ip: str = "127.0.0.1", count: int = 40) -> str:
    """
    Simulates an ICMP Echo Request Ping Flood.
    Rapidly sends ICMP Type 8 (Echo Request) packets to flood the link.
    """
    print(f"[*] Starting ICMP Ping Flood simulation on {target_ip} ({count} pings)...")
    for i in range(count):
        pkt = IP(dst=target_ip)/ICMP(type=8, id=1234, seq=i)
        send(pkt, verbose=False)
        time.sleep(0.03)
    msg = f"[+] ICMP Ping Flood completed: Sent {count} ICMP Echo Requests to {target_ip}."
    print(msg)
    return msg


def simulate_stealth_scans(target_ip: str = "127.0.0.1", target_port: int = 80) -> str:
    """
    Simulates TCP Stealth Scans violating RFC 793:
      - Xmas Scan: FIN + PSH + URG
      - NULL Scan: Flags = 0x00
      - SYN-FIN Scan: Flags = SYN + FIN
    """
    print(f"[*] Simulating TCP Stealth Scans against {target_ip}:{target_port}...")
    
    # 1. Xmas Tree Scan
    xmas_pkt = IP(dst=target_ip)/TCP(dport=target_port, sport=55555, flags="FPU")
    send(xmas_pkt, verbose=False)
    time.sleep(0.1)

    # 2. NULL Scan
    null_pkt = IP(dst=target_ip)/TCP(dport=target_port, sport=55556, flags="")
    send(null_pkt, verbose=False)
    time.sleep(0.1)

    # 3. Malformed SYN-FIN Scan
    synfin_pkt = IP(dst=target_ip)/TCP(dport=target_port, sport=55557, flags="SF")
    send(synfin_pkt, verbose=False)
    time.sleep(0.1)

    msg = f"[+] Stealth Scans sent: Xmas (FPU), NULL (none), and SYN-FIN to {target_ip}:{target_port}."
    print(msg)
    return msg


def simulate_dns_activity() -> str:
    """
    Triggers legitimate DNS queries to public domains (Google, GitHub, Wikipedia, etc.)
    allowing LANGuard to passively learn IP <-> Domain Name mappings in real time!
    """
    domains = [
        "google.com", "github.com", "wikipedia.org",
        "python.org", "cloudflare.com", "microsoft.com"
    ]
    print("[*] Generating DNS resolution queries to test Passive DNS Snooper...")
    resolved = []
    for d in domains:
        try:
            ip = socket.gethostbyname(d)
            resolved.append(f"{d} -> {ip}")
            time.sleep(0.1)
        except Exception:
            pass
    msg = f"[+] DNS Queries generated for {len(resolved)} domains: {', '.join(domains[:3])}..."
    print(msg)
    return msg


def simulate_traffic_burst(target_ip: str = "127.0.0.1", count: int = 60) -> str:
    """
    Simulates an instantaneous traffic surge to trigger the Statistical Anomaly Engine (Z-Score > 3.0).
    """
    print(f"[*] Generating high-rate traffic burst ({count} packets) to test Statistical Anomaly Engine...")
    for i in range(count):
        pkt = IP(dst=target_ip)/UDP(dport=9999, sport=30000 + i)/("X" * 200)
        send(pkt, verbose=False)
        time.sleep(0.005)  # Extreme rate to cause Z-score outlier
    msg = f"[+] Traffic burst completed: Sent {count} high-speed UDP packets to trigger Anomaly Engine."
    print(msg)
    return msg


def test_website_traffic(domain_or_url: str) -> str:
    """
    Generates real network packets to a specific website (e.g. w3schools.com, google.com).
    Resolves domain, initiates a TLS handshake with Server Name Indication (SNI),
    and forces LANGuard to capture and map the website name in real time!
    """
    import ssl
    from core.dns_resolver import dns_resolver

    # Clean domain input (e.g. 'https://www.w3schools.com/python' -> 'www.w3schools.com')
    clean = domain_or_url.strip().lower()
    for prefix in ["https://", "http://"]:
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    clean = clean.split("/")[0].split(":")[0]

    # Auto-append .com if user just typed 'w3schools'
    if "." not in clean:
        clean = f"{clean}.com"

    try:
        ip = socket.gethostbyname(clean)
        dns_resolver.learn_dns_mapping(ip, clean, is_passive=True)

        # Send live TLS ClientHello with SNI to destination IP
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, 443), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                req = f"GET / HTTP/1.1\r\nHost: {clean}\r\nUser-Agent: LANGuard-Inspector/2.0\r\nConnection: close\r\n\r\n"
                ssock.sendall(req.encode())
                try:
                    _ = ssock.recv(512)
                except Exception:
                    pass

        msg = f"[+] Success! Generated live traffic to '{clean}' (IP: {ip}). Check Tab 1: '{clean}' is now mapped in the Destination column!"
        print(msg)
        return msg
    except Exception as e:
        msg = f"[!] Could not connect to '{clean}': {e}"
        print(msg)
        return msg


def run_full_demo(target_ip: str = "127.0.0.1") -> None:
    """Runs a sequenced demonstration of all attacks with intervals."""
    print("=================================================================")
    print(" LANGuard - Automated Comprehensive Lab Demonstration Mode       ")
    print("=================================================================")
    
    print("\n--- Phase 1: DNS Resolution & Passive Learning ---")
    simulate_dns_activity()
    time.sleep(2)

    print("\n--- Phase 2: Stealth Port Scans (Xmas, NULL, SYN-FIN) ---")
    simulate_stealth_scans(target_ip)
    time.sleep(2)

    print("\n--- Phase 3: Vertical Port Scan ---")
    simulate_vertical_port_scan(target_ip)
    time.sleep(3)

    print("\n--- Phase 4: ICMP Ping Flood ---")
    simulate_icmp_ping_flood(target_ip)
    time.sleep(3)

    print("\n--- Phase 5: TCP SYN Flood (DoS) ---")
    simulate_syn_flood(target_ip)
    time.sleep(3)

    print("\n--- Phase 6: Statistical Traffic Anomaly Burst ---")
    simulate_traffic_burst(target_ip)

    print("\n=================================================================")
    print(" [+] Full Demonstration Finished! Check LANGuard Dashboard Alerts ")
    print("=================================================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LANGuard Network Attack & Traffic Simulation Tool")
    parser.add_argument("--attack", choices=["scan", "syn_flood", "ping_flood", "stealth", "dns", "burst"],
                        help="Specific attack type to simulate")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--demo-all", action="store_true", help="Run full demonstration suite")

    args = parser.parse_args()

    if args.demo_all:
        run_full_demo(args.target)
    elif args.attack == "scan":
        simulate_vertical_port_scan(args.target)
    elif args.attack == "syn_flood":
        simulate_syn_flood(args.target)
    elif args.attack == "ping_flood":
        simulate_icmp_ping_flood(args.target)
    elif args.attack == "stealth":
        simulate_stealth_scans(args.target)
    elif args.attack == "dns":
        simulate_dns_activity()
    elif args.attack == "burst":
        simulate_traffic_burst(args.target)
    else:
        parser.print_help()
