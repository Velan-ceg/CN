"""
LANGuard - Network Protocol Dissectors & Constants
===================================================
Computer Networks (CN) Core Implementation Module
---------------------------------------------------
This module provides detailed decoding, parsing, and classification of
the TCP/IP Protocol Stack across the OSI model layers:

  Layer 2 (Data Link Layer):   Ethernet II Frames, MAC Addressing, ARP (RFC 826)
  Layer 3 (Network Layer):     IPv4 (RFC 791), IPv6 (RFC 8200), ICMP (RFC 792)
  Layer 4 (Transport Layer):   TCP (RFC 793), UDP (RFC 768)
  Layer 7 (Application Layer): DNS (RFC 1035), HTTP, DHCP, etc.

Key CN Concepts Demonstrated:
1. Packet Header Dissection (Parsing bitfields, offsets, and checksums)
2. TCP Flag Decoding (SYN, ACK, FIN, RST, PSH, URG) for 3-way handshake analysis
3. EtherType and IP Protocol Number multiplexing/demultiplexing
4. Port addressing and Application-layer protocol identification
"""

from typing import Dict, Any, Optional, Tuple, List
from scapy.all import Packet, Ether, IP, IPv6, ARP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw

# ============================================================================
# LAYER 2: DATA LINK LAYER CONSTANTS (IEEE 802.3 / Ethernet II)
# ============================================================================
# EtherType values identify the protocol encapsulated inside the Ethernet frame payload.
ETHER_TYPE_IPV4 = 0x0800  # Internet Protocol Version 4
ETHER_TYPE_ARP  = 0x0806  # Address Resolution Protocol (RFC 826)
ETHER_TYPE_IPV6 = 0x86DD  # Internet Protocol Version 6

ETHER_TYPE_NAMES = {
    ETHER_TYPE_IPV4: "IPv4",
    ETHER_TYPE_ARP:  "ARP",
    ETHER_TYPE_IPV6: "IPv6",
}

# ============================================================================
# LAYER 3: NETWORK LAYER PROTOCOL NUMBERS (Assigned by IANA)
# ============================================================================
# In the IPv4 header, the 8-bit 'Protocol' field defines the Layer 4 transport protocol.
IP_PROTO_ICMP = 1   # Internet Control Message Protocol (RFC 792)
IP_PROTO_IGMP = 2   # Internet Group Management Protocol
IP_PROTO_TCP  = 6   # Transmission Control Protocol (RFC 793)
IP_PROTO_UDP  = 17  # User Datagram Protocol (RFC 768)
IP_PROTO_GRE  = 47  # Generic Routing Encapsulation
IP_PROTO_ESP  = 50  # Encapsulating Security Payload (IPsec)
IP_PROTO_AH   = 51  # Authentication Header (IPsec)

IP_PROTO_NAMES = {
    1:  "ICMP",
    2:  "IGMP",
    6:  "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
}

# ============================================================================
# LAYER 4: TRANSPORT LAYER - TCP CONTROL BITS (FLAGS)
# ============================================================================
# In RFC 793, TCP header bytes 12-13 contain 6 control bits essential for state
# machines (connection establishment, data push, teardown, and reset):
TCP_FLAG_FIN = 0x01  # Finish: No more data from sender (teardown)
TCP_FLAG_SYN = 0x02  # Synchronize: Synchronize sequence numbers (initiate 3-way handshake)
TCP_FLAG_RST = 0x04  # Reset: Abort and reset the connection
TCP_FLAG_PSH = 0x08  # Push: Receiver should pass data to application immediately
TCP_FLAG_ACK = 0x10  # Acknowledgment: Acknowledgment field is significant
TCP_FLAG_URG = 0x20  # Urgent: Urgent pointer field is significant
TCP_FLAG_ECE = 0x40  # ECN-Echo (Explicit Congestion Notification)
TCP_FLAG_CWR = 0x80  # Congestion Window Reduced

# ============================================================================
# LAYER 4: WELL-KNOWN TRANSPORT PORTS (0 - 1023) & REGISTERED PORTS
# ============================================================================
WELL_KNOWN_PORTS: Dict[int, str] = {
    20:   "FTP-DATA",
    21:   "FTP-CONTROL",
    22:   "SSH",
    23:   "TELNET",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP-SERVER",
    68:   "DHCP-CLIENT",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    123:  "NTP",
    137:  "NETBIOS-NS",
    138:  "NETBIOS-DGM",
    139:  "NETBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP-TRAP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    514:  "SYSLOG",
    587:  "SMTP-SUBMISSION",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    3306: "MYSQL",
    3389: "RDP",
    5353: "mDNS",
    5432: "POSTGRESQL",
    6379: "REDIS",
    8000: "HTTP-ALT",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
    9092: "KAFKA",
    27017:"MONGODB",
}

# ============================================================================
# ICMP TYPE CODES (RFC 792)
# ============================================================================
ICMP_TYPES: Dict[int, str] = {
    0:  "Echo Reply (Ping Response)",
    3:  "Destination Unreachable",
    4:  "Source Quench",
    5:  "Redirect",
    8:  "Echo Request (Ping)",
    9:  "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded (TTL expired)",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}


def get_service_name(port: int, default: str = "Unknown") -> str:
    """Resolve transport port number to well-known service name."""
    return WELL_KNOWN_PORTS.get(port, default)


def parse_tcp_flags(flags_val) -> Tuple[str, Dict[str, bool]]:
    """
    Decodes the TCP 8-bit flags field into human-readable flags string
    and a boolean flag dictionary for rule verification.
    
    Example: SYN-ACK returns ('SYN, ACK', {'SYN': True, 'ACK': True, ...})
    """
    flag_int = int(flags_val)
    flag_map = {
        "FIN": bool(flag_int & TCP_FLAG_FIN),
        "SYN": bool(flag_int & TCP_FLAG_SYN),
        "RST": bool(flag_int & TCP_FLAG_RST),
        "PSH": bool(flag_int & TCP_FLAG_PSH),
        "ACK": bool(flag_int & TCP_FLAG_ACK),
        "URG": bool(flag_int & TCP_FLAG_URG),
        "ECE": bool(flag_int & TCP_FLAG_ECE),
        "CWR": bool(flag_int & TCP_FLAG_CWR),
    }
    active_flags = [name for name, is_set in flag_map.items() if is_set]
    flag_str = ", ".join(active_flags) if active_flags else "NONE"
    return flag_str, flag_map


def extract_tls_sni(payload: bytes) -> Optional[str]:
    """
    Extracts the Server Name Indication (SNI) from a TLS Client Hello packet (RFC 6066).
    Enables LANGuard to identify the exact website domain name (e.g. w3schools.com, youtube.com)
    even when DNS-over-HTTPS (DoH) is used or DNS is cached by the operating system!
    """
    if not payload or len(payload) < 44 or payload[0] != 0x16:
        return None
    try:
        # Byte 0: 0x16 (Handshake record)
        # Byte 5: 0x01 (Handshake Type: Client Hello)
        if len(payload) <= 5 or payload[5] != 0x01:
            return None

        # Skip Handshake header (4) + Client Version (2) + Random (32) = 38 bytes
        pos = 5 + 38
        if pos >= len(payload):
            return None

        # Session ID Length
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return None

        # Cipher Suites Length
        cipher_suites_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2 + cipher_suites_len
        if pos + 1 > len(payload):
            return None

        # Compression Methods Length
        comp_methods_len = payload[pos]
        pos += 1 + comp_methods_len
        if pos + 2 > len(payload):
            return None

        # Extensions Length
        ext_total_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        end_ext = min(pos + ext_total_len, len(payload))

        # Walk through extensions looking for Type 0x0000 (Server Name Indication)
        while pos + 4 <= end_ext:
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0:  # Server Name Indication (SNI)
                if pos + 5 <= end_ext:
                    name_type = payload[pos+2]  # 0 = host_name
                    if name_type == 0:
                        name_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                        if pos + 5 + name_len <= end_ext:
                            return payload[pos+5:pos+5+name_len].decode('utf-8', errors='ignore')
            pos += ext_len
    except Exception:
        return None
    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    """Extracts Host: header domain from cleartext HTTP/1.1 request packets."""
    if not payload or len(payload) < 14:
        return None
    try:
        if payload[:3] in (b'GET', b'PUT') or payload[:4] in (b'POST', b'HEAD') or payload[:7] == b'OPTIONS':
            text = payload[:600].decode('latin1', errors='ignore')
            for line in text.split('\r\n'):
                if line.lower().startswith('host:'):
                    return line.split(':', 1)[1].strip()
    except Exception:
        pass
    return None


def dissect_packet(packet: Packet) -> Optional[Dict[str, Any]]:
    """
    Main Computer Networks Dissector:
    Transforms a raw captured frame into a structured dictionary capturing
    every header field across Layers 2, 3, 4, and 7.
    
    Returns None if packet is malformed or unsupported.
    """
    try:
        timestamp = float(packet.time)
        packet_len = len(packet)
        
        # Default Layer 2 extraction
        src_mac = packet.src if hasattr(packet, 'src') else "00:00:00:00:00:00"
        dst_mac = packet.dst if hasattr(packet, 'dst') else "00:00:00:00:00:00"
        ether_type = packet.type if hasattr(packet, 'type') else 0
        
        # Initialize parsed packet structure
        data: Dict[str, Any] = {
            "timestamp": timestamp,
            "packet_length": packet_len,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "ether_type": ether_type,
            "layer3_proto": "Other",
            "layer4_proto": "None",
            "app_proto": "None",
            "src_ip": "N/A",
            "dst_ip": "N/A",
            "src_port": None,
            "dst_port": None,
            "tcp_flags": "",
            "tcp_flag_map": {},
            "tcp_seq": None,
            "tcp_ack": None,
            "tcp_window": None,
            "tcp_dataofs": None,
            "tcp_chksum": None,
            "udp_len": None,
            "udp_chksum": None,
            "ip_ttl": None,
            "ip_id": None,
            "ip_len": None,
            "ip_ihl": None,
            "ip_chksum": None,
            "icmp_type": None,
            "icmp_code": None,
            "icmp_name": None,
            "arp_opcode": None,
            "dns_queries": [],
            "dns_answers": [],
            "payload_len": 0,
            "payload_hex": "",
            "payload_ascii": "",
            "tls_sni": None,
            "http_host": None,
            "summary": packet.summary(),
        }

        # Payload extraction (Application Layer Data)
        if packet.haslayer(Raw):
            load_bytes = bytes(packet[Raw].load)
            data["payload_len"] = len(load_bytes)
            data["payload_hex"] = " ".join(f"{b:02x}" for b in load_bytes[:48])
            data["payload_ascii"] = "".join(chr(b) if 32 <= b <= 126 else "." for b in load_bytes[:64])

            # Passive TLS Server Name Indication (SNI) snooping for HTTPS
            sni = extract_tls_sni(load_bytes)
            if sni:
                data["tls_sni"] = sni
                data["app_proto"] = f"HTTPS: {sni}"

            # Cleartext HTTP Host Header snooping
            http_host = extract_http_host(load_bytes)
            if http_host:
                data["http_host"] = http_host
                data["app_proto"] = f"HTTP: {http_host}"

        # ---------------------------------------------------------
        # Case 1: ARP Packet (Address Resolution Protocol - RFC 826)
        # ---------------------------------------------------------
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]
            data["layer3_proto"] = "ARP"
            data["arp_opcode"] = arp_layer.op  # 1 = who-has (request), 2 = is-at (reply)
            data["src_ip"] = arp_layer.psrc
            data["dst_ip"] = arp_layer.pdst
            data["src_mac"] = arp_layer.hwsrc
            data["dst_mac"] = arp_layer.hwdst
            opcode_str = "ARP Request" if arp_layer.op == 1 else "ARP Reply"
            data["app_proto"] = opcode_str
            return data

        # ---------------------------------------------------------
        # Case 2: IPv4 Packet (Internet Protocol v4 - RFC 791)
        # ---------------------------------------------------------
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            data["layer3_proto"] = "IPv4"
            data["src_ip"] = ip_layer.src
            data["dst_ip"] = ip_layer.dst
            data["ip_ttl"] = ip_layer.ttl
            data["ip_id"] = ip_layer.id
            data["ip_len"] = ip_layer.len
            data["ip_ihl"] = ip_layer.ihl
            data["ip_chksum"] = ip_layer.chksum
            proto_num = ip_layer.proto
            data["layer4_proto"] = IP_PROTO_NAMES.get(proto_num, f"Proto-{proto_num}")
            
            # Sub-case 2a: TCP (Transmission Control Protocol - RFC 793)
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                data["layer4_proto"] = "TCP"
                data["src_port"] = tcp_layer.sport
                data["dst_port"] = tcp_layer.dport
                data["tcp_seq"] = tcp_layer.seq
                data["tcp_ack"] = tcp_layer.ack
                data["tcp_window"] = tcp_layer.window
                data["tcp_dataofs"] = tcp_layer.dataofs
                data["tcp_chksum"] = tcp_layer.chksum
                
                flags_str, flag_map = parse_tcp_flags(tcp_layer.flags)
                data["tcp_flags"] = flags_str
                data["tcp_flag_map"] = flag_map
                
                # Identify Application Layer
                if data["src_port"] in WELL_KNOWN_PORTS:
                    data["app_proto"] = WELL_KNOWN_PORTS[data["src_port"]]
                elif data["dst_port"] in WELL_KNOWN_PORTS:
                    data["app_proto"] = WELL_KNOWN_PORTS[data["dst_port"]]
                else:
                    data["app_proto"] = "TCP-Data"

            # Sub-case 2b: UDP (User Datagram Protocol - RFC 768)
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                data["layer4_proto"] = "UDP"
                data["src_port"] = udp_layer.sport
                data["dst_port"] = udp_layer.dport
                data["udp_len"] = udp_layer.len
                data["udp_chksum"] = udp_layer.chksum
                
                # Check for DNS over UDP
                if packet.haslayer(DNS):
                    data["app_proto"] = "DNS"
                    _extract_dns_records(packet[DNS], data)
                elif data["src_port"] in WELL_KNOWN_PORTS:
                    data["app_proto"] = WELL_KNOWN_PORTS[data["src_port"]]
                elif data["dst_port"] in WELL_KNOWN_PORTS:
                    data["app_proto"] = WELL_KNOWN_PORTS[data["dst_port"]]
                else:
                    data["app_proto"] = "UDP-Data"

            # Sub-case 2c: ICMP (Control Message Protocol - RFC 792)
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                data["layer4_proto"] = "ICMP"
                data["icmp_type"] = icmp_layer.type
                data["icmp_code"] = icmp_layer.code
                data["icmp_name"] = ICMP_TYPES.get(icmp_layer.type, f"ICMP Type {icmp_layer.type}")
                data["app_proto"] = data["icmp_name"]

            return data

        # ---------------------------------------------------------
        # Case 3: IPv6 Packet (RFC 8200)
        # ---------------------------------------------------------
        if packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            data["layer3_proto"] = "IPv6"
            data["src_ip"] = ip6.src
            data["dst_ip"] = ip6.dst
            if packet.haslayer(TCP):
                data["layer4_proto"] = "TCP"
                data["src_port"] = packet[TCP].sport
                data["dst_port"] = packet[TCP].dport
                flags_str, flag_map = parse_tcp_flags(packet[TCP].flags)
                data["tcp_flags"] = flags_str
                data["tcp_flag_map"] = flag_map
            elif packet.haslayer(UDP):
                data["layer4_proto"] = "UDP"
                data["src_port"] = packet[UDP].sport
                data["dst_port"] = packet[UDP].dport
            return data

        return None

    except Exception:
        # Ignore unparseable frames safely
        return None


def _extract_dns_records(dns_layer: DNS, data: Dict[str, Any]) -> None:
    """Helper to extract DNS query hostnames and resolved answer IPs."""
    try:
        # Extract DNS Queries
        if dns_layer.qdcount > 0 and dns_layer.qd:
            query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            data["dns_queries"].append(query_name)
            
        # Extract DNS Answers (A, AAAA records)
        if dns_layer.ancount > 0 and dns_layer.an:
            curr = dns_layer.an
            for _ in range(dns_layer.ancount):
                if curr is None:
                    break
                # Type 1 = A Record (IPv4)
                if curr.type == 1 and hasattr(curr, 'rdata'):
                    rdata_ip = str(curr.rdata)
                    qname = curr.rrname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(curr, 'rrname') else ""
                    data["dns_answers"].append((rdata_ip, qname))
                curr = curr.payload if hasattr(curr, 'payload') and isinstance(curr.payload, DNSRR) else None
    except Exception:
        pass
