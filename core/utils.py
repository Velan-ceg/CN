"""
LANGuard - Utility Functions & Formatters
=========================================
Computer Networks (CN) Helper Utilities
-----------------------------------------
Provides formatting helpers for network statistics, bandwidth calculations,
IP subnet classifications, and UI badge styles.
"""

import time
import ipaddress
from datetime import datetime
from typing import Tuple


def format_bytes(byte_count: int) -> str:
    """Format byte integers into human-friendly data units."""
    if byte_count is None:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(byte_count) < 1024.0:
            return f"{byte_count:.1f} {unit}"
        byte_count /= 1024.0
    return f"{byte_count:.1f} PB"


def format_bps(bytes_per_sec: float) -> str:
    """Format bytes per second into network throughput (bps, Kbps, Mbps)."""
    bits_per_sec = (bytes_per_sec or 0) * 8
    for unit in ["bps", "Kbps", "Mbps", "Gbps"]:
        if abs(bits_per_sec) < 1000.0:
            return f"{bits_per_sec:.1f} {unit}"
        bits_per_sec /= 1000.0
    return f"{bits_per_sec:.1f} Tbps"


def format_timestamp(ts: float) -> str:
    """Format Unix epoch timestamp into standard readable time."""
    if not ts:
        return "N/A"
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def format_timestamp_full(ts: float) -> str:
    """Format Unix epoch timestamp into date and time."""
    if not ts:
        return "N/A"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def classify_ip(ip: str) -> str:
    """
    Classify IP address according to Computer Networks IANA specifications:
    - RFC 1918 Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - RFC 1122 Loopback (127.0.0.0/8)
    - RFC 3927 Link-Local (169.254.0.0/16)
    - RFC 5771 Multicast (224.0.0.0/4)
    - Public Internet IP
    """
    if not ip or ip == "N/A":
        return "Unknown"
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback:
            return "Loopback"
        elif ip_obj.is_private:
            return "Private LAN"
        elif ip_obj.is_link_local:
            return "Link-Local"
        elif ip_obj.is_multicast:
            return "Multicast"
        else:
            return "Public WAN"
    except ValueError:
        return "Invalid IP"


def get_severity_color(severity: str) -> str:
    """Return styling color hex code based on alert severity."""
    s = (severity or "").upper()
    if s == "CRITICAL":
        return "#FF2B2B"  # Bright Red
    elif s == "HIGH":
        return "#FF8C00"  # Orange
    elif s == "MEDIUM":
        return "#FFD700"  # Gold / Yellow
    elif s == "LOW":
        return "#1E90FF"  # Dodger Blue
    return "#888888"      # Gray
