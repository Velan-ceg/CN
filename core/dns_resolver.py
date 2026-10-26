"""
LANGuard - Passive & Active Reverse DNS Resolution Engine
==========================================================
Computer Networks (CN) Domain Name System (DNS) Module
----------------------------------------------------------
This module implements a hybrid DNS resolution mechanism to associate
raw IP addresses with human-readable website and hostnames:

1. Passive DNS Snooping:
   Intercepts standard DNS responses (RFC 1035 A and AAAA records) passing
   through the network interface. When a LAN host resolves a domain like
   'github.com', LANGuard immediately learns and records that IP -> domain
   mapping without generating any extra traffic.

2. Active Reverse DNS (PTR) Resolution:
   For IP addresses not observed during DNS query/response cycles, an
   asynchronous thread pool performs reverse PTR lookups with an LRU cache,
   ensuring the real-time packet capture loop is never blocked.

3. LAN Host Profiler:
   Identifies standard RFC 1918 private address ranges (10.0.0.0/8,
   172.16.0.0/12, 192.168.0.0/16, and 127.0.0.1 loopback) and labels
   gateways and local nodes.
"""

import socket
import ipaddress
import threading
import time
from typing import Dict, Optional, Tuple
from collections import OrderedDict

from config import DNS_CACHE_TTL, DNS_REVERSE_LOOKUP_TIMEOUT, DNS_MAX_WORKER_THREADS


class HybridDNSResolver:
    """Thread-safe hybrid DNS resolver with passive sniffing and background PTR lookups."""
    
    def __init__(self, cache_ttl: int = DNS_CACHE_TTL):
        self.cache_ttl = cache_ttl
        # In-memory cache: ip -> (hostname, expiry_timestamp, is_passive)
        self._cache: Dict[str, Tuple[str, float, bool]] = {}
        self._lock = threading.Lock()
        
        # Queue for pending asynchronous lookups
        self._pending_queue: OrderedDict[str, float] = OrderedDict()
        self._queue_lock = threading.Lock()
        
        # Worker control
        self._running = True
        self._workers = []
        for i in range(DNS_MAX_WORKER_THREADS):
            t = threading.Thread(target=self._worker_loop, name=f"DNS-Worker-{i}", daemon=True)
            t.start()
            self._workers.append(t)
            
        # Pre-seed well-known loopback and broadcast addresses
        self.learn_dns_mapping("127.0.0.1", "localhost", is_passive=True)
        self.learn_dns_mapping("::1", "localhost", is_passive=True)
        self.learn_dns_mapping("255.255.255.255", "Broadcast", is_passive=True)

    def learn_dns_mapping(self, ip: str, hostname: str, is_passive: bool = True) -> None:
        """
        Record an IP -> Domain mapping (e.g. extracted passively from a DNS Answer).
        Passively snooped domains take precedence and overwrite generic PTR records.
        """
        if not ip or not hostname or ip == "N/A":
            return
        
        cleaned_host = hostname.strip().lower()
        now = time.time()
        
        with self._lock:
            # If already present as passive, don't overwrite unless newer
            existing = self._cache.get(ip)
            if existing and existing[2] and not is_passive:
                return  # Prefer passive DNS over generic PTR
            self._cache[ip] = (cleaned_host, now + self.cache_ttl, is_passive)

    def get_hostname(self, ip: str) -> Optional[str]:
        """
        Retrieve hostname for an IP from cache. If not cached, triggers background
        lookup and returns None immediately (non-blocking).
        """
        if not ip or ip == "N/A":
            return None
            
        now = time.time()
        with self._lock:
            cached = self._cache.get(ip)
            if cached:
                hostname, expiry, _ = cached
                if now < expiry:
                    return hostname
                else:
                    # Expired
                    del self._cache[ip]
                    
        # Not in cache: queue for background active reverse DNS lookup
        self._enqueue_lookup(ip)
        return None

    def get_display_name(self, ip: str) -> str:
        """
        Returns a friendly formatted display string for dashboards and logs.
        E.g., 'google.com (142.250.190.46)' or '10.10.56.170 (Local Host)' or '192.168.1.1'
        """
        if not ip or ip == "N/A":
            return "N/A"
            
        host = self.get_hostname(ip)
        if host:
            if host == ip or host == "localhost":
                return host
            return f"{host} ({ip})"
            
        # Check if it's a private network address
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                if ip.endswith(".1"):
                    return f"LAN Gateway ({ip})"
                return f"LAN Host ({ip})"
            elif ip_obj.is_multicast:
                return f"Multicast ({ip})"
        except ValueError:
            pass
            
        return ip

    def _enqueue_lookup(self, ip: str) -> None:
        """Queue IP for background PTR reverse lookup without duplicates."""
        # Skip invalid, multicast, or broadcast IPs
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_multicast or ip_obj.is_unspecified:
                return
        except ValueError:
            return

        with self._queue_lock:
            if ip not in self._pending_queue and len(self._pending_queue) < 1000:
                self._pending_queue[ip] = time.time()

    def _worker_loop(self) -> None:
        """Background worker thread executing socket reverse DNS lookups."""
        while self._running:
            ip_to_resolve = None
            with self._queue_lock:
                if self._pending_queue:
                    ip_to_resolve, _ = self._pending_queue.popitem(last=False)
                    
            if not ip_to_resolve:
                time.sleep(0.2)
                continue
                
            try:
                # Perform standard socket PTR reverse resolution with timeout
                # getnameinfo avoids deep OS delays compared to gethostbyaddr
                hostname, _ = socket.getnameinfo((ip_to_resolve, 0), socket.NI_NAMEREQD)
                if hostname and hostname != ip_to_resolve:
                    self.learn_dns_mapping(ip_to_resolve, hostname, is_passive=False)
                else:
                    self.learn_dns_mapping(ip_to_resolve, ip_to_resolve, is_passive=False)
            except (socket.herror, socket.gaierror, socket.timeout, OSError):
                # Reverse DNS failed or timed out; cache negative result to avoid re-querying immediately
                self.learn_dns_mapping(ip_to_resolve, ip_to_resolve, is_passive=False)

    def shutdown(self) -> None:
        """Stop background worker threads."""
        self._running = False


# Global singleton resolver instance
dns_resolver = HybridDNSResolver()
