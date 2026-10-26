"""
LANGuard - SQLite Database Storage & Aggregations
==================================================
Computer Networks (CN) Traffic Logging & Analysis DB
--------------------------------------------------
Stores packet headers, security alerts, host inventories, and time-series
metrics for live querying and forensic post-analysis.
Uses SQLite with Write-Ahead Logging (WAL) for concurrency.
"""

import sqlite3
import threading
import time
from typing import Dict, List, Any, Optional, Tuple
from config import DATABASE_PATH


class DatabaseManager:
    """Thread-safe SQLite database manager for network traffic and security events."""
    
    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a configured SQLite connection with row factories and WAL mode."""
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Performance tuning for real-time packet ingress:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA cache_size=-64000;")  # 64MB cache
        return conn

    def _init_db(self) -> None:
        """Create database tables and performance indexes."""
        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            
            # 1. Packets Table (Layer 2 - Layer 4 Header metadata)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_host TEXT,
                dst_host TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                layer3_proto TEXT,
                layer4_proto TEXT,
                app_proto TEXT,
                packet_length INTEGER,
                tcp_flags TEXT,
                ip_ttl INTEGER,
                ip_id INTEGER,
                tcp_seq INTEGER,
                tcp_ack INTEGER,
                tcp_window INTEGER,
                payload_ascii TEXT,
                summary TEXT
            );
            """)
            
            # 2. Security Alerts Table (IDS and Anomaly Engine Detections)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_host TEXT,
                dst_host TEXT,
                signature TEXT,
                description TEXT,
                mitigation TEXT,
                status TEXT DEFAULT 'Under Investigation',
                notes TEXT DEFAULT ''
            );
            """)
            
            # 3. LAN Host Inventory (Endpoints active on the network)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS host_inventory (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                hostname TEXT,
                first_seen REAL,
                last_seen REAL,
                total_sent_packets INTEGER DEFAULT 0,
                total_recv_packets INTEGER DEFAULT 0,
                total_sent_bytes INTEGER DEFAULT 0,
                total_recv_bytes INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0
            );
            """)
            
            # 4. Traffic Metrics Table (Aggregated time-series buckets)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS traffic_metrics (
                timestamp REAL PRIMARY KEY,
                packet_count INTEGER DEFAULT 0,
                byte_count INTEGER DEFAULT 0,
                tcp_count INTEGER DEFAULT 0,
                udp_count INTEGER DEFAULT 0,
                icmp_count INTEGER DEFAULT 0,
                arp_count INTEGER DEFAULT 0,
                other_count INTEGER DEFAULT 0
            );
            """)
            
            # Indexes for fast querying
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_time ON packets (timestamp DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets (src_ip);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets (dst_ip);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (timestamp DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);")
            
            # Migration check: Ensure newly added columns exist in case table existed earlier
            for col, ctype in [
                ("ip_ttl", "INTEGER"), ("ip_id", "INTEGER"), ("tcp_seq", "INTEGER"),
                ("tcp_ack", "INTEGER"), ("tcp_window", "INTEGER"), ("payload_ascii", "TEXT")
            ]:
                try:
                    cur.execute(f"ALTER TABLE packets ADD COLUMN {col} {ctype};")
                except sqlite3.OperationalError:
                    pass

            for col, ctype in [("status", "TEXT DEFAULT 'Under Investigation'"), ("notes", "TEXT DEFAULT ''")]:
                try:
                    cur.execute(f"ALTER TABLE alerts ADD COLUMN {col} {ctype};")
                except sqlite3.OperationalError:
                    pass

            conn.commit()
            conn.close()

    def insert_packets_batch(self, packet_records: List[Dict[str, Any]]) -> None:
        """Batch insert parsed packet records for high throughput."""
        if not packet_records:
            return
            
        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            
            sql = """
            INSERT INTO packets (
                timestamp, src_ip, dst_ip, src_host, dst_host,
                src_port, dst_port, layer3_proto, layer4_proto,
                app_proto, packet_length, tcp_flags, ip_ttl,
                ip_id, tcp_seq, tcp_ack, tcp_window, payload_ascii, summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            rows = [
                (
                    p["timestamp"],
                    p.get("src_ip", "N/A"),
                    p.get("dst_ip", "N/A"),
                    p.get("src_host", ""),
                    p.get("dst_host", ""),
                    p.get("src_port"),
                    p.get("dst_port"),
                    p.get("layer3_proto", "Other"),
                    p.get("layer4_proto", "None"),
                    p.get("app_proto", "None"),
                    p.get("packet_length", 0),
                    p.get("tcp_flags", ""),
                    p.get("ip_ttl"),
                    p.get("ip_id"),
                    p.get("tcp_seq"),
                    p.get("tcp_ack"),
                    p.get("tcp_window"),
                    p.get("payload_ascii", ""),
                    p.get("summary", "")
                )
                for p in packet_records
            ]
            
            cur.executemany(sql, rows)
            conn.commit()
            conn.close()

    def insert_alert(self, alert: Dict[str, Any]) -> None:
        """Insert a security intrusion alert or anomaly detection event."""
        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            sql = """
            INSERT INTO alerts (
                timestamp, severity, alert_type, src_ip, dst_ip,
                src_host, dst_host, signature, description, mitigation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cur.execute(sql, (
                alert.get("timestamp", time.time()),
                alert.get("severity", "MEDIUM"),
                alert.get("alert_type", "General Alert"),
                alert.get("src_ip", "N/A"),
                alert.get("dst_ip", "N/A"),
                alert.get("src_host", ""),
                alert.get("dst_host", ""),
                alert.get("signature", ""),
                alert.get("description", ""),
                alert.get("mitigation", "")
            ))
            
            # Increment alert count on the offending host if exists
            if alert.get("src_ip"):
                cur.execute("""
                UPDATE host_inventory 
                SET alert_count = alert_count + 1 
                WHERE ip = ?
                """, (alert["src_ip"],))
                
            conn.commit()
            conn.close()

    def update_host_inventory(self, host_updates: List[Dict[str, Any]]) -> None:
        """Upsert host information and traffic counters."""
        if not host_updates:
            return
            
        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            
            sql = """
            INSERT INTO host_inventory (
                ip, mac, hostname, first_seen, last_seen,
                total_sent_packets, total_recv_packets,
                total_sent_bytes, total_recv_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                mac = COALESCE(excluded.mac, host_inventory.mac),
                hostname = CASE 
                    WHEN excluded.hostname IS NOT NULL AND excluded.hostname != '' AND excluded.hostname != excluded.ip 
                    THEN excluded.hostname 
                    ELSE host_inventory.hostname 
                END,
                last_seen = excluded.last_seen,
                total_sent_packets = host_inventory.total_sent_packets + excluded.total_sent_packets,
                total_recv_packets = host_inventory.total_recv_packets + excluded.total_recv_packets,
                total_sent_bytes = host_inventory.total_sent_bytes + excluded.total_sent_bytes,
                total_recv_bytes = host_inventory.total_recv_bytes + excluded.total_recv_bytes
            """
            
            rows = [
                (
                    h["ip"],
                    h.get("mac", ""),
                    h.get("hostname", ""),
                    h.get("timestamp", time.time()),
                    h.get("timestamp", time.time()),
                    h.get("sent_packets", 0),
                    h.get("recv_packets", 0),
                    h.get("sent_bytes", 0),
                    h.get("recv_bytes", 0),
                )
                for h in host_updates if h.get("ip") and h.get("ip") != "N/A"
            ]
            
            cur.executemany(sql, rows)
            conn.commit()
            conn.close()

    def insert_traffic_metric(self, metric: Dict[str, Any]) -> None:
        """Insert 1-second interval aggregated statistics."""
        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            sql = """
            INSERT OR REPLACE INTO traffic_metrics (
                timestamp, packet_count, byte_count,
                tcp_count, udp_count, icmp_count, arp_count, other_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            cur.execute(sql, (
                metric["timestamp"],
                metric.get("packet_count", 0),
                metric.get("byte_count", 0),
                metric.get("tcp_count", 0),
                metric.get("udp_count", 0),
                metric.get("icmp_count", 0),
                metric.get("arp_count", 0),
                metric.get("other_count", 0),
            ))
            conn.commit()
            conn.close()

    # -------------------------------------------------------------
    # QUERY METHODS FOR DASHBOARD & ANALYSIS
    # -------------------------------------------------------------
    def get_summary_stats(self) -> Dict[str, Any]:
        """Returns overall system counts."""
        conn = self._get_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT COUNT(*), COALESCE(SUM(packet_length), 0) FROM packets;")
        total_packets, total_bytes = cur.fetchone()
        
        cur.execute("SELECT COUNT(*) FROM alerts;")
        total_alerts = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM host_inventory;")
        total_hosts = cur.fetchone()[0]
        
        conn.close()
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_alerts": total_alerts,
            "total_hosts": total_hosts
        }

    def get_recent_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent packets ordered by newest first."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?;", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def get_packets_paged(self, limit: int = 100, offset: int = 0, proto: str = "All", search: str = "") -> Tuple[List[Dict[str, Any]], int]:
        """
        Retrieve historical packets with server-side pagination, protocol filtering,
        and deep keyword search across all stored historical packets in SQLite.
        Returns (rows, total_matching_count).
        """
        conn = self._get_connection()
        cur = conn.cursor()

        where_clauses = []
        params: List[Any] = []

        if proto and proto != "All":
            if proto == "ARP":
                where_clauses.append("layer3_proto = 'ARP'")
            else:
                where_clauses.append("layer4_proto = ?")
                params.append(proto)

        if search:
            s = f"%{search.strip().lower()}%"
            where_clauses.append("""
                (LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR 
                 LOWER(src_host) LIKE ? OR LOWER(dst_host) LIKE ? OR 
                 LOWER(summary) LIKE ? OR LOWER(app_proto) LIKE ? OR 
                 CAST(id AS TEXT) LIKE ?)
            """)
            params.extend([s, s, s, s, s, s, s])

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        # Total matching rows in database
        cur.execute(f"SELECT COUNT(*) FROM packets {where_sql};", params)
        total_count = cur.fetchone()[0]

        # Fetch the requested page of rows
        query_sql = f"SELECT * FROM packets {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
        cur.execute(query_sql, params + [limit, offset])
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows, total_count

    def get_packet_by_id(self, packet_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a specific single packet by its primary key ID (used for locked inspection)."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM packets WHERE id = ?;", (packet_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent security alerts."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?;", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def update_alert_investigation(self, alert_id: int, status: str, notes: str = "") -> None:
        """Update investigation status and analyst notes for an alert."""
        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("UPDATE alerts SET status = ?, notes = ? WHERE id = ?;", (status, notes, alert_id))
            conn.commit()
            conn.close()

    def get_all_packets_for_export(self, limit: int = 5000) -> List[Dict[str, Any]]:
        """Retrieve packets formatted for forensic CSV / JSON export."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
        SELECT 
            id, datetime(timestamp, 'unixepoch', 'localtime') as log_time,
            src_ip, src_host, src_port, dst_ip, dst_host, dst_port,
            layer3_proto, layer4_proto, app_proto, packet_length,
            tcp_flags, ip_ttl, summary
        FROM packets ORDER BY timestamp DESC LIMIT ?;
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def get_all_alerts_for_export(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Retrieve alerts formatted for forensic CSV / JSON export."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
        SELECT 
            id, datetime(timestamp, 'unixepoch', 'localtime') as alert_time,
            severity, alert_type, signature, src_ip, src_host,
            dst_ip, dst_host, status, notes, description, mitigation
        FROM alerts ORDER BY timestamp DESC LIMIT ?;
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def get_protocol_distribution(self) -> Dict[str, int]:
        """Returns count of packets per Layer 4 / ARP protocol."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
        SELECT 
            CASE 
                WHEN layer3_proto = 'ARP' THEN 'ARP'
                WHEN layer4_proto IN ('TCP', 'UDP', 'ICMP') THEN layer4_proto
                ELSE 'Other'
            END as proto,
            COUNT(*) as count
        FROM packets
        GROUP BY proto
        ORDER BY count DESC;
        """)
        results = {r["proto"]: r["count"] for r in cur.fetchall()}
        conn.close()
        return results

    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns top active IP endpoints sorted by total bytes."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
        SELECT 
            ip, 
            COALESCE(hostname, ip) as display_name, 
            mac,
            total_sent_packets + total_recv_packets as total_packets,
            total_sent_bytes + total_recv_bytes as total_bytes,
            alert_count,
            last_seen
        FROM host_inventory
        ORDER BY total_bytes DESC
        LIMIT ?;
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def get_time_series_metrics(self, limit_seconds: int = 60) -> List[Dict[str, Any]]:
        """Returns time-series throughput for the last N seconds."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
        SELECT * FROM traffic_metrics 
        ORDER BY timestamp DESC 
        LIMIT ?;
        """, (limit_seconds,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        rows.reverse()
        return rows

    def clear_database(self) -> None:
        """Wipe database records (used for fresh test sessions)."""
        with self._lock:
            conn = self._get_connection()
            cur = conn.cursor()
            cur.execute("DELETE FROM packets;")
            cur.execute("DELETE FROM alerts;")
            cur.execute("DELETE FROM host_inventory;")
            cur.execute("DELETE FROM traffic_metrics;")
            conn.commit()
            conn.close()


# Global singleton instance
db_manager = DatabaseManager()
