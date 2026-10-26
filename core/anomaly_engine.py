"""
LANGuard - Statistical Traffic Anomaly Detection Engine
======================================================
Computer Networks (CN) Traffic Modeling & Outlier Analysis
------------------------------------------------------
This module models baseline network traffic characteristics and uses
statistical methods (Moving Average, Sample Standard Deviation, and
Z-Score distance) to flag significant deviations from normal behavior.

Mathematical Foundations:
  1. Mean (μ): Baseline average packet rate or byte throughput over a
     sliding window of size N:
         μ = (1 / N) * Σ (x_i)

  2. Standard Deviation (σ): Measure of traffic dispersion/variance:
         σ = sqrt((1 / (N - 1)) * Σ (x_i - μ)^2)

  3. Z-Score (Standard Score): Measures how many standard deviations the
     current instantaneous traffic rate (x) deviates from the historical mean:
         Z = (x - μ) / σ

  Threshold Condition:
     If Z > 3.0 (representing a 99.7% confidence interval under normal
     distribution) or Instantaneous_Rate > k * Mean, an Anomaly is flagged.
"""

import time
import math
import threading
from collections import deque
from typing import Dict, Any, List, Optional, Tuple

from config import ANOMALY_CONFIG
from core.database import db_manager


class StatisticalAnomalyEngine:
    """Detects network traffic anomalies via rolling statistical profiles and Z-scores."""

    def __init__(self):
        self._lock = threading.Lock()
        
        # Rolling windows for per-second packet counts and byte counts
        self.window_size = ANOMALY_CONFIG.get("BASELINE_WINDOW_SIZE", 30)
        self.z_threshold = ANOMALY_CONFIG.get("Z_SCORE_THRESHOLD", 3.0)
        self.min_samples = ANOMALY_CONFIG.get("MIN_SAMPLES_FOR_BASELINE", 10)
        self.packet_burst_ratio = ANOMALY_CONFIG.get("PACKET_RATE_BURST_RATIO", 3.5)
        self.byte_burst_ratio = ANOMALY_CONFIG.get("BYTE_RATE_BURST_RATIO", 4.0)

        # History queues: store (timestamp, pps, bps)
        self._packet_rate_history: deque = deque(maxlen=self.window_size)
        self._byte_rate_history: deque = deque(maxlen=self.window_size)

        # Real-time state metrics for dashboard visualization
        self.latest_stats = {
            "timestamp": time.time(),
            "current_pps": 0,
            "mean_pps": 0.0,
            "std_pps": 0.0,
            "z_score_pps": 0.0,
            "threshold_pps": 0.0,
            "current_bps": 0,
            "mean_bps": 0.0,
            "is_anomaly": False
        }
        
        self._last_alert_time = 0.0
        self.cooldown_seconds = 5.0

    def record_interval_metric(self, timestamp: float, packet_count: int, byte_count: int) -> Optional[Dict[str, Any]]:
        """
        Record a 1-second interval measurement and check for statistical anomalies.
        Returns an alert dictionary if an anomaly threshold is breached.
        """
        with self._lock:
            # 1. Update rolling window
            self._packet_rate_history.append(packet_count)
            self._byte_rate_history.append(byte_count)

            # Need sufficient baseline samples to avoid cold-start false positives
            if len(self._packet_rate_history) < self.min_samples:
                self.latest_stats.update({
                    "timestamp": timestamp,
                    "current_pps": packet_count,
                    "current_bps": byte_count,
                    "is_anomaly": False
                })
                return None

            # 2. Calculate Mean and Standard Deviation for Packet Rate
            pps_list = list(self._packet_rate_history)
            n = len(pps_list)
            mean_pps = sum(pps_list) / n
            
            variance_pps = sum((x - mean_pps) ** 2 for x in pps_list) / (n - 1) if n > 1 else 0.0
            std_pps = math.sqrt(variance_pps)

            # Calculate Mean for Byte Rate
            bps_list = list(self._byte_rate_history)
            mean_bps = sum(bps_list) / n

            # 3. Compute Z-Score
            # Add small epsilon (0.01) to standard deviation to prevent division by zero in quiet LANs
            effective_std = std_pps if std_pps > 0.5 else 1.0
            z_score = (packet_count - mean_pps) / effective_std
            upper_threshold_pps = mean_pps + (self.z_threshold * effective_std)

            # Check Anomaly Conditions
            is_z_anomaly = (z_score >= self.z_threshold and packet_count > 15)
            is_pps_burst = (packet_count > 25 and packet_count >= mean_pps * self.packet_burst_ratio)
            is_bps_burst = (byte_count > 100000 and byte_count >= mean_bps * self.byte_burst_ratio)

            is_anomaly = is_z_anomaly or is_pps_burst or is_bps_burst

            # Update state for dashboard plotting
            self.latest_stats = {
                "timestamp": timestamp,
                "current_pps": packet_count,
                "mean_pps": round(mean_pps, 2),
                "std_pps": round(std_pps, 2),
                "z_score_pps": round(z_score, 2),
                "threshold_pps": round(upper_threshold_pps, 2),
                "current_bps": byte_count,
                "mean_bps": round(mean_bps, 2),
                "is_anomaly": is_anomaly
            }

            # 4. Generate Alert if Threshold Breached
            if is_anomaly and (timestamp - self._last_alert_time > self.cooldown_seconds):
                self._last_alert_time = timestamp
                
                reason_details = []
                if is_z_anomaly:
                    reason_details.append(f"Z-Score {z_score:.2f} exceeds threshold {self.z_threshold}")
                if is_pps_burst:
                    reason_details.append(f"Packet burst {packet_count} pps is {packet_count/max(1, mean_pps):.1f}x baseline mean")
                if is_bps_burst:
                    reason_details.append(f"Throughput burst {byte_count/1024:.1f} KB/s is {byte_count/max(1, mean_bps):.1f}x baseline")

                reason_str = "; ".join(reason_details)
                alert = {
                    "timestamp": timestamp,
                    "severity": "HIGH" if z_score > 4.5 else "MEDIUM",
                    "alert_type": "Statistical Traffic Anomaly",
                    "src_ip": "Multiple / LAN Aggregated",
                    "dst_ip": "LAN Subnet",
                    "src_host": "Aggregated Traffic",
                    "dst_host": "Local Network",
                    "signature": "ANOMALY-STAT-ZSCORE",
                    "description": f"Abnormal traffic volume spike: {packet_count} pkts/s (Mean: {mean_pps:.1f}, "
                                f"StdDev: {std_pps:.1f}). Reason: {reason_str}.",
                    "mitigation": "Check Top Talkers host matrix for offending IP; verify if legitimate file transfer, backup, or DDoS flood."
                }
                db_manager.insert_alert(alert)
                return alert

            return None

    def get_latest_stats(self) -> Dict[str, Any]:
        """Returns the current anomaly detection metrics for dashboard telemetry."""
        with self._lock:
            return dict(self.latest_stats)


# Global singleton anomaly engine instance
anomaly_engine = StatisticalAnomalyEngine()
