"""
BeaconSentry - Statistical Traffic Analyzer & Flow Engine
Author: Elite Cybersecurity Defensive Engineer
Module: analyzer.py

Description:
    Core mathematical and algorithmic detection engine for BeaconSentry.
    Maintains thread-safe sliding windows of connection timestamps per flow (Dst_IP:Dst_Port),
    calculates inter-arrival timing deltas, computes descriptive statistical metrics
    (mean interval, standard deviation / jitter spread, and coefficient of variation CV),
    and classifies traffic into human vs machine periodic C2 beacons.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class ThreatClassification(Enum):
    """Threat severity levels for classified outbound flows."""
    INSUFFICIENT_DATA = "Collecting Data"
    NORMAL = "Normal Traffic"
    WHITELISTED = "Trusted / Whitelisted"
    SUSPICIOUS = "Suspicious Periodic Traffic"
    C2_BEACON = "High Confidence C2 Beacon"


@dataclass
class FlowStats:
    """
    Snapshot of computed statistical metrics and classification for a specific destination flow.
    """
    destination_ip: str
    destination_port: int
    packet_count: int
    window_size: int
    intervals: List[float] = field(default_factory=list)
    mean_interval: float = 0.0
    std_dev: float = 0.0
    coefficient_of_variation: float = 0.0
    classification: ThreatClassification = ThreatClassification.INSUFFICIENT_DATA
    last_seen: float = 0.0
    is_quarantined: bool = False
    hostname: str = ""
    details: str = ""

    @property
    def flow_key(self) -> Tuple[str, int]:
        return self.destination_ip, self.destination_port

    @property
    def target_str(self) -> str:
        if self.hostname:
            return f"{self.destination_ip}:{self.destination_port} ({self.hostname})"
        return f"{self.destination_ip}:{self.destination_port}"

    @property
    def seconds_since_last_seen(self) -> float:
        return max(0.0, time.time() - self.last_seen)


class FlowRecord:
    """
    Maintains the sliding window of connection timestamps for an individual flow
    and performs the statistical inter-arrival timing calculations.
    """

    def __init__(self, dst_ip: str, dst_port: int, window_size: int = 20):
        self.dst_ip: str = dst_ip
        self.dst_port: int = dst_port
        self.window_size: int = max(5, window_size)
        self.timestamps: deque[float] = deque(maxlen=self.window_size)
        self.total_packets: int = 0
        self.last_seen: float = 0.0
        self.is_quarantined: bool = False
        self._lock: threading.Lock = threading.Lock()

    def record_event(self, timestamp: Optional[float] = None) -> None:
        """
        Record a new packet / connection event timestamp.
        """
        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            self.total_packets += 1
            self.last_seen = timestamp
            self.timestamps.append(timestamp)

    def compute_stats(
        self,
        min_bursts: int = 5,
        min_interval_mean: float = 5.0,
        max_interval_mean: float = 300.0,
        c2_cv_threshold: float = 0.30,
        suspicious_cv_threshold: float = 0.50,
    ) -> FlowStats:
        """
        Calculates inter-arrival timing deltas and statistical metrics:
            - Mean Interval: mu = sum(delta) / N
            - Standard Deviation: sigma = sqrt(sum((delta - mu)^2) / N)
            - Coefficient of Variation: CV = sigma / mu

        Classification heuristics:
            - Minimum burst count: Requires at least `min_bursts` packets (default 5).
            - High Confidence C2 Beacon: 5s <= mu <= 300s and CV <= 0.30.
            - Suspicious Periodic Traffic: 5s <= mu <= 300s and 0.30 < CV <= 0.50.
            - Normal: Any other pattern.
        """
        with self._lock:
            ts_list = list(self.timestamps)
            total_pkts = self.total_packets
            last_ts = self.last_seen
            quarantined = self.is_quarantined

        # Calculate consecutive timing intervals delta_i = t_i - t_{i-1}
        deltas: List[float] = []
        if len(ts_list) > 1:
            for i in range(1, len(ts_list)):
                delta = ts_list[i] - ts_list[i - 1]
                if delta >= 0:
                    deltas.append(delta)

        n = len(deltas)
        # Check minimum burst requirement
        if total_pkts < min_bursts or n < (min_bursts - 1):
            return FlowStats(
                destination_ip=self.dst_ip,
                destination_port=self.dst_port,
                packet_count=total_pkts,
                window_size=len(ts_list),
                intervals=deltas,
                mean_interval=0.0,
                std_dev=0.0,
                coefficient_of_variation=0.0,
                classification=ThreatClassification.INSUFFICIENT_DATA,
                last_seen=last_ts,
                is_quarantined=quarantined,
                details=f"Need {min_bursts - total_pkts} more bursts to establish baseline",
            )

        # 1. Mean calculation: mu = sum(delta) / N
        mean_delta = sum(deltas) / n

        # 2. Standard deviation calculation: sigma = sqrt(sum((delta - mu)^2) / N)
        variance = sum((d - mean_delta) ** 2 for d in deltas) / n
        std_dev = math.sqrt(variance)

        # 3. Coefficient of Variation: CV = sigma / mu
        if mean_delta > 1e-6:
            cv = std_dev / mean_delta
        else:
            cv = 0.0

        # Anomaly Classification Heuristic
        classification = ThreatClassification.NORMAL
        details = "Aperiodic human-like or non-beaconing traffic"

        if min_interval_mean <= mean_delta <= max_interval_mean:
            if cv <= c2_cv_threshold:
                classification = ThreatClassification.C2_BEACON
                details = (
                    f"Machine periodic timing detected: mu={mean_delta:.2f}s, "
                    f"sigma={std_dev:.2f}s, CV={cv:.3f} <= {c2_cv_threshold:.2f}"
                )
            elif cv <= suspicious_cv_threshold:
                classification = ThreatClassification.SUSPICIOUS
                details = (
                    f"Elevated periodic consistency: mu={mean_delta:.2f}s, "
                    f"sigma={std_dev:.2f}s, CV={cv:.3f} <= {suspicious_cv_threshold:.2f}"
                )

        return FlowStats(
            destination_ip=self.dst_ip,
            destination_port=self.dst_port,
            packet_count=total_pkts,
            window_size=len(ts_list),
            intervals=deltas,
            mean_interval=mean_delta,
            std_dev=std_dev,
            coefficient_of_variation=cv,
            classification=classification,
            last_seen=last_ts,
            is_quarantined=quarantined,
            details=details,
        )


class TrafficAnalyzer:
    """
    Central flow tracking and statistical analysis manager.
    Coordinates flow windows, updates statistics in a thread-safe manner,
    and supports dynamic query search / filtering for terminal inspection.
    """

    def __init__(
        self,
        window_size: int = 20,
        min_bursts: int = 5,
        min_interval_mean: float = 5.0,
        max_interval_mean: float = 300.0,
        c2_cv_threshold: float = 0.30,
        suspicious_cv_threshold: float = 0.50,
        whitelist_checker: Optional[Any] = None,
        threat_intel: Optional[Any] = None,
    ):
        self.window_size: int = window_size
        self.min_bursts: int = min_bursts
        self.min_interval_mean: float = min_interval_mean
        self.max_interval_mean: float = max_interval_mean
        self.c2_cv_threshold: float = c2_cv_threshold
        self.suspicious_cv_threshold: float = suspicious_cv_threshold
        self.whitelist_checker = whitelist_checker
        self.threat_intel = threat_intel

        self._flows: Dict[Tuple[str, int], FlowRecord] = {}
        self._lock: threading.Lock = threading.Lock()
        self.total_inspected_packets: int = 0
        self.start_time: float = time.time()

    def register_packet(
        self, dst_ip: str, dst_port: int, timestamp: Optional[float] = None
    ) -> FlowStats:
        """
        Ingest a packet for destination IP:Port, record timing,
        and return the updated FlowStats.
        """
        key = (dst_ip, dst_port)
        with self._lock:
            self.total_inspected_packets += 1
            if key not in self._flows:
                self._flows[key] = FlowRecord(
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    window_size=self.window_size,
                )
            record = self._flows[key]

        record.record_event(timestamp)
        stats = record.compute_stats(
            min_bursts=self.min_bursts,
            min_interval_mean=self.min_interval_mean,
            max_interval_mean=self.max_interval_mean,
            c2_cv_threshold=self.c2_cv_threshold,
            suspicious_cv_threshold=self.suspicious_cv_threshold,
        )

        # Apply whitelist suppression if configured
        if self.whitelist_checker and self.whitelist_checker(dst_ip, dst_port):
            stats.classification = ThreatClassification.WHITELISTED
            stats.details = "Destination is in configured trusted whitelist"

        # Apply threat intelligence enrichment
        if self.threat_intel:
            stats.hostname = self.threat_intel.get_hostname(dst_ip)

        return stats

    def mark_quarantined(self, dst_ip: str, dst_port: Optional[int] = None) -> None:
        """
        Mark a destination flow (or all flows to dst_ip) as quarantined in the state table.
        """
        with self._lock:
            for (ip, port), record in self._flows.items():
                if ip == dst_ip and (dst_port is None or port == dst_port):
                    record.is_quarantined = True

    def mark_unquarantined(self, dst_ip: str, dst_port: Optional[int] = None) -> None:
        """
        Unmark quarantine status for destination IP / flow.
        """
        with self._lock:
            for (ip, port), record in self._flows.items():
                if ip == dst_ip and (dst_port is None or port == dst_port):
                    record.is_quarantined = False

    def get_flow_stats(self, dst_ip: str, dst_port: int) -> Optional[FlowStats]:
        """Fetch computed statistics for a single destination flow."""
        key = (dst_ip, dst_port)
        with self._lock:
            record = self._flows.get(key)
        if record:
            return record.compute_stats(
                min_bursts=self.min_bursts,
                min_interval_mean=self.min_interval_mean,
                max_interval_mean=self.max_interval_mean,
                c2_cv_threshold=self.c2_cv_threshold,
                suspicious_cv_threshold=self.suspicious_cv_threshold,
            )
        return None

    def get_all_stats(self, search_query: Optional[str] = None) -> List[FlowStats]:
        """
        Fetch snapshots of all active tracked flows, sorted by threat severity
        and most recent activity. Supports search filter by IP or Port.
        """
        with self._lock:
            records = list(self._flows.values())

        stats_list: List[FlowStats] = []
        for rec in records:
            stat = rec.compute_stats(
                min_bursts=self.min_bursts,
                min_interval_mean=self.min_interval_mean,
                max_interval_mean=self.max_interval_mean,
                c2_cv_threshold=self.c2_cv_threshold,
                suspicious_cv_threshold=self.suspicious_cv_threshold,
            )

            # Apply whitelist suppression if configured
            if self.whitelist_checker and self.whitelist_checker(stat.destination_ip, stat.destination_port):
                stat.classification = ThreatClassification.WHITELISTED
                stat.details = "Trusted whitelisted endpoint"

            # Apply threat intelligence enrichment
            if self.threat_intel:
                stat.hostname = self.threat_intel.get_hostname(stat.destination_ip)

            # Apply search filter if query is present
            if search_query:
                q = search_query.strip().lower()
                target_str = f"{stat.destination_ip}:{stat.destination_port} {stat.hostname}".lower()
                classification_str = stat.classification.value.lower()
                if q not in target_str and q not in classification_str:
                    continue

            stats_list.append(stat)

        # Priority order: C2_BEACON (0), SUSPICIOUS (1), INSUFFICIENT_DATA (2), NORMAL (3)
        priority_map = {
            ThreatClassification.C2_BEACON: 0,
            ThreatClassification.SUSPICIOUS: 1,
            ThreatClassification.INSUFFICIENT_DATA: 2,
            ThreatClassification.NORMAL: 3,
        }

        stats_list.sort(key=lambda s: (priority_map.get(s.classification, 4), -s.last_seen))
        return stats_list

    def get_flagged_beacons(self) -> List[FlowStats]:
        """Return all flows currently evaluated as High Confidence C2 Beacons."""
        return [
            s for s in self.get_all_stats()
            if s.classification == ThreatClassification.C2_BEACON
        ]

    def prune_idle_flows(self, max_idle_seconds: float = 3600.0) -> int:
        """Remove flows that have seen no traffic for max_idle_seconds."""
        now = time.time()
        pruned = 0
        with self._lock:
            keys_to_remove = [
                key for key, rec in self._flows.items()
                if (now - rec.last_seen) > max_idle_seconds and not rec.is_quarantined
            ]
            for key in keys_to_remove:
                del self._flows[key]
                pruned += 1
        return pruned

    def get_summary_metrics(self) -> Dict[str, int | float]:
        """Calculate high-level telemetry for the dashboard header."""
        all_stats = self.get_all_stats()
        c2_count = sum(1 for s in all_stats if s.classification == ThreatClassification.C2_BEACON)
        suspicious_count = sum(1 for s in all_stats if s.classification == ThreatClassification.SUSPICIOUS)
        quarantined_count = sum(1 for s in all_stats if s.is_quarantined)

        return {
            "uptime_seconds": time.time() - self.start_time,
            "total_inspected_packets": self.total_inspected_packets,
            "active_flows": len(all_stats),
            "flagged_c2_channels": c2_count,
            "suspicious_channels": suspicious_count,
            "quarantined_targets": quarantined_count,
        }
