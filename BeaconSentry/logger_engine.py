"""
BeaconSentry - Structured SIEM & Forensic Incident Logger
Author: Elite Cybersecurity Defensive Engineer
Module: logger_engine.py

Description:
    High-fidelity structured security telemetry exporter.
    Outputs events in Elastic Common Schema (ECS) / JSON Lines (JSONL) format
    ready for direct ingestion by Splunk, Wazuh, Elastic Security, and Sentinel.
    Maps detections to MITRE ATT&CK Matrix (T1071, T1573).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("BeaconSentry.Logger")


class SIEMIncidentLogger:
    """
    Thread-safe SIEM telemetry exporter writing to /var/log/beaconsentry/incidents.jsonl.
    """

    def __init__(self, log_dir: str = "/var/log/beaconsentry", enabled: bool = True):
        self.enabled: bool = enabled
        self.log_dir: str = log_dir
        self.log_file: str = os.path.join(self.log_dir, "incidents.jsonl")
        self._lock: threading.Lock = threading.Lock()

        if self.enabled:
            try:
                os.makedirs(self.log_dir, exist_ok=True)
            except Exception as e:
                # Fallback to local logs directory if /var/log is not writeable
                self.log_dir = "logs"
                self.log_file = os.path.join(self.log_dir, "incidents.jsonl")
                os.makedirs(self.log_dir, exist_ok=True)

    def log_incident(
        self,
        event_type: str,
        dst_ip: str,
        dst_port: int,
        mean_interval: float,
        std_dev: float,
        cv: float,
        packet_count: int,
        classification: str,
        quarantined: bool,
        hostname: Optional[str] = None,
        notes: str = "",
    ) -> None:
        """
        Record a high-confidence C2 detection or firewall containment event in ECS format.
        """
        if not self.enabled:
            return

        now_iso = datetime.now(timezone.utc).isoformat()
        record: Dict[str, Any] = {
            "@timestamp": now_iso,
            "event": {
                "kind": "alert",
                "category": ["network", "intrusion_detection"],
                "type": ["indicator", "containment" if quarantined else "detection"],
                "action": "c2_beacon_identified",
                "severity": 9 if classification == "High Confidence C2 Beacon" else 5,
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": "T1071",
                    "name": "Application Layer Protocol",
                    "subtechnique": "C2 Periodic Beaconing",
                },
                "tactic": {"id": "TA0011", "name": "Command and Control"},
            },
            "destination": {
                "ip": dst_ip,
                "port": dst_port,
                "domain": hostname or "",
            },
            "beaconsentry": {
                "classification": classification,
                "burst_count": packet_count,
                "mean_interval_sec": round(mean_interval, 3),
                "jitter_std_dev_sec": round(std_dev, 3),
                "coefficient_of_variation": round(cv, 4),
                "quarantined": quarantined,
                "firewall_rule": f"iptables -A OUTPUT -d {dst_ip} -j DROP" if quarantined else "none",
                "notes": notes,
            },
        }

        line = json.dumps(record) + "\n"
        with self._lock:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception as e:
                logger.error("Failed to append incident to %s: %s", self.log_file, e)
