"""
BeaconSentry - Production Configuration & Whitelist Manager
Author: Elite Cybersecurity Defensive Engineer
Module: config.py

Description:
    Centralized configuration engine supporting YAML/JSON configuration files,
    whitelist management (CIDRs, trusted domains, cloud telemetry),
    detection thresholds, and SOC/SIEM export policies.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class BeaconSentryConfig:
    # Network Capture
    interface: str = "any"
    window_size: int = 20
    bpf_filter: str = "tcp"

    # Algorithmic Detection Thresholds
    min_bursts: int = 5
    min_interval_mean: float = 5.0
    max_interval_mean: float = 300.0
    c2_cv_threshold: float = 0.30
    suspicious_cv_threshold: float = 0.50

    # Active Defense
    quarantine_enabled: bool = False
    dry_run: bool = False
    auto_flush_on_exit: bool = False

    # Forensic & Logging
    log_dir: str = "/var/log/beaconsentry"
    enable_json_logging: bool = True
    dump_c2_pcaps: bool = False

    # Threat Intelligence & Whitelists
    enable_dns_resolution: bool = True
    whitelist_ips: Set[str] = field(default_factory=lambda: {
        "127.0.0.1", "::1", "0.0.0.0"
    })
    whitelist_cidrs: List[str] = field(default_factory=lambda: [
        # Common local/private subnets can be whitelisted or audited
    ])
    whitelist_ports: Set[int] = field(default_factory=lambda: {
        # 123 (NTP), etc.
    })

    def is_whitelisted(self, ip_str: str, port: Optional[int] = None) -> bool:
        """Check if an IP or Port is whitelisted from active defense and alerting."""
        if ip_str in self.whitelist_ips:
            return True

        if port is not None and port in self.whitelist_ports:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for cidr in self.whitelist_cidrs:
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        return True
                except ValueError:
                    pass
        except ValueError:
            pass

        return False

    @classmethod
    def load_from_file(cls, path: str = "/etc/beaconsentry/config.json") -> BeaconSentryConfig:
        """Load configuration from JSON file with safe defaults."""
        if not os.path.exists(path):
            return cls()

        try:
            with open(path, "r", encoding="utf-8") as f:
                data: Dict[str, Any] = json.load(f)

            return cls(
                interface=data.get("interface", "any"),
                window_size=int(data.get("window_size", 20)),
                bpf_filter=data.get("bpf_filter", "tcp"),
                min_bursts=int(data.get("min_bursts", 5)),
                min_interval_mean=float(data.get("min_interval_mean", 5.0)),
                max_interval_mean=float(data.get("max_interval_mean", 300.0)),
                c2_cv_threshold=float(data.get("c2_cv_threshold", 0.30)),
                suspicious_cv_threshold=float(data.get("suspicious_cv_threshold", 0.50)),
                quarantine_enabled=bool(data.get("quarantine_enabled", False)),
                dry_run=bool(data.get("dry_run", False)),
                auto_flush_on_exit=bool(data.get("auto_flush_on_exit", False)),
                log_dir=data.get("log_dir", "/var/log/beaconsentry"),
                enable_json_logging=bool(data.get("enable_json_logging", True)),
                dump_c2_pcaps=bool(data.get("dump_c2_pcaps", False)),
                enable_dns_resolution=bool(data.get("enable_dns_resolution", True)),
                whitelist_ips=set(data.get("whitelist_ips", ["127.0.0.1", "::1"])),
                whitelist_cidrs=list(data.get("whitelist_cidrs", [])),
                whitelist_ports=set(int(p) for p in data.get("whitelist_ports", [])),
            )
        except Exception:
            return cls()

    def export_default_config(self, path: str = "/etc/beaconsentry/config.json") -> None:
        """Save standard production configuration template."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        config_dict = {
            "interface": self.interface,
            "window_size": self.window_size,
            "min_bursts": self.min_bursts,
            "min_interval_mean": self.min_interval_mean,
            "max_interval_mean": self.max_interval_mean,
            "c2_cv_threshold": self.c2_cv_threshold,
            "suspicious_cv_threshold": self.suspicious_cv_threshold,
            "quarantine_enabled": self.quarantine_enabled,
            "dry_run": self.dry_run,
            "auto_flush_on_exit": self.auto_flush_on_exit,
            "log_dir": self.log_dir,
            "enable_json_logging": self.enable_json_logging,
            "dump_c2_pcaps": self.dump_c2_pcaps,
            "enable_dns_resolution": self.enable_dns_resolution,
            "whitelist_ips": list(self.whitelist_ips),
            "whitelist_cidrs": self.whitelist_cidrs,
            "whitelist_ports": list(self.whitelist_ports),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=4)
