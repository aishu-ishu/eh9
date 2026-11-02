"""
BeaconSentry - Asynchronous Threat Intelligence & Reverse DNS Resolver
Author: Elite Cybersecurity Defensive Engineer
Module: threat_intel.py

Description:
    Non-blocking background hostname/PTR resolver with LRU caching.
    Enriches remote destination IP addresses with domain context without
    blocking the high-throughput packet processing engine or Rich UI loop.
"""

from __future__ import annotations

import socket
import threading
from typing import Dict, Optional


class ThreatIntelEnricher:
    """
    Asynchronous reverse-DNS and threat intelligence context resolver.
    """

    def __init__(self, enabled: bool = True, cache_size: int = 1000):
        self.enabled: bool = enabled
        self.cache_size: int = cache_size
        self._cache: Dict[str, str] = {}
        self._in_progress: set[str] = set()
        self._lock: threading.Lock = threading.Lock()

    def get_hostname(self, ip_str: str) -> str:
        """
        Return cached hostname if available, otherwise queue non-blocking resolution.
        """
        if not self.enabled or not ip_str or ip_str in ("127.0.0.1", "::1", "0.0.0.0"):
            return ""

        with self._lock:
            if ip_str in self._cache:
                return self._cache[ip_str]
            if ip_str in self._in_progress:
                return ""
            self._in_progress.add(ip_str)

        # Spawn non-blocking thread to resolve PTR
        thread = threading.Thread(target=self._resolve_worker, args=(ip_str,), daemon=True)
        thread.start()
        return ""

    def _resolve_worker(self, ip_str: str) -> None:
        hostname = ""
        try:
            # Set short socket timeout to prevent hanging on unreachable DNS
            socket.setdefaulttimeout(1.5)
            host, _, _ = socket.gethostbyaddr(ip_str)
            hostname = host
        except Exception:
            hostname = ""
        finally:
            with self._lock:
                if len(self._cache) >= self.cache_size:
                    # Evict oldest entry
                    self._cache.pop(next(iter(self._cache)))
                self._cache[ip_str] = hostname
                self._in_progress.discard(ip_str)

    def format_target(self, ip_str: str, port: int) -> str:
        """
        Format target IP and port with enriched hostname if available.
        Example: '1.1.1.1:443 (one.one.one.one)'
        """
        host = self.get_hostname(ip_str)
        if host:
            return f"{ip_str}:{port} ({host})"
        return f"{ip_str}:{port}"
