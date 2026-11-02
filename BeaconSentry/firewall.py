"""
BeaconSentry - Kali Linux Active Defense Firewall Controller
Author: Elite Cybersecurity Defensive Engineer
Module: firewall.py

Description:
    Active host-based network containment wrapper around Linux iptables.
    Provides non-destructive rule inspection, idempotency checks, automated
    outbound drop containment, session state tracking, and graceful signal-safe
    rule cleanup during incident response or tool termination.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
from typing import Callable, List, Optional, Set


class FirewallManager:
    """
    Thread-safe interface for managing Kali Linux iptables active containment rules.
    Maintains a strict ledger of IPs quarantined during the current session
    to ensure full recovery and prevent firewall rule leakage.
    """

    def __init__(self, dry_run: bool = False, whitelist_checker: Optional[Callable[[str], bool]] = None):
        self.dry_run: bool = dry_run
        self.whitelist_checker = whitelist_checker
        self._quarantined_ips: Set[str] = set()
        self._lock: threading.Lock = threading.Lock()
        self._iptables_path: Optional[str] = shutil.which("iptables")

    @property
    def has_root_privileges(self) -> bool:
        """Verify whether the current execution context has superuser permissions."""
        if os.name != "posix":
            return False
        return hasattr(os, "geteuid") and os.geteuid() == 0

    @property
    def is_iptables_available(self) -> bool:
        """Verify if the iptables binary is present in system PATH."""
        return self._iptables_path is not None

    def _execute_command(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """
        Execute an iptables command with subprocess safety.
        """
        if self.dry_run:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        if not self.is_iptables_available:
            raise FileNotFoundError("iptables executable was not found on this system.")

        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def is_ip_blocked(self, target_ip: str) -> bool:
        """
        Check if an active DROP rule for the target IP already exists in the OUTPUT chain.
        `iptables -C OUTPUT -d <target_ip> -j DROP`
        """
        cmd = ["iptables", "-C", "OUTPUT", "-d", target_ip, "-j", "DROP"]
        result = self._execute_command(cmd)
        return result.returncode == 0

    def block_ip(self, target_ip: str, callback: Optional[Callable[[str, bool, str], None]] = None) -> bool:
        """
        Contain a malicious C2 endpoint by appending an iptables DROP rule:
        `iptables -A OUTPUT -d <target_ip> -j DROP`

        Returns:
            bool: True if newly quarantined or already blocked, False on failure.
        """
        # Exclude loopback or local invalid addresses
        if target_ip in ("127.0.0.1", "::1", "0.0.0.0", "localhost"):
            if callback:
                callback(target_ip, False, "Refusing to quarantine loopback address")
            return False

        if self.whitelist_checker and self.whitelist_checker(target_ip):
            if callback:
                callback(target_ip, False, "Target IP is in configured trusted whitelist")
            return False

        with self._lock:
            # Check session ledger and iptables state to guarantee idempotency
            if target_ip in self._quarantined_ips or self.is_ip_blocked(target_ip):
                self._quarantined_ips.add(target_ip)
                if callback:
                    callback(target_ip, True, "Already quarantined")
                return True

            if not self.dry_run and not self.has_root_privileges:
                err_msg = "Root / sudo privileges required to insert iptables containment rules."
                if callback:
                    callback(target_ip, False, err_msg)
                return False

            cmd = ["iptables", "-A", "OUTPUT", "-d", target_ip, "-j", "DROP"]
            try:
                res = self._execute_command(cmd)
                if res.returncode == 0:
                    self._quarantined_ips.add(target_ip)
                    if callback:
                        msg = "[DRY-RUN] Simulated block" if self.dry_run else "Successfully added OUTPUT DROP rule"
                        callback(target_ip, True, msg)
                    return True
                else:
                    err_msg = res.stderr.strip() or f"iptables exited with code {res.returncode}"
                    if callback:
                        callback(target_ip, False, err_msg)
                    return False
            except Exception as exc:
                if callback:
                    callback(target_ip, False, str(exc))
                return False

    def unblock_ip(self, target_ip: str, callback: Optional[Callable[[str, bool, str], None]] = None) -> bool:
        """
        Remove an outbound quarantine rule for the given IP:
        `iptables -D OUTPUT -d <target_ip> -j DROP`
        """
        with self._lock:
            if not self.dry_run and not self.has_root_privileges:
                if callback:
                    callback(target_ip, False, "Root privileges required to delete iptables rules")
                return False

            cmd = ["iptables", "-D", "OUTPUT", "-d", target_ip, "-j", "DROP"]
            try:
                res = self._execute_command(cmd)
                if res.returncode == 0:
                    self._quarantined_ips.discard(target_ip)
                    if callback:
                        callback(target_ip, True, "Successfully deleted OUTPUT DROP rule")
                    return True
                else:
                    self._quarantined_ips.discard(target_ip)
                    if callback:
                        callback(target_ip, False, res.stderr.strip() or "Rule not present in chain")
                    return False
            except Exception as exc:
                if callback:
                    callback(target_ip, False, str(exc))
                return False

    def flush_quarantine(self, callback: Optional[Callable[[str, bool, str], None]] = None) -> int:
        """
        Remove all firewall rules inserted by BeaconSentry during this session.
        Returns the number of rules removed.
        """
        removed_count = 0
        with self._lock:
            active_ips = list(self._quarantined_ips)

        for ip in active_ips:
            success = self.unblock_ip(ip, callback=callback)
            if success:
                removed_count += 1

        return removed_count

    def get_quarantined_ips(self) -> List[str]:
        """Return a copy of all quarantined target IPs currently tracked in this session."""
        with self._lock:
            return sorted(list(self._quarantined_ips))
