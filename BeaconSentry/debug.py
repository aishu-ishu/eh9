#!/usr/bin/env python3
"""
BeaconSentry - Self-Diagnostic & Error Detection Suite
Run with: sudo python3 debug.py
"""

import os
import socket
import sys
import threading
import time
import traceback


def run_diagnostics():
    print("=" * 70)
    print(" [*] BEACONSENTRY SELF-DIAGNOSTIC & ERROR DETECTION SUITE")
    print("=" * 70)

    # 1. Check Root Privileges
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    print(f" [1] Superuser / Root Privileges : {'YES (OK)' if is_root else 'NO (Required for iptables/raw sniff)'}")
    if not is_root:
        print("     [!] Warning: You must run this script with 'sudo python3 debug.py'!")

    # 2. Check Module Imports
    print("\n [2] Testing Python Module Imports...")
    modules = [
        ("rich", "UI Dashboard Engine"),
        ("scapy.all", "Packet Capture Engine"),
        ("numpy", "Math Engine"),
        ("config", "BeaconSentry Configuration"),
        ("threat_intel", "Threat Intel / Reverse DNS"),
        ("logger_engine", "SIEM Logging Engine"),
        ("analyzer", "Mathematical Detection Engine"),
        ("firewall", "iptables Firewall Engine"),
        ("sniffer", "Sniffer Engine"),
    ]

    all_imports_ok = True
    for mod_name, desc in modules:
        try:
            __import__(mod_name)
            print(f"     [✓] {mod_name:<16} ({desc}) : OK")
        except Exception as e:
            all_imports_ok = False
            print(f"     [✗] {mod_name:<16} ({desc}) : FAILED -> {e}")
            traceback.print_exc()

    if not all_imports_ok:
        print("\n [!] Import errors detected. Please check missing packages or syntax errors.")
        return

    # 3. Check Scapy Interfaces
    from scapy.all import conf, get_if_list, sniff
    print("\n [3] Network Interfaces Detected:")
    try:
        if_list = get_if_list()
        for iface in if_list:
            is_def = " (Default Route)" if iface == conf.iface else ""
            print(f"     - {iface}{is_def}")
    except Exception as e:
        print(f"     [!] Failed to query interfaces: {e}")

    # 4. Check Linux iptables state
    print("\n [4] Checking Linux Firewall (iptables):")
    try:
        import subprocess
        res = subprocess.run(["iptables", "-L", "OUTPUT", "-n", "-v"], capture_output=True, text=True)
        lines = res.stdout.strip().split("\n")
        print(f"     [✓] iptables is functional. OUTPUT chain has {len(lines)-2} active rule(s).")
        drop_count = sum(1 for line in lines if "DROP" in line)
        if drop_count > 0:
            print(f"     [!] WARNING: {drop_count} DROP rule(s) found in OUTPUT chain! Flushing recommended.")
            for line in lines:
                if "DROP" in line:
                    print(f"         -> {line.strip()}")
        else:
            print("     [✓] No blocking DROP rules currently present.")
    except Exception as e:
        print(f"     [!] iptables check failed: {e}")

    # 5. Live Packet Sniffing & Ingestion Test
    print("\n [5] Live Packet Capture & Detection Test:")
    from analyzer import ThreatClassification, TrafficAnalyzer
    from firewall import FirewallManager
    from sniffer import PacketSniffer

    analyzer = TrafficAnalyzer(min_bursts=3, min_interval_mean=1.0, max_interval_mean=10.0, c2_cv_threshold=0.30)
    fw = FirewallManager(dry_run=True)
    captured_packets = []

    def debug_callback(sev, msg):
        print(f"     [ALERT CALLBACK] [{sev}] {msg}")

    sniffer = PacketSniffer(
        analyzer=analyzer,
        firewall=fw,
        interface="any",
        quarantine_enabled=False,
        include_loopback=True,
        alert_callback=debug_callback,
    )

    print("     [*] Starting sniffer in background...")
    try:
        sniffer.start()
        time.sleep(1.0)  # Allow sockets to attach
    except Exception as e:
        print(f"     [✗] Failed to start sniffer: {e}")
        traceback.print_exc()
        return

    print("     [*] Transmitting 3 test connection attempts to 127.0.0.1:9999 (1s interval)...")
    for i in range(1, 4):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect_ex(("127.0.0.1", 9999))
        except:
            pass
        s.close()
        print(f"         - Sent burst {i}/3")
        time.sleep(1.0)

    time.sleep(0.5)
    sniffer.stop()

    stats = analyzer.get_all_stats()
    print(f"\n [6] Ingestion Results:")
    print(f"     - Total packets inspected : {analyzer.total_inspected_packets}")
    print(f"     - Tracked flows in memory : {len(stats)}")

    if stats:
        for s in stats:
            print(f"     [✓] Captured Flow -> {s.destination_ip}:{s.destination_port} | Packets: {s.packet_count} | Mean: {s.mean_interval:.2f}s | CV: {s.coefficient_of_variation:.3f} | Status: {s.classification.value}")
        print("\n" + "=" * 70)
        print(" [✓] DIAGNOSTIC PASSED: Sniffer and Analyzer are 100% operational!")
        print("=" * 70)
    else:
        print(f"     [✗] No flows recorded! The packet was not captured.")
        print("\n" + "=" * 70)
        print(" [!] DIAGNOSTIC FAILED: Packet capture did not receive the test bursts.")
        print("=" * 70)


if __name__ == "__main__":
    run_diagnostics()
