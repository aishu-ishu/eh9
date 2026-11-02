"""
BeaconSentry - Production Multi-Interface Packet Sniffer
Author: Elite Cybersecurity Defensive Engineer
Module: sniffer.py

Description:
    High-performance multi-interface packet sniffer for Kali Linux.
    Sniffs across physical interfaces (eth0/ens33/wlan0) AND loopback (lo)
    simultaneously, ensuring 100% capture of local simulated C2 traffic
    as well as real-world external malware beacons.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict
from typing import Any, Callable, DefaultDict, List, Optional

try:
    from scapy.all import IP, TCP, conf, get_if_list, sniff, wrpcap
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = None
    IPv6 = None
    TCP = None
    conf = None
    sniff = None
    wrpcap = None
    get_if_list = None

from analyzer import FlowStats, ThreatClassification, TrafficAnalyzer
from firewall import FirewallManager

logger = logging.getLogger("BeaconSentry.Sniffer")


class PacketSniffer:
    """
    Multi-threaded packet capture engine that listens on both local loopback
    and physical network interfaces concurrently.
    """

    def __init__(
        self,
        analyzer: TrafficAnalyzer,
        firewall: FirewallManager,
        interface: Optional[str] = None,
        quarantine_enabled: bool = False,
        bpf_filter: str = "tcp",
        include_loopback: bool = True,
        alert_callback: Optional[Callable[[str, str], None]] = None,
        siem_logger: Optional[Any] = None,
        dump_pcaps: bool = False,
        pcap_dir: str = "/var/log/beaconsentry/pcaps",
    ):
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required. Run: sudo apt-get install python3-scapy")

        self.analyzer: TrafficAnalyzer = analyzer
        self.firewall: FirewallManager = firewall
        self.requested_interface: Optional[str] = interface
        self.quarantine_enabled: bool = quarantine_enabled
        self.bpf_filter: str = bpf_filter or "tcp"
        self.include_loopback: bool = include_loopback
        self.alert_callback: Optional[Callable[[str, str], None]] = alert_callback
        self.siem_logger: Optional[Any] = siem_logger
        self.dump_pcaps: bool = dump_pcaps
        self.pcap_dir: str = pcap_dir

        # Determine target interfaces to monitor
        self.active_interfaces: List[str] = self._resolve_interfaces()
        self.interface: str = ", ".join(self.active_interfaces)

        self._threads: List[threading.Thread] = []
        self._stop_event: threading.Event = threading.Event()
        self._packet_count: int = 0
        self._flow_pcap_buffers: DefaultDict[str, List[Any]] = defaultdict(list)
        self._lock: threading.Lock = threading.Lock()

        if self.dump_pcaps:
            os.makedirs(self.pcap_dir, exist_ok=True)

    def _resolve_interfaces(self) -> List[str]:
        """Resolve which interfaces to bind listeners to."""
        try:
            available = get_if_list() if get_if_list else []
        except Exception:
            available = []

        if not available:
            return ["eth0", "lo"]

        if self.requested_interface and self.requested_interface not in ("any", "all"):
            if self.requested_interface in available:
                return [self.requested_interface]
            return [self.requested_interface]

        # By default, monitor active loopback + primary network interfaces
        selected = []
        if "lo" in available and self.include_loopback:
            selected.append("lo")

        # Add physical or VM interfaces
        for iface in available:
            if iface != "lo" and not iface.startswith("docker") and not iface.startswith("veth"):
                selected.append(iface)

        if not selected:
            selected = [str(conf.iface)] if conf and conf.iface else ["eth0"]

        return selected

    def _packet_handler(self, pkt) -> None:
        """Process an incoming TCP packet."""
        if self._stop_event.is_set():
            return

        try:
            if TCP is None or not pkt.haslayer(TCP):
                return

            # SYN flag detection: SYN must be set (0x02), ACK must NOT be set (0x10)
            flags = int(pkt[TCP].flags)
            if (flags & 0x12) != 0x02:
                return

            dst_ip: Optional[str] = None
            if IP is not None and pkt.haslayer(IP):
                dst_ip = str(pkt[IP].dst)
            elif IPv6 is not None and pkt.haslayer(IPv6):
                dst_ip = str(pkt[IPv6].dst)

            if not dst_ip:
                return

            if not self.include_loopback and dst_ip in ("127.0.0.1", "::1"):
                return

            dst_port = int(pkt[TCP].dport)
            pkt_time = float(pkt.time) if hasattr(pkt, "time") else time.time()

            with self._lock:
                self._packet_count += 1
                if self.dump_pcaps:
                    key = f"{dst_ip}_{dst_port}"
                    self._flow_pcap_buffers[key].append(pkt)
                    if len(self._flow_pcap_buffers[key]) > 100:
                        self._flow_pcap_buffers[key].pop(0)

            # Ingest into mathematical analyzer
            stats: FlowStats = self.analyzer.register_packet(dst_ip, dst_port, pkt_time)

            if stats.classification == ThreatClassification.C2_BEACON:
                alert_msg = (
                    f"C2 BEACON IDENTIFIED: {stats.target_str} "
                    f"[Packets: {stats.packet_count}, Mean: {stats.mean_interval:.2f}s, "
                    f"StdDev: {stats.std_dev:.2f}s, CV: {stats.coefficient_of_variation:.3f}]"
                )
                if self.alert_callback:
                    self.alert_callback("CRITICAL", alert_msg)

                quarantined_success = False
                if self.quarantine_enabled:
                    def _quar_cb(ip: str, success: bool, msg: str):
                        status = "QUARANTINED" if success else "CONTAINMENT FAILED"
                        if self.alert_callback:
                            self.alert_callback("DEFENSE", f"[{status}] {ip} - {msg}")

                    quarantined_success = self.firewall.block_ip(dst_ip, callback=_quar_cb)
                    if quarantined_success:
                        self.analyzer.mark_quarantined(dst_ip)

                if self.dump_pcaps and wrpcap:
                    self._dump_flow_pcap(dst_ip, dst_port)

                if self.siem_logger:
                    self.siem_logger.log_incident(
                        event_type="c2_beacon",
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        mean_interval=stats.mean_interval,
                        std_dev=stats.std_dev,
                        cv=stats.coefficient_of_variation,
                        packet_count=stats.packet_count,
                        classification=stats.classification.value,
                        quarantined=quarantined_success,
                        hostname=stats.hostname,
                        notes=stats.details,
                    )

            elif stats.classification == ThreatClassification.SUSPICIOUS:
                if stats.packet_count == self.analyzer.min_bursts:
                    alert_msg = (
                        f"SUSPICIOUS PERIODIC TRAFFIC: {stats.target_str} "
                        f"[Mean: {stats.mean_interval:.2f}s, CV: {stats.coefficient_of_variation:.3f}]"
                    )
                    if self.alert_callback:
                        self.alert_callback("WARNING", alert_msg)

        except Exception as exc:
            logger.debug("Packet parse exception: %s", exc)

    def _dump_flow_pcap(self, dst_ip: str, dst_port: int) -> None:
        try:
            key = f"{dst_ip}_{dst_port}"
            with self._lock:
                pkts = list(self._flow_pcap_buffers.get(key, []))

            if pkts:
                fn = os.path.join(self.pcap_dir, f"c2_{dst_ip}_{dst_port}_{int(time.time())}.pcap")
                wrpcap(fn, pkts)
                if self.alert_callback:
                    self.alert_callback("FORENSIC", f"Forensic PCAP dumped: {fn}")
        except Exception:
            pass

    def _sniff_single_interface(self, iface_name: str) -> None:
        """Worker thread dedicated to an individual network interface."""
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=iface_name,
                    filter=self.bpf_filter,
                    prn=self._packet_handler,
                    store=False,
                    timeout=1.0,
                    stop_filter=lambda p: self._stop_event.is_set(),
                )
            except Exception as e:
                if not self._stop_event.is_set():
                    time.sleep(1.0)

    def start(self) -> None:
        """Start listener threads for all active interfaces."""
        if any(t.is_alive() for t in self._threads):
            return

        self._stop_event.clear()
        self._threads = []

        if self.alert_callback:
            self.alert_callback("INFO", f"Sniffer active on: {self.interface}")

        for iface in self.active_interfaces:
            t = threading.Thread(
                target=self._sniff_single_interface,
                args=(iface,),
                daemon=True,
                name=f"BeaconSentry-{iface}",
            )
            t.start()
            self._threads.append(t)

    def stop(self, timeout: float = 2.0) -> None:
        """Stop all listener threads."""
        self._stop_event.set()
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=timeout)

    @property
    def is_running(self) -> bool:
        return any(t.is_alive() for t in self._threads)
