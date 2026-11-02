"""
BeaconSentry - Production Real-Time C2 Statistical Detection & Autonomous Defense
Author: Elite Cybersecurity Defensive Engineer
Module: main.py

Description:
    Primary CLI interface and visual security operations dashboard.
    Runs a live interactive Rich terminal UI displaying monitored outbound flows,
    real-time inter-arrival timing statistics (mean delta, standard deviation, CV),
    threat classifications, reverse DNS intelligence, and active iptables quarantine status.
    Supports headless background service mode (--daemon) and SIEM logging.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from collections import deque
from datetime import datetime
from typing import Deque, List, Optional, Tuple

try:
    from rich import box
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from analyzer import FlowStats, ThreatClassification, TrafficAnalyzer
from config import BeaconSentryConfig
from firewall import FirewallManager
from logger_engine import SIEMIncidentLogger
from sniffer import PacketSniffer
from threat_intel import ThreatIntelEnricher


class BeaconSentryApp:
    """
    Main application controller managing the packet sniffer, mathematical analyzer,
    threat intelligence resolver, SIEM logging, and live Rich UI event loop.
    """

    ASCII_BANNER = r"""[bold cyan]  ____                                ____             _                 [/]
[bold cyan] | __ )  ___  __ _  ___ ___  _ __   / ___|  ___ _ __ | |_ _ __ _   _   [/]
[bold cyan] |  _ \ / _ \/ _` |/ __/ _ \| '_ \  \___ \ / _ \ '_ \| __| '__| | | |  [/]
[bold cyan] | |_) |  __/ (_| | (_| (_) | | | |  ___) |  __/ | | | |_| |  | |_| |  [/]
[bold cyan] |____/ \___|\__,_|\___\___/|_| |_| |____/ \___|_| |_|\__|_|   \__, |  [/]
[bold cyan]                                                               |___/   [/]
[bold yellow]   >>> Autonomous C2 Beacon Detection Engine & Active iptables Quarantine <<<   [/]"""

    def __init__(
        self,
        config: Optional[BeaconSentryConfig] = None,
        search_filter: Optional[str] = None,
        daemon_mode: bool = False,
    ):
        if not RICH_AVAILABLE and not daemon_mode:
            print("[ERROR] The 'rich' library is required for interactive terminal UI.")
            sys.exit(1)

        self.config: BeaconSentryConfig = config or BeaconSentryConfig()
        self.search_filter: Optional[str] = search_filter.strip() if search_filter else None
        self.daemon_mode: bool = daemon_mode
        self.console: Console = Console() if RICH_AVAILABLE else None
        self.alerts: Deque[Tuple[str, str, str]] = deque(maxlen=8)

        # 1. Threat Intelligence & Hostname Resolver
        self.threat_intel = ThreatIntelEnricher(enabled=self.config.enable_dns_resolution)

        # 2. SIEM & Forensic Incident Logger
        self.siem_logger = SIEMIncidentLogger(
            log_dir=self.config.log_dir,
            enabled=self.config.enable_json_logging,
        )

        # 3. Core Mathematical Detection Analyzer
        self.analyzer = TrafficAnalyzer(
            window_size=self.config.window_size,
            min_bursts=self.config.min_bursts,
            min_interval_mean=self.config.min_interval_mean,
            max_interval_mean=self.config.max_interval_mean,
            c2_cv_threshold=self.config.c2_cv_threshold,
            suspicious_cv_threshold=self.config.suspicious_cv_threshold,
            whitelist_checker=self.config.is_whitelisted,
            threat_intel=self.threat_intel,
        )

        # 4. Active Defense Firewall Manager
        self.firewall = FirewallManager(
            dry_run=self.config.dry_run,
            whitelist_checker=self.config.is_whitelisted,
        )

        # 5. Packet Sniffer
        self.sniffer = PacketSniffer(
            analyzer=self.analyzer,
            firewall=self.firewall,
            interface=self.config.interface,
            quarantine_enabled=self.config.quarantine_enabled,
            bpf_filter=self.config.bpf_filter,
            include_loopback=True,
            alert_callback=self._on_security_alert,
            siem_logger=self.siem_logger,
            dump_pcaps=self.config.dump_c2_pcaps,
            pcap_dir=os.path.join(self.config.log_dir, "pcaps"),
        )

        self.is_running: bool = False

    def _on_security_alert(self, severity: str, message: str) -> None:
        """Callback to store security events in the live dashboard activity log."""
        ts = datetime.now().strftime("%H:%M:%S")
        self.alerts.append((ts, severity, message))
        if self.daemon_mode:
            print(f"[{ts}] [{severity}] {message}", flush=True)

    def _build_header_panel(self) -> Panel:
        return Panel(Text.from_markup(self.ASCII_BANNER), border_style="cyan", box=box.ROUNDED)

    def _build_summary_panel(self) -> Panel:
        """Generate top dashboard telemetry summary table."""
        metrics = self.analyzer.get_summary_metrics()
        uptime = int(metrics["uptime_seconds"])
        mins, secs = divmod(uptime, 60)
        hours, mins = divmod(mins, 60)
        uptime_str = f"{hours:02d}:{mins:02d}:{secs:02d}"

        summary_table = Table.grid(expand=True)
        summary_table.add_column(justify="left", ratio=1)
        summary_table.add_column(justify="left", ratio=1)
        summary_table.add_column(justify="left", ratio=1)
        summary_table.add_column(justify="left", ratio=1)

        if self.config.quarantine_enabled:
            mode_style = "[bold white on red] ACTIVE QUARANTINE [/]"
            if self.config.dry_run:
                mode_style += " [bold yellow](DRY-RUN)[/]"
        else:
            mode_style = "[bold black on green] PASSIVE AUDIT [/]"

        iface_disp = self.sniffer.interface or "any"
        filter_disp = f"[bold cyan]{self.search_filter}[/]" if self.search_filter else "[dim]None (All Flows)[/]"

        summary_table.add_row(
            f"[bold cyan]Interface:[/] {iface_disp}",
            f"[bold cyan]Defense Mode:[/] {mode_style}",
            f"[bold cyan]Tracked Flows:[/] [bold]{metrics['active_flows']}[/]",
            f"[bold cyan]Uptime:[/] {uptime_str}",
        )
        summary_table.add_row(
            f"[bold cyan]Inspected SYN:[/] {metrics['total_inspected_packets']}",
            f"[bold cyan]Flagged C2s:[/] [bold red]{metrics['flagged_c2_channels']}[/]",
            f"[bold cyan]Suspicious:[/] [bold yellow]{metrics['suspicious_channels']}[/]",
            f"[bold cyan]Quarantined:[/] [bold magenta]{metrics['quarantined_targets']}[/]",
        )

        return Panel(
            summary_table,
            title="[bold white] SYSTEM DEFENSE TELEMETRY [/]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )

    def _build_search_bar_panel(self) -> Panel:
        """Render a dedicated terminal search bar panel."""
        if self.search_filter:
            search_text = (
                f"[bold green]🔍 SEARCH ACTIVE:[/] [bold white on blue] {self.search_filter} [/] "
                f"[dim]| Filtering destination IP, Port, Domain & Status[/]"
            )
            border_style = "bright_blue"
        else:
            search_text = (
                "[bold cyan]🔍 SEARCH BAR:[/] [dim italic]Displaying all active flows. "
                "Filter specific IP/Port using:[/] [bold yellow]-s <query>[/]"
            )
            border_style = "bright_black"

        return Panel(
            Text.from_markup(search_text),
            box=box.ROUNDED,
            border_style=border_style,
            height=3,
        )

    def _build_flow_table(self) -> Table:
        """Generate the real-time flow analysis table with statistical indicators."""
        table = Table(
            box=box.ROUNDED,
            expand=True,
            header_style="bold magenta",
            border_style="bright_black",
        )

        table.add_column("Destination (IP:Port / Hostname)", justify="left", style="bold white", ratio=3)
        table.add_column("Packets", justify="right", style="cyan", ratio=1)
        table.add_column("Mean Delta (μ)", justify="right", style="bright_yellow", ratio=2)
        table.add_column("Jitter (σ)", justify="right", style="yellow", ratio=2)
        table.add_column("CV (σ / μ)", justify="right", style="bold", ratio=1)
        table.add_column("Threat Classification", justify="center", ratio=3)
        table.add_column("Firewall State", justify="center", ratio=2)
        table.add_column("Last Seen", justify="right", style="dim", ratio=1)

        flows = self.analyzer.get_all_stats(search_query=self.search_filter)

        if not flows:
            table.add_row(
                "[dim]No active outbound TCP flows matching filter[/]",
                "-", "-", "-", "-",
                "[dim]Awaiting Traffic[/]",
                "-", "-",
            )
            return table

        for f in flows[:15]:
            if f.classification == ThreatClassification.INSUFFICIENT_DATA:
                mean_str = f"[dim]{f.mean_interval:.2f}s[/]" if f.mean_interval > 0 else "[dim]Gathering[/]"
                std_str = f"[dim]±{f.std_dev:.2f}s[/]" if f.std_dev > 0 else "[dim]-[/]"
                cv_str = "[dim]-[/]"
                threat_badge = f"[dim cyan]GATHERING ({f.packet_count}/{self.analyzer.min_bursts})[/]"
            else:
                mean_str = f"{f.mean_interval:.2f}s"
                std_str = f"±{f.std_dev:.2f}s"
                cv_color = "bold red" if f.coefficient_of_variation <= 0.30 else ("yellow" if f.coefficient_of_variation <= 0.50 else "green")
                cv_str = f"[{cv_color}]{f.coefficient_of_variation:.3f}[/]"

                if f.classification == ThreatClassification.C2_BEACON:
                    threat_badge = "[bold white on red] C2 BEACON [/]"
                elif f.classification == ThreatClassification.SUSPICIOUS:
                    threat_badge = "[bold black on yellow] SUSPICIOUS [/]"
                elif f.classification == ThreatClassification.WHITELISTED:
                    threat_badge = "[bold white on blue] WHITELISTED [/]"
                else:
                    threat_badge = "[green]NORMAL TRAFFIC[/]"

            if f.is_quarantined:
                fw_badge = "[bold white on dark_red] BLOCKED [DROP] [/]"
            elif self.config.quarantine_enabled:
                fw_badge = "[dim green]MONITORED[/]"
            else:
                fw_badge = "[dim]AUDIT ONLY[/]"

            ago = f.seconds_since_last_seen
            ago_str = f"{ago:.1f}s ago" if ago < 60 else f"{int(ago // 60)}m ago"

            table.add_row(
                f.target_str,
                str(f.packet_count),
                mean_str,
                std_str,
                cv_str,
                threat_badge,
                fw_badge,
                ago_str,
            )

        return table

    def _build_alerts_panel(self) -> Panel:
        """Render recent security incidents and containment events."""
        if not self.alerts:
            content = Text("No active security alerts. Network baseline running cleanly.", style="dim")
        else:
            lines = []
            for ts, sev, msg in self.alerts:
                if sev == "CRITICAL":
                    prefix = f"[{ts}] [bold red]CRITICAL ALERT[/]"
                elif sev == "DEFENSE":
                    prefix = f"[{ts}] [bold green]CONTAINMENT[/]"
                elif sev == "WARNING":
                    prefix = f"[{ts}] [bold yellow]WARNING[/]"
                elif sev == "FORENSIC":
                    prefix = f"[{ts}] [bold magenta]PCAP FORENSIC[/]"
                elif sev == "ERROR":
                    prefix = f"[{ts}] [bold magenta]ERROR[/]"
                else:
                    prefix = f"[{ts}] [bold cyan]INFO[/]"
                lines.append(f"{prefix} : {msg}")
            content = Text.from_markup("\n".join(lines))

        return Panel(
            content,
            title="[bold white] REAL-TIME INCIDENT & ACTIVE DEFENSE AUDIT LOG [/]",
            border_style="red" if any(s == "CRITICAL" for _, s, _ in self.alerts) else "bright_black",
            box=box.ROUNDED,
        )

    def _build_layout(self) -> Layout:
        """Compose the composite layout."""
        layout = Layout()
        layout.split_column(
            Layout(self._build_header_panel(), size=9),
            Layout(self._build_summary_panel(), size=5),
            Layout(self._build_search_bar_panel(), size=3),
            Layout(self._build_flow_table(), ratio=3),
            Layout(self._build_alerts_panel(), size=6),
            Layout(Text.from_markup("[bold white]Controls:[/] [bold yellow]Ctrl+C[/] Exit & Flush | [bold cyan]Search:[/] [bold yellow]-s <query>[/] | [bold red]Defense:[/] [bold yellow]-q[/]"), size=1),
        )
        return layout

    def start(self) -> None:
        """Launch sniffing engine and run the Live UI or Headless Daemon."""
        self.sniffer.start()
        self.is_running = True

        self._on_security_alert("INFO", f"Sniffing initiated on interface '{self.sniffer.interface}'")
        if self.config.quarantine_enabled:
            self._on_security_alert("INFO", "Automated iptables quarantine enabled (Rules: iptables -A OUTPUT -d <target> -j DROP)")

        if self.daemon_mode:
            print("[*] BeaconSentry running in headless DAEMON mode. Press Ctrl+C to stop.", flush=True)
            try:
                while self.is_running:
                    time.sleep(1.0)
            except KeyboardInterrupt:
                pass
            finally:
                self.shutdown()
        else:
            try:
                with Live(self._build_layout(), refresh_per_second=2, screen=True) as live:
                    while self.is_running:
                        time.sleep(0.5)
                        live.update(self._build_layout())
            except KeyboardInterrupt:
                pass
            finally:
                self.shutdown()

    def shutdown(self) -> None:
        """Perform orderly shutdown and offer safe firewall flush."""
        self.is_running = False
        self.sniffer.stop()

        if self.console:
            self.console.print("\n[bold cyan][*] BeaconSentry packet sniffing terminated.[/]")

        quarantined = self.firewall.get_quarantined_ips()
        if quarantined:
            if self.console:
                self.console.print("\n[bold red][!] Quarantined C2 Destinations During This Session:[/]")
                for ip in quarantined:
                    self.console.print(f"    - {ip} (iptables -A OUTPUT -d {ip} -j DROP)")

            should_flush = self.config.auto_flush_on_exit
            if not should_flush and not self.daemon_mode:
                try:
                    resp = input("\n[?] Do you want to FLUSH all BeaconSentry iptables quarantine rules? [y/N]: ")
                    should_flush = resp.strip().lower() in ("y", "yes")
                except (EOFError, KeyboardInterrupt):
                    should_flush = False

            if should_flush:
                count = self.firewall.flush_quarantine()
                if self.console:
                    self.console.print(f"[bold green][✓] Successfully flushed {count} firewall rule(s).[/]")
        else:
            if self.console:
                self.console.print("[green][✓] No hosts were quarantined. Firewall left unmodified.[/]")


def parse_arguments() -> Tuple[argparse.Namespace, BeaconSentryConfig]:
    """Parse command line parameters and merge with config file."""
    parser = argparse.ArgumentParser(
        description="BeaconSentry: Production C2 Beacon Detection & Active Defense",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-c", "--config", type=str, default="/etc/beaconsentry/config.json", help="Path to JSON configuration file")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface (default: any)")
    parser.add_argument("-w", "--window", type=int, default=None, help="Sliding window size (default: 20)")
    parser.add_argument("-q", "--quarantine", action="store_true", help="Enable active iptables containment")
    parser.add_argument("-s", "--search", type=str, default=None, help="Filter/search flows by IP, Port, or Domain")
    parser.add_argument("--dry-run", action="store_true", help="Simulate iptables blocking without executing")
    parser.add_argument("--auto-flush", action="store_true", help="Auto-flush all iptables rules on exit without prompting")
    parser.add_argument("--pcap", action="store_true", help="Automatically dump forensic PCAP files of flagged C2 flows")
    parser.add_argument("--daemon", action="store_true", help="Run in headless daemon mode (ideal for systemd background service)")
    parser.add_argument("--log-dir", type=str, default=None, help="Directory for SIEM incident logs and PCAPs")
    parser.add_argument("--export-config", action="store_true", help="Export default configuration file template and exit")

    args = parser.parse_args()

    # Load file config
    cfg = BeaconSentryConfig.load_from_file(args.config)

    # CLI arguments override config file
    if args.interface: cfg.interface = args.interface
    if args.window: cfg.window_size = args.window
    if args.quarantine: cfg.quarantine_enabled = True
    if args.dry_run: cfg.dry_run = True
    if args.auto_flush: cfg.auto_flush_on_exit = True
    if args.pcap: cfg.dump_c2_pcaps = True
    if args.log_dir: cfg.log_dir = args.log_dir

    return args, cfg


def main():
    args, cfg = parse_arguments()

    if args.export_config:
        cfg.export_default_config(args.config)
        print(f"[✓] Default configuration exported to {args.config}")
        sys.exit(0)

    app = BeaconSentryApp(
        config=cfg,
        search_filter=args.search,
        daemon_mode=args.daemon,
    )

    def sig_handler(sig, frame):
        app.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    app.start()


if __name__ == "__main__":
    main()
