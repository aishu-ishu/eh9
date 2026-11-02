"""
BeaconSentry - Adversary C2 Beaconing & Traffic Simulator
Author: Elite Cybersecurity Defensive Engineer
Module: simulate_c2.py

Description:
    Adversary emulation script designed for validation, blue-team drills,
    and live demonstrations of BeaconSentry. Simulates realistic Command and Control (C2)
    beaconing profiles (Cobalt Strike, Sliver, Metasploit) with configurable base
    sleep intervals and randomized jitter percentages. Also supports human-traffic
    simulation and a built-in mock listener for isolated laboratory testing.
"""

from __future__ import annotations

import argparse
import math
import random
import socket
import sys
import threading
import time
from typing import List


class C2Simulator:
    """
    Simulates outbound Command and Control beaconing connections.
    Calculates empirical timing metrics on the fly to verify mathematical alignment
    with BeaconSentry's statistical detection thresholds.
    """

    def __init__(
        self,
        target_ip: str = "127.0.0.1",
        target_port: int = 4444,
        interval: float = 5.0,
        jitter: float = 0.15,
        total_beacons: int = 0,
        traffic_type: str = "c2",
    ):
        self.target_ip: str = target_ip
        self.target_port: int = target_port
        self.interval: float = max(0.1, interval)
        self.jitter: float = max(0.0, min(1.0, jitter))
        self.total_beacons: int = total_beacons
        self.traffic_type: str = traffic_type.lower()

        self.sent_count: int = 0
        self.timestamps: List[float] = []
        self.deltas: List[float] = []

    def _compute_next_sleep(self) -> float:
        """
        Calculate sleep duration based on traffic profile:
        - C2 beacon: Interval with uniform jitter +/- (jitter * Interval)
        - Human traffic: Highly variable random interval with high variance
        - Constant beacon: Zero jitter
        """
        if self.traffic_type == "human":
            # Pareto or exponential distribution mimicking sporadic browsing
            return random.expovariate(1.0 / self.interval) + random.uniform(2.0, 15.0)

        elif self.traffic_type == "constant":
            return self.interval

        else:  # Standard C2 with jitter
            jitter_range = self.interval * self.jitter
            delta_offset = random.uniform(-jitter_range, jitter_range)
            return max(0.5, self.interval + delta_offset)

    def _transmit_beacon(self) -> Tuple[bool, float]:
        """
        Attempt a TCP connection to the target endpoint.
        This forces the Linux kernel network stack to generate an outbound TCP SYN packet.
        """
        start_ts = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        connected = False
        try:
            # connect_ex triggers a SYN packet even if the target port is closed or listening
            res = s.connect_ex((self.target_ip, self.target_port))
            connected = (res == 0)
        except socket.timeout:
            connected = False
        except socket.error:
            connected = False
        finally:
            try:
                s.close()
            except Exception:
                pass

        elapsed = time.time() - start_ts
        return connected, elapsed

    def run(self) -> None:
        """Execute the beaconing loop."""
        print("=" * 70)
        print(" [!] BEACONSENTRY C2 ADVERSARY EMULATOR")
        print("=" * 70)
        print(f" [*] Target Destination : {self.target_ip}:{self.target_port}")
        print(f" [*] Emulation Profile  : {self.traffic_type.upper()}")
        print(f" [*] Base Sleep Interval: {self.interval:.2f} seconds")
        print(f" [*] Jitter Variation   : ±{self.jitter * 100:.1f}%")
        if self.total_beacons > 0:
            print(f" [*] Beacon Limit       : {self.total_beacons} iterations")
        else:
            print(" [*] Beacon Limit       : Infinite (Press Ctrl+C to stop)")
        print("=" * 70)
        print(f"{'Seq':<5} | {'Timestamp':<10} | {'Delta':<8} | {'Mean (μ)':<9} | {'StdDev (σ)':<10} | {'CV (σ/μ)':<8} | {'Status'}")
        print("-" * 70)

        try:
            while True:
                now = time.time()
                self.timestamps.append(now)
                self.sent_count += 1

                if len(self.timestamps) > 1:
                    delta = self.timestamps[-1] - self.timestamps[-2]
                    self.deltas.append(delta)

                # Compute running statistics
                if len(self.deltas) >= 1:
                    n = len(self.deltas)
                    mean_val = sum(self.deltas) / n
                    variance = sum((d - mean_val) ** 2 for d in self.deltas) / n
                    std_dev = math.sqrt(variance)
                    cv = (std_dev / mean_val) if mean_val > 0 else 0.0
                else:
                    delta = 0.0
                    mean_val = 0.0
                    std_dev = 0.0
                    cv = 0.0

                # Transmit outbound TCP connection initiation (SYN)
                connected, _ = self._transmit_beacon()
                status_str = "ACK/ESTAB" if connected else "SYN SENT"

                # Formatting output
                time_str = time.strftime("%H:%M:%S", time.localtime(now))
                delta_str = f"{delta:.2f}s" if self.sent_count > 1 else "-"
                mean_str = f"{mean_val:.2f}s" if self.sent_count > 1 else "-"
                std_str = f"±{std_dev:.2f}s" if self.sent_count > 1 else "-"
                cv_str = f"{cv:.3f}" if self.sent_count > 1 else "-"

                # Highlight when threshold matches BeaconSentry
                if len(self.deltas) >= 4 and cv <= 0.30 and 5.0 <= mean_val <= 300.0:
                    threat_indicator = f"-> [TRIGGER: C2 BEACON CV={cv:.3f} <= 0.30]"
                elif len(self.deltas) >= 4 and cv <= 0.50 and 5.0 <= mean_val <= 300.0:
                    threat_indicator = f"-> [TRIGGER: SUSPICIOUS CV={cv:.3f}]"
                else:
                    threat_indicator = ""

                print(
                    f"{self.sent_count:<5} | {time_str:<10} | {delta_str:<8} | "
                    f"{mean_str:<9} | {std_str:<10} | {cv_str:<8} | {status_str} {threat_indicator}"
                )

                if 0 < self.total_beacons <= self.sent_count:
                    print("-" * 70)
                    print(f"[✓] Completed {self.sent_count} scheduled beacons.")
                    break

                # Calculate next sleep interval
                next_sleep = self._compute_next_sleep()
                time.sleep(next_sleep)

        except KeyboardInterrupt:
            print("\n[-] Beaconing interrupted by user.")


def run_mock_server(host: str = "0.0.0.0", port: int = 4444) -> None:
    """Run a lightweight mock C2 listener to accept incoming test beacons."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
        server.listen(5)
        print(f"[+] Mock C2 Listener listening on {host}:{port}")
        while True:
            client, addr = server.accept()
            print(f"[+] Inbound beacon received from {addr[0]}:{addr[1]}")
            client.close()
    except KeyboardInterrupt:
        print("\n[-] Mock listener terminated.")
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(
        description="Simulate C2 beaconing activity with jitter for BeaconSentry testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-t", "--target",
        type=str,
        default="127.0.0.1",
        help="Target C2 server destination IP (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=4444,
        help="Target C2 destination port (default: 4444)",
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=5.0,
        help="Base beacon interval in seconds (default: 5.0)",
    )
    parser.add_argument(
        "-j", "--jitter",
        type=float,
        default=0.15,
        help="Jitter percentage +/- (e.g. 0.15 for 15%% jitter, default: 0.15)",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Total number of beacons to send (default: 0 for infinite)",
    )
    parser.add_argument(
        "--profile",
        choices=["c2", "human", "constant"],
        default="c2",
        help="Traffic profile: 'c2' (jittered periodic), 'human' (aperiodic), or 'constant'",
    )
    parser.add_argument(
        "--listener",
        action="store_true",
        help="Run in mock listener mode to accept beacon connections",
    )

    args = parser.parse_args()

    if args.listener:
        run_mock_server(host=args.target, port=args.port)
    else:
        sim = C2Simulator(
            target_ip=args.target,
            target_port=args.port,
            interval=args.interval,
            jitter=args.jitter,
            total_beacons=args.count,
            traffic_type=args.profile,
        )
        sim.run()


if __name__ == "__main__":
    main()
