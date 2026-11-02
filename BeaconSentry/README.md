# BeaconSentry: Real-Time C2 Statistical Detection & Autonomous Active Defense

```
  ____                                ____             _                 
 | __ )  ___  __ _  ___ ___  _ __   / ___|  ___ _ __ | |_ _ __ _   _   
 |  _ \ / _ \/ _` |/ __/ _ \| '_ \  \___ \ / _ \ '_ \| __| '__| | | |  
 | |_) |  __/ (_| | (_| (_) | | | |  ___) |  __/ | | | |_| |  | |_| |  
 |____/ \___|\__,_|\___\___/|_| |_| |____/ \___|_| |_|\__|_|   \__, |  
                                                               |___/   
   Autonomous C2 Beacon Detection Engine & Active iptables Quarantine   
```

---

## 1. Executive Summary & Problem Context

Modern adversary simulation frameworks and stealth malware—such as **Cobalt Strike**, **Sliver**, **Mythic**, and **Metasploit**—rely on periodic outbound "beaconing" back to external Command and Control (C2) servers to maintain persistent control, receive staged tasks, and exfiltrate credentials.

To evade signature-based intrusion detection systems (IDS/IPS) and deep packet inspection (DPI):
- Adversaries wrap payloads inside encrypted protocols (**HTTPS/TLS**, **DNS over HTTPS**, **mTLS**, **WebSockets**).
- Malware authors inject **"jitter"** (pseudo-random sleep offsets, e.g., $\pm 10\%$ to $\pm 30\%$) into sleep loops to evade fixed-interval detection.

However, **the physics of time remain invariant**. Despite TLS encryption and jitter, the inter-arrival delta sequence $\Delta t = t_i - t_{i-1}$ of outbound connection attempts exhibits an unmistakable mathematical fingerprint: **stochastic stationarity with low variance**. In contrast, human network activity (browsing, chat, media streaming) is aperiodic, bursty, and follows heavy-tailed (Pareto/Poisson) distributions with high dispersion.

**BeaconSentry** sniffs outbound connection handshakes (TCP SYN packets) directly off the wire, maintains sliding time windows per flow (`Dst_IP:Dst_Port`), computes real-time descriptive statistics (Mean $\mu$, Standard Deviation $\sigma$, and Coefficient of Variation $CV = \frac{\sigma}{\mu}$), and autonomously drops malicious egress traffic via Linux `iptables` containment rules.

---

## 2. Mathematical & Algorithmic Foundation

### 2.1 Sliding Window Flow Tracking
For each unique destination tuple $(\text{Dst\_IP}, \text{Dst\_Port})$, BeaconSentry tracks a sliding temporal history of connection timestamps:
$$T = \{t_1, t_2, t_3, \dots, t_k\} \quad (k \le W)$$
where $W$ is the sliding window size (default: 20 bursts).

### 2.2 Inter-Arrival Delta Calculation
For consecutive connection bursts in the sliding window, the inter-arrival intervals are computed as:
$$\Delta_i = t_i - t_{i-1} \quad \text{for } i \in \{2, 3, \dots, k\}$$
Total observed intervals: $N = k - 1$.

### 2.3 Statistical Indicators
1. **Sample Mean Interval ($\mu$):**
   $$\mu = \frac{1}{N} \sum_{i=1}^{N} \Delta_i$$
2. **Standard Deviation / Jitter Spread ($\sigma$):**
   $$\sigma = \sqrt{\frac{1}{N} \sum_{i=1}^{N} (\Delta_i - \mu)^2}$$
3. **Coefficient of Variation ($CV$):**
   $$CV = \frac{\sigma}{\mu}$$
   The Coefficient of Variation normalizes the jitter dispersion relative to the base sleep interval, providing a scale-invariant metric.

### 2.4 Mathematical Proof: Why Jittered C2 Triggers $CV \le 0.30$
Suppose an adversary sets a base sleep interval $I_0 = 10\text{s}$ with a jitter of $J = \pm 15\%$ ($0.15$). The sleep duration $\Delta$ follows a continuous uniform distribution:
$$\Delta \sim \mathcal{U}\left(I_0(1 - J), I_0(1 + J)\right) = \mathcal{U}(8.5, 11.5)$$

- Expected Value:
  $$\mathbb{E}[\Delta] = \mu = \frac{a + b}{2} = 10.0\text{s}$$
- Theoretical Variance:
  $$\mathrm{Var}(\Delta) = \sigma^2 = \frac{(b - a)^2}{12} = \frac{(11.5 - 8.5)^2}{12} = \frac{3.0^2}{12} = \frac{9.0}{12} = 0.75$$
- Standard Deviation:
  $$\sigma = \sqrt{0.75} \approx 0.866\text{s}$$
- Coefficient of Variation:
  $$CV = \frac{\sigma}{\mu} = \frac{0.866}{10.0} \approx \mathbf{0.0866}$$

Even with $30\%$ jitter ($J = 0.30$), the theoretical CV is:
$$\sigma = \sqrt{\frac{(6.0)^2}{12}} = \sqrt{3.0} \approx 1.732\text{s} \implies CV = \frac{1.732}{10.0} = \mathbf{0.1732} \ll 0.30$$

Adversaries must apply over $52\%$ random jitter before $CV$ exceeds $0.30$, which significantly impairs C2 operational cadence.

### 2.5 Threat Classification Decision Engine

| Classification | Burst Count | Mean Interval ($\mu$) | Coefficient of Variation ($CV$) | Automated Action |
|---|---|---|---|---|
| **High Confidence C2 Beacon** | $\ge 5$ | $5.0\text{s} \le \mu \le 300.0\text{s}$ | $CV \le 0.30$ | Issue `iptables` DROP containment rule |
| **Suspicious Periodic Traffic** | $\ge 5$ | $5.0\text{s} \le \mu \le 300.0\text{s}$ | $0.30 < CV \le 0.50$ | Log warning; elevate watch state |
| **Normal Traffic** | $\ge 5$ | Any | $CV > 0.50$ or $\mu \notin [5, 300]$ | Normal passive monitoring |
| **Collecting Data** | $< 5$ | N/A | N/A | Accumulate baseline bursts |

---

## 3. Directory & File Structure

```
BeaconSentry/
├── analyzer.py        # Core mathematical detection engine (sliding window, mu, sigma, CV)
├── firewall.py        # Kali Linux active defense controller (iptables wrapper & cleanup)
├── sniffer.py         # Packet capture engine (Scapy BPF SYN sniffer)
├── main.py            # CLI entry point with Rich live dashboard & search bar
├── simulate_c2.py     # Adversary C2 beaconing & traffic simulator
├── requirements.txt   # Python dependency specifications
└── README.md          # Comprehensive technical documentation & Kali runbook
```

---

## 4. Kali Linux Installation & System-Wide Integration

BeaconSentry can be installed system-wide on Kali Linux so that:
1. **It appears in the Kali Linux Application Search Bar** (press Super/Windows key and search `beacon`).
2. **It can be executed globally from any terminal** simply by typing `beaconsentry` or `simulate-c2`.

### 4.1 Automated 1-Command System-Wide Install
Run the installer with root privileges:
```bash
cd ~/BeaconSentry
chmod +x install.sh
sudo ./install.sh
```

This automatically:
- Installs all dependencies (`python3-scapy`, `python3-rich`, `python3-numpy`, `iptables`, `net-tools`) via `apt`.
- Deploys the code to `/opt/beaconsentry/`.
- Links global binaries: `/usr/local/bin/beaconsentry` and `/usr/local/bin/simulate-c2`.
- Installs the `.desktop` launcher and high-res vector icon into `/usr/share/applications/` and `/usr/share/icons/`.
- Registers Zsh and Bash tab autocompletion.
- Updates Kali's application desktop database.

---

## 5. Live Demonstration Guide (Terminal & Search Bar)

### 5.1 Launching from Kali Linux Application Search Bar
1. Press the **`Super` (Windows)** key or click the Kali dragon menu icon in the top-left corner.
2. In the search bar, type:
   ```text
   beacon
   ```
   or
   ```text
   beaconsentry
   ```
3. Click the **BeaconSentry** application icon.
4. It launches inside a dedicated terminal running active quarantine defense (`-q`) with the live telemetry UI!

---

### 5.2 Launching Globally from Any Terminal

Because BeaconSentry is registered in your system `PATH`, you do **not** need to `cd` into any folder. You can open any terminal tab and run:

#### Terminal 1 — Start Mock C2 Listener
```bash
simulate-c2 --listener -t 0.0.0.0 -p 4444
```

#### Terminal 2 — Run BeaconSentry with Active Quarantine
```bash
# Passive monitoring on default interface:
beaconsentry

# Active defense with automated iptables quarantine on eth0:
beaconsentry -i eth0 -q

# Lab testing over loopback:
beaconsentry -i lo --loopback -q

# Live filtering with the Terminal Search Bar:
beaconsentry -i eth0 -q -s 4444
```

#### Terminal 3 — Execute the Jittered C2 Beacon Simulation
```bash
simulate-c2 -t 127.0.0.1 -p 4444 -i 5.0 -j 0.15
```
*Notes on CLI flags:*
- `-i lo`: Monitors the loopback interface for local VM simulation. In production, use your physical interface (e.g., `-i eth0` or omit `-i` for auto-detection).
- `--loopback`: Instructs BeaconSentry to inspect localhost packets during lab drills.
- `-q` or `--quarantine`: Enables autonomous execution of `iptables -A OUTPUT -d <ip> -j DROP`.
- `-s` or `--search`: Filter flows in the UI search bar (e.g., `-s 4444` or `-s 192.168`).

BeaconSentry renders the **Rich Live Dashboard**:
- Top telemetry panel (Packets Inspected, Tracked Flows, Flagged C2 Channels, Quarantine Status).
- Search Bar panel displaying active search criteria.
- Real-time Flow Table displaying destination, burst count, mean delta, jitter, CV, and classification badge.
- Bottom Incident Alert & Containment Log.

---

### Terminal 3: Launch Adversary C2 Beaconing Simulation
In a third terminal, initiate the simulated C2 beacon:
```bash
python3 simulate_c2.py -t 127.0.0.1 -p 4444 -i 5.0 -j 0.15
```
*Parameters:*
- `-t 127.0.0.1`: Target C2 IP.
- `-p 4444`: Target C2 port.
- `-i 5.0`: 5.0-second base sleep interval.
- `-j 0.15`: $\pm 15\%$ random jitter.

#### What Happens Step-by-Step:
1. **Bursts 1-4:** BeaconSentry records packet timestamps. The flow table displays `GATHERING (x/5)` while baseline intervals accumulate.
2. **Burst 5:** BeaconSentry computes the statistical metrics:
   $$\mu \approx 5.0\text{s}, \quad \sigma \approx \pm 0.43\text{s}, \quad CV \approx 0.086 \le 0.30$$
3. **Detection Triggered:** Threat classification immediately transitions to **`[bold white on red] C2 BEACON [/]`**.
4. **Active Defense:** Because `-q` is enabled, BeaconSentry issues:
   ```bash
   iptables -A OUTPUT -d 127.0.0.1 -j DROP
   ```
   *(Note: For safety on loopback, BeaconSentry will warn or isolate dummy target IPs. To test live kernel dropping without disrupting localhost, use a secondary test IP as shown below).*
5. The Live UI reflects `BLOCKED [DROP]` and logs the incident in the alerts pane.

---

## 6. Testing with Non-Loopback Target IPs (Full Kernel Drop Verification)

To observe the Linux kernel dropping packets in real time:

### Step 1: Assign a Dummy Interface Alias
```bash
sudo ip addr add 192.168.99.100/32 dev eth0
```

### Step 2: Run BeaconSentry on `eth0` with Active Containment
```bash
sudo python3 main.py -i eth0 -q
```

### Step 3: Run the C2 Simulator against the Target IP
```bash
python3 simulate_c2.py -t 192.168.99.100 -p 4444 -i 5.0 -j 0.15
```

### Step 4: Verify the Kernel `iptables` Drop Rule
In another terminal, inspect the active kernel firewall table:
```bash
sudo iptables -L OUTPUT -v -n
```
*You will observe the newly created rule:*
```text
Chain OUTPUT (policy ACCEPT 120 packets, 18K bytes)
 pkts bytes target     prot opt in     out     source               destination         
    6   360 DROP       all  --  *      *       0.0.0.0/0            192.168.99.100      
```
Notice that outbound packets to `192.168.99.100` are intercepted and discarded directly inside the Linux network stack!

---

## 7. Using the Search Bar & Flow Filter

BeaconSentry features a dedicated Search Bar widget in the terminal interface.

### Search by Destination IP:
```bash
sudo python3 main.py -i eth0 -s 192.168.99.100
```

### Search by Destination Port:
```bash
sudo python3 main.py -i eth0 -s 4444
```

### Search by Threat Classification:
```bash
sudo python3 main.py -i eth0 -s beacon
```

The search bar dynamically highlights matching flows and suppresses irrelevant baseline traffic.

---

## 8. Graceful Teardown & Firewall Cleanup

BeaconSentry implements signal handlers (`SIGINT` / `SIGTERM`) to prevent orphan firewall rules:

1. Press **`Ctrl+C`** in the BeaconSentry console.
2. The sniffer halts packet ingestion cleanly.
3. BeaconSentry outputs a security audit report of all IPs quarantined during the session:
   ```text
   [*] BeaconSentry packet sniffing terminated.

   [!] Quarantined C2 Destinations During This Session:
   ┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
   ┃ Quarantined IP Address ┃ Applied iptables Rule                     ┃ Status           ┃
   ┣━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━━┫
   ┃ 192.168.99.100         ┃ iptables -A OUTPUT -d 192.168.99.100 -j DROP ┃ ACTIVE IN KERNEL ┃
   ┗━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━┛

   [?] Do you want to FLUSH all BeaconSentry iptables quarantine rules? [y/N]: y
   [*] Flushing quarantine rules from iptables OUTPUT chain...
       [-] Unblocking 192.168.99.100: Successfully deleted OUTPUT DROP rule
   [✓] Successfully flushed 1 firewall rule(s).
   ```
4. Enter `y` to flush all rules, or `n` to persist containment.
5. In automated environments, use `--auto-flush` to flush rules automatically on termination.

---

## 9. Contrast Testing: Normal Human Traffic vs. C2

To verify that BeaconSentry avoids false positives on erratic human-generated traffic, run the simulator with `--profile human`:
```bash
python3 simulate_c2.py -t 192.168.99.100 -p 8080 -i 5.0 --profile human
```
*Observed Metrics:*
- $\mu = 14.82\text{s}$
- $\sigma = \pm 18.25\text{s}$
- $CV = \frac{18.25}{14.82} = \mathbf{1.231} > 0.50$
- **Classification:** `NORMAL TRAFFIC` (Green badge; zero quarantine action).

---

## 10. Real-World Enterprise & SOC Capabilities

BeaconSentry includes features designed for deployment in production environments and integration with Security Operations Centers (SOC):

### 10.1 Structured SIEM Export (Elastic Common Schema / JSONL)
BeaconSentry streams structured security incident events to `/var/log/beaconsentry/incidents.jsonl` in **Elastic Common Schema (ECS)**. These logs are ingestible by **Wazuh, Splunk, Elastic Security, and Microsoft Sentinel**:
```json
{
  "@timestamp": "2026-10-24T14:25:38.120Z",
  "event": {
    "kind": "alert",
    "category": ["network", "intrusion_detection"],
    "action": "c2_beacon_identified",
    "severity": 9
  },
  "threat": {
    "framework": "MITRE ATT&CK",
    "technique": {"id": "T1071", "name": "Application Layer Protocol", "subtechnique": "C2 Periodic Beaconing"},
    "tactic": {"id": "TA0011", "name": "Command and Control"}
  },
  "destination": {"ip": "1.1.1.1", "port": 443, "domain": "one.one.one.one"},
  "beaconsentry": {
    "classification": "High Confidence C2 Beacon",
    "burst_count": 5,
    "mean_interval_sec": 5.16,
    "jitter_std_dev_sec": 0.06,
    "coefficient_of_variation": 0.011,
    "quarantined": true,
    "firewall_rule": "iptables -A OUTPUT -d 1.1.1.1 -j DROP"
  }
}
```

### 10.2 Automated Forensic PCAP Capture (`--pcap`)
When `--pcap` is enabled, BeaconSentry automatically dumps the raw network packets of the flagged C2 flow to `/var/log/beaconsentry/pcaps/c2_<IP>_<port>_<timestamp>.pcap`. These PCAP files can be opened in **Wireshark** or **NetworkMiner** to extract:
- Cobalt Strike Malleable C2 profiles.
- HTTP Request Headers and URI parameters.
- Encrypted TLS Client Hello signatures and JA3 fingerprints.

### 10.3 Background 24/7 Monitoring via Systemd Service
To run BeaconSentry permanently in the background without keeping a terminal open:
```bash
# Start background service:
sudo systemctl start beaconsentry

# Enable service on boot:
sudo systemctl enable beaconsentry

# Inspect real-time service logs:
sudo journalctl -u beaconsentry -f
```

### 10.4 Whitelisting Policy Configuration
Edit `/etc/beaconsentry/config.json` to configure trusted CIDR ranges and endpoints (e.g. corporate VPNs, update servers, NTP):
```json
{
    "whitelist_ips": ["127.0.0.1", "::1", "10.0.0.1"],
    "whitelist_cidrs": ["192.168.1.0/24"],
    "whitelist_ports": [123],
    "quarantine_enabled": true,
    "dump_c2_pcaps": true
}
```

---

## 11. CLI Reference Summary

```text
usage: main.py [-h] [-i INTERFACE] [-w WINDOW] [-q] [-s SEARCH]
               [--min-bursts MIN_BURSTS] [--min-interval MIN_INTERVAL]
               [--max-interval MAX_INTERVAL] [--cv-threshold CV_THRESHOLD]
               [--suspicious-cv SUSPICIOUS_CV] [--loopback] [--dry-run]
               [--bpf BPF] [--auto-flush]

options:
  -h, --help            show this help message and exit
  -i, --interface       Network interface (e.g. eth0, wlan0, lo, any)
  -w, --window          Sliding window size of timestamps per flow (default: 20)
  -q, --quarantine      Enable active defense: drops outbound traffic to flagged C2 via iptables
  -s, --search          Filter flows by destination IP, port, or classification
  --min-bursts          Minimum connection bursts required to establish baseline (default: 5)
  --min-interval        Minimum mean interval in seconds for C2 heuristic (default: 5.0)
  --max-interval        Maximum mean interval in seconds for C2 heuristic (default: 300.0)
  --cv-threshold        Maximum CV threshold for High Confidence C2 (default: 0.30)
  --suspicious-cv       Maximum CV threshold for Suspicious Traffic (default: 0.50)
  --loopback            Include loopback addresses (127.0.0.1) in packet monitoring
  --dry-run             Simulate iptables blocking without modifying kernel rules
  --bpf BPF             Override default BPF capture filter
  --auto-flush          Automatically flush all iptables rules on exit without prompt
```
