#!/usr/bin/env bash
# ==============================================================================
# BeaconSentry - Enterprise Installation & System-Wide Integration Script
# ==============================================================================
# Installs BeaconSentry as:
# 1. Global terminal CLI (`beaconsentry` & `simulate-c2`)
# 2. Systemd 24/7 background service (`beaconsentry.service`)
# 3. Searchable apps in Kali Application Launcher / Whisker Menu
# 4. Enterprise SIEM logging (/var/log/beaconsentry/incidents.jsonl)
# 5. Forensic PCAP dumper (/var/log/beaconsentry/pcaps/)
# 6. Whitelist & threat intelligence engine (/etc/beaconsentry/config.json)
# ==============================================================================

set -euo pipefail

INSTALL_DIR="/opt/beaconsentry"
CONFIG_DIR="/etc/beaconsentry"
LOG_DIR="/var/log/beaconsentry"
PCAP_DIR="${LOG_DIR}/pcaps"
SYSTEMD_FILE="/etc/systemd/system/beaconsentry.service"

echo "[*] Step 1/6: Installing system dependencies via APT..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-scapy python3-rich python3-numpy iptables net-tools

echo "[*] Step 2/6: Setting up directories and deploying production files..."
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}" "${PCAP_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -f "${SCRIPT_DIR}"/*.py "${INSTALL_DIR}/" 2>/dev/null || true
chmod 755 "${INSTALL_DIR}"/*.py

# Export default configuration if not already present
if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
    python3 "${INSTALL_DIR}/main.py" --export-config -c "${CONFIG_DIR}/config.json" || true
fi

echo "[*] Step 3/6: Installing global CLI runners in /usr/local/bin/..."
cat << "RUNNER" > /usr/local/bin/beaconsentry
#!/usr/bin/env bash
if [[ $EUID -ne 0 ]]; then
    exec sudo python3 /opt/beaconsentry/main.py "$@"
else
    exec python3 /opt/beaconsentry/main.py "$@"
fi
RUNNER

cat << "RUNNER" > /usr/local/bin/simulate-c2
#!/usr/bin/env bash
exec python3 /opt/beaconsentry/simulate_c2.py "$@"
RUNNER

chmod 755 /usr/local/bin/beaconsentry /usr/local/bin/simulate-c2
ln -sf /usr/local/bin/beaconsentry /usr/local/bin/beacon-sentry

echo "[*] Step 4/6: Configuring Systemd 24/7 background daemon service..."
cat << "SERVICE" > "${SYSTEMD_FILE}"
[Unit]
Description=BeaconSentry - Autonomous C2 Detection & Active Defense Engine
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/beaconsentry
ExecStart=/usr/local/bin/beaconsentry --daemon -q --log-dir /var/log/beaconsentry
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=beaconsentry
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload

echo "[*] Step 5/6: Installing Desktop search bar entries & custom icons..."
mkdir -p /usr/share/icons/hicolor/scalable/apps

# Shield Icon for BeaconSentry
cat << "SVG" > /usr/share/icons/hicolor/scalable/apps/beaconsentry.svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <path d="M64 8 L114 26 C114 74 64 120 64 120 C64 120 14 74 14 26 Z" fill="#0d1b2a" stroke="#00f2fe" stroke-width="4"/>
  <circle cx="64" cy="60" r="14" fill="#ff0844"/>
  <circle cx="64" cy="60" r="26" fill="none" stroke="#00f2fe" stroke-width="2.5" stroke-dasharray="6,4"/>
  <circle cx="64" cy="60" r="38" fill="none" stroke="#4facfe" stroke-width="1.5" stroke-dasharray="4,6"/>
</svg>
SVG

# Red Crosshair Icon for C2 Simulator
cat << "SVG" > /usr/share/icons/hicolor/scalable/apps/simulate-c2.svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <circle cx="64" cy="64" r="50" fill="#1a0000" stroke="#ff0844" stroke-width="4"/>
  <circle cx="64" cy="64" r="32" fill="none" stroke="#ff4757" stroke-width="2" stroke-dasharray="6,4"/>
  <circle cx="64" cy="64" r="10" fill="#ff0844"/>
  <line x1="64" y1="6" x2="64" y2="122" stroke="#ff4757" stroke-width="2"/>
  <line x1="6" y1="64" x2="122" y2="64" stroke="#ff4757" stroke-width="2"/>
</svg>
SVG

# Desktop Entry for BeaconSentry Defender
cat << "DESKTOP" > /usr/share/applications/beaconsentry.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=BeaconSentry
GenericName=C2 Beacon Detection & Active Defense
Comment=Statistical C2 Beacon Detection & iptables Active Defense
Exec=sudo /usr/local/bin/beaconsentry -q
Icon=beaconsentry
Terminal=true
Categories=09-forensics;10-reporting;08-sniffing-spoofing;01-info-gathering;Security;Network;System;
Keywords=beacon;beaconsentry;c2;cobaltstrike;sliver;network;ids;sniff;iptables;defense;firewall;
StartupNotify=true
X-Kali-Package=beaconsentry
DESKTOP

# Desktop Entry for BeaconSentry C2 Simulator
cat << "DESKTOP" > /usr/share/applications/simulate-c2.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=BeaconSentry C2 Simulator
GenericName=Adversary C2 Beacon Simulator
Comment=Simulate Cobalt Strike, Sliver & Metasploit Jittered Beaconing
Exec=simulate-c2 -t 127.0.0.1 -p 4444 -i 5.0 -j 0.15
Icon=simulate-c2
Terminal=true
Categories=08-exploitation-tools;09-forensics;Security;Network;System;
Keywords=simulator;simulate;c2;beacon;cobaltstrike;sliver;metasploit;redteam;
StartupNotify=true
X-Kali-Package=beaconsentry
DESKTOP

chmod 644 /usr/share/applications/beaconsentry.desktop /usr/share/applications/simulate-c2.desktop
update-desktop-database /usr/share/applications || true
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true

echo "[*] Step 6/6: Adding tab completions..."
mkdir -p /etc/bash_completion.d
cat << "COMP" > /etc/bash_completion.d/beaconsentry
complete -W "-i --interface -w --window -q --quarantine -s --search --pcap --daemon --dry-run --auto-flush --export-config -c --config" beaconsentry beacon-sentry
COMP

echo ""
echo "=========================================================================="
echo " [✓] BEACONSENTRY ENTERPRISE INSTALLATION COMPLETE!"
echo "=========================================================================="
echo " • Configuration File  : /etc/beaconsentry/config.json"
echo " • SIEM JSONL Log File : /var/log/beaconsentry/incidents.jsonl"
echo " • Forensic PCAPs Dir  : /var/log/beaconsentry/pcaps/"
echo " • Systemd 24/7 Daemon : sudo systemctl start beaconsentry"
echo " • Interactive TUI     : beaconsentry -q (or search 'beacon' in menu)"
echo " • Adversary Simulator : simulate-c2 (or search 'simulator' in menu)"
echo "=========================================================================="
