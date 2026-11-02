#!/usr/bin/env bash
# ==============================================================================
# BeaconSentry - Kali Linux System-Wide Uninstaller
# ==============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo -e "\033[0;31m[ERROR] This uninstaller must be run as root.\033[0m"
   echo -e "Please run with: sudo ./uninstall.sh"
   exit 1
fi

echo "[*] Removing BeaconSentry system files..."

# Remove global binaries
rm -f /usr/local/bin/beaconsentry
rm -f /usr/local/bin/beacon-sentry
rm -f /usr/local/bin/simulate-c2
rm -f /usr/local/bin/beaconsentry-sim

# Remove desktop launcher & icon
rm -f /usr/share/applications/beaconsentry.desktop
rm -f /usr/share/icons/hicolor/scalable/apps/beaconsentry.svg

# Remove completions
rm -f /etc/bash_completion.d/beaconsentry
rm -f /usr/share/zsh/vendor-completions/_beaconsentry

# Remove installation directory
rm -rf /opt/beaconsentry

# Update desktop database
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi

echo "[✓] BeaconSentry uninstalled successfully."
