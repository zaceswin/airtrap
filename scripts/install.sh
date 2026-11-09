#!/usr/bin/env bash
# Installs airtrap on Debian/Ubuntu/Raspberry Pi OS.  Usage: sudo ./scripts/install.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0"; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX=/opt/airtrap

apt-get update
apt-get install -y python3 python3-venv python3-pip iw iproute2 nftables hostapd dnsmasq rfkill wireless-tools

if [ -z "${AIRTRAP_KEEP_DNSMASQ:-}" ]; then
  # The distro dnsmasq binds *:53 and would collide with the honeypot's private instance.
  systemctl disable --now dnsmasq 2>/dev/null || true
  echo "Disabled the system dnsmasq service (set AIRTRAP_KEEP_DNSMASQ=1 to skip)."
fi

python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --upgrade pip
"$PREFIX/venv/bin/pip" install "$SRC"
ln -sf "$PREFIX/venv/bin/airtrap" /usr/local/bin/airtrap

mkdir -p /etc/airtrap /var/log/airtrap /var/lib/airtrap
[ -f /etc/airtrap/airtrap.yml ] || install -m 600 "$SRC/config/airtrap.example.yml" /etc/airtrap/airtrap.yml
install -m 644 "$SRC/deploy/airtrap.service" /etc/systemd/system/airtrap.service
systemctl daemon-reload
rfkill unblock wifi || true

cat <<MSG

airtrap installed.
  1. Edit /etc/airtrap/airtrap.yml (interface names, country, protected networks)
       sudo airtrap check -c /etc/airtrap/airtrap.yml
       sudo airtrap learn -c /etc/airtrap/airtrap.yml      # discover your BSSIDs
  2. Start:  sudo systemctl enable --now airtrap
  3. Logs:   tail -f /var/log/airtrap/events.jsonl | jq
MSG
