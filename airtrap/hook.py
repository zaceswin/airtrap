"""Entry point used by dnsmasq (--dhcp-script) and hostapd_cli (-a) to report events."""
import os
import sys

from . import ipc
from .utils import norm_mac

HOSTAPD_EVENTS = {
    "AP-STA-CONNECTED": ("honeypot_sta_connected", "high"),
    "AP-STA-POSSIBLE-PSK-MISMATCH": ("psk_guess_attempt", "high"),
    "EAPOL-4WAY-HS-COMPLETED": ("honeypot_handshake_completed", "high"),
    "AP-STA-DISCONNECTED": ("honeypot_sta_disconnected", "info"),
}


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else ""
    if kind == "dhcp" and len(sys.argv) >= 5:
        action, mac, ip = sys.argv[2:5]
        host = sys.argv[5] if len(sys.argv) > 5 else ""
        if action in ("add", "old"):
            ipc.send({
                "event": "dhcp_lease", "severity": "warning", "action": action,
                "attacker_mac": norm_mac(mac), "attacker_ip": ip, "hostname": host,
                "vendor_class": os.environ.get("DNSMASQ_VENDOR_CLASS", ""),
            })
    elif kind == "hostapd" and len(sys.argv) >= 4:
        parts = " ".join(sys.argv[3:]).split()
        if parts and parts[0] in HOSTAPD_EVENTS:
            name, sev = HOSTAPD_EVENTS[parts[0]]
            mac = norm_mac(parts[1]) if len(parts) > 1 else None
            ipc.send({"event": name, "severity": sev, "interface": sys.argv[2], "attacker_mac": mac})


if __name__ == "__main__":
    main()
