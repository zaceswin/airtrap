import re
from pathlib import Path

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else None


def is_randomized(mac):
    """Locally-administered bit set => probably a privacy/randomized MAC."""
    return bool(int(mac[:2], 16) & 0x02)


def iface_mac(iface):
    try:
        return Path(f"/sys/class/net/{iface}/address").read_text().strip().lower()
    except OSError:
        return None


def arp_lookup(ip):
    try:
        for line in Path("/proc/net/arp").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) >= 4 and f[0] == ip and f[3] != "00:00:00:00:00:00":
                return f[3].lower()
    except OSError:
        pass
    return None
