import copy

import yaml

DEFAULTS = {
    "runtime_dir": "/run/airtrap",
    "sensor": {
        "interface": "wlan1",          # adapter that supports monitor mode
        "channels": [1, 6, 11],        # channels to hop across (add 36,40,... for 5 GHz)
        "hop_interval": 0.4,
        "manage_monitor_mode": True,
    },
    "logging": {
        "file": "/var/log/airtrap/events.jsonl",
        "stdout": True,
        "max_bytes": 10_485_760,
        "backups": 5,
    },
    "detection": {
        "window_seconds": 5,
        "deauth_threshold": 15,        # deauth/disassoc frames per window per BSSID
        "beacon_flood_threshold": 30,  # NEW BSSIDs per window
        "warmup_seconds": 60,          # ignore beacon-flood heuristic right after start
        "karma_ssid_threshold": 4,     # distinct SSIDs answered by one BSSID
        "handshake_window_seconds": 20,
        "rssi_spoof_delta_db": 12,
        "alert_cooldown": 30,
        # SSID -> list of ALL legitimate BSSIDs (every AP/band/mesh node).  Use `airtrap learn`.
        "protected_networks": {},
    },
    "honeypot": {
        "enabled": False,
        "interface": "wlan2",          # SECOND adapter that supports AP mode
        "ssid": "Linksys_Setup",
        "passphrase": "12345678",      # deliberately weak-looking
        "wps": False,                  # advertise WPS (extra lure)
        "channel": 6,
        "country": "US",               # CHANGE to your country code (regulatory!)
        "gateway": "10.66.0.1",
        "cidr": 24,
        "dhcp_start": "10.66.0.50",
        "dhcp_end": "10.66.0.150",
        "tarpit_port": 9999,
        "tarpit_delay": 5.0,
        "max_connections": 300,
        "max_duration": 3600,
        "payload_bytes": 256,
        "log_http_body": True,         # captured bodies may contain credentials: treat logs as sensitive
    },
    "response": {
        "enabled": True,
        "mode": "flag",                # flag = track only | block = also enforce
        "state_file": "/var/lib/airtrap/attackers.json",
        "block_score": 5,              # severity points: warning=1 high=3 critical=5
        "block_seconds": 3600,
        "nftables": True,
        "hostapd_interfaces": [],      # real APs on THIS host to push deny-lists to
        "webhook_url": "",
        "hook_command": [],            # e.g. ["/usr/local/bin/push-to-router.sh"]
        "never_block": [],
    },
}


def _merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict) and k != "protected_networks":
            _merge(base[k], v)
        else:
            base[k] = v


def load(path=None):
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        with open(path) as fh:
            _merge(cfg, yaml.safe_load(fh) or {})
    return cfg
