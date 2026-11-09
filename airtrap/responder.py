"""Countermeasures: flag, score, track and (optionally) block attackers.

Design rules
  * NO active attacks / deauth "containment": it is illegal in many jurisdictions.
  * Never block a protected BSSID, an own interface, or anything in never_block
    (attackers forge MACs; blocking spoofed identities would be a self-inflicted DoS).
  * Default mode is `flag` (track + alert). `block` must be enabled explicitly.
"""
import json
import os
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

from . import logger
from .utils import is_randomized, norm_mac

SEV = {"info": 0, "warning": 1, "high": 3, "critical": 5}
IGNORE = {"attacker_flagged", "attacker_blocked", "subscriber_error", "frame_parse_error"}


class Firewall:
    TEMPLATE = """
table inet airtrap {{
  set blocked_macs {{ type ether_addr; flags timeout; }}
  set blocked_ips {{ type ipv4_addr; flags timeout; }}
  chain input {{
    type filter hook input priority -10; policy accept;
    iifname != "{hp}" ether saddr @blocked_macs drop
    iifname != "{hp}" ip saddr @blocked_ips drop
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    iifname != "{hp}" ether saddr @blocked_macs drop
    iifname != "{hp}" ip saddr @blocked_ips drop
  }}
}}
"""

    def __init__(self, hp_iface):
        subprocess.run(["nft", "delete", "table", "inet", "airtrap"], capture_output=True)
        subprocess.run(["nft", "-f", "-"], input=self.TEMPLATE.format(hp=hp_iface or "none"),
                       text=True, check=True, capture_output=True)

    @staticmethod
    def block(mac, ip, secs):
        ok = True
        for setname, val in (("blocked_macs", mac), ("blocked_ips", ip)):
            if val:
                r = subprocess.run(["nft", "add", "element", "inet", "airtrap", setname,
                                    f"{{ {val} timeout {int(secs)}s }}"], capture_output=True)
                ok = ok and r.returncode == 0
        return ok

    @staticmethod
    def cleanup():
        subprocess.run(["nft", "delete", "table", "inet", "airtrap"], capture_output=True)


class Responder:
    def __init__(self, cfg, own_macs=(), hp_iface=None):
        r = cfg["response"]
        self.cfg, self.r = cfg, r
        self.enabled = r["enabled"]
        self.block_mode = r["mode"] == "block"
        self.path = Path(r["state_file"])
        self.lock = threading.RLock()
        self.never = {m.lower() for m in r["never_block"]} | {m.lower() for m in own_macs if m}
        for bssids in cfg["detection"]["protected_networks"].values():
            self.never |= {b.lower() for b in bssids}
        self.attackers = self._load()
        self.fw = None
        if self.enabled and self.block_mode and r["nftables"]:
            try:
                self.fw = Firewall(hp_iface)
                now = time.time()
                for key, a in self.attackers.items():       # restore still-active blocks
                    if a.get("blocked_until", 0) > now:
                        self.fw.block(norm_mac(key), (a["ips"] or [None])[-1], a["blocked_until"] - now)
            except Exception as exc:
                logger.emit("firewall_unavailable", "high", error=str(exc))

    # ---------------------------------------------------------------- state
    def _load(self):
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.attackers, indent=1))
            os.replace(tmp, self.path)
        except OSError:
            pass

    # ---------------------------------------------------------------- main hook
    def handle(self, rec):
        if not self.enabled or rec.get("event") in IGNORE:
            return
        sev = SEV.get(rec.get("severity"), 0)
        mac, ip = norm_mac(rec.get("attacker_mac")), rec.get("attacker_ip")
        key = mac or ip
        if not key or sev == 0:
            return
        now = time.time()
        with self.lock:
            a = self.attackers.setdefault(key, {
                "first_seen": rec["@timestamp"], "score": 0, "events": {}, "ips": [], "hostnames": [],
                "randomized_mac": bool(mac and is_randomized(mac)), "flagged": False})
            a["last_seen"] = rec["@timestamp"]
            a["score"] += sev
            a["events"][rec["event"]] = a["events"].get(rec["event"], 0) + 1
            if ip and ip not in a["ips"]:
                a["ips"].append(ip)
            host = rec.get("hostname")
            if host and host not in a["hostnames"]:
                a["hostnames"].append(host)
            if rec.get("vendor_class"):
                a["dhcp_vendor_class"] = rec["vendor_class"]
            if not a["flagged"]:
                a["flagged"] = True
                logger.emit("attacker_flagged", "high", attacker_mac=mac, attacker_ip=ip,
                            first_event=rec["event"], randomized_mac=a["randomized_mac"])
                self._notify("attacker_flagged", key, a)
            if (self.block_mode and a["score"] >= self.r["block_score"]
                    and a.get("blocked_until", 0) < now and (mac or "") not in self.never):
                self._block(key, mac, a, now)
            self._save()

    def _block(self, key, mac, a, now):
        secs = self.r["block_seconds"]
        a["blocked_until"] = now + secs
        ip = (a["ips"] or [None])[-1]
        actions = []
        if self.fw and self.fw.block(mac, ip, secs):
            actions.append("nftables")
        for ifc in self.r["hostapd_interfaces"]:
            if mac:
                subprocess.run(["hostapd_cli", "-i", ifc, "deny_acl", "ADD_MAC", mac], capture_output=True)
                subprocess.run(["hostapd_cli", "-i", ifc, "disassociate", mac], capture_output=True)
                actions.append(f"hostapd:{ifc}")
        if self.r["hook_command"]:
            env = dict(os.environ, AIRTRAP_MAC=mac or "", AIRTRAP_IP=ip or "",
                       AIRTRAP_SCORE=str(a["score"]), AIRTRAP_SECONDS=str(secs))
            subprocess.Popen(self.r["hook_command"], env=env, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            actions.append("hook_command")
        logger.emit("attacker_blocked", "high", attacker_mac=mac, attacker_ip=ip, score=a["score"],
                    block_seconds=secs, actions=actions)
        self._notify("attacker_blocked", key, a)

    def _notify(self, kind, key, a):
        url = self.r["webhook_url"]
        if not url:
            return
        body = json.dumps({"event": kind, "attacker": key, **a}).encode()

        def post():
            try:
                req = urllib.request.Request(url, body, {"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).read()
            except Exception:
                pass
        threading.Thread(target=post, daemon=True).start()

    def cleanup(self):
        self._save()
        if self.fw:
            self.fw.cleanup()
