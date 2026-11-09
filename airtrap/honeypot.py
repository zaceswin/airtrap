"""Fake, enticing AP (hostapd) + isolated DHCP/DNS (dnsmasq) + nftables isolation."""
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import logger
from .utils import arp_lookup, iface_mac

DNS_RE = re.compile(r"query\[(\w+)\] (\S+) from (\S+)")


def _run(cmd, check=False, **kw):
    return subprocess.run(cmd, check=check, capture_output=True, text=True, **kw)


class Honeypot:
    def __init__(self, cfg):
        self.cfg, self.h = cfg, cfg["honeypot"]
        self.iface, self.ssid = self.h["interface"], self.h["ssid"]
        self.bssid = iface_mac(self.iface)
        self.rt = Path(cfg["runtime_dir"])
        self.procs = []

    # ------------------------------------------------------------ config files
    def _hostapd_conf(self):
        h = self.h
        lines = [
            f"interface={self.iface}", "driver=nl80211", f"ssid={h['ssid']}",
            f"country_code={h['country']}", "ieee80211d=1",
            f"hw_mode={'a' if int(h['channel']) > 14 else 'g'}", f"channel={h['channel']}",
            "ieee80211n=1", "wmm_enabled=1", "auth_algs=1", "ap_isolate=1",
            "wpa=2", "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP", f"wpa_passphrase={h['passphrase']}",
            f"ctrl_interface={self.rt}/hostapd", "ctrl_interface_group=0",
            "logger_stdout=-1", "logger_stdout_level=2",
        ]
        if h["wps"]:
            lines += ["eap_server=1", "wps_state=2", "ap_setup_locked=0", "ap_pin=12345670",
                      "device_name=Router", "manufacturer=Generic", "config_methods=label display push_button keypad",
                      "uuid=12345678-9abc-def0-1234-56789abcdef0"]
        p = self.rt / "hostapd.conf"
        p.write_text("\n".join(lines) + "\n")
        return p

    def _dnsmasq_conf(self):
        h = self.h
        mask = ".".join(str((0xffffffff << (32 - h["cidr"]) >> s) & 255) for s in (24, 16, 8, 0))
        lines = [
            f"interface={self.iface}", "bind-interfaces", "no-resolv", "no-hosts", "log-queries",
            "log-facility=-", f"dhcp-range={h['dhcp_start']},{h['dhcp_end']},{mask},12h",
            f"dhcp-option=3,{h['gateway']}", f"dhcp-option=6,{h['gateway']}",
            f"address=/#/{h['gateway']}",                       # every DNS name resolves to us
            f"dhcp-script={self.rt}/dhcp-hook.sh", "pid-file=",
        ]
        p = self.rt / "dnsmasq.conf"
        p.write_text("\n".join(lines) + "\n")
        return p

    def _write_hooks(self):
        pkg_root = str(Path(__file__).resolve().parent.parent)
        for name, kind in (("dhcp-hook.sh", "dhcp"), ("hostapd-hook.sh", "hostapd")):
            p = self.rt / name
            p.write_text(f'#!/bin/sh\nexport PYTHONPATH="{pkg_root}:$PYTHONPATH"\n'
                         f'export AIRTRAP_SOCK="{self.rt}/airtrap.sock"\n'
                         f'exec "{sys.executable}" -m airtrap.hook {kind} "$@"\n')
            p.chmod(0o755)

    def _isolation(self):
        i, tp = self.iface, self.h["tarpit_port"]
        rules = f'''
table inet airtrap_hp {{
  chain input {{
    type filter hook input priority -5; policy accept;
    iifname != "{i}" return
    ct state established,related accept
    udp dport {{ 67, 53 }} accept
    tcp dport {{ 53, {tp} }} accept
    icmp type echo-request accept
    drop
  }}
  chain forward {{
    type filter hook forward priority -5; policy accept;
    iifname "{i}" drop
    oifname "{i}" drop
  }}
}}
table ip airtrap_hp_nat {{
  chain prerouting {{
    type nat hook prerouting priority -100; policy accept;
    iifname "{i}" tcp dport != 53 redirect to :{tp}
  }}
}}
'''
        for t in ("inet airtrap_hp", "ip airtrap_hp_nat"):
            _run(["nft", "delete", "table", *t.split()])
        _run(["nft", "-f", "-"], check=True, input=rules)

    # ------------------------------------------------------------ lifecycle
    def start(self):
        self.rt.mkdir(parents=True, exist_ok=True)
        (self.rt / "hostapd").mkdir(exist_ok=True)
        _run(["rfkill", "unblock", "wifi"])
        _run(["nmcli", "dev", "set", self.iface, "managed", "no"])
        self._write_hooks()
        self._isolation()                                       # isolate BEFORE the AP is visible
        hconf, dconf = self._hostapd_conf(), self._dnsmasq_conf()

        self.procs.append(subprocess.Popen(["hostapd", str(hconf)], stdout=open(self.rt / "hostapd.log", "w"),
                                           stderr=subprocess.STDOUT))
        time.sleep(2.5)
        if self.procs[0].poll() is not None:
            raise RuntimeError(f"hostapd exited; see {self.rt}/hostapd.log (adapter must support AP mode)")
        self.bssid = iface_mac(self.iface)
        _run(["ip", "addr", "flush", "dev", self.iface])
        _run(["ip", "addr", "add", f"{self.h['gateway']}/{self.h['cidr']}", "dev", self.iface], check=True)
        _run(["ip", "link", "set", self.iface, "up"])

        dns = subprocess.Popen(["dnsmasq", "-k", "-C", str(dconf)], stderr=subprocess.PIPE, text=True)
        self.procs.append(dns)
        threading.Thread(target=self._dns_reader, args=(dns,), daemon=True, name="dns").start()
        self.procs.append(subprocess.Popen(
            ["hostapd_cli", "-p", f"{self.rt}/hostapd", "-i", self.iface, "-a", str(self.rt / "hostapd-hook.sh")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        logger.emit("honeypot_started", "info", ssid=self.ssid, bssid=self.bssid,
                    interface=self.iface, channel=self.h["channel"])

    def _dns_reader(self, proc):
        for line in proc.stderr:
            m = DNS_RE.search(line)
            if m:
                ip = m.group(3)
                logger.emit("dns_query", "info", query_type=m.group(1), name=m.group(2),
                            attacker_ip=ip, attacker_mac=arp_lookup(ip))

    def stop(self):
        for p in reversed(self.procs):
            if p.poll() is None:
                p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        for t in ("inet airtrap_hp", "ip airtrap_hp_nat"):
            _run(["nft", "delete", "table", *t.split()])
        _run(["ip", "addr", "flush", "dev", self.iface])
        _run(["nmcli", "dev", "set", self.iface, "managed", "yes"])
        logger.emit("honeypot_stopped", "info")
