import argparse
import shutil
import subprocess
import sys
import threading
from collections import defaultdict
from pathlib import Path

import yaml

from . import __version__, config


def cmd_run(args):
    from .daemon import run
    run(config.load(args.config))


def cmd_learn(args):
    """Passively learn nearby SSID/BSSID pairs and print a protected_networks block."""
    from scapy.all import sniff
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

    from . import monitor
    cfg = config.load(args.config)
    iface = args.interface or cfg["sensor"]["interface"]
    stop, found = threading.Event(), defaultdict(set)
    monitor.enable(iface)
    monitor.ChannelHopper(iface, cfg["sensor"]["channels"], cfg["sensor"]["hop_interval"], stop).start()

    def on(pkt):
        if pkt.haslayer(Dot11Beacon):
            elt = pkt.getlayer(Dot11Elt)
            if elt is not None and elt.ID == 0 and elt.info:
                found[elt.info.decode(errors="replace")].add(pkt[Dot11].addr3.lower())
    try:
        sniff(iface=iface, prn=on, store=False, timeout=args.seconds)
    finally:
        stop.set()
        monitor.disable(iface)
    print("# Keep ONLY your own networks, then paste under detection: in airtrap.yml\n")
    print(yaml.safe_dump({"detection": {"protected_networks": {k: sorted(v) for k, v in sorted(found.items())}}},
                         sort_keys=False))


def cmd_check(args):
    cfg = config.load(args.config)
    ok = True
    for b in ("iw", "ip", "nft", "hostapd", "hostapd_cli", "dnsmasq"):
        found = shutil.which(b)
        print(f"[{'ok' if found else 'MISSING'}] {b}")
        ok &= bool(found)
    for role, iface in (("sensor", cfg["sensor"]["interface"]), ("honeypot", cfg["honeypot"]["interface"])):
        exists = Path(f"/sys/class/net/{iface}").exists()
        print(f"[{'ok' if exists else 'MISSING'}] {role} interface {iface}")
    try:
        out = subprocess.run(["iw", "list"], capture_output=True, text=True).stdout
        print(f"[{'ok' if '* monitor' in out else 'WARN'}] a radio advertises monitor mode")
        print(f"[{'ok' if '* AP' in out else 'WARN'}] a radio advertises AP mode (needed for honeypot)")
    except FileNotFoundError:
        pass
    sys.exit(0 if ok else 1)


def main(argv=None):
    p = argparse.ArgumentParser(prog="airtrap", description="Wi-Fi honeypot + wireless IDS")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("run", cmd_run), ("learn", cmd_learn), ("check", cmd_check)):
        sp = sub.add_parser(name)
        sp.add_argument("-c", "--config", default=None)
        sp.set_defaults(fn=fn)
        if name == "learn":
            sp.add_argument("-i", "--interface")
            sp.add_argument("-t", "--seconds", type=int, default=30)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
