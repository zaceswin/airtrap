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
    if not Path(f"/sys/class/net/{iface}").exists():
        sys.exit(f"Interface {iface} not found. Run `iw dev` and set sensor.interface in the config.")
    stop, found, frames = threading.Event(), defaultdict(set), [0]
    monitor.enable(iface)
    monitor.ChannelHopper(iface, cfg["sensor"]["channels"], cfg["sensor"]["hop_interval"], stop).start()

    def on(pkt):
        frames[0] += 1
        if pkt.haslayer(Dot11Beacon):
            elt = pkt.getlayer(Dot11Elt)
            if elt is not None and elt.ID == 0 and elt.info:
                found[elt.info.decode(errors="replace")].add(pkt[Dot11].addr3.lower())
    try:
        sniff(iface=iface, prn=on, store=False, timeout=args.seconds)
    finally:
        stop.set()
        monitor.disable(iface)
    if not frames[0]:
        print(f"WARNING: no frames captured on {iface}. Check `iw dev {iface} info` shows type monitor, "
              "stop NetworkManager/wpa_supplicant, and try a USB adapter.", file=sys.stderr)
    elif not found:
        print(f"{frames[0]} frames seen but no beacons: add your channels (e.g. 36,40,44,48) to sensor.channels.",
              file=sys.stderr)
    print("# Keep ONLY your own networks, then paste under detection: in airtrap.yml\n")
    print(yaml.safe_dump({"detection": {"protected_networks": {k: sorted(v) for k, v in sorted(found.items())}}},
                         sort_keys=False))


def cmd_replay(args):
    """Run a saved pcap/pcapng (or the built-in demo) through the detectors, offline."""
    import tempfile

    from . import logger, sample
    from . import replay as rp
    cfg = config.load(args.config)
    pcap, hp_bssid, hp_ssid = args.pcap, args.hp_bssid, args.hp_ssid
    if args.demo:
        pcap = str(Path(tempfile.mkdtemp()) / "airtrap-demo.pcap")
        sample.build(pcap)
        cfg["detection"]["protected_networks"].update(sample.DEMO_PROTECTED)
        hp_bssid, hp_ssid = sample.DEMO_HONEYPOT
        print(f"demo capture written to {pcap}", file=sys.stderr)
    if not pcap:
        sys.exit("usage: airtrap replay CAPTURE.pcap   (or: airtrap replay --demo)")
    for spec in args.protect:
        ssid, _, macs = spec.partition("=")
        cfg["detection"]["protected_networks"][ssid] = [m.strip().lower() for m in macs.split(",") if m.strip()]
    if args.respond:
        import tempfile as _tf
        cfg["response"]["state_file"] = str(Path(_tf.mkdtemp()) / "attackers.json")
    logger.setup(args.out, stdout=True)
    _, stats = rp.replay(cfg, pcap, hp_bssid, hp_ssid, respond=args.respond)
    print(f"\nframes: {stats['frames']}  802.11 frames: {stats['dot11_frames']}", file=sys.stderr)
    if not stats["dot11_frames"]:
        print("WARNING: no 802.11 frames: capture in monitor mode (radiotap / link type 127 or 105).", file=sys.stderr)
    for name, n in sorted(stats["events"].items()):
        print(f"  {n:4d}  {name}", file=sys.stderr)
    if not stats["events"]:
        print("  no detections", file=sys.stderr)


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
    for name, fn in (("run", cmd_run), ("learn", cmd_learn), ("check", cmd_check), ("replay", cmd_replay)):
        sp = sub.add_parser(name)
        sp.add_argument("-c", "--config", default=None)
        sp.set_defaults(fn=fn)
        if name == "replay":
            sp.add_argument("pcap", nargs="?", help="capture file (.pcap / .pcapng)")
            sp.add_argument("--demo", action="store_true", help="generate and replay a synthetic attack capture")
            sp.add_argument("--protect", action="append", default=[], metavar="SSID=MAC[,MAC]",
                            help="protected network (repeatable)")
            sp.add_argument("--hp-bssid")
            sp.add_argument("--hp-ssid")
            sp.add_argument("--respond", action="store_true", help="also run attacker scoring (never blocks)")
            sp.add_argument("-o", "--out", help="also write JSON lines to this file")
        if name == "learn":
            sp.add_argument("-i", "--interface")
            sp.add_argument("-t", "--seconds", type=int, default=30)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
