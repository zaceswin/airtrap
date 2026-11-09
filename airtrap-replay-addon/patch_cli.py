"""Run from the repo root:  python3 patch_cli.py   (adds `airtrap replay` to cli.py + README)."""
import pathlib

p = pathlib.Path("airtrap/cli.py")
s = p.read_text()
if "cmd_replay" in s:
    print("cli.py already patched")
else:
    func = '''def cmd_replay(args):
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
    print(f"\\nframes: {stats['frames']}  802.11 frames: {stats['dot11_frames']}", file=sys.stderr)
    if not stats["dot11_frames"]:
        print("WARNING: no 802.11 frames: capture in monitor mode (radiotap / link type 127 or 105).", file=sys.stderr)
    for name, n in sorted(stats["events"].items()):
        print(f"  {n:4d}  {name}", file=sys.stderr)
    if not stats["events"]:
        print("  no detections", file=sys.stderr)


'''
    s = s.replace("def cmd_check(args):", func + "def cmd_check(args):", 1)
    s = s.replace('("check", cmd_check))', '("check", cmd_check), ("replay", cmd_replay))', 1)
    block = '''        if name == "replay":
            sp.add_argument("pcap", nargs="?", help="capture file (.pcap / .pcapng)")
            sp.add_argument("--demo", action="store_true", help="generate and replay a synthetic attack capture")
            sp.add_argument("--protect", action="append", default=[], metavar="SSID=MAC[,MAC]",
                            help="protected network (repeatable)")
            sp.add_argument("--hp-bssid")
            sp.add_argument("--hp-ssid")
            sp.add_argument("--respond", action="store_true", help="also run attacker scoring (never blocks)")
            sp.add_argument("-o", "--out", help="also write JSON lines to this file")
'''
    s = s.replace('        if name == "learn":', block + '        if name == "learn":', 1)
    p.write_text(s)
    print("patched airtrap/cli.py")

r = pathlib.Path("README.md")
if r.exists() and "## Offline replay" not in r.read_text():
    r.write_text(r.read_text().replace("## Layout", '''## Offline replay (no radio needed)

```bash
airtrap replay --demo                              # synthetic capture with every attack type
airtrap replay capture.pcap --protect "HomeWiFi=aa:bb:cc:dd:ee:01"
airtrap replay capture.pcap --hp-bssid 02:11:22:33:44:55 --hp-ssid Linksys_Setup -o events.jsonl
```

Captures must be taken in monitor mode (radiotap or raw 802.11). Event times in the output come from the
capture (`capture_time`). Replay never touches the firewall, even with `--respond`.

## Layout''', 1))
    print("README updated")
