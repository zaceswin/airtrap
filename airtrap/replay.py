"""Offline replay: feed a pcap/pcapng capture through the detectors (no radio, no root needed)."""
import time
from collections import Counter

from . import logger
from .detectors import Detector


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t * 1000) % 1000:03d}Z"


def replay(cfg, path, hp_bssid=None, hp_ssid=None, respond=False, quiet=False):
    """Returns (results, stats). results = [(event, severity, fields)], timestamps come from the capture."""
    from scapy.layers.dot11 import Dot11
    from scapy.utils import PcapReader

    if respond:
        from .responder import Responder
        cfg["response"]["mode"] = "flag"          # replay must never touch the real firewall
        logger.subscribe(Responder(cfg).handle)

    det = Detector(cfg, hp_bssid, hp_ssid)
    results, frames, dot11 = [], 0, 0
    reader = PcapReader(str(path))
    try:
        for pkt in reader:
            frames += 1
            if not pkt.haslayer(Dot11):
                continue
            dot11 += 1
            t = float(pkt.time)
            for kind, sev, fields in det.process(pkt, now=t):
                fields = dict(fields, capture_time=_iso(t), replay=True)
                results.append((kind, sev, fields))
                if not quiet:
                    logger.emit(kind, sev, **fields)
    finally:
        reader.close()
    stats = {"frames": frames, "dot11_frames": dot11, "events": dict(Counter(r[0] for r in results))}
    return results, stats
