"""Synthetic 802.11 capture containing every attack airtrap detects (for demos, docs and tests)."""
import random

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import LLC, SNAP
from scapy.utils import wrpcap

AP = "aa:bb:cc:00:00:01"
ROGUE = "66:66:66:00:00:03"
CLIENT = "de:ad:be:ef:00:02"
HP = "02:11:22:33:44:55"
ATTACKER = "3c:77:ab:12:34:56"
KARMA = "9a:00:00:00:00:09"
BCAST = "ff:ff:ff:ff:ff:ff"
RSN = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"

DEMO_PROTECTED = {"HomeWiFi": [AP]}
DEMO_HONEYPOT = (HP, "FreeWiFi_Guest")


def _rt(rssi=None):
    return RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi) if rssi is not None else RadioTap()


def _beacon(bssid, ssid, secure=True, rssi=-40):
    p = (_rt(rssi) / Dot11(type=0, subtype=8, addr1=BCAST, addr2=bssid, addr3=bssid)
         / Dot11Beacon(cap="ESS+privacy" if secure else "ESS") / Dot11Elt(ID=0, info=ssid.encode()))
    return p / Dot11Elt(ID=48, info=RSN) if secure else p


def _deauth(rssi=-75):
    return (_rt(rssi) / Dot11(type=0, subtype=12, addr1=CLIENT, addr2=AP, addr3=AP) / Dot11Deauth(reason=7))


def build(path, seed=1):
    rnd = random.Random(seed)
    t0 = 1_700_000_000.0
    frames = []                                    # (time, packet)

    def add(t, pkt):
        pkt.time = t0 + t
        frames.append((t, pkt))

    for i in range(20):                            # legit AP baseline (0-10 s)
        add(i * 0.5, _beacon(AP, "HomeWiFi"))
    for i in range(6):                             # evil twin: unknown BSSID, open (5-8 s)
        add(5 + i * 0.5, _beacon(ROGUE, "HomeWiFi", secure=False, rssi=-48))
    for i in range(30):                            # forged deauth flood from "the AP" (20-21.5 s)
        add(20 + i * 0.05, _deauth())
    add(22, RadioTap() / Dot11(type=2, subtype=0, FCfield=0x02, addr1=CLIENT, addr2=AP, addr3=AP)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x888E) / EAPOL(type=3))
    add(30, _beacon(AP, "HomeWiFi", secure=False))   # trusted BSSID suddenly open (cloned)
    for i, s in enumerate(("Starbucks", "airport_free", "linksys", "hotel_guest", "AndroidAP")):
        add(35 + i * 0.2, _rt(-50) / Dot11(type=0, subtype=5, addr1=CLIENT, addr2=KARMA, addr3=KARMA)
            / Dot11ProbeResp(cap="ESS") / Dot11Elt(ID=0, info=s.encode()))
    hp_bssid, hp_ssid = DEMO_HONEYPOT                # someone pokes the honeypot (45-47 s)
    add(45, _rt(-55) / Dot11(type=0, subtype=4, addr1=BCAST, addr2=ATTACKER, addr3=BCAST)
        / Dot11ProbeReq() / Dot11Elt(ID=0, info=hp_ssid.encode()))
    add(46, _rt(-55) / Dot11(type=0, subtype=11, addr1=hp_bssid, addr2=ATTACKER, addr3=hp_bssid)
        / Dot11Auth(algo=0, seqnum=1, status=0))
    add(46.1, _rt(-55) / Dot11(type=0, subtype=0, addr1=hp_bssid, addr2=ATTACKER, addr3=hp_bssid)
        / Dot11AssoReq(cap="ESS") / Dot11Elt(ID=0, info=hp_ssid.encode()))
    for i in range(45):                            # mdk4-style beacon flood after warm-up (90 s)
        mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(rnd.randrange(256) for _ in range(5))
        add(90 + i * 0.04, _beacon(mac, "fake_%d" % i, secure=False, rssi=-60))

    frames.sort(key=lambda x: x[0])
    wrpcap(str(path), [p for _, p in frames])
    return len(frames)
