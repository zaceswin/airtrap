from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap
from scapy.layers.eap import EAPOL
from scapy.layers.l2 import LLC, SNAP

from airtrap.config import load
from airtrap.detectors import Detector

AP, CLIENT, ROGUE, HP = "aa:bb:cc:00:00:01", "de:ad:be:ef:00:02", "66:66:66:00:00:03", "02:11:22:33:44:55"
RSN = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"


def beacon(bssid, ssid, security="WPA2", rssi=-40):
    cap = "ESS+privacy" if security != "OPEN" else "ESS"
    p = (RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi) / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
         / Dot11Beacon(cap=cap) / Dot11Elt(ID=0, info=ssid.encode()))
    if security != "OPEN":
        p = p / Dot11Elt(ID=48, info=RSN)
    return RadioTap(bytes(p))


def deauth(rssi=-70):
    return RadioTap(bytes(RadioTap(present="dBm_AntSignal", dBm_AntSignal=rssi) / Dot11(type=0, subtype=12, addr1=CLIENT, addr2=AP, addr3=AP)
                          / Dot11Deauth(reason=7)))


def eapol():
    p = (RadioTap() / Dot11(type=2, subtype=0, FCfield=0x02, addr1=CLIENT, addr2=AP, addr3=AP)
         / LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=0x888E) / EAPOL(type=3))
    return RadioTap(bytes(p))


def cfg(**protected):
    c = load()
    c["detection"]["protected_networks"] = protected
    return c


def test_deauth_flood_flags_spoofed_source():
    d = Detector(cfg())
    d.process(beacon(AP, "Home"), now=0)
    events = []
    for i in range(20):
        events += d.process(deauth(), now=1 + i * 0.1)
    flood = [e for e in events if e[0] == "deauth_flood"]
    assert len(flood) == 1
    assert flood[0][2]["source_spoofed_likely"] is True
    assert flood[0][2]["attacker_mac"] is None


def test_evil_twin_detected_and_legit_ignored():
    d = Detector(cfg(Home=[AP]))
    assert d.process(beacon(AP, "Home"), now=0) == []
    ev = d.process(beacon(ROGUE, "Home"), now=1)
    assert ev and ev[0][0] == "evil_twin" and ev[0][2]["attacker_mac"] == ROGUE


def test_open_clone_of_trusted_bssid():
    d = Detector(cfg(Home=[AP]))
    ev = d.process(beacon(AP, "Home", security="OPEN"), now=0)
    assert ev and ev[0][0] == "security_downgrade"


def test_honeypot_association():
    d = Detector(cfg(), honeypot_bssid=HP, honeypot_ssid="Free")
    pkt = RadioTap(bytes(RadioTap() / Dot11(type=0, subtype=0, addr1=HP, addr2=CLIENT, addr3=HP) / Dot11AssoReq()))
    ev = d.process(pkt, now=0)
    assert ev and ev[0][0] == "honeypot_association" and ev[0][2]["attacker_mac"] == CLIENT


def test_handshake_after_flood():
    d = Detector(cfg())
    d.process(beacon(AP, "Home"), now=0)
    for i in range(20):
        d.process(deauth(), now=1 + i * 0.1)
    ev = d.process(eapol(), now=4)
    assert any(e[0] == "handshake_capture_suspected" for e in ev)
