"""802.11 frame analysis.  Pure logic: feed it scapy packets, get (event, severity, fields) tuples."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
)
from scapy.layers.eap import EAPOL

BROADCAST = "ff:ff:ff:ff:ff:ff"


def _int(v):
    return int(getattr(v, "value", v))


class SlidingCounter:
    def __init__(self, seconds):
        self.seconds = seconds
        self.hits = defaultdict(deque)

    def add(self, key, now):
        q = self.hits[key]
        q.append(now)
        while q and q[0] < now - self.seconds:
            q.popleft()
        if len(self.hits) > 5000:
            for k in [k for k, v in self.hits.items() if not v or v[-1] < now - self.seconds]:
                del self.hits[k]
        return len(q)


class Detector:
    def __init__(self, cfg, honeypot_bssid=None, honeypot_ssid=None, channel_fn=lambda: None):
        d = cfg["detection"]
        self.win = d["window_seconds"]
        self.deauth_thr = d["deauth_threshold"]
        self.beacon_thr = d["beacon_flood_threshold"]
        self.karma_thr = d["karma_ssid_threshold"]
        self.hs_win = d["handshake_window_seconds"]
        self.rssi_delta = d["rssi_spoof_delta_db"]
        self.cooldown = d["alert_cooldown"]
        self.warmup = d["warmup_seconds"]
        self.protected = {s: {b.lower() for b in bs} for s, bs in d["protected_networks"].items()}
        self.hp_bssid = honeypot_bssid.lower() if honeypot_bssid else None
        self.hp_ssid = honeypot_ssid
        self.channel_fn = channel_fn

        self.started = None
        self.deauth_ctr = SlidingCounter(self.win)
        self.new_aps = SlidingCounter(self.win)
        self.seen_bssids = set()
        self.ap_rssi = {}                      # EWMA of beacon RSSI per BSSID
        self.karma = defaultdict(dict)         # bssid -> {ssid: last_seen}
        self.victims = {}                      # client mac -> last deauth time
        self.flood_seen = {}                   # bssid -> last flood time
        self._last = {}

    # ---------------------------------------------------------------- helpers
    def _quiet(self, kind, key, now, cooldown=None):
        k = (kind, key)
        last = self._last.get(k)
        if last is not None and now - last < (cooldown or self.cooldown):
            return True
        self._last[k] = now
        return False

    @staticmethod
    def _ssid(pkt):
        elt = pkt.getlayer(Dot11Elt)
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0:
                return elt.info.decode(errors="replace")
            elt = elt.payload.getlayer(Dot11Elt)
        return ""

    @staticmethod
    def _elt_ids(pkt):
        ids, elt = {}, pkt.getlayer(Dot11Elt)
        while isinstance(elt, Dot11Elt):
            ids.setdefault(elt.ID, elt.info)
            elt = elt.payload.getlayer(Dot11Elt)
        return ids

    def _security(self, pkt, layer):
        ids = self._elt_ids(pkt)
        if 48 in ids:
            return "WPA2/WPA3"
        if 221 in ids and ids[221][:4] == b"\x00\x50\xf2\x01":
            return "WPA"
        if _int(layer.cap) & 0x0010:
            return "WEP"
        return "OPEN"

    def _channel(self, pkt):
        ds = self._elt_ids(pkt).get(3)
        return ds[0] if ds else self.channel_fn()

    # ---------------------------------------------------------------- entry
    def process(self, pkt, now=None):
        now = now if now is not None else time.time()
        if self.started is None:
            self.started = now
        if not pkt.haslayer(Dot11):
            return []
        d11 = pkt[Dot11]
        rt = pkt.getlayer(RadioTap)
        rssi = getattr(rt, "dBm_AntSignal", None) if rt is not None else None
        out = []
        if pkt.haslayer(Dot11Beacon):
            out += self._beacon(pkt, d11, rssi, now)
        elif pkt.haslayer(Dot11ProbeResp):
            out += self._probe_resp(pkt, d11, now)
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            out += self._deauth(pkt, d11, rssi, now)
        elif pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11Auth) or pkt.haslayer(Dot11AssoReq):
            out += self._honeypot_mgmt(pkt, d11, rssi, now)
        if pkt.haslayer(EAPOL):
            out += self._eapol(d11, now)
        return out

    # ---------------------------------------------------------------- detectors
    def _beacon(self, pkt, d11, rssi, now):
        out = []
        bssid = (d11.addr3 or "").lower()
        if not bssid:
            return out
        ssid = self._ssid(pkt)
        sec = self._security(pkt, pkt[Dot11Beacon])
        if rssi is not None:
            prev = self.ap_rssi.get(bssid)
            self.ap_rssi[bssid] = rssi if prev is None else 0.9 * prev + 0.1 * rssi

        if bssid not in self.seen_bssids:
            if len(self.seen_bssids) > 50000:
                self.seen_bssids.clear()
            self.seen_bssids.add(bssid)
            n = self.new_aps.add("all", now)
            if (now - self.started > self.warmup and n >= self.beacon_thr
                    and not self._quiet("beacon_flood", "all", now)):
                out.append(("beacon_flood", "high", dict(new_bssids=n, window_s=self.win,
                                                        channel=self._channel(pkt), attacker_mac=None)))

        trusted = self.protected.get(ssid)
        if trusted is not None:
            if bssid not in trusted:
                if not self._quiet("evil_twin", bssid, now):
                    out.append(("evil_twin", "critical", dict(
                        ssid=ssid, rogue_bssid=bssid, attacker_mac=bssid, security=sec,
                        channel=self._channel(pkt), rssi=rssi, trusted_bssids=sorted(trusted),
                        reason="unknown BSSID advertising a protected SSID")))
            elif sec == "OPEN" and not self._quiet("security_downgrade", bssid, now):
                out.append(("security_downgrade", "critical", dict(
                    ssid=ssid, bssid=bssid, security=sec, channel=self._channel(pkt), rssi=rssi,
                    reason="trusted BSSID advertised WITHOUT encryption (cloned BSSID?)")))
        return out

    def _probe_resp(self, pkt, d11, now):
        bssid, ssid = (d11.addr3 or "").lower(), self._ssid(pkt)
        if not bssid or not ssid:
            return []
        seen = self.karma[bssid]
        seen[ssid] = now
        for s in [s for s, t in seen.items() if t < now - self.win * 6]:
            del seen[s]
        if len(seen) >= self.karma_thr and not self._quiet("karma", bssid, now):
            return [("karma_attack", "high", dict(
                attacker_mac=bssid, distinct_ssids=len(seen), sample_ssids=list(seen)[:10],
                reason="one BSSID answering probes for many different SSIDs"))]
        return []

    def _deauth(self, pkt, d11, rssi, now):
        src, dst, bssid = ((x or "").lower() for x in (d11.addr2, d11.addr1, d11.addr3))
        layer = pkt[Dot11Deauth] if pkt.haslayer(Dot11Deauth) else pkt[Dot11Disas]
        client = next((m for m in (dst, src) if m and m not in (bssid, BROADCAST)), None)
        if client:
            self.victims[client] = now
        n = self.deauth_ctr.add(bssid, now)
        if n < self.deauth_thr:
            return []
        self.flood_seen[bssid] = now
        if self._quiet("deauth_flood", bssid, now):
            return []
        base = self.ap_rssi.get(bssid)
        spoofed = None
        if rssi is not None and base is not None:
            spoofed = abs(rssi - base) >= self.rssi_delta
        # The transmitter address of deauth attacks is almost always forged (AP's or client's MAC).
        third_party = src not in (bssid, client, "")
        return [("deauth_flood", "high", dict(
            frames=n, window_s=self.win, bssid=bssid, target=dst, source=src,
            broadcast=(dst == BROADCAST), reason_code=getattr(layer, "reason", None),
            rssi=rssi, beacon_rssi_baseline=None if base is None else round(base, 1),
            source_spoofed_likely=spoofed, channel=self.channel_fn(),
            attacker_mac=src if third_party else None,
            attribution="source-mac" if third_party else "spoofed-source: use rssi/channel to locate"))]

    def _honeypot_mgmt(self, pkt, d11, rssi, now):
        if not self.hp_bssid:
            return []
        a1, a2, a3 = ((x or "").lower() for x in (d11.addr1, d11.addr2, d11.addr3))
        if pkt.haslayer(Dot11ProbeReq):
            if self.hp_ssid and self._ssid(pkt) == self.hp_ssid and not self._quiet("hp_probe", a2, now, 60):
                return [("honeypot_probe", "warning", dict(attacker_mac=a2, ssid=self.hp_ssid, rssi=rssi))]
            return []
        if self.hp_bssid in (a1, a3) and a2 != self.hp_bssid:
            kind = "honeypot_association" if pkt.haslayer(Dot11AssoReq) else "honeypot_auth"
            if not self._quiet(kind, a2, now, 60):
                return [(kind, "high", dict(attacker_mac=a2, bssid=self.hp_bssid, rssi=rssi,
                                            channel=self.channel_fn()))]
        return []

    def _eapol(self, d11, now):
        fc = _int(d11.FCfield)
        to_ds, from_ds = fc & 1, fc & 2
        if to_ds and not from_ds:
            bssid, client = d11.addr1, d11.addr2
        elif from_ds and not to_ds:
            bssid, client = d11.addr2, d11.addr1
        else:
            return []
        bssid, client = (bssid or "").lower(), (client or "").lower()
        out = []
        if self.hp_bssid and bssid == self.hp_bssid and not self._quiet("hp_eapol", client, now, 10):
            out.append(("honeypot_handshake", "high", dict(attacker_mac=client, bssid=bssid,
                                                          reason="EAPOL exchange with honeypot AP")))
        t = self.victims.get(client)
        if (t is not None and now - t <= self.hs_win and now - self.flood_seen.get(bssid, -1e9) <= 60
                and not self._quiet("handshake", client, now)):
            out.append(("handshake_capture_suspected", "high", dict(
                victim=client, bssid=bssid, seconds_since_deauth=round(now - t, 2), attacker_mac=None,
                reason="client re-handshaked right after a deauth flood on its AP")))
        return out
