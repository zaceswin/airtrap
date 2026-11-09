# airtrap

**Layer 2 Wi-Fi honeypot + wireless intrusion detection system (WIDS)** for Linux and Raspberry Pi.
airtrap passively watches 802.11 frames for attacks on *your* networks, optionally broadcasts an
isolated, enticing decoy AP with a tarpit behind it, and writes everything as **JSON lines** for your
SIEM or dashboard.

| Detects | How |
|---|---|
| Deauth / disassoc floods | per-BSSID frame rate, RSSI-vs-beacon check for forged sources |
| Handshake capture attempts | deauth flood followed by a client re-handshake (EAPOL) on that AP |
| Evil twin / rogue AP | protected SSID advertised by an unknown BSSID |
| Cloned BSSID without encryption | trusted BSSID seen as OPEN |
| Karma / MANA attacks | one BSSID answering probes for many different SSIDs |
| Beacon floods (mdk4-style) | burst of new BSSIDs |
| Anyone touching the honeypot | probes, auth, association, EAPOL, wrong-PSK guesses, DHCP, DNS, TCP |

> **Legal / ethical use.** Only deploy on networks you own or are authorised to defend. airtrap is
> deliberately **passive**: it never sends deauth frames or jams ("containment"), which regulators such as
> the FCC treat as unlawful interference. Logs contain MAC addresses (personal data under laws such as GDPR
> and Kenya's Data Protection Act): set retention and access accordingly. The honeypot broadcasts a radio
> signal: set the correct `country` code and keep to local power/channel rules.

## Architecture

```
 USB adapter #1 (monitor mode, channel hopping)        USB adapter #2 (AP mode, optional)
          │ 802.11 frames (RadioTap)                              │
          ▼                                                       ▼
   Sensor (scapy) ──► Detector ──┐                  hostapd (decoy SSID, ap_isolate)
                                 │                  dnsmasq (DHCP + wildcard DNS) ─┐
   hostapd_cli / dnsmasq hooks ──┼─► IPC socket     nftables: drop everything except │
   Tarpit (asyncio TCP) ─────────┤                  DHCP/DNS/tarpit, no forwarding   │
                                 ▼                  all TCP redirected to tarpit ◄───┘
                        logger.emit() ──► events.jsonl ──► Filebeat/Promtail/Vector ──► SIEM
                                 │
                                 ▼
                           Responder: score → flag → (opt-in) block
                           nftables sets · hostapd deny_acl · webhook · hook_command
```

* **Why two adapters?** Most USB adapters cannot do monitor and AP mode at once. Use one adapter per role
  (monitor-capable chipsets: MediaTek MT7612U/MT7610U, Atheros AR9271, Realtek RTL8812AU with the right driver).
* The honeypot network `10.66.0.0/24` is **never routed** to your LAN or the internet (`ap_isolate=1`,
  `forward` dropped, `input` restricted). Every TCP port lands in a **tarpit** that drips data slowly, so scanners
  and brute-forcers waste time while you log source MAC, IP, DNS lookups, HTTP requests and typed credentials.
* Run the sensor on a box that is **not** itself on the network you are defending if you can.

## Quick start

```bash
git clone https://github.com/<you>/airtrap && cd airtrap
sudo ./scripts/install.sh                         # Debian / Ubuntu / Raspberry Pi OS
sudo nano /etc/airtrap/airtrap.yml                # interfaces, country, protected networks
sudo airtrap check -c /etc/airtrap/airtrap.yml    # dependency + adapter capability check
sudo airtrap learn -c /etc/airtrap/airtrap.yml    # prints your SSID→BSSID map (keep only YOUR networks)
sudo systemctl enable --now airtrap
tail -f /var/log/airtrap/events.jsonl | jq
```

Docker (Linux host only, it needs the host's radios):

```bash
cp config/airtrap.example.yml config/airtrap.yml   # edit it, then point docker-compose.yml at it
docker compose up -d --build
# Raspberry Pi / ARM from an x86 machine:
docker buildx build --platform linux/arm64 -t airtrap:arm64 .
```

## Log format

```json
{"@timestamp":"2026-11-08T10:15:02.113Z","sensor":"pi-wids","event":"evil_twin","severity":"critical",
 "ssid":"HomeWiFi","rogue_bssid":"66:66:66:00:00:03","attacker_mac":"66:66:66:00:00:03",
 "security":"OPEN","channel":6,"rssi":-48,"trusted_bssids":["aa:bb:cc:dd:ee:01"],
 "reason":"unknown BSSID advertising a protected SSID"}
```

Events: `deauth_flood`, `handshake_capture_suspected`, `evil_twin`, `security_downgrade`, `karma_attack`,
`beacon_flood`, `honeypot_probe|auth|association|handshake`, `honeypot_sta_connected`, `psk_guess_attempt`,
`dhcp_lease`, `dns_query`, `tarpit_connection|http|login|payload|closed`, `attacker_flagged`, `attacker_blocked`.
Severities: `info < warning < high < critical`. Ship with Filebeat (`filestream` + `ndjson` parser), Vector,
Promtail or `tail -F | curl`, or set `response.webhook_url` for flag/block notifications.
Per-attacker state (score, IPs, hostnames, DHCP vendor class, randomized-MAC flag) is in
`/var/lib/airtrap/attackers.json`.

## Countermeasures: flag, track, block

1. **Flag & track (default):** every event carrying an attributable `attacker_mac`/`attacker_ip` adds
   severity points (warning 1, high 3, critical 5) to that attacker's record and fires one `attacker_flagged`.
2. **Block (opt-in, `response.mode: block`)** once score ≥ `block_score`, for `block_seconds`:
   * `nftables` sets drop the MAC and IP on this host's input/forward path (use airtrap on your gateway or bridge),
   * `hostapd_interfaces` pushes `deny_acl` + disassociate to real APs run by hostapd on the same machine,
   * `hook_command` runs your script with `AIRTRAP_MAC/IP/SCORE/SECONDS` (OpenWrt `ubus`, pfSense/OPNsense API, Omada/UniFi MAC filter),
   * `webhook_url` notifies your SOC tooling.
3. **Safety rails:** protected BSSIDs, own interfaces and `never_block` are never blocked; blocks expire.

**Attribution limits (important):** deauth attackers nearly always forge the source MAC (it is the AP's or the
victim's). airtrap therefore records `source_spoofed_likely`, RSSI and channel instead of "blocking" a fake
identity. Real attacker identifiers appear when they touch the honeypot (MAC, IP, hostname, DHCP vendor class,
DNS and HTTP behaviour). Randomized MACs are flagged. Fix deauth for good with **802.11w/PMF** (mandatory in
WPA3) on your real APs, plus WPA3-SAE with a strong passphrase.

## Offline replay (no radio needed)

```bash
airtrap replay --demo                              # synthetic capture with every attack type
airtrap replay capture.pcap --protect "HomeWiFi=aa:bb:cc:dd:ee:01"
airtrap replay capture.pcap --hp-bssid 02:11:22:33:44:55 --hp-ssid Linksys_Setup -o events.jsonl
```

Captures must be taken in monitor mode (radiotap or raw 802.11). Event times in the output come from the
capture (`capture_time`). Replay never touches the firewall, even with `--respond`.

## Layout

```
airtrap/      detectors.py (frame logic) · sensor.py · monitor.py · honeypot.py · tarpit.py
              responder.py · logger.py · ipc.py/hook.py · daemon.py · cli.py
config/       airtrap.example.yml        deploy/   airtrap.service
scripts/      install.sh                 tests/    pytest suite (crafted 802.11 frames)
Dockerfile · docker-compose.yml · .github/workflows/ci.yml
```

## Limitations

* Channel hopping means short attacks on unscanned channels can be missed: pin `channels` to the ones you use.
* The honeypot's weak passphrase is a lure: if an attacker "cracks" it they land in the isolated tarpit network only.
* Heuristic thresholds need tuning per site (`detection:` block). Run `flag` mode for a week before enabling `block`.
* Tested logic: frame detectors and responder (see `tests/`). Radio/hostapd/nftables paths need real hardware: please open issues.

## Contributing

PRs welcome: new detectors (WPS brute force, PMKID probing, SAE downgrade), OUI vendor lookup, dashboards.
Run `pip install -e ".[dev]" && ruff check . && pytest`.

MIT licensed.
