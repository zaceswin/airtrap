from airtrap import sample
from airtrap.config import load
from airtrap.replay import replay


def test_demo_capture_triggers_every_detector(tmp_path):
    pcap = tmp_path / "demo.pcap"
    n = sample.build(pcap)
    cfg = load()
    cfg["detection"]["protected_networks"] = dict(sample.DEMO_PROTECTED)
    results, stats = replay(cfg, pcap, *sample.DEMO_HONEYPOT, quiet=True)
    kinds = set(stats["events"])
    assert stats["frames"] == n
    assert {"evil_twin", "security_downgrade", "deauth_flood", "handshake_capture_suspected",
            "karma_attack", "honeypot_probe", "honeypot_auth", "honeypot_association",
            "beacon_flood"} <= kinds
    flood = next(f for k, _, f in results if k == "deauth_flood")
    assert flood["source_spoofed_likely"] is True and flood["attacker_mac"] is None
    assert all(f["replay"] for _, _, f in results)


def test_replay_without_config_finds_no_twin(tmp_path):
    pcap = tmp_path / "demo.pcap"
    sample.build(pcap)
    _, stats = replay(load(), pcap, quiet=True)
    assert "evil_twin" not in stats["events"] and "deauth_flood" in stats["events"]
