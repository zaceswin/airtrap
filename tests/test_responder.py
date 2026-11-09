from airtrap.config import load
from airtrap.responder import Responder


def rec(event, sev, mac):
    return {"@timestamp": "2026-01-01T00:00:00.000Z", "event": event, "severity": sev, "attacker_mac": mac}


def test_flag_then_score(tmp_path):
    c = load()
    c["response"]["state_file"] = str(tmp_path / "a.json")
    c["response"]["mode"] = "flag"
    r = Responder(c)
    r.handle(rec("honeypot_auth", "high", "aa:aa:aa:aa:aa:01"))
    r.handle(rec("honeypot_association", "high", "aa:aa:aa:aa:aa:01"))
    a = r.attackers["aa:aa:aa:aa:aa:01"]
    assert a["score"] == 6 and a["flagged"] and "blocked_until" not in a


def test_never_block_protected(tmp_path):
    c = load()
    c["response"].update(state_file=str(tmp_path / "a.json"), mode="block", nftables=False)
    c["detection"]["protected_networks"] = {"Home": ["aa:bb:cc:00:00:01"]}
    r = Responder(c)
    r.handle(rec("evil_twin", "critical", "aa:bb:cc:00:00:01"))
    assert "blocked_until" not in r.attackers["aa:bb:cc:00:00:01"]
