import pytest
from test_policy import sample

from research_hardening import collect
from research_hardening.formats import Invalid, decode, encode
from research_hardening.policy import parse_policy


def policy():
    doc = decode(sample("windows-policy"))
    doc["profile"] = "workstation"
    return parse_policy(encode(doc))


def test_unauthorized_never_probes(monkeypatch):
    monkeypatch.setattr(collect, "local_scope", lambda: pytest.fail("scope read"))
    with pytest.raises(Invalid, match="authorization_required"):
        collect.collect(policy(), "owner")


def test_collect_partial_redacts_native_error(monkeypatch):
    monkeypatch.setattr(collect, "local_scope", lambda: "windows-native")
    calls = []

    def denied(check, *args):
        calls.append(check["id"])
        return "permission_denied", b"private-sentinel"

    monkeypatch.setattr(collect, "probe", denied)
    snap, code = collect.collect(policy(), "owner", local=True, confirm_owner_controlled=True)
    assert code == 2 and snap["status"] == "partial" and len(calls) == 4
    assert b"private-sentinel" not in encode(snap)
