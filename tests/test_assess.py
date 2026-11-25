from datetime import UTC, datetime, timedelta

import pytest
from test_policy import sample

from research_hardening.assess import assess
from research_hardening.formats import Invalid, decode, encode
from research_hardening.policy import parse_policy
from research_hardening.snapshot import observation

NOW = datetime(2020, 1, 1, 12, tzinfo=UTC)


def scenario(platform, edits=None, policy_edits=None, now=NOW, trusted=False):
    raw = sample(platform + "-policy")
    doc = decode(sample("synthetic-" + platform))
    if policy_edits:
        raw = encode({**decode(raw), **policy_edits})
        p = parse_policy(raw)
        doc.update(policy_digest=p.digest, policy_sha256=p.raw_hash)
    if edits:
        edits(doc)
    doc["status"] = (
        "complete"
        if doc["observations"] and all(r["status"] == "observed" for r in doc["observations"])
        else "partial"
    )
    return assess(raw, encode(doc), now, trust_local=trusted)


def replace(doc, cid, status, value=None):
    rows = doc["observations"]
    i = next(i for i, r in enumerate(rows) if r["check_id"] == cid)
    rows[i] = observation(cid, status, value)


@pytest.mark.parametrize("os", ["linux", "windows"])
def test_complete_fixture(os):
    r = scenario(os)
    assert r["exit_code"] == 0 and r["assurance"] == "synthetic"


@pytest.mark.parametrize(
    "changes,code",
    [
        ([("WIN-BOOT-001", "permission_denied", None)], 0),
        ([("WIN-DISK-001", "permission_denied", None)], 2),
        ([("WIN-FW-001", "observed", {"Domain": True, "Private": True, "Public": False})], 1),
    ],
)
def test_required_optional(changes, code):
    r = scenario("windows", lambda d: [replace(d, *change) for change in changes])
    assert r["exit_code"] == code


def test_gap_preserves_known_finding():
    def edit(d):
        replace(d, "LIN-ASLR-001", "observed", 1)
        replace(d, "LIN-KPTR-001", "unavailable")

    r = scenario("linux", edit)
    assert r["exit_code"] == 2 and r["required_findings"] == ["LIN-ASLR-001"]
    assert r["required_gaps"] == ["LIN-KPTR-001"]


def test_stale_boundary_and_future():
    assert scenario("linux", now=NOW + timedelta(hours=24))["exit_code"] == 0
    assert scenario("linux", now=NOW + timedelta(hours=24, seconds=1))["exit_code"] == 2
    with pytest.raises(Invalid, match="future"):
        scenario("linux", now=NOW - timedelta(seconds=1))


@pytest.mark.parametrize(
    "collection,trusted,expected",
    [
        ("synthetic_fixture", True, 2),
        ("local_capture", False, 2),
        ("operator_import", True, 2),
        ("local_capture", True, 0),
    ],
)
def test_operator_trust(collection, trusted, expected):
    r = scenario(
        "linux",
        lambda d: d.update(collection=collection),
        {"profile": "workstation"},
        trusted=trusted,
    )
    assert r["exit_code"] == expected


def test_no_evidence():
    r = scenario("linux", lambda d: d["observations"].clear())
    assert r["exit_code"] == 2 and all(row["coverage"] == "missing" for row in r["checks"])


def test_scope_mismatch():
    with pytest.raises(Invalid, match="scope_mismatch"):
        scenario("linux", lambda d: d.update(scope="wsl-linux", environment="wsl-linux"))
