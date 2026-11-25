from datetime import timedelta

import pytest
from test_assess import NOW, replace, scenario

from research_hardening.compare import compare_reports, read_assessment
from research_hardening.formats import Invalid, encode


def test_coverage_loss_and_optional():
    a = scenario("linux")
    b = scenario("linux", lambda d: replace(d, "LIN-DMESG-001", "permission_denied"))
    change = compare_reports(encode(a), encode(b))["changes"][0]
    assert change["changes"] == ["state_changed", "coverage_changed"] and b["exit_code"] == 0


def test_freshness_and_time():
    a = encode(scenario("linux"))
    assert (
        compare_reports(a, encode(scenario("linux", now=NOW + timedelta(hours=3))))["exit_code"]
        == 0
    )
    result = compare_reports(a, encode(scenario("linux", now=NOW + timedelta(days=2))))
    assert all("freshness_changed" in r["changes"] for r in result["changes"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(exit_code=True),
        lambda d: d["checks"].pop(),
        lambda d: d.update(required_findings=["LIN-KPTR-001"]),
        lambda d: d["counts"]["required"].update(satisfied=0),
        lambda d: d.update(policy_digest="0" * 64),
        lambda d: d["checks"][0].update(observed_value=0),
    ],
)
def test_compare_recomputes_saved_verdict(mutate):
    doc = scenario("linux")
    mutate(doc)
    with pytest.raises(Invalid):
        read_assessment(encode(doc))


def test_identity_mismatch():
    a = encode(scenario("linux"))
    b = encode(scenario("linux", lambda d: d.update(subject="different")))
    assert compare_reports(a, b)["incompatible"] == ["subject"]


def test_raw_policy_format():
    a = encode(scenario("linux"))
    b = encode(scenario("linux", policy_edits={"scope": "linux-visible"}))
    result = compare_reports(a, b)
    assert result["raw_policy_changed"] and result["exit_code"] == 0
