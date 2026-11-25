from importlib.resources import files

import pytest

from research_hardening.formats import Invalid, decode, encode
from research_hardening.policy import drive, parse_policy
from research_hardening.snapshot import parse_snapshot


def sample(name):
    return files("research_hardening").joinpath("fixtures", name + ".json").read_bytes()


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_examples(platform):
    p = parse_policy(sample(platform + "-policy"))
    assert parse_snapshot(sample("synthetic-" + platform))["policy_digest"] == p.digest
    reordered = decode(sample(platform + "-policy"))
    reordered["checks"].reverse()
    other = parse_policy(encode(reordered))
    assert other.digest == p.digest and other.raw_hash != p.raw_hash


@pytest.mark.parametrize(
    "change",
    [
        {"catalog_version": True},
        {"max_age_hours": 0},
        {"max_age_hours": 8761},
        {"checks": []},
        {"scope": "linux-visible"},
        {"unknown": 1},
        {"checks": [{"id": "WIN-BOOT-001", "required": False}]},
        {"checks": [{"id": "W", "required": True}]},
    ],
)
def test_bad_policy(change):
    doc = decode(sample("windows-policy"))
    with pytest.raises(Invalid):
        parse_policy(encode({**doc, **change}))


@pytest.mark.parametrize("value", ["C:/", "c", "C:;", "Ｄ:", None, 1])
def test_invalid_drive(value):
    with pytest.raises(Invalid):
        drive(value)
