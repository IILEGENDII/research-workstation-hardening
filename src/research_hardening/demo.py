from copy import deepcopy
from datetime import timedelta
from importlib.resources import files

from .assess import assess
from .compare import compare_reports
from .formats import Invalid, decode, encode, instant, require
from .policy import parse_policy
from .render import render
from .snapshot import observation
from .storage import new_workspace, write_new


def demo(workspace):
    root = new_workspace(workspace)
    fixtures = files("research_hardening").joinpath("fixtures")
    results = {}

    def record(name, report, expected):
        require(report["exit_code"] == expected, "unexpected_demo_outcome")
        results[name] = expected
        write_new(root / (name + ".json"), encode(report))
        write_new(root / (name + ".txt"), render(report, "text"), ".txt")

    for platform, failing, missing in (
        ("windows", "WIN-FW-001", "WIN-DISK-001"),
        ("linux", "LIN-ASLR-001", "LIN-KPTR-001"),
    ):
        policy = fixtures.joinpath(platform + "-policy.json").read_bytes()
        original = fixtures.joinpath("synthetic-" + platform + ".json").read_bytes()
        write_new(root / (platform + "-policy.json"), policy)
        write_new(root / (platform + "-snapshot.json"), original)
        doc = decode(original)
        now = instant(doc["observed_at"])
        good = assess(policy, original, now)
        record(platform + "-satisfied", good, 0)
        changed = deepcopy(doc)
        rows = {r["check_id"]: r for r in changed["observations"]}
        if platform == "windows":
            rows[failing]["value"]["Public"] = False
        else:
            rows[failing]["value"] = 1
        record(platform + "-finding", assess(policy, encode(changed), now), 1)
        for r in doc["observations"]:
            if r["check_id"] == missing:
                r.update(
                    observation(
                        missing, "permission_denied" if platform == "windows" else "unavailable"
                    )
                )
        doc["status"] = "partial"
        record(platform + "-gap", assess(policy, encode(doc), now), 2)
        rows[missing].update(observation(missing, "unavailable"))
        changed["status"] = "partial"
        adverse = assess(policy, encode(changed), now)
        record(platform + "-mixed", adverse, 2)
        record(platform + "-drift", compare_reports(encode(good), encode(adverse)), 1)
        record(platform + "-stale", assess(policy, original, now + timedelta(days=2)), 2)
        workstation = encode({**decode(policy), "profile": "workstation"})
        p = parse_policy(workstation)
        relabeled = {**decode(original), "policy_digest": p.digest, "policy_sha256": p.raw_hash}
        record(platform + "-fixture-workstation", assess(workstation, encode(relabeled), now), 2)
    linux = decode(fixtures.joinpath("synthetic-linux.json").read_bytes())
    windows = parse_policy(fixtures.joinpath("windows-policy.json").read_bytes())
    linux.update(scope="wsl-linux", environment="wsl-linux", policy_digest=windows.digest)
    for name, raw, reason in (
        ("guest-host", encode(linux), "scope_mismatch"),
        ("duplicate", b'{"x":1,"x":2}', "duplicate_key"),
    ):
        try:
            assess(fixtures.joinpath("windows-policy.json").read_bytes(), raw, now)
        except Invalid as exc:
            require(str(exc) == reason, "unexpected_demo_outcome")
            results[name] = 2
        else:
            raise Invalid("unexpected_demo_outcome")
    summary = {
        "schema_version": 1,
        "operation": "demo",
        "completed": True,
        "status": "complete",
        "collection": "synthetic_fixture",
        "scenario_exits": results,
    }
    write_new(root / "summary.json", encode(summary))
    return summary
