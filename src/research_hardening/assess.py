from datetime import UTC, datetime

from . import __version__
from .catalog import CONTROLS
from .formats import instant, require, sha, stamp
from .policy import parse_policy
from .snapshot import parse_snapshot


def judge(check, value):
    cid = check["id"]
    gaps, findings = [], []
    if cid == "WIN-FW-001":
        findings = ["disabled_" + p.lower() for p in sorted(value) if not value[p]]
    elif cid == "WIN-FW-002":
        findings = ["inbound_allow_" + p.lower() for p in sorted(value) if value[p] == "Allow"]
        gaps = ["unresolved_" + p.lower() for p in sorted(value) if value[p] == "NotConfigured"]
    elif cid == "WIN-AV-001":
        if value["mode"] != "Normal":
            gaps.append("defender_mode")
        else:
            findings = [
                key + "_disabled" for key in ("service", "antivirus", "realtime") if not value[key]
            ]
    elif cid == "WIN-AV-002":
        if value > check["max_age_days"]:
            findings.append("signature_age")
    elif cid == "WIN-DISK-001":
        require(value["volume"] == check["volume"], "volume_mismatch")
        if value["state"] != "FullyEncrypted" or value["percent"] != 100:
            findings.append("encryption_incomplete")
        if value["protection"] == "Off":
            findings.append("protection_off")
    elif cid == "WIN-BOOT-001" and not value:
        findings.append("secure_boot_off")
    elif cid == "LIN-DATA-001":
        require(value["directory_subject"] == check["directory_subject"], "directory_mismatch")
        if not value["directory"] or not value["owned"]:
            findings.append("directory_type_or_owner")
        if check["private"] and value["mode"] & 0o077:
            findings.append("shared_mode")
    elif cid in ("LIN-ASLR-001", "LIN-KPTR-001", "LIN-DMESG-001"):
        minimum = {"LIN-ASLR-001": 2, "LIN-KPTR-001": check.get("minimum", 1), "LIN-DMESG-001": 1}[
            cid
        ]
        if value < minimum:
            findings.append("below_policy")
    return gaps, findings


def assess(policy_bytes, snapshot_bytes, now=None, *, trust_local=False):
    policy = parse_policy(policy_bytes)
    snapshot = parse_snapshot(snapshot_bytes)
    evaluated = stamp(now or datetime.now(UTC))
    return evaluate(policy, snapshot, sha(snapshot_bytes), evaluated, trust_local)


def evaluate(policy, snapshot, snapshot_hash, evaluated, trust_local):
    settings = policy.settings
    require(type(trust_local) is bool)
    require(snapshot["policy_digest"] == policy.digest, "policy_mismatch")
    require(snapshot["scope"] == settings["scope"], "scope_mismatch")
    clock = instant(evaluated)
    require(instant(snapshot["ended_at"]) <= clock, "future_snapshot")
    # Use the beginning of the interval so an early observation cannot gain extra lifetime.
    age = (clock - instant(snapshot["started_at"])).total_seconds()
    stale = age > settings["max_age_hours"] * 3600
    kind = snapshot["collection"]
    assurance = {
        "synthetic_fixture": "synthetic",
        "operator_import": "operator_import",
        "local_capture": "unverified_local_claim",
    }[kind]
    if kind == "local_capture" and trust_local:
        assurance = "operator_selected_local_file"
    expected = "synthetic" if settings["profile"] == "synthetic" else "operator_selected_local_file"
    reasons = []
    if assurance != expected:
        reasons.append("assurance_mismatch")
    if snapshot["environment"] != settings["scope"]:
        reasons.append("unknown_environment")
    if stale:
        reasons.append("stale")
    reasons.extend(snapshot["issues"])
    by_id = {r["check_id"]: r for r in snapshot["observations"]}
    checks = settings["checks"]
    require(by_id.keys() <= {c["id"] for c in checks}, "unselected_check")
    rows = []
    for check in checks:
        cid = check["id"]
        obs = by_id.get(cid)
        status = obs["status"] if obs else "missing"
        value = obs["value"] if obs else None
        gaps, findings = judge(check, value) if status == "observed" else ([status], [])
        gaps = reasons + gaps
        state = "inconclusive" if gaps else ("finding" if findings else "satisfied")
        rows.append(
            {
                "check_id": cid,
                "required": check["required"],
                "state": state,
                "observed_at": snapshot["observed_at"] if obs else None,
                "source": obs["source"] if obs else None,
                "coverage": status,
                "reason_codes": gaps,
                "finding_codes": findings,
                "observed_value": value,
                "scope": snapshot["scope"],
                "guidance": CONTROLS[cid].review,
            }
        )
    counts = {}
    for group, required in (("required", True), ("optional", False)):
        selected = [r for r in rows if r["required"] == required]
        counts[group] = {
            s: sum(r["state"] == s for r in selected)
            for s in ("satisfied", "finding", "inconclusive")
        }
    findings = [r["check_id"] for r in rows if r["required"] and r["finding_codes"]]
    gaps = [r["check_id"] for r in rows if r["required"] and r["reason_codes"]]
    code = 2 if gaps else int(bool(findings))
    return {
        "schema_version": 1,
        "catalog_version": 1,
        "tool": "research-hardening",
        "tool_version": __version__,
        "operation": "assess",
        "completed": True,
        "status": ("satisfied", "finding", "incomplete")[code],
        "exit_code": code,
        "subject": snapshot["subject"],
        "scope": snapshot["scope"],
        "profile": settings["profile"],
        "assurance": assurance,
        "observed_at": snapshot["observed_at"],
        "evaluated_at": evaluated,
        "policy_digest": policy.digest,
        "policy_sha256": policy.raw_hash,
        "snapshot_sha256": snapshot_hash,
        "counts": counts,
        "required_findings": findings,
        "required_gaps": gaps,
        "checks": rows,
        "policy": settings,
        "snapshot": snapshot,
    }
