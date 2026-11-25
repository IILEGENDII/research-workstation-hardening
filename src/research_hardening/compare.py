from datetime import UTC, datetime

from .assess import evaluate
from .formats import decode, digest, encode, instant, require, sha
from .policy import Policy, parse_policy
from .snapshot import parse_snapshot


def read_assessment(raw):
    doc = decode(raw)
    required = (
        "policy",
        "snapshot",
        "policy_sha256",
        "snapshot_sha256",
        "evaluated_at",
        "assurance",
    )
    require(all(k in doc for k in required))
    policy = parse_policy(encode(doc["policy"]))
    policy = Policy(policy.settings, digest(doc["policy_sha256"]))
    snapshot = parse_snapshot(encode(doc["snapshot"]))
    require(instant(doc["evaluated_at"]) <= datetime.now(UTC), "future_assessment")
    expected = evaluate(
        policy,
        snapshot,
        digest(doc["snapshot_sha256"]),
        doc["evaluated_at"],
        doc["assurance"] == "operator_selected_local_file",
    )
    # Recompute verdicts from the exported inputs. Raw file hashes remain producer assertions.
    require(encode(doc) == encode(expected), "inconsistent_assessment")
    return doc


def compare_reports(before, after):
    a, b = read_assessment(before), read_assessment(after)
    incompatible = [
        k
        for k in ("subject", "scope", "profile", "catalog_version", "policy_digest")
        if a[k] != b[k]
    ]
    changes = []
    if not incompatible:
        previous = {r["check_id"]: r for r in a["checks"]}
        for row in b["checks"]:
            old = previous[row["check_id"]]
            kinds = []
            if (
                old["coverage"] == row["coverage"] == "observed"
                and old["observed_value"] != row["observed_value"]
            ):
                kinds.append("value_changed")
            if (old["state"], old["finding_codes"]) != (row["state"], row["finding_codes"]):
                kinds.append("state_changed")
            if (
                old["coverage"] != row["coverage"]
                or a["assurance"] != b["assurance"]
                or set(old["reason_codes"]) - {"stale"} != set(row["reason_codes"]) - {"stale"}
            ):
                kinds.append("coverage_changed")
            if old["source"] != row["source"]:
                kinds.append("source_changed")
            if ("stale" in old["reason_codes"]) != ("stale" in row["reason_codes"]):
                kinds.append("freshness_changed")
            if kinds:
                changes.append(
                    {
                        "check_id": row["check_id"],
                        "changes": kinds,
                        "before_state": old["state"],
                        "after_state": row["state"],
                        "before_coverage": old["coverage"],
                        "after_coverage": row["coverage"],
                    }
                )
    code = 2 if incompatible else int(bool(changes))
    return {
        "schema_version": 1,
        "operation": "compare",
        "completed": not incompatible,
        "status": ("unchanged", "changed", "incompatible")[code],
        "exit_code": code,
        "before_sha256": sha(before),
        "after_sha256": sha(after),
        "raw_policy_changed": a["policy_sha256"] != b["policy_sha256"],
        "assurance": "unverified_producers",
        "subject_binding": "operator_label",
        "incompatible": incompatible,
        "changes": changes,
    }
