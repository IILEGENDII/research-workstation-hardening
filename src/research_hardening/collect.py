import time
from datetime import UTC, datetime
from pathlib import Path

from . import __version__, windows
from .environment import local_scope
from .formats import Invalid, decode, encode, keys, label, require, stamp
from .paths import local_path
from .runner import probe
from .snapshot import observation, parse_snapshot, validate_value


def collect(policy, subject, directory=None, *, local=False, confirm_owner_controlled=False):
    require(local is True and confirm_owner_controlled is True, "authorization_required")
    label(subject)
    settings = policy.settings
    require(settings["profile"] == "workstation", "workstation_policy_required")
    checks = settings["checks"]
    needs_directory = any(c["id"] == "LIN-DATA-001" for c in checks)
    require(needs_directory == (directory is not None), "directory_selection")
    if directory is not None:
        require(Path(directory).is_absolute(), "absolute_directory_required")
        directory = local_path(directory)
    started = datetime.now(UTC)
    deadline = time.monotonic() + 58
    scope = local_scope()
    require(scope == settings["scope"], "scope_mismatch")
    rows = []
    issues = []
    cache = {}
    for check in checks:
        cid = check["id"]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            issues = ["deadline"]
            rows.append(observation(cid, "not_collected"))
            continue
        op = windows.OPERATIONS.get(cid, cid)
        if op not in cache:
            cache[op] = probe(check, scope, directory, min(9, remaining))
        status, raw = cache[op]
        if cid in windows.OPERATIONS:
            row = windows.result(check, status, raw)
        elif status == "ok":
            try:
                doc = decode(raw, 65536)
                keys(doc, "value")
                validate_value(cid, doc["value"])
                row = observation(cid, "observed", doc["value"])
            except Invalid:
                row = observation(cid, "invalid")
        else:
            row = observation(cid, status)
        rows.append(row)
    end = datetime.now(UTC)
    complete = not issues and all(r["status"] == "observed" for r in rows)
    doc = {
        "schema_version": 1,
        "catalog_version": 1,
        "tool": "research-hardening",
        "tool_version": __version__,
        "operation": "collect",
        "subject": subject,
        "scope": scope,
        "environment": scope,
        "collection": "local_capture",
        "observed_at": stamp(started),
        "started_at": stamp(started),
        "ended_at": stamp(end),
        "policy_sha256": policy.raw_hash,
        "policy_digest": policy.digest,
        "observations": rows,
        "issues": issues,
        "completed": not issues,
        "status": "complete" if complete else "partial",
    }
    required = {c["id"] for c in checks if c["required"]}
    code = (
        2
        if issues or any(r["status"] != "observed" and r["check_id"] in required for r in rows)
        else 0
    )
    return parse_snapshot(encode(doc)), code
