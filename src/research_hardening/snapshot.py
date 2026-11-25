from . import __version__
from .catalog import CONTROLS, PROFILES, SCOPES
from .formats import decode, digest, instant, integer, keys, label, require
from .policy import drive

GAPS = ("not_collected", "permission_denied", "unsupported", "unavailable", "invalid", "timeout")


def observation(cid, status, value=None):
    return {
        "check_id": cid,
        "source": CONTROLS[cid].source,
        "status": status,
        "reason": None if status == "observed" else status,
        "value": value,
    }


def validate_value(cid, value):
    if cid in ("WIN-FW-001", "WIN-FW-002"):
        keys(value, " ".join(PROFILES))
        for item in value.values():
            require(
                type(item) is bool
                if cid == "WIN-FW-001"
                else item in ("Block", "Allow", "NotConfigured")
            )
    elif cid == "WIN-AV-001":
        keys(value, "service antivirus realtime mode")
        require(all(type(value[k]) is bool for k in ("service", "antivirus", "realtime")))
        require(value["mode"] in ("Normal", "Passive Mode", "EDR Block Mode", "SxS Passive Mode"))
    elif cid == "WIN-AV-002":
        integer(value, 0, 65534)
    elif cid == "WIN-DISK-001":
        keys(value, "volume state percent protection")
        require(drive(value["volume"]) == value["volume"])
        require(
            value["state"]
            in (
                "FullyEncrypted",
                "FullyDecrypted",
                "EncryptionInProgress",
                "DecryptionInProgress",
                "EncryptionPaused",
                "DecryptionPaused",
            )
        )
        integer(value["percent"], 0, 100)
        require(value["state"] != "FullyEncrypted" or value["percent"] == 100)
        require(value["state"] != "FullyDecrypted" or value["percent"] == 0)
        require(value["protection"] in ("On", "Off"))
    elif cid == "WIN-BOOT-001":
        require(type(value) is bool)
    elif cid == "LIN-DATA-001":
        keys(value, "directory_subject directory owned mode")
        label(value["directory_subject"])
        require(type(value["directory"]) is bool and type(value["owned"]) is bool)
        integer(value["mode"], 0, 0o7777)
    else:
        integer(value, 0, 1 if cid == "LIN-DMESG-001" else 2)


def parse_snapshot(raw):
    doc = decode(raw)
    keys(
        doc,
        "schema_version catalog_version tool tool_version operation subject scope environment collection observed_at started_at ended_at policy_sha256 policy_digest observations issues completed status",
    )
    for key in ("schema_version", "catalog_version"):
        integer(doc[key], 1, 1)
    require(
        doc["tool"] == "research-hardening"
        and doc["tool_version"] == __version__
        and doc["operation"] == "collect"
    )
    label(doc["subject"])
    require(doc["scope"] in SCOPES and doc["environment"] in (*SCOPES, "unknown"))
    require(doc["environment"] in (doc["scope"], "unknown"))
    require(doc["collection"] in ("synthetic_fixture", "operator_import", "local_capture"))
    start, observed, end = (instant(doc[k]) for k in ("started_at", "observed_at", "ended_at"))
    require(start <= observed <= end and (end - start).total_seconds() <= 60, "invalid_interval")
    digest(doc["policy_sha256"])
    digest(doc["policy_digest"])
    rows = doc["observations"]
    require(type(rows) is list and len(rows) <= len(CONTROLS))
    seen = set()
    for row in rows:
        keys(row, "check_id status source value reason")
        cid = row["check_id"]
        require(type(cid) is str and cid in CONTROLS and cid not in seen)
        require(cid.startswith("WIN-") == (doc["scope"] == "windows-native"))
        seen.add(cid)
        require(row["source"] == CONTROLS[cid].source)
        if row["status"] == "observed":
            require(row["reason"] is None)
            validate_value(cid, row["value"])
        else:
            require(
                row["status"] in GAPS and row["reason"] == row["status"] and row["value"] is None
            )
    require(doc["issues"] in ([], ["deadline"], ["interrupted"]))
    require(type(doc["completed"]) is bool and doc["completed"] == (not doc["issues"]))
    complete = bool(rows) and doc["completed"] and all(r["status"] == "observed" for r in rows)
    require(doc["status"] == ("complete" if complete else "partial"))
    return doc
