import re
from dataclasses import dataclass

from .catalog import CONTROLS, SCOPES
from .formats import POLICY_LIMIT, decode, encode, integer, keys, label, require, sha


def drive(value):
    require(type(value) is str and re.fullmatch("[A-Za-z]:", value), "invalid_volume")
    return value.upper()


@dataclass(frozen=True)
class Policy:
    settings: dict
    raw_hash: str

    @property
    def digest(self):
        return sha(encode(self.settings))


def parse_policy(raw):
    doc = decode(raw, POLICY_LIMIT)
    keys(doc, "schema_version catalog_version policy_id profile scope max_age_hours checks")
    integer(doc["schema_version"], 1, 1)
    integer(doc["catalog_version"], 1, 1)
    label(doc["policy_id"])
    require(doc["profile"] in ("workstation", "synthetic") and doc["scope"] in SCOPES)
    integer(doc["max_age_hours"], 1, 8760)
    checks = doc["checks"]
    require(type(checks) is list and 1 <= len(checks) <= len(CONTROLS))
    seen = set()
    for row in checks:
        require(type(row) is dict)
        cid = row.get("id")
        require(type(cid) is str and cid in CONTROLS and cid not in seen)
        require(cid.startswith("WIN-") == (doc["scope"] == "windows-native"))
        seen.add(cid)
        extra = {
            "WIN-AV-002": "max_age_days",
            "WIN-DISK-001": "volume",
            "LIN-KPTR-001": "minimum",
            "LIN-DATA-001": "private directory_subject",
        }.get(cid, "")
        require(
            set(row) <= set(("id required " + extra).split()) and type(row.get("required")) is bool
        )
        if cid == "WIN-AV-002":
            row["max_age_days"] = integer(row.get("max_age_days", 7), 0, 365)
        elif cid == "WIN-DISK-001":
            row["volume"] = drive(row.get("volume"))
        elif cid == "LIN-KPTR-001":
            row["minimum"] = integer(row.get("minimum", 1), 1, 2)
        elif cid == "LIN-DATA-001":
            label(row.get("directory_subject"))
            require(type(row.setdefault("private", True)) is bool)
    require(any(c["required"] for c in checks))
    checks.sort(key=lambda c: c["id"])
    return Policy(doc, sha(raw))
