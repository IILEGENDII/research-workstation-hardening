import hashlib
import json
import re
from datetime import UTC, datetime

POLICY_LIMIT = 64 * 1024
REPORT_LIMIT = 512 * 1024


class Invalid(ValueError):
    pass


def require(condition, reason="invalid_schema"):
    if not condition:
        raise Invalid(reason)


def keys(obj, names):
    require(type(obj) is dict and set(obj) == set(names.split()))


def integer(value, lo, hi):
    require(type(value) is int and lo <= value <= hi)
    return value


def label(value):
    require(type(value) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,47}", value))
    return value


def digest(value):
    require(type(value) is str and re.fullmatch("[a-f0-9]{64}", value))
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def stamp(value):
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def instant(value):
    require(
        type(value) is str
        and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value)
    )
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise Invalid("invalid_time") from None


def _object(pairs):
    out = dict(pairs)
    require(len(out) == len(pairs), "duplicate_key")
    return out


def _number(token):
    require(len(token) <= 16, "number_limit")
    return int(token)


def _reject(token):
    raise Invalid("invalid_number")


def decode(raw, limit=REPORT_LIMIT):
    require(type(raw) is bytes and len(raw) <= limit, "input_size")
    try:
        text = raw.decode("utf-8")
        quoted = escaped = False
        depth = tokens = start = 0
        for i, ch in enumerate(text):
            if quoted:
                require(i - start <= 4097, "string_limit")
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    quoted = False
            elif ch == '"':
                quoted, start = True, i
            elif ch in "{}[],:":
                tokens += 1
                depth += int(ch in "{[") - int(ch in "}]")
                require(0 <= depth <= 24 and tokens <= 24000, "structure_limit")
        doc = json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_number,
            parse_float=_reject,
            parse_constant=_reject,
        )
        require(type(doc) is dict)
        return doc
    except Invalid:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise Invalid("invalid_json") from None
