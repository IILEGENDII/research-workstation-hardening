import io
from pathlib import Path

import pytest

from research_hardening import linux, windows
from research_hardening.catalog import PROFILES
from research_hardening.environment import classify
from research_hardening.formats import Invalid, encode


@pytest.mark.parametrize(
    "platform,release,container,guest,scope",
    [
        ("linux", "microsoft", False, False, "wsl-linux"),
        ("linux", "test", True, False, "container-linux"),
        ("linux", "test", False, True, "virtualized-guest"),
        ("linux", "test", False, False, "linux-visible"),
        ("linux", "Microsoft", True, False, "unknown"),
        ("win32", "", False, False, "windows-native"),
        ("darwin", "", False, False, "unknown"),
    ],
)
def test_visible_scope(platform, release, container, guest, scope):
    assert classify(platform, release, container, guest) == scope


@pytest.mark.parametrize(
    "cid,raw,expected",
    [
        ("LIN-ASLR-001", b" 0\n", 0),
        ("LIN-ASLR-001", b"1", 1),
        ("LIN-ASLR-001", b"2", 2),
        ("LIN-KPTR-001", b"2", 2),
        ("LIN-DMESG-001", b"1", 1),
        ("LIN-DMESG-001", b"2", None),
        ("LIN-KPTR-001", b"2 1", None),
        ("LIN-KPTR-001", b" " * 65 + b"1", None),
    ],
)
def test_kernel_reader(monkeypatch, cid, raw, expected):
    monkeypatch.setattr(Path, "open", lambda *args: io.BytesIO(raw))
    if expected is None:
        with pytest.raises(Invalid):
            linux.read_setting(cid)
    else:
        assert linux.read_setting(cid) == expected


def fw():
    return [{"name": n, "enabled": "True", "inbound": "Block"} for n in reversed(PROFILES)]


@pytest.mark.parametrize("bad", ["missing", "duplicate", "unexpected", "object", "boolean"])
def test_firewall_requires_exact_profiles(bad):
    rows = fw()
    if bad == "missing":
        rows.pop()
    elif bad == "duplicate":
        rows[0] = rows[1]
    elif bad == "unexpected":
        rows[0]["name"] = "other"
    elif bad == "boolean":
        rows[0]["enabled"] = 1
    else:
        rows = rows[0]
    assert windows.result({"id": "WIN-FW-001"}, "ok", encode({"rows": rows}))["status"] == "invalid"


def test_disabled_profile_and_unresolved_action():
    rows = fw()
    rows[0].update(enabled="False", inbound="NotConfigured")
    assert windows.parse_response("WIN-FW-001", encode({"rows": rows}))["Public"] is False
    assert windows.parse_response("WIN-FW-002", encode({"rows": rows}))["Public"] == "NotConfigured"


@pytest.mark.parametrize(
    "cid,rows,status",
    [
        ("WIN-BOOT-001", [False], "observed"),
        ("WIN-BOOT-001", [True], "observed"),
        ("WIN-BOOT-001", [1], "invalid"),
        ("WIN-BOOT-001", [], "invalid"),
        (
            "WIN-DISK-001",
            [{"volume": "D:", "state": "FullyEncrypted", "percent": 100, "protection": "On"}],
            "invalid",
        ),
        (
            "WIN-DISK-001",
            [{"volume": "C:", "state": "FullyEncrypted", "percent": 100, "protection": "Off"}],
            "observed",
        ),
    ],
)
def test_native_projection(cid, rows, status):
    assert (
        windows.result({"id": cid, "volume": "C:"}, "ok", encode({"rows": rows}))["status"]
        == status
    )


@pytest.mark.parametrize("age", [None, 65535, 4294967295, True, -1])
def test_invalid_signature_age(age):
    row = {"age": age, "mode": "Normal", "service": True, "realtime": True, "antivirus": True}
    assert (
        windows.result({"id": "WIN-AV-002"}, "ok", encode({"rows": [row]}))["status"] == "invalid"
    )


def test_command_boundary():
    argv, env = windows.command(Path("X:/system"), "bitlocker", "c:")
    assert env["HARDENING_VOLUME"] == "C:" and "C:" not in argv[-1]
    assert "-NoProfile" in argv and "KeyProtector" not in argv[-1]
    for op, volume in [("arbitrary", None), ("bitlocker", "C:;bad"), ("boot", "C:")]:
        with pytest.raises(Invalid):
            windows.command(Path("X:/system"), op, volume)
