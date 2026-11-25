import io
import os
import socket
from pathlib import Path

import pytest
from test_assess import replace, scenario
from test_policy import sample

from research_hardening import linux, runner, windows
from research_hardening.cli import main
from research_hardening.formats import Invalid, decode, encode
from research_hardening.policy import parse_policy
from research_hardening.snapshot import parse_snapshot
from research_hardening.storage import new_workspace, read_file, write_new


def test_short_proc_reads_are_not_truncated(monkeypatch):
    class ShortReads(io.BytesIO):
        def read(self, n):
            return super().read(min(n, 1))

    monkeypatch.setattr(Path, "open", lambda *args: ShortReads(b"1\nbad"))
    with pytest.raises(Invalid):
        linux.read_setting("LIN-ASLR-001")


def test_demo_refuses_backup_parent(tmp_path):
    parent = tmp_path / "backups"
    parent.mkdir(mode=0o700)
    with pytest.raises(Invalid):
        new_workspace(parent / "demo")


def test_demo_refuses_repository(tmp_path):
    (tmp_path / ".git").mkdir()
    with pytest.raises(Invalid):
        new_workspace(tmp_path / "demo")


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s.update(schema_version=True),
        lambda s: s.update(completed=False),
        lambda s: s.update(status="partial"),
        lambda s: s.update(issues=["private-sentinel"]),
        lambda s: s["observations"].append(s["observations"][0]),
        lambda s: s["observations"][0].update(source="private-sentinel"),
        lambda s: s["observations"][0].update(status="unavailable", reason="unavailable"),
        lambda s: s.update(ended_at="2020-01-01T12:02:00Z"),
    ],
)
def test_contradictory_metadata(change):
    doc = decode(sample("synthetic-linux"))
    change(doc)
    with pytest.raises(Invalid):
        parse_snapshot(encode(doc))


@pytest.mark.parametrize(
    "mode,enabled,state",
    [
        ("Normal", True, "satisfied"),
        ("Normal", False, "finding"),
        ("Passive Mode", False, "inconclusive"),
        ("EDR Block Mode", True, "inconclusive"),
    ],
)
def test_defender_mode(mode, enabled, state):
    val = {"mode": mode, "realtime": enabled, "antivirus": True, "service": True}
    r = scenario("windows", lambda d: replace(d, "WIN-AV-001", "observed", val))
    assert next(row for row in r["checks"] if row["check_id"] == "WIN-AV-001")["state"] == state


@pytest.mark.parametrize(
    "state,percent,protection,expected",
    [
        ("FullyEncrypted", 100, "On", 0),
        ("FullyEncrypted", 100, "Off", 1),
        ("EncryptionInProgress", 47, "On", 1),
        ("FullyDecrypted", 0, "Off", 1),
    ],
)
def test_bitlocker_policy(state, percent, protection, expected):
    val = {"state": state, "volume": "C:", "percent": percent, "protection": protection}
    assert (
        scenario("windows", lambda d: replace(d, "WIN-DISK-001", "observed", val))["exit_code"]
        == expected
    )


@pytest.mark.parametrize("age,expected", [(7, 0), (8, 1)])
def test_signature_threshold(age, expected):
    assert (
        scenario("windows", lambda d: replace(d, "WIN-AV-002", "observed", age))["exit_code"]
        == expected
    )


def test_reject_unselected_or_injected_fields():
    row = {
        "volume": "C:",
        "state": "FullyEncrypted",
        "percent": 100,
        "protection": "On",
        "key": "private-sentinel",
    }
    result = windows.result({"id": "WIN-DISK-001", "volume": "C:"}, "ok", encode({"rows": [row]}))
    assert result["status"] == "invalid" and b"private-sentinel" not in encode(result)


def test_cli_errors_do_not_reveal_inputs(capsys):
    assert main(["collect", "--host", "private-sentinel"]) == 2
    assert "private-sentinel" not in capsys.readouterr().err
    assert main(["controls", "--plat", "windows"]) == 2


def test_offline_commands_never_probe(tmp_path, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected network or child process")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(runner.subprocess, "Popen", forbidden)
    assert main(["controls", "--platform", "linux"]) == 0
    root = tmp_path / "demo"
    assert main(["demo", "--workspace", str(root)]) == 0
    assert (
        main(
            [
                "assess",
                "--policy",
                str(root / "windows-policy.json"),
                "--snapshot",
                str(root / "windows-snapshot.json"),
            ]
        )
        == 2
    )
    assert (
        main(
            [
                "compare",
                "--before",
                str(root / "linux-satisfied.json"),
                "--after",
                str(root / "linux-mixed.json"),
            ]
        )
        == 1
    )


def test_failed_publish_removes_own_temp(tmp_path, monkeypatch):
    def fail(*args):
        raise PermissionError

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(PermissionError):
        write_new(tmp_path / "out.json", b"x")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory metadata")
def test_only_selected_directory_metadata(tmp_path, monkeypatch):
    path = tmp_path / "dataset"
    path.mkdir(mode=0o700)
    secret = path / "private-sentinel"
    secret.write_bytes(b"fixture")
    monkeypatch.setattr(Path, "iterdir", lambda *args: pytest.fail("traversal"))
    monkeypatch.setattr(Path, "open", lambda *args: pytest.fail("content read"))
    assert linux.read_directory(path, "data") == {
        "directory_subject": "data",
        "directory": True,
        "owned": True,
        "mode": 0o700,
    }
    path.chmod(0o750)
    assert linux.read_directory(path, "data")["mode"] == 0o750
    assert not linux.read_directory(secret, "data")["directory"]
    (tmp_path / "alias").symlink_to(path)
    with pytest.raises(Invalid):
        linux.read_directory(tmp_path / "alias", "data")


def test_protected_selections():
    from research_hardening.paths import selected_path

    for p in (Path.home(), Path.cwd().anchor):
        with pytest.raises(Invalid):
            selected_path(p)


def test_unchanged_regular_file(tmp_path):
    path = tmp_path / "evidence.json"
    write_new(path, b"123\n")
    assert read_file(path) == b"123\n"


def test_duplicate_policy_rows():
    doc = decode(sample("linux-policy"))
    doc["checks"].append(doc["checks"][0])
    with pytest.raises(Invalid):
        parse_policy(encode(doc))
