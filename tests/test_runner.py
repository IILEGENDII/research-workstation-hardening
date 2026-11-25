import os
import sys
from pathlib import Path

import pytest

from research_hardening.runner import _capture


@pytest.mark.parametrize(
    "script,timeout,state",
    [
        ("print(23)", 3, "ok"),
        ("import time; time.sleep(3)", 0.1, "timeout"),
        ("import sys; sys.stdout.buffer.write(b'x'*65537)", 3, "invalid"),
        ("import sys; sys.stderr.buffer.write(b'x'*65537)", 3, "invalid"),
        ("raise SystemExit(3)", 3, "unavailable"),
        ("raise SystemExit(20)", 3, "permission_denied"),
    ],
)
def test_harmless_child(tmp_path, script, timeout, state):
    status, raw = _capture(
        [sys.executable, "-I", "-c", script], dict(os.environ), tmp_path, timeout
    )
    assert status == state
    assert raw.strip() == (b"23" if state == "ok" else b"")


def test_missing_executable(tmp_path):
    assert _capture([str(tmp_path / "absent")], {}, Path(tmp_path), 1) == ("unavailable", b"")
