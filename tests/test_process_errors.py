import io
import subprocess

import pytest

from research_hardening import runner
from research_hardening.windows import result


@pytest.mark.parametrize("interrupt,cleanup", [(True, False), (False, True)])
def test_uncertain_process_is_a_gap(monkeypatch, tmp_path, interrupt, cleanup):
    class Child:
        stdout = io.BufferedReader(io.BytesIO(b"ignored"))
        stderr = io.BufferedReader(io.BytesIO(b"private-sentinel"))
        returncode = None
        first = True

        def poll(self):
            if self.first and interrupt:
                self.first = False
                raise KeyboardInterrupt
            return self.returncode

        def kill(self):
            self.returncode = -1

        def wait(self, timeout):
            if cleanup:
                raise subprocess.TimeoutExpired("test", timeout)
            return self.returncode

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Child())
    assert runner._capture(["synthetic"], {}, tmp_path, 0.01) == ("unavailable", b"")


@pytest.mark.parametrize(
    "status", ["permission_denied", "timeout", "unavailable", "unsupported", "invalid"]
)
def test_runner_errors_never_become_values(status):
    row = result({"id": "WIN-BOOT-001"}, status, b"private-sentinel")
    assert row["value"] is None and row["reason"] == status


def test_malformed_success():
    assert result({"id": "WIN-BOOT-001"}, "ok", b"not json")["status"] == "invalid"
