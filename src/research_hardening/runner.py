import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import windows
from .formats import Invalid, require
from .linux import NODES

CAP = 65536


def _capture(argv, env, cwd, timeout):
    if timeout <= 0:
        return "timeout", b""
    end = time.monotonic() + min(10, timeout)
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
    except (OSError, ValueError):
        return "unavailable", b""
    stdout = bytearray()
    stop = threading.Event()
    errors = []

    def drain(stream, keep):
        size = 0
        try:
            with stream:
                while chunk := stream.read1(4096):
                    size += len(chunk)
                    if size > CAP:
                        errors.append("invalid")
                        stop.set()
                        return
                    if keep:
                        stdout.extend(chunk)
        except (OSError, ValueError):
            errors.append("unavailable")
            stop.set()

    threads = [
        threading.Thread(target=drain, args=(s, k), daemon=True)
        for s, k in ((proc.stdout, True), (proc.stderr, False))
    ]
    status = "ok"
    try:
        for thread in threads:
            thread.start()
        while proc.poll() is None or any(t.is_alive() for t in threads):
            if errors or time.monotonic() >= end:
                status = errors[0] if errors else "timeout"
                break
            stop.wait(min(0.01, max(0, end - time.monotonic())))
    except (OSError, RuntimeError, KeyboardInterrupt):
        status = "unavailable"
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=0.4)
            for thread in threads:
                if thread.ident is not None:
                    thread.join(0.15)
            if any(t.is_alive() for t in threads):
                status = "unavailable"
        except (OSError, subprocess.TimeoutExpired):
            status = "unavailable"
    if status == "ok":
        status = (
            errors[0]
            if errors
            else {0: "ok", 20: "permission_denied", 21: "unsupported", 23: "invalid"}.get(
                proc.returncode, "unavailable"
            )
        )
    return status, bytes(stdout) if status == "ok" else b""


def probe(check, scope, directory, timeout):
    cid = check["id"]
    if cid in windows.OPERATIONS:
        try:
            system = windows.system_directory()
            argv, env = windows.command(system, windows.OPERATIONS[cid], check.get("volume"))
        except Invalid as exc:
            return str(exc), b""
        return _capture(argv, env, system / "System32", timeout)
    require(cid in NODES or cid == "LIN-DATA-001")
    argv = [
        sys.executable,
        "-I",
        "-m",
        "research_hardening.linux_worker",
        "--local",
        "--confirm-owner-controlled",
        scope,
        cid,
    ]
    if cid == "LIN-DATA-001":
        require(directory is not None, "directory_required")
        argv.extend([check["directory_subject"], os.fspath(directory)])
    return _capture(argv, {}, Path("/"), timeout)
