import os
import sys
from pathlib import Path


def classify(platform, release="", container=False, guest=False):
    if platform == "win32":
        return "windows-native"
    if platform != "linux":
        return "unknown"
    wsl = "microsoft" in release.lower()
    if sum((wsl, container, guest)) > 1:
        return "unknown"
    if wsl:
        return "wsl-linux"
    if container:
        return "container-linux"
    return "virtualized-guest" if guest else "linux-visible"


def local_scope():
    if sys.platform != "linux":
        return classify(sys.platform)
    container = any(
        Path(p).exists() for p in ("/.dockerenv", "/run/.containerenv", "/run/systemd/container")
    )
    return classify("linux", os.uname().release, container, Path("/sys/hypervisor/type").exists())
