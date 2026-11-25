import os
import stat
from pathlib import Path

from .formats import Invalid, require
from .paths import outside_repository, plain, selected_path
from .snapshot import validate_value

NODES = {
    "LIN-ASLR-001": Path("/proc/sys/kernel/randomize_va_space"),
    "LIN-KPTR-001": Path("/proc/sys/kernel/kptr_restrict"),
    "LIN-DMESG-001": Path("/proc/sys/kernel/dmesg_restrict"),
}


def read_setting(cid):
    require(cid in NODES)
    raw = bytearray()
    with NODES[cid].open("rb") as stream:
        while len(raw) < 65 and (chunk := stream.read(65 - len(raw))):
            raw.extend(chunk)
    require(len(raw) <= 64 and raw.strip() in (b"0", b"1", b"2"))
    value = int(raw)
    validate_value(cid, value)
    return value


def read_directory(directory, subject):
    require(directory is not None, "directory_required")
    path = selected_path(directory)
    info = path.lstat()
    plain(info)
    outside_repository(path.parent)
    if stat.S_ISDIR(info.st_mode):
        require(not os.path.lexists(path / ".git"), "repository_directory")
    for entry in (path, *path.parents):
        if entry != Path(entry.anchor) and entry.is_mount():
            raise Invalid("mount_boundary")
    return {
        "directory_subject": subject,
        "directory": stat.S_ISDIR(info.st_mode),
        "owned": info.st_uid == os.getuid(),
        "mode": stat.S_IMODE(info.st_mode),
    }
