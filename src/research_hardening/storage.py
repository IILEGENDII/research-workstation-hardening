import os
import stat
import tempfile
from pathlib import Path

from .formats import REPORT_LIMIT, require
from .paths import ancestry, local_path, outside_repository, plain, selected_path


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        # Windows path and handle stat calls can disagree on change time.
        info.st_ctime_ns if os.name != "nt" else None,
    )


def read_file(value, limit=REPORT_LIMIT):
    path = local_path(value)
    ancestry(path)
    original = path.lstat()
    plain(original)
    require(
        stat.S_ISREG(original.st_mode) and original.st_nlink == 1 and original.st_size <= limit,
        "unsafe_input",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    with os.fdopen(os.open(path, flags), "rb") as f:
        require(identity(original) == identity(os.fstat(f.fileno())), "unstable_input")
        raw = f.read(limit + 1)
        require(
            len(raw) == original.st_size
            and identity(original) == identity(os.fstat(f.fileno()))
            and identity(original) == identity(path.lstat()),
            "unstable_input",
        )
    return raw


def private_directory(path):
    info = path.lstat()
    plain(info)
    require(stat.S_ISDIR(info.st_mode), "unsafe_parent")
    if os.name == "posix":
        require(info.st_uid == os.getuid() and not info.st_mode & 0o077, "private_parent_required")


def output_path(value, suffix):
    path = local_path(value)
    require(path.suffix == suffix, "invalid_extension")
    ancestry(path)
    private_directory(path.parent)
    require(not os.path.lexists(path), "output_exists")
    return path


def write_new(value, data, suffix=".json"):
    path = output_path(value, suffix)
    require(len(data) <= REPORT_LIMIT, "output_size")
    fd, name = tempfile.mkstemp(prefix=".hardening-", dir=path.parent)
    tmp = Path(name)
    original = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        require(os.path.samestat(original, tmp.lstat()), "unstable_output")
        if os.name == "nt":
            os.rename(tmp, path)
        else:
            os.link(tmp, path)
    finally:
        try:
            if os.path.samestat(original, tmp.lstat()):
                tmp.unlink()
        except FileNotFoundError:
            pass


def new_workspace(value):
    path = selected_path(value)
    private_directory(path.parent)
    outside_repository(path.parent)
    path.mkdir(mode=0o700)
    return path
