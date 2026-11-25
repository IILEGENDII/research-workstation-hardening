import os
import re
import stat
from pathlib import Path, PureWindowsPath

from .formats import require


def local_path(value):
    text = os.fspath(value)
    require(type(text) is str and 0 < len(text) <= 2048, "unsafe_path")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in text), "unsafe_path")
    win = PureWindowsPath(text)
    require(not text.startswith(("\\", "//")) and "://" not in text, "unsafe_path")
    require(
        not win.drive or (os.name == "nt" and re.fullmatch("[A-Za-z]:", win.drive) and win.root),
        "unsafe_path",
    )
    require(os.name == "nt" or "\\" not in text, "unsafe_path")
    parts = win.parts[1:] if win.anchor else win.parts
    for part in parts:
        require(part not in (".", "..") and not part.endswith((" ", ".")), "unsafe_path")
        require(not any(c in part for c in ':*?"<>|'), "unsafe_path")
        require(
            not re.fullmatch(
                r"(?:CON|AUX|NUL|PRN|CONIN\$|CONOUT\$|(?:LPT|COM)[0-9¹²³])(?:\..*)?",
                part,
                re.IGNORECASE,
            ),
            "unsafe_path",
        )
    return Path(text).absolute()


def plain(info):
    require(
        not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
        "linked_path",
    )


def ancestry(path):
    for parent in reversed(path.parents):
        info = parent.lstat()
        plain(info)
        require(stat.S_ISDIR(info.st_mode), "unsafe_parent")


def selected_path(value):
    path = local_path(value)
    require(
        Path(value).is_absolute() and path != Path.home() and path != Path(path.anchor),
        "protected_directory",
    )
    if os.name == "nt":
        blocked = {
            "windows",
            "program files",
            "program files (x86)",
            "programdata",
            "recovery",
            "system volume information",
        }
    else:
        blocked = {
            "boot",
            "bin",
            "dev",
            "etc",
            "lib",
            "lib64",
            "proc",
            "root",
            "run",
            "sbin",
            "sys",
            "usr",
            "var",
            "mnt",
            "media",
        }
    require(len(path.parts) > 1 and path.parts[1].lower() not in blocked, "protected_directory")
    ancestry(path)
    return path


def outside_repository(path):
    for parent in (path, *path.parents):
        require(not os.path.lexists(parent / ".git"), "repository_directory")
