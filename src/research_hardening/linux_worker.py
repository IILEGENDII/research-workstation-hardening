import sys

from .catalog import LINUX
from .environment import local_scope
from .formats import Invalid, encode, label, require
from .linux import NODES, read_directory, read_setting


def main(args):
    try:
        require(len(args) in (4, 6) and args[:2] == ["--local", "--confirm-owner-controlled"])
        scope, cid = args[2:4]
        require(scope in LINUX and scope == local_scope())
        if cid == "LIN-DATA-001":
            require(len(args) == 6)
            value = read_directory(args[5], label(args[4]))
        else:
            require(len(args) == 4 and cid in NODES)
            value = read_setting(cid)
        sys.stdout.buffer.write(encode({"value": value}))
        return 0
    except PermissionError:
        return 20
    except FileNotFoundError:
        return 21
    except Invalid:
        return 23
    except OSError:
        return 22


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
