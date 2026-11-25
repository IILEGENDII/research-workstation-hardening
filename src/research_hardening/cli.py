import argparse
import sys
from dataclasses import asdict

from . import __version__
from .catalog import CONTROLS
from .formats import Invalid, encode


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, allow_abbrev=False, **kwargs)

    def error(self, message):
        raise Invalid("invalid_arguments")


def parser():
    p = Parser(prog="research-hardening")
    p.add_argument("--version", action="version", version=__version__)
    subs = p.add_subparsers(dest="verb", required=True)
    controls = subs.add_parser("controls")
    controls.add_argument("--platform", choices=("linux", "windows"), required=True)
    return p


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        rows = {
            cid: asdict(c)
            for cid, c in CONTROLS.items()
            if cid.startswith("WIN" if args.platform == "windows" else "LIN")
        }
        print(
            encode(
                {
                    "operation": "controls",
                    "completed": True,
                    "status": "complete",
                    "catalog_version": 1,
                    "controls": rows,
                }
            )
            .decode()
            .rstrip()
        )
        return 0
    except Invalid as exc:
        print(str(exc), file=sys.stderr)
        return 2
