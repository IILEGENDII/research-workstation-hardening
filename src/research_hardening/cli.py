import argparse
import sys
from dataclasses import asdict

from . import __version__
from .assess import assess
from .catalog import CONTROLS
from .collect import collect
from .compare import compare_reports
from .demo import demo
from .formats import POLICY_LIMIT, Invalid, require
from .policy import parse_policy
from .render import render
from .storage import output_path, read_file, write_new


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
    collect_cmd = subs.add_parser("collect")
    for option in ("policy", "subject", "output"):
        collect_cmd.add_argument("--" + option, required=True)
    collect_cmd.add_argument("--directory")
    collect_cmd.add_argument("--local", action="store_true")
    collect_cmd.add_argument("--confirm-owner-controlled", action="store_true")
    assess_cmd = subs.add_parser("assess")
    for option in ("policy", "snapshot"):
        assess_cmd.add_argument("--" + option, required=True)
    assess_cmd.add_argument("--trust-local-file", action="store_true")
    assess_cmd.add_argument("--output")
    assess_cmd.add_argument("--format", choices=("json", "text"), default="json")
    demo_cmd = subs.add_parser("demo")
    demo_cmd.add_argument("--workspace", required=True)
    compare_cmd = subs.add_parser("compare")
    compare_cmd.add_argument("--before", required=True)
    compare_cmd.add_argument("--after", required=True)
    compare_cmd.add_argument("--output")
    compare_cmd.add_argument("--format", choices=("json", "text"), default="json")
    return p


def run(args):
    if args.verb == "controls":
        rows = {
            cid: asdict(c)
            for cid, c in CONTROLS.items()
            if cid.startswith("WIN" if args.platform == "windows" else "LIN")
        }
        return {
            "operation": "controls",
            "completed": True,
            "status": "complete",
            "catalog_version": 1,
            "controls": rows,
        }, 0
    if args.verb == "demo":
        return demo(args.workspace), 0
    if args.verb == "compare":
        doc = compare_reports(read_file(args.before), read_file(args.after))
        return doc, doc["exit_code"]
    if args.verb == "collect":
        require(args.local and args.confirm_owner_controlled, "authorization_required")
        output_path(args.output, ".json")
        policy = parse_policy(read_file(args.policy, POLICY_LIMIT))
        return collect(
            policy,
            args.subject,
            args.directory,
            local=args.local,
            confirm_owner_controlled=args.confirm_owner_controlled,
        )
    doc = assess(
        read_file(args.policy, POLICY_LIMIT),
        read_file(args.snapshot),
        trust_local=args.trust_local_file,
    )
    return doc, doc["exit_code"]


def main(argv=None):
    try:
        args = parser().parse_args(argv)
        doc, code = run(args)
        fmt = getattr(args, "format", "json")
        raw = render(doc, fmt)
        if getattr(args, "output", None):
            write_new(args.output, raw, ".json" if fmt == "json" else ".txt")
        else:
            print(raw.decode().rstrip())
        return code
    except (Invalid, OSError) as exc:
        print(str(exc) if isinstance(exc, Invalid) else "filesystem_error", file=sys.stderr)
        return 2
