"""Exercise the three owned JSON readers with bounded synthetic inputs."""

import argparse
import json
import random
from importlib.resources import files

from research_hardening.assess import assess
from research_hardening.compare import read_assessment
from research_hardening.formats import Invalid, decode, encode, instant
from research_hardening.policy import parse_policy
from research_hardening.snapshot import parse_snapshot


def run(seed, count):
    rng = random.Random(seed)
    data = files("research_hardening").joinpath("fixtures")
    p = data.joinpath("linux-policy.json").read_bytes()
    s = data.joinpath("synthetic-linux.json").read_bytes()
    report = assess(p, s, instant(decode(s)["observed_at"]))
    assert report["exit_code"] == 0
    results = {}
    for name, source, reader in (
        ("policy", p, parse_policy),
        ("snapshot", s, parse_snapshot),
        ("assessment", encode(report), read_assessment),
    ):
        reader(source)
        counts = {"accepted": 0, "rejected": 0}
        for i in range(count):
            pos = rng.randrange(len(source))
            samples = (
                source + b" ",
                source[:pos],
                source[:pos] + b"\xff" + source[pos + 1 :],
                source[:pos] + b'"' + source[pos:],
                source[:pos] + source[pos : pos + 3] + source[pos:],
                b'{"unknown":true}',
            )
            try:
                reader(samples[i % len(samples)])
            except Invalid:
                counts["rejected"] += 1
            else:
                counts["accepted"] += 1
        results[name] = counts
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=71)
    parser.add_argument("--count", type=int, choices=range(1, 501), metavar="1..500", default=120)
    args = parser.parse_args()
    print(json.dumps(run(args.seed, args.count), sort_keys=True))
