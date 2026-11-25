import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
with (ROOT / "pyproject.toml").open("rb") as config:
    VERSION = tomllib.load(config)["project"]["version"]
DIST = "research_workstation_hardening-" + VERSION


def source_files():
    files = {
        p.name: p
        for p in (
            ROOT / name
            for name in (
                "AGENTS.md",
                "CHANGELOG.md",
                "CONTRIBUTING.md",
                "SECURITY.md",
                "LICENSE",
                "README.md",
                "MANIFEST.in",
                "pyproject.toml",
            )
        )
    }
    for name, pattern in (
        ("docs", "*.md"),
        ("tools", "*.py"),
        ("tests", "*.py"),
        ("src/research_hardening", "*.py"),
        ("src/research_hardening/fixtures", "*.json"),
    ):
        for p in (ROOT / name).glob(pattern):
            files[p.relative_to(ROOT).as_posix()] = p
    return files


def inspect(archive):
    source = source_files()
    if archive.suffix == ".whl":
        expected = {n[4:]: p for n, p in source.items() if n.startswith("src/")}
        meta = {
            DIST + ".dist-info/" + n
            for n in (
                "METADATA",
                "WHEEL",
                "entry_points.txt",
                "licenses/LICENSE",
                "RECORD",
                "top_level.txt",
            )
        }
        with zipfile.ZipFile(archive) as wheel:
            names = wheel.namelist()
            assert len(names) == len(set(names)) and set(names) == expected.keys() | meta
            assert (
                wheel.read(DIST + ".dist-info/licenses/LICENSE") == source["LICENSE"].read_bytes()
            )
            for name, path in expected.items():
                assert wheel.read(name) == path.read_bytes(), name
    else:
        expected = set(source)
        metadata = {"PKG-INFO", "setup.cfg"} | {
            "src/research_workstation_hardening.egg-info/" + n
            for n in (
                "PKG-INFO",
                "SOURCES.txt",
                "dependency_links.txt",
                "entry_points.txt",
                "top_level.txt",
                "requires.txt",
            )
        }
        seen = set()
        with tarfile.open(archive) as tgz:
            for member in tgz:
                assert member.isfile() or member.isdir()
                if member.isdir():
                    continue
                prefix, _, name = member.name.partition("/")
                assert prefix == DIST and name in expected | metadata and name not in seen, name
                seen.add(name)
                if name in expected:
                    assert tgz.extractfile(member).read() == source[name].read_bytes(), name
        assert expected <= seen


def smoke(archive):
    with tempfile.TemporaryDirectory(prefix="hardening-install-") as tmp:
        root = Path(tmp).resolve()
        env_dir = root / "env"
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", env_dir], check=True)
        bin_dir = env_dir / ("Scripts" if os.name == "nt" else "bin")
        python = bin_dir / ("python.exe" if os.name == "nt" else "python")
        cli = bin_dir / ("research-hardening.exe" if os.name == "nt" else "research-hardening")
        pip = [sys.executable, "-m", "pip", "--python", str(python)]
        env = {**os.environ, "PIP_NO_CACHE_DIR": "1"}
        subprocess.run([*pip, "install", archive], cwd=root, env=env, check=True)
        subprocess.run([*pip, "check"], cwd=root, env=env, check=True)

        def run(*args, code=0):
            p = subprocess.run(
                args, cwd=root, env=env, capture_output=True, timeout=30, check=False
            )
            if p.returncode != code:
                raise RuntimeError(
                    f"expected exit {code}, observed {p.returncode}: {p.stderr[:150]!r}"
                )
            return p.stdout

        for entry in ([cli], [python, "-I", "-m", "research_hardening"]):
            assert run(*entry, "--version").strip() == VERSION.encode()
            assert b"collect" in run(*entry, "--help")
        for platform, count in (("linux", 4), ("windows", 6)):
            assert (
                len(json.loads(run(cli, "controls", "--platform", platform))["controls"]) == count
            )
        demo = root / "demo"
        summary = json.loads(run(cli, "demo", "--workspace", demo))
        assert len(summary["scenario_exits"]) == 16
        args = ("--policy", demo / "linux-policy.json", "--snapshot", demo / "linux-snapshot.json")
        assert json.loads(run(cli, "assess", *args, code=2))["status"] == "incomplete"
        assert b"stale" in run(cli, "assess", *args, "--format", "text", code=2)
        args = ("--before", demo / "linux-satisfied.json", "--after", demo / "linux-mixed.json")
        assert json.loads(run(cli, "compare", *args, code=1))["changes"]
        assert b"coverage_changed" in run(cli, "compare", *args, "--format", "text", code=1)
    print(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}", flush=True)


if __name__ == "__main__":
    archives = sorted((ROOT / "dist").glob("*"))
    assert {p.name for p in archives} == {DIST + "-py3-none-any.whl", DIST + ".tar.gz"}
    for archive in archives:
        inspect(archive)
        smoke(archive)
