import json

from research_hardening.cli import main


def test_demo_and_compare(tmp_path, capsys):
    root = tmp_path / "demo"
    assert main(["demo", "--workspace", str(root)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert len(summary["scenario_exits"]) == 16
    assert (
        main(
            [
                "assess",
                "--policy",
                str(root / "linux-policy.json"),
                "--snapshot",
                str(root / "linux-snapshot.json"),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["required_gaps"]
    assert (
        main(
            [
                "compare",
                "--before",
                str(root / "linux-satisfied.json"),
                "--after",
                str(root / "linux-mixed.json"),
                "--format",
                "text",
            ]
        )
        == 1
    )
    assert "coverage_changed" in capsys.readouterr().out
    assert main(["demo", "--workspace", str(root)]) == 2
