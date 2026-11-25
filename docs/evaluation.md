# Release verification

The fixture clock is 2020-01-01T12:00:00Z. The demo verifies 16 scenarios covering both operating systems, combined findings and gaps, stale evidence, scope and trust mismatches, and duplicate JSON keys. A later ordinary assessment of those historical snapshots returns 2.

Local phase gates on Windows with Python 3.14 recorded 30, 43 and 76 passing tests for contracts, evaluation and fixed adapters. The process/storage gate passed 96 tests with two link-operation skips under the sandbox. The drift/demo gate passed 107 with the same skips. Defensive review passed 143 with three skips (link operations and POSIX metadata). No native workstation security setting was queried. Synthetic status tests are separate from actual harmless process and disposable filesystem tests.

Regression tests reproduced and corrected three issues during development: inconsistent Windows change time between path and handle stats, a short proc-style read that could hide trailing malformed text, and a demo that accepted a backup-named parent. The JSON depth tests also cover escaped quotes, backslashes and literal brackets. The seed-71 input driver exercised 120 cases for each of three readers. A rejection is expected for invalid input. Counts describe these generated cases only.

```sh
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest -q -rs
python tools/robustness.py --seed 71 --count 120
python -m build
python tools/verify_distribution.py
```

The distribution check verifies package members and source bytes, installs the two distributions into separate fresh virtual environments, runs pip check and exercises both CLI entry points, controls, demo, assess and compare. It prints SHA-256 for the archives it actually tested. GitHub Actions uses checkout v7.0.1 and setup-python v7.1.0 pinned to their Git revisions. All hosted jobs use fixtures, including Windows jobs.

The final naming and comment review covered the runtime, tests, fixtures, packaging tools and operator documentation. It clarified the setting evaluator and firewall fixture names, kept the Windows file-identity and evidence-time explanations, and placed the synthetic examples in package resources so the installed CLI can reproduce them without a checkout.
