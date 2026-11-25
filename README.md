# Research Workstation Hardening Auditor

`research-hardening` checks six Windows and four Linux configuration controls against a local policy. A report shows what was observed, which required settings failed, and which settings could not be verified. All commands except explicitly authorized collection operate offline on static descriptions or selected files.

## Try it with fixtures

Install the tested wheel from the GitHub release, or install a local checkout with `python -m pip install .`. Requires Python 3.11 or newer. There are no third-party runtime dependencies.

```sh
research-hardening --version
python -m research_hardening controls --platform windows
research-hardening controls --platform linux
```

From a private directory outside a repository, use the following POSIX example. On Windows, give --workspace an absolute path under a directory whose ACL you control. The demo directory must be new.

```sh
research-hardening demo --workspace "$PWD/demo"
research-hardening assess --policy demo/linux-policy.json --snapshot demo/linux-snapshot.json --format text
research-hardening compare --before demo/linux-satisfied.json --after demo/linux-mixed.json --format text
```

The historical fixture assessment returns **2** for stale evidence. The comparison returns **1** and identifies both an ASLR finding and a loss of kernel-pointer evidence. Demo success is measured against a fixed synthetic clock. For ordinary assessments, 0 means all required checks satisfy the selected policy, 1 means a required finding, and 2 means a required gap or invalid operation. Optional gaps remain visible.

See the [operating guide](docs/operating-guide.md), [control sources](docs/controls.md), [policy format](docs/policy-format.md), [snapshot format](docs/evidence-format.md), [integration contract](docs/integration-contract.md), [trust model](docs/threat-model.md), [limits](docs/limitations.md), [workstation checklist](docs/workstation-checklist.md) and [test procedure](docs/evaluation.md).
