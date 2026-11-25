# Local operation

Start with a new owner-controlled directory outside repositories and backup or evidence trees. On POSIX use an owned directory with mode 0700. On Windows verify its ACL independently. Supply a new filename for each output. Use .json for JSON or .txt for text. Omit --output on assessment and comparison to print the report. Raw native output is never a CLI output format.

Use controls to review the available checks and official sources. Review the packaged example for your platform, copy it privately, set profile to workstation, choose the correct visible scope and set requirements before collecting. Use an opaque subject label. Supply --directory with an absolute private local path only for LIN-DATA-001. For example, from your private workspace on an authorized Windows workstation with a reviewed Windows policy:

```text
research-hardening collect --policy windows-local.json --subject workstation-main --output first.json --local --confirm-owner-controlled
research-hardening assess --policy windows-local.json --snapshot first.json --trust-local-file --format json --output first-assessment.json
research-hardening compare --before first-assessment.json --after later-assessment.json --format text
```

Only use --trust-local-file when you trust the origin and custody of that particular capture. Investigate gaps with the owner and official documentation. Do not elevate privileges to obtain a passing report. Keep the original policy, snapshot and reports together privately. Repeat the process after a configuration or OS change. A changed observation calls for review and may reflect changed access rather than changed protection.
