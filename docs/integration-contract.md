# Assessment contract v1

An assessment names its operation, tool version, catalog and schema versions, observed and evaluated UTC times, operator subject label, scope, profile and assurance. Each selected control has a row, even if no evidence exists. Required and optional counts are derived independently. Required gaps take precedence over required findings. Both lists are retained. Exit 0 means all required checks were satisfied within scope, 1 means a required finding and 2 means incomplete or invalid.

The normalized policy and snapshot are embedded for comparison. The policy digest hashes canonical JSON with ordered checks and explicit defaults. The raw policy and snapshot SHA-256 fields describe the original bytes. Compare recomputes verdicts and counts, rejects contradictory metadata and records both assessment file digests. A standalone export does not authenticate any of those claims. Keep original files privately to verify raw hashes independently.

Run the demo to produce a synthetic sample named windows-satisfied.json. Its assurance is synthetic and its subject is fixture-main. Project 6 v0.1.1 has no adapter for this format. A future integration needs separate authorization and fixtures for adverse and incomplete states.
