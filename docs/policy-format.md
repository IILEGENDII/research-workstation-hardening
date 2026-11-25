# Policy v1

A policy is a UTF-8 JSON object with exactly schema_version and catalog_version (integer 1), policy_id, profile, scope, max_age_hours and checks. Labels match an ASCII lowercase letter followed by up to 47 lowercase letters, digits or hyphens. Use opaque labels. Profiles are synthetic and workstation. At least one selected control must be required. The age limit is 1 through 8760 hours, inclusive.

Each check has an id and an exact boolean required flag. Firewall controls always cover Domain, Private and Public. WIN-AV-002 accepts max_age_days, 0 through 365, default 7. WIN-DISK-001 requires one ASCII drive letter and colon. LIN-KPTR-001 accepts minimum 1 or 2, default 1. LIN-DATA-001 requires directory_subject and accepts private, default true. With private false, ownership and directory type remain required, while group and other permission bits are allowed. Supply the actual local directory only at collection.

The logical digest hashes UTF-8, compact, key-sorted JSON with checks sorted by ID, defaults expanded, drive letter uppercased, and one trailing LF. policy_sha256 hashes the file bytes as supplied. Changing whitespace or check order can change only the raw hash. Policy and snapshot must share logical identity; their raw policy hashes may differ.

The package includes complete synthetic templates in src/research_hardening/fixtures. A Windows policy accepts only windows-native. Supported Linux scope labels are linux-visible, wsl-linux, container-linux and virtualized-guest (Linux guest). Scope matching is exact. There is no bare-metal or physical-host policy.
