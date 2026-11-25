# Snapshots

Snapshot v1 uses tool research-hardening, tool_version 0.1.0, catalog_version 1 and operation collect. The subject and scope identify the owner's declared subject and intended visibility. Environment records the collector's classification or unknown. UTC times use whole seconds with a trailing Z. started_at ≤ observed_at ≤ ended_at and the interval is at most 60 seconds. Assessment uses the beginning for freshness and rejects future end times.

Collection is synthetic_fixture, operator_import or local_capture. Each selected observation contains check_id, fixed source method, status, reason and value. Known values pass exact shape and type checks. Missing observations become gaps. A non-observed value must be null with a reason equal to its status. Allowed gaps are not_collected, permission_denied, unsupported, unavailable, invalid and timeout. An absent provider or denied request says nothing about the setting. See controls.md for the allowed values.

A completed snapshot can be partial when a probe produced a gap. A collection-wide interruption or deadline makes completed false, with an issue; those issues block the assessment. Collection return 0 means all required probes returned known structured values. A disabled control can therefore produce collection exit 0 and assessment exit 1. Missing optional evidence remains visible in either case.

Files are bounded to 64 KiB for policy and 512 KiB for reports. JSON objects disallow duplicate keys, fractional and nonfinite numbers. Limits include 24 nesting levels, 24,000 structural tokens, 16 characters per integer token and 4,096 characters of string source. Only exact schema fields enter exportable data.
