# Boundaries in 0.1.0

No host posture was collected during development or fixture CI. Native Windows PowerShell cmdlet outputs, Windows 11 installation variants, Linux kernel values and WSL/guest heuristics have fixture coverage. Owner-supplied directory metadata and process/filesystem behavior are separate from live posture validation. macOS supports offline use only; it has no collector.

An OS name alone cannot identify bare metal. Linux checks the kernel release for WSL, fixed container markers and a hypervisor marker. Conflicting signals yield unknown. A plain linux-visible result says only what Linux exposes, even when a VM marker is absent. Unknown environment, stale evidence or untrusted capture claims cannot satisfy a required policy.

The application relies on a stable local filesystem in the owner's control. It checks path ancestry and rejects detected links, reparse points and hardlinked input files. Local path tests cannot identify every bind mount, redirected folder, network mount or backup tree. Directory probes examine the selected item's metadata and fixed repository markers without visiting dataset files. Use genuinely local private storage. Windows ACLs and parent-directory durability after a power loss are outside the verified guarantees. POSIX publication requires same-filesystem hard-link support.

Native processes have a bounded stream size of 64 KiB each, a nine-second probe budget, and bounded cleanup. Collection reserves cleanup time within a 60-second interval. OS process creation, filesystem calls and scheduler stalls cannot be forcibly time-bounded in every kernel state. This is not a hostile-program sandbox and imposes no hard memory or CPU quota. A cleanup failure yields incomplete evidence.

Manual coverage includes firewall rules and actual connectivity, OS patch level, accounts, third-party antivirus, Linux firewall, Linux encryption, Linux Secure Boot, ACLs, encryption key custody and backup recovery. The auditor offers no malware diagnosis, remote attestation, compliance certification or proof of exploitability.
