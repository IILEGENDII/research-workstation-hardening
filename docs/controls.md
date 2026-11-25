# Control sources

| ID | Source and accepted evidence | Limit of the observation |
| --- | --- | --- |
| WIN-FW-001 | ActiveStore profiles Domain, Private and Public, each explicitly enabled | Profile settings do not identify active network associations, open ports or rule effects. |
| WIN-FW-002 | Each profile has an explicit inbound Block action. Allow is a finding and NotConfigured is unresolved. | A persistent default cannot substitute for effective policy. |
| WIN-AV-001 | Normal mode with service, antivirus and real-time flags true. Passive Mode, SxS Passive Mode and EDR Block Mode are inconclusive. | No malware scan, exclusions or other vendor inventory. Unknown modes are unsupported evidence. |
| WIN-AV-002 | Nonnegative integer days through 65534, within the selected threshold | Missing, sentinel or unexpected types are gaps. The default seven days is a local choice. |
| WIN-DISK-001 | One selected fixed drive; matching volume, FullyEncrypted, 100 percent and protection On | Suspended protection is a finding. No keys, recovery material, other volumes or backup assertions. |
| WIN-BOOT-001 | Genuine boolean from Confirm-SecureBootUEFI | The cmdlet commonly requires administrator privileges; inaccessible status is a gap. |
| LIN-ASLR-001 | kernel/randomize_va_space equals 2 | A kernel policy does not establish one program's memory layout. |
| LIN-KPTR-001 | kernel/kptr_restrict is 1 or 2 and meets the selected minimum | Covers some kernel pointer exposure. |
| LIN-DMESG-001 | kernel/dmesg_restrict equals 1 | Covers access to selected kernel messages. |
| LIN-DATA-001 | Selected directory label, type, current-owner match and integer mode. Private policies reject any group/other bits. | No directory listing, file-content access, ACL check, mount encryption or Windows ACL inference. |

The Windows process uses the system Windows PowerShell 5.1 executable and system module manifests on Windows build 22000 or newer. It requests only the local NetSecurity, Defender, BitLocker or SecureBoot operation selected by policy. The six parsers have synthetic contract tests. Live OS/provider compatibility is unverified. Native enum names outside the allowlist become gaps. The Linux readers take up to 65 bytes from the three fixed /proc/sys/kernel nodes, accepting a single allowed digit with surrounding ASCII whitespace and at most 64 bytes. Restricted containers can expose no usable value.

Official references are [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile), [Get-MpComputerStatus](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus), [Get-BitLockerVolume](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume), [Confirm-SecureBootUEFI](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi), [Linux kernel settings](https://docs.kernel.org/admin-guide/sysctl/kernel.html) and [WSL versions](https://learn.microsoft.com/en-us/windows/wsl/compare-versions).
