from dataclasses import dataclass

LEARN = "https://learn.microsoft.com/en-us/powershell/module/"
KERNEL = "https://docs.kernel.org/admin-guide/sysctl/kernel.html"
PROFILES = ("Domain", "Private", "Public")
LINUX = ("linux-visible", "container-linux", "wsl-linux", "virtualized-guest")
SCOPES = ("windows-native", *LINUX)


@dataclass(frozen=True)
class Control:
    source: str
    setting: str
    review: str
    reference: str


CONTROLS = {
    "WIN-FW-001": Control(
        "windows.active-firewall-profile.v1",
        "Domain, Private and Public enabled",
        "Review each profile in the active policy store.",
        LEARN + "netsecurity/get-netfirewallprofile",
    ),
    "WIN-FW-002": Control(
        "windows.active-firewall-profile.v1",
        "Explicit Block for inbound traffic on all profiles",
        "Review effective inbound defaults for each profile.",
        LEARN + "netsecurity/get-netfirewallprofile",
    ),
    "WIN-AV-001": Control(
        "windows.defender-status.v1",
        "Normal mode with service, antivirus and real-time protection enabled",
        "Review Defender mode and protection status with the owner.",
        LEARN + "defender/get-mpcomputerstatus",
    ),
    "WIN-AV-002": Control(
        "windows.defender-status.v1",
        "Signature age within the policy limit",
        "Review signature updates and the local age threshold.",
        LEARN + "defender/get-mpcomputerstatus",
    ),
    "WIN-DISK-001": Control(
        "windows.bitlocker-volume.v1",
        "Selected fixed drive fully encrypted with protection on",
        "Review encryption progress and whether protection is suspended.",
        LEARN + "bitlocker/get-bitlockervolume",
    ),
    "WIN-BOOT-001": Control(
        "windows.secure-boot.v1",
        "UEFI Secure Boot enabled",
        "Review firmware and access with the owner.",
        LEARN + "secureboot/confirm-securebootuefi",
    ),
    "LIN-ASLR-001": Control(
        "linux.randomize_va_space.v1",
        "Kernel randomization policy equals 2",
        "Review randomize_va_space in the visible Linux environment.",
        KERNEL + "#randomize-va-space",
    ),
    "LIN-KPTR-001": Control(
        "linux.kptr_restrict.v1",
        "Kernel pointer restriction meets policy minimum",
        "Review kptr_restrict against the selected minimum.",
        KERNEL + "#kptr-restrict",
    ),
    "LIN-DMESG-001": Control(
        "linux.dmesg_restrict.v1",
        "Kernel log restriction equals 1",
        "Review dmesg_restrict in the visible Linux environment.",
        KERNEL + "#dmesg-restrict",
    ),
    "LIN-DATA-001": Control(
        "linux.directory-mode.v1",
        "Directory type, owner and permitted mode",
        "Review ownership, access bits and ACLs for the selected directory.",
        "https://man7.org/linux/man-pages/man2/lstat.2.html",
    ),
}
