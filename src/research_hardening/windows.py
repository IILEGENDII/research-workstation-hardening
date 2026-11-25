from pathlib import Path

from .catalog import PROFILES
from .formats import Invalid, decode, keys, require
from .policy import drive
from .snapshot import GAPS, observation, validate_value

MODULES = {
    "firewall": "NetSecurity",
    "defender": "Defender",
    "bitlocker": "BitLocker",
    "boot": "SecureBoot",
}
OPERATIONS = {
    "WIN-FW-001": "firewall",
    "WIN-FW-002": "firewall",
    "WIN-AV-001": "defender",
    "WIN-AV-002": "defender",
    "WIN-DISK-001": "bitlocker",
    "WIN-BOOT-001": "boot",
}

SCRIPTS = {
    "firewall": r"""
$rows = @(NetSecurity\Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
    @{name=[string]$_.Name; enabled=[string]$_.Enabled; inbound=[string]$_.DefaultInboundAction}
})
""",
    "defender": r"""
$rows = @(Defender\Get-MpComputerStatus | ForEach-Object {
    @{service=$_.AMServiceEnabled; antivirus=$_.AntivirusEnabled; realtime=$_.RealTimeProtectionEnabled; mode=$_.AMRunningMode; age=$_.AntivirusSignatureAge}
})
""",
    "bitlocker": r"""
$volume = $env:HARDENING_VOLUME
if ([IO.DriveInfo]::new($volume).DriveType -ne [IO.DriveType]::Fixed) { exit 21 }
$rows = @(BitLocker\Get-BitLockerVolume -MountPoint $volume | ForEach-Object {
    @{volume=$_.MountPoint; state=[string]$_.VolumeStatus; percent=$_.EncryptionPercentage; protection=[string]$_.ProtectionStatus}
})
""",
    "boot": r"""
$rows = @(SecureBoot\Confirm-SecureBootUEFI)
""",
}


def command(system, operation, volume=None):
    require(operation in SCRIPTS, "unknown_operation")
    require((operation == "bitlocker") == (volume is not None), "invalid_volume")
    home = system / "System32" / "WindowsPowerShell" / "v1.0"
    env = {
        "SystemRoot": str(system),
        "windir": str(system),
        "PATH": str(system / "System32"),
        "PSModulePath": str(home / "Modules"),
    }
    if volume is not None:
        env["HARDENING_VOLUME"] = drive(volume)
    module = MODULES[operation]
    script = (
        r"""
$ErrorActionPreference='Stop'
$WarningPreference=$VerbosePreference=$InformationPreference=$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { exit 21 }
$env:PSModulePath="$PSHOME\Modules"
try {
    Import-Module "$PSHOME\Modules\MODULE_NAME\MODULE_NAME.psd1" -ErrorAction Stop
""".replace("MODULE_NAME", module)
        + SCRIPTS[operation]
        + r"""
    $json=Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject @{rows=$rows} -Depth 4 -Compress
    [Console]::WriteLine($json)
} catch [System.UnauthorizedAccessException] { exit 20 }
catch [System.PlatformNotSupportedException] { exit 21 }
catch {
    if ($_.CategoryInfo.Category -eq 'PermissionDenied') { exit 20 }
    if ($_.CategoryInfo.Category -in 'ObjectNotFound','NotImplemented') { exit 21 }
    exit 22
}
"""
    )
    return [
        str(home / "powershell.exe"),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ], env


def system_directory():
    import ctypes
    import sys

    require(sys.platform == "win32" and sys.getwindowsversion().build >= 22000, "unsupported")
    buf = ctypes.create_unicode_buffer(32768)
    size = ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, len(buf))
    require(0 < size < len(buf), "unavailable")
    return Path(buf.value)


def parse_response(cid, raw, volume=None):
    doc = decode(raw, 65536)
    keys(doc, "rows")
    rows = doc["rows"]
    require(type(rows) is list)
    if OPERATIONS[cid] == "firewall":
        require(len(rows) == 3)
        value = {}
        for row in rows:
            keys(row, "name enabled inbound")
            name = row["name"]
            require(name in PROFILES and name not in value)
            if cid == "WIN-FW-001":
                require(row["enabled"] in ("True", "False"))
                value[name] = row["enabled"] == "True"
            else:
                value[name] = row["inbound"]
    else:
        require(len(rows) == 1)
        row = rows[0]
        if OPERATIONS[cid] == "defender":
            keys(row, "service antivirus realtime mode age")
            value = (
                row["age"] if cid == "WIN-AV-002" else {k: v for k, v in row.items() if k != "age"}
            )
        else:
            value = row
    validate_value(cid, value)
    if cid == "WIN-DISK-001":
        require(value["volume"] == drive(volume))
    return value


def result(check, status, raw):
    cid = check["id"]
    if status in GAPS:
        return observation(cid, status)
    try:
        require(status == "ok")
        return observation(cid, "observed", parse_response(cid, raw, check.get("volume")))
    except Invalid:
        return observation(cid, "invalid")
