# BYOVD Scanner

A Windows command-line tool that detects **Bring Your Own Vulnerable Driver** threats by comparing local `.sys` files against the [LOLDrivers](https://www.loldrivers.io) database and inspecting kernel API imports for exploitation indicators.

---

## Features

### Driver Enumeration
Collects `.sys` files from two sources:
- **Disk scan** — `System32\drivers`, `DriverStore\FileRepository`, `SysWOW64\drivers`
- **Active drivers** — `driverquery /v /fo csv` (loaded kernel modules only)

### LOLDrivers Cross-Reference
Downloads and caches the [loldrivers.io](https://www.loldrivers.io/api/drivers.json) JSON database (refreshed every 12 hours), then runs two comparison passes:

| Pass | Method | Reliability |
|------|--------|-------------|
| Name match | Filename vs. LOLDrivers tags | Indicative — trivially spoofable |
| Hash match | SHA-256 vs. known vulnerable samples | Confirmed — definitive identification |

### PE Import Analysis
Parses the **Import Directory** of active drivers (PE32 and PE32+ both supported) and flags imports of kernel APIs commonly abused in BYOVD exploitation chains:

| Category | APIs |
|----------|------|
| Physical memory R/W | `MmMapIoSpace`, `MmMapIoSpaceEx`, `MmCopyMemory` |
| Process termination | `ZwTerminateProcess` |
| Process hollowing | `ZwUnmapViewOfSection` |
| EDR bypass | `KeStackAttachProcess`, `KeUnstackDetachProcess` |
| Process access | `ZwOpenProcess`, `PsLookupProcessByProcessId` |
| Remote memory | `ZwAllocateVirtualMemory`, `ZwWriteVirtualMemory`, `ZwProtectVirtualMemory` |

Drivers already confirmed vulnerable by hash are skipped in this pass to avoid duplicate reporting.

---

## Requirements

- .NET Framework 4.5+
- Windows (requires `driverquery.exe`)
- Administrator privileges recommended (some driver paths are ACL-restricted)

---

## Output

Color-coded console output:

| Color | Meaning |
|-------|---------|
| 🟡 Yellow | Filename match against LOLDrivers tags |
| 🔴 Red | SHA-256 hash confirmed in LOLDrivers database |
| 🟣 Magenta | Driver imports one or more BYOVD-relevant kernel APIs |

---

## Notes

- The LOLDrivers JSON is cached locally as `drivers.json` and re-downloaded after 12 hours.
- Import analysis operates on **file offset level** with correct RVA-to-offset resolution via the section table — both PE32 (x86) and PE32+ (x64) formats are handled.
- Name-based matching is **not reliable for detection**; treat it as a triage hint only.
- False positives are possible in the import analysis pass: some legitimate drivers import these APIs for valid reasons. Cross-reference with the hash pass before drawing conclusions.

---

## References

- [LOLDrivers project](https://www.loldrivers.io)
- [Microsoft PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [BYOVD attack technique – MITRE T1068](https://attack.mitre.org/techniques/T1068/)
