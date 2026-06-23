# Unhide Tool

A Windows console utility that detects processes hidden via DKOM (Direct Kernel Object Manipulation) by cross-checking multiple independent data sources.

## Overview

Most process enumeration APIs read from the same kernel-linked process list. A rootkit that unlinks an `EPROCESS` entry can disappear from all of them at once. This tool supplements standard enumeration with channels that query process existence through different paths, then flags inconsistencies that persist across repeated scans.

## Detection Methods

| Source | Purpose |
|--------|---------|
| `EnumProcesses` | Standard PSAPI enumeration |
| `CreateToolhelp32Snapshot` | Toolhelp process snapshot |
| `NtQuerySystemInformation` | Native system process query |
| PID bruteforce | `OpenProcess` sweep with `GetProcessId` verification |
| `SystemExtendedHandleInformation` | PIDs referenced in the system handle table |
| `EnumWindows` | Processes owning visible windows |

Findings are only reported when a signal is stable across **two scan passes** separated by a short delay, and when the process is absent from all three APL sources in both passes. This reduces false positives from short-lived processes and enumeration races.

### Alert Types

- **DKOM hidden (bruteforce)** — process opens by PID but is missing from every enumeration source
- **DKOM hidden (handles)** — process appears in the handle table but not in enumeration
- **Ghost window** — process owns a window but is missing from enumeration

## Requirements

- Windows 10 or later (x64)
- Visual Studio 2022 with the C++ desktop workload
- Administrator privileges recommended for full handle-table access

## Build

Open `Unhide tool.sln` in Visual Studio, select **Release | x64**, and build.

The output binary is written to:

```
x64\Release\Unhide tool.exe
```

## Usage

Run from an elevated command prompt:

```
Unhide tool.exe
```

Example output on a clean system:

```
[+] DKOM Scanner

[+] Scanning...
[+] 236 procs | 0 wins | 230 ms
[+] No suspicious processes.
[+] Press any key to exit.
```

When a hidden process is found, the tool prints the PID, image name, detection reason, and which channels confirmed it.

## Limitations

This is a user-mode tool. It does not load a kernel driver and does not perform offline memory analysis. A sophisticated kernel rootkit that hooks or filters every channel used here — including `OpenProcess` and handle queries — may evade detection.

Use this as a practical layer in a broader assessment workflow, not as a standalone guarantee of a clean system.

## Project Structure

```
Unhide tool/
├── m.cpp                 Entry point and console output
├── ProcessDkomCheck.h    Detection engine interface
├── ProcessDkomCheck.cpp  Enumeration, bruteforce, and analysis logic
└── Unhide tool.vcxproj   Visual Studio project
```

## Disclaimer

This software is intended for security research, malware analysis, and system administration on systems you own or are authorized to test.
