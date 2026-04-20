# Custom Shell Detection

## Overview
Detects custom shells that avoid spawning child processes. Identifies processes performing shell-like operations (ls, cat, mv) using direct syscalls instead of executing system binaries.

## Detection Method
- **Process Tree Analysis**: Monitors parent-child relationships
- **Shell Behavior Profiling**: Detects shell-like activity without subprocess execution
- **File Descriptor Monitoring**: Identifies file operations without /bin/ls, /bin/cat

## How It Works
1. Monitors process execution and child process creation
2. Detects shell-like runtime (>30 seconds) with 0 child processes
3. Identifies file access patterns without corresponding subprocess logs
4. Flags non-standard binaries exhibiting shell behavior

## Requirements
```bash
python3 -m venv venv
source venv/bin/activate
pip install psutil
```

## Usage
```bash
python3 shell_detector.py
```

## Expected Output
```
[DETECTION] Custom Shell Detector

Process: custom_shell (PID: 12345)
Command: ./custom_shell
Child processes: 0
Open files: 8
Risk Score: 85/100
Classification: HIGH

[ALERT] Anomalies Detected (2):
  Type: shell_no_children
  Confidence: 85%
  Evidence: Running 45s with 0 child processes (typical shells spawn commands)

  Type: custom_shell_indicator
  Confidence: 75%
  Evidence: Non-standard shell binary 'custom_shell' with file access
```

## Detection Capabilities
- ✓ Detects shell-like processes with 0 child processes
- ✓ Identifies file operations without /bin/ls, /bin/cat, /bin/mv
- ✓ Flags non-standard binaries with shell behavior
- ✓ Catches syscall-based evasion of CommandLine logging

## Evades Detection From
This detection script catches evasion techniques used against:
- MS Defender for Endpoint (DeviceProcessEvents, ProcessRollup2)
- CrowdStrike Falcon (ProcessRollup2 command-line arguments)
- Sysmon (Event ID 1 - Process Creation correlation)

## Precision/Recall Balance
- **Precision**: High (normal shells spawn child processes)
- **Recall**: High (catches custom shells avoiding subprocess execution)
- **False Positives**: Low (legitimate shells like bash always spawn subprocesses)

## Expected Behavior Comparison
```
LEGITIMATE Shell:
  bash (PID 1000)
    ├─ ls (PID 1001) - subprocess
    ├─ cat (PID 1002) - subprocess
    └─ mv (PID 1003) - subprocess
  CommandLine logs: "ls -la", "cat file.txt", "mv src dest"

EVASION Technique:
  custom_shell (PID 2000)
    └─ 0 child processes
  Direct syscalls: syscall.Open(), syscall.Read(), syscall.Rename()
  CommandLine logs: NONE (evasion successful)
```

## Detection Indicators

| Indicator | Legitimate Shell | Custom Shell (Evasion) |
|-----------|-----------------|----------------------|
| **Child processes** | >0 (spawns /bin/ls, /bin/cat) | 0 (direct syscalls) |
| **CommandLine logs** | Full command args visible | Empty or minimal |
| **File operations** | Via subprocesses | In-process syscalls |
| **Runtime** | Variable | Long-running (shell session) |

## Integration
Can be integrated with:
- EDR platforms (custom detection rules for process trees)
- SIEM correlation rules (detect missing subprocess logs)
- Endpoint monitoring (Sysmon Event ID 1, auditd)

## SIEM Query Examples

### Splunk
```spl
index=edr EventCode=1
| stats dc(ParentProcessId) as children by ProcessId, ProcessName
| where ProcessName IN ("bash", "sh", "zsh", "custom*") AND children=0
| eval risk_score=85
```

### Elastic (EQL)
```
process where process.name : ("custom_shell", "*shell*")
  and process.parent.name != null
  and not descendant of [process where true]
```

## References
- Evasion Engineering (Chow & LaSalvia), Chapter 2
- MS Defender ProcessRollup2 correlation
- Sysmon Event ID 1 (Process Creation)
