# Avoiding Risky Binaries - Custom Shell

## Setup
```bash
# Build the custom shell
go build -o custom_shell custom_shell.go

# Run it
./custom_shell
```

## What This Evades
Bypasses EDR command-line logging and process chain detection:
- Microsoft Defender for Endpoint (DeviceProcessEvents CommandLine field)
- CrowdStrike Falcon (ProcessRollup2 command-line arguments)
- Sysmon Event ID 1 (process creation with shell commands)

## How It Works
- Reimplements common commands (ls, cat, mv) using direct syscalls
- No child processes spawned (no /bin/ls, /bin/cat, /bin/mv)
- Single-process execution prevents parent-child correlation
- EDR sees single process with no suspicious command-line arguments

**Direct Syscalls Used**:
- `syscall.Open()` - open files/directories
- `syscall.Read()` - read file contents
- `syscall.Rename()` - move/rename files
- `syscall.Close()` - close file descriptors

## Why This Matters (2026 Context)
79% of 2024 cyberattacks used no malware - only LOLBins (cmd.exe, powershell.exe, bash). EDRs heavily focus on:
- Command-line argument logging
- Parent-child process correlation
- Known shell binary execution patterns

Custom shells bypass all three detection layers by reimplementing functionality in-process.

## Example Usage
```
$ ./custom_shell
[Custom Shell] No child processes spawned
[Custom Shell] Commands: ls, cat, mv, exit

$ ls /tmp
file1.txt
file2.log

$ cat /tmp/file1.txt
Hello World

$ mv /tmp/file1.txt /tmp/renamed.txt
Moved /tmp/file1.txt -> /tmp/renamed.txt

$ exit
Exiting...
```

## Reference
Evasion Engineering, Chapter 2 - Listing 2-7  
https://nostarch.com/evasion-engineering
