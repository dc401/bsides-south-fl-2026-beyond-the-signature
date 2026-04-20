# Avoiding Risky Binaries - Custom Shell

## Evasion Techniques
- **Bypass command-line logging**: Custom shell reimplements commands (ls, cat, mv) using direct syscalls - no child processes spawned
- **Eliminate process chains**: Single-process execution prevents parent-child correlation in EDR behavioral analysis
- **Evade LOLBin signatures**: No subprocess execution means EDR CommandLine fields remain empty - no /bin/ls, /bin/cat logs

## Evades (Specific Mechanisms)
- **Microsoft Defender for Endpoint** - DeviceProcessEvents table captures CommandLine field; custom shell generates no child processes, no command arguments logged
- **CrowdStrike Falcon** - ProcessRollup2 logs command-line arguments; syscall-based shell avoids process creation, no CommandLine data
- **Sysmon Event ID 1** - Process creation logging with full command lines; custom shell creates no child processes for commands

## Code Sample
```go
// BAD: Spawns subprocess, logs "ls /tmp" in CommandLine field
exec.Command("ls", "/tmp").Run()  // EDR DETECTS THIS

// GOOD: Custom shell with direct syscalls, no child process
func cmdLs(args []string) {
    fd, _ := syscall.Open(path, syscall.O_RDONLY, 0)
    defer syscall.Close(fd)
    entries, _ := os.ReadDir(path)
    for _, entry := range entries {
        fmt.Println(entry.Name())  // EDR sees file access only
    }
}

// BAD: Spawns subprocess for file operations
exec.Command("cat", "file.txt").Run()  // EDR DETECTS THIS

// GOOD: Direct syscall read
func cmdCat(args []string) {
    fd, _ := syscall.Open(args[0], syscall.O_RDONLY, 0)
    defer syscall.Close(fd)
    buf := make([]byte, 4096)
    syscall.Read(fd, buf)  // No subprocess spawned
}
```

## Detection Comparison
```
Traditional Shell (DETECTED):
- Process: bash -> /bin/ls /tmp
- Process: bash -> /bin/cat file.txt
- EDR Logs: CommandLine="/bin/ls /tmp", CommandLine="/bin/cat file.txt"
- Detection: ✗ Flagged as enumeration pattern

Custom Shell (EVADES):
- Process: custom_shell (only)
- Child processes: 0
- EDR Logs: CommandLine="./custom_shell"
- Detection: ✓ No suspicious child processes, no command arguments
```

## Direct Syscalls Used
```go
syscall.Open()    // Open files/directories
syscall.Read()    // Read file contents
syscall.Rename()  // Move/rename files
syscall.Close()   // Close file descriptors
```

## References
- Evasion Engineering (Chow & LaSalvia), Chapter 2 - Listing 2-7
- Book: https://nostarch.com/evasion-engineering
- Author Code: https://github.com/dc401
- LOLBins 2026 Threat Landscape: https://hivesecurity.gitlab.io/blog/lolbins-living-off-the-land-windows-2026/
- MDE Process Events: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- MDE Command Line Auditing: https://medium.com/falconforce/microsoft-defender-for-endpoint-internals-0x02-audit-settings-and-telemetry-1d0af3ebfb27
- CrowdStrike ProcessRollup2: https://research.splunk.com/sources/cbb06880-9dd9-4542-ac60-bd6e5d3c3e4e/
- LOLBins Detection Strategies: https://www.huntress.com/blog/detecting-malicious-use-of-lolbins-pt-ii
