#!/usr/bin/env python3
# Behavioral detection for custom shells that avoid spawning child processes
# Detects: Shell-like processes doing file operations WITHOUT subprocess execution
# Defender perspective: "Flip the script"

import os
import psutil
from datetime import datetime

def monitor_process(pid):
    """Monitor process for custom shell behavior"""
    try:
        process = psutil.Process(pid)
        info = {
            "pid": pid,
            "name": process.name(),
            "cmdline": " ".join(process.cmdline()) if process.cmdline() else "",
            "children": len(process.children()),
            "open_files": len(process.open_files()),
            "num_fds": process.num_fds() if hasattr(process, 'num_fds') else 0,
            "create_time": datetime.fromtimestamp(process.create_time())
        }
        return info
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

def analyze_shell_behavior(process_info):
    """Analyze for custom shell evasion patterns"""
    anomalies = []
    risk_score = 0

    # 1. Shell-like runtime with 0 child processes
    if process_info["children"] == 0:
        # Check if process has been running (shell sessions run >30 seconds)
        uptime = (datetime.now() - process_info["create_time"]).total_seconds()
        if uptime > 30:
            anomalies.append({
                "type": "shell_no_children",
                "confidence": 0.85,
                "evidence": f"Running {uptime:.0f}s with 0 child processes (typical shells spawn commands)"
            })
            risk_score += 50

    # 2. File descriptor activity without subprocess execution
    if process_info["open_files"] > 3 and process_info["children"] == 0:
        anomalies.append({
            "type": "file_ops_no_subprocess",
            "confidence": 0.80,
            "evidence": f"{process_info['open_files']} open files, 0 child processes (avoiding /bin/ls, /bin/cat)"
        })
        risk_score += 40

    # 3. Custom binary (not system shell) with shell-like behavior
    system_shells = ["bash", "sh", "zsh", "powershell", "cmd"]
    if not any(shell in process_info["name"].lower() for shell in system_shells):
        if process_info["children"] == 0 and process_info["open_files"] > 0:
            anomalies.append({
                "type": "custom_shell_indicator",
                "confidence": 0.75,
                "evidence": f"Non-standard shell binary '{process_info['name']}' with file access"
            })
            risk_score += 35

    classification = "HIGH" if risk_score >= 70 else "MEDIUM" if risk_score >= 40 else "LOW"

    return {
        "process": process_info["name"],
        "pid": process_info["pid"],
        "cmdline": process_info["cmdline"],
        "children": process_info["children"],
        "open_files": process_info["open_files"],
        "anomalies": anomalies,
        "risk_score": min(risk_score, 100),
        "classification": classification
    }

def visualize_detection(analysis_results):
    """Visualize detection results"""
    print(f"\n{'='*70}")
    print(f"CUSTOM SHELL DETECTION")
    print(f"{'='*70}\n")

    print(f"Process: {analysis_results['process']} (PID: {analysis_results['pid']})")
    print(f"Command: {analysis_results['cmdline']}")
    print(f"Child processes: {analysis_results['children']}")
    print(f"Open files: {analysis_results['open_files']}")
    print(f"Risk Score: {analysis_results['risk_score']}/100")
    print(f"Classification: {analysis_results['classification']}\n")

    if analysis_results['anomalies']:
        print(f"[ALERT] Anomalies Detected ({len(analysis_results['anomalies'])}):\n")
        for anomaly in analysis_results['anomalies']:
            print(f"  Type: {anomaly['type']}")
            print(f"  Confidence: {anomaly['confidence']*100:.0f}%")
            print(f"  Evidence: {anomaly['evidence']}\n")

        print("Recommended Action:")
        if analysis_results['risk_score'] >= 70:
            print("  [HIGH] Investigate immediately - likely custom shell evasion")
        elif analysis_results['risk_score'] >= 40:
            print("  [MEDIUM] Monitor closely - potential custom shell")
        else:
            print("  [LOW] Baseline monitoring")
    else:
        print("[OK] No anomalies detected")

    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    print("[DETECTION] Custom Shell Detector\n")
    print("[DEMO] Simulating detection of custom shell (no child processes)\n")

    # Simulate custom shell process behavior
    simulated_process = {
        "pid": 12345,
        "name": "custom_shell",
        "cmdline": "./custom_shell",
        "children": 0,  # KEY: No child processes spawned
        "open_files": 8,  # But accessing files (ls, cat operations)
        "num_fds": 12,
        "create_time": datetime.now()
    }

    print("Simulated Process Info:")
    print(f"  Name: {simulated_process['name']}")
    print(f"  Command: {simulated_process['cmdline']}")
    print(f"  Child processes: {simulated_process['children']} (expected: >0 for normal shells)")
    print(f"  Open files: {simulated_process['open_files']}")
    print()

    # Analyze
    results = analyze_shell_behavior(simulated_process)

    # Visualize
    visualize_detection(results)

    print("[DETECTION] Custom shell detected - file operations WITHOUT child processes")
    print("[NOTE] Normal shells (bash, cmd.exe) spawn child processes (/bin/ls, /bin/cat)")
    print("       Custom shells use direct syscalls to avoid CommandLine logging")
