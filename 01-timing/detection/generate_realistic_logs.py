#!/usr/bin/env python3
# Generate realistic timing logs for detection analysis
# Creates two scenarios: Network traffic and Process behavior

import json
import random
from datetime import datetime, timedelta

def generate_randomized_network_traffic(start_time, num_events=35):
    """
    Evasive network traffic: Steady randomized intervals
    Attacker trying to hide C2 beaconing with random jitter
    """
    events = []
    current_time = start_time

    for i in range(num_events):
        events.append({
            "timestamp": current_time.isoformat(),
            "type": "network_connection",
            "destination": "api.cloudservice.com",  # Typosquatted domain
            "process": "svchost.exe",
            "event_id": 3,  # Sysmon Event ID 3
            "source_ip": "192.168.1.100",
            "dest_ip": "104.21.45.123",  # Cloudflare IP
            "dest_port": 443
        })

        # Random interval: 15-75 minutes (steady randomization)
        interval_minutes = random.randint(15, 75)
        current_time += timedelta(minutes=interval_minutes)

    return events

def generate_bursty_user_traffic(start_time, num_events=35):
    """
    Legitimate user traffic: Clustered bursts during work hours
    User researching topics, then working, then back to research
    """
    events = []
    current_time = start_time

    # Simulate work day pattern: 9am-5pm with lunch break
    event_count = 0

    while event_count < num_events:
        # Morning research burst (9:00-9:30am)
        if event_count < 8:
            burst_size = random.randint(3, 5)
            for _ in range(min(burst_size, num_events - event_count)):
                events.append({
                    "timestamp": current_time.isoformat(),
                    "type": "network_connection",
                    "destination": random.choice([
                        "stackoverflow.com",
                        "github.com",
                        "docs.microsoft.com",
                        "google.com",
                        "reddit.com"
                    ]),
                    "process": "chrome.exe",
                    "event_id": 3,
                    "source_ip": "192.168.1.100",
                    "dest_ip": "172.217.14.206",
                    "dest_port": 443
                })
                # Burst: 1-3 minutes between requests
                current_time += timedelta(minutes=random.randint(1, 3))
                event_count += 1

            # Work gap: 45-90 minutes
            current_time += timedelta(minutes=random.randint(45, 90))

        # Mid-morning burst (10:30-11:00am)
        elif event_count < 14:
            burst_size = random.randint(2, 4)
            for _ in range(min(burst_size, num_events - event_count)):
                events.append({
                    "timestamp": current_time.isoformat(),
                    "type": "network_connection",
                    "destination": random.choice([
                        "linkedin.com",
                        "medium.com",
                        "aws.amazon.com"
                    ]),
                    "process": "chrome.exe",
                    "event_id": 3,
                    "source_ip": "192.168.1.100",
                    "dest_ip": "13.224.167.20",
                    "dest_port": 443
                })
                current_time += timedelta(minutes=random.randint(1, 4))
                event_count += 1

            # Lunch break: 60-75 minutes
            current_time += timedelta(minutes=random.randint(60, 75))

        # Afternoon burst (1:00-2:00pm)
        elif event_count < 22:
            burst_size = random.randint(3, 5)
            for _ in range(min(burst_size, num_events - event_count)):
                events.append({
                    "timestamp": current_time.isoformat(),
                    "type": "network_connection",
                    "destination": random.choice([
                        "atlassian.net",
                        "slack.com",
                        "zoom.us"
                    ]),
                    "process": "chrome.exe",
                    "event_id": 3,
                    "source_ip": "192.168.1.100",
                    "dest_ip": "54.230.128.100",
                    "dest_port": 443
                })
                current_time += timedelta(minutes=random.randint(2, 5))
                event_count += 1

            # Work gap: 30-60 minutes
            current_time += timedelta(minutes=random.randint(30, 60))

        # Late afternoon burst (3:30-4:30pm)
        else:
            for _ in range(num_events - event_count):
                events.append({
                    "timestamp": current_time.isoformat(),
                    "type": "network_connection",
                    "destination": random.choice([
                        "github.com",
                        "stackoverflow.com"
                    ]),
                    "process": "chrome.exe",
                    "event_id": 3,
                    "source_ip": "192.168.1.100",
                    "dest_ip": "140.82.113.4",
                    "dest_port": 443
                })
                current_time += timedelta(minutes=random.randint(1, 3))
                event_count += 1

    return events

def generate_evasive_process_events(start_time, num_events=30):
    """
    Evasive long-running process: Delayed operations to avoid detection
    Example: Persistence mechanism with randomized execution
    """
    events = []
    current_time = start_time

    for i in range(num_events):
        events.append({
            "timestamp": current_time.isoformat(),
            "type": "process_execution",
            "process": "WindowsUpdateCheck.exe",
            "parent_process": "taskeng.exe",
            "event_id": 4688,  # Windows Event ID 4688
            "command_line": "C:\\Windows\\System32\\WindowsUpdateCheck.exe",
            "user": "SYSTEM"
        })

        # Randomized delays: 18-65 minutes
        interval_minutes = random.randint(18, 65)
        current_time += timedelta(minutes=interval_minutes)

    return events

def generate_normal_process_events(start_time, num_events=30):
    """
    Normal scheduled task: Predictable execution pattern
    Example: Legitimate Windows Update check
    """
    events = []
    current_time = start_time

    # Windows Update pattern: Daily check with predictable timing
    for i in range(num_events):
        events.append({
            "timestamp": current_time.isoformat(),
            "type": "process_execution",
            "process": "UsoClient.exe",
            "parent_process": "svchost.exe",
            "event_id": 4688,
            "command_line": "C:\\Windows\\System32\\UsoClient.exe StartScan",
            "user": "SYSTEM"
        })

        # Predictable pattern: Daily at same time, or burst checks
        if i % 5 == 0:
            # Daily check: 24 hour gap
            current_time += timedelta(hours=24)
        else:
            # Burst checks: 5-15 minutes during update window
            current_time += timedelta(minutes=random.randint(5, 15))

    return events

if __name__ == "__main__":
    print("[INFO] Generating realistic timing logs for detection analysis\n")

    start_time = datetime(2026, 4, 19, 9, 0, 0)  # 9:00 AM workday start

    # Scenario A: Network Traffic Patterns
    print("Generating Scenario A: Network Traffic")
    randomized_traffic = generate_randomized_network_traffic(start_time, num_events=35)
    bursty_traffic = generate_bursty_user_traffic(start_time, num_events=35)
    print(f"  - Randomized (evasive): {len(randomized_traffic)} events")
    print(f"  - Bursty user (legitimate): {len(bursty_traffic)} events")

    # Scenario B: Process Behavior Patterns
    print("\nGenerating Scenario B: Process Execution")
    evasive_process = generate_evasive_process_events(start_time, num_events=30)
    normal_process = generate_normal_process_events(start_time, num_events=30)
    print(f"  - Evasive long-runner: {len(evasive_process)} events")
    print(f"  - Normal scheduled task: {len(normal_process)} events")

    # Save to JSON
    output = {
        "scenario_a_network": {
            "randomized_evasive": randomized_traffic,
            "bursty_legitimate": bursty_traffic
        },
        "scenario_b_process": {
            "evasive_delayed": evasive_process,
            "normal_scheduled": normal_process
        }
    }

    output_file = "realistic_timing_logs.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n[SUCCESS] Logs written to {output_file}")
    print(f"[INFO] Total events generated: {len(randomized_traffic) + len(bursty_traffic) + len(evasive_process) + len(normal_process)}")
