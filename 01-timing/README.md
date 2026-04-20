# Timing Evasion - Randomized Intervals

## Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (none required for this example)
pip install -r requirements.txt

# Run the example
python3 timing_evasion.py
```

## What This Evades
Breaks correlation-based detection in SIEM/EDR platforms that use fixed 1-hour time windows:
- Splunk Enterprise Security
- Microsoft Defender for Endpoint
- Elastic Security
- IBM QRadar
- Chronicle SIEM

## How It Works
- Uses dynamic seeding (time + PID) for unpredictable randomization
- Generates intervals between 16-77 minutes
- Falls outside standard 60-minute correlation windows used by most SIEMs

## Windows Event Log Examples

See `EXAMPLE_LOGS_README.md` and run:
```bash
# Generate realistic Windows Event logs (Event ID 4688, Sysmon Event ID 3)
python3 example_logs.py

# Analyze logs with detection script
cd detection
python3 winevent_analyzer.py
```

**Demonstrates**:
- WinEvent ID 4688 (Process Creation) - Malicious persistence with randomized intervals
- Sysmon Event ID 3 (Network Connection) - C2 beaconing with jitter
- Legitimate Windows Update - Normal clustered pattern (for comparison)
- Statistical detection identifying timing anomalies
- SIEM integration examples (Splunk, Elastic, Sentinel)

## Reference
Evasion Engineering, Chapter 2 - Listing 2-1  
https://nostarch.com/evasion-engineering
