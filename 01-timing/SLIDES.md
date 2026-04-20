# Optimizing Timing - Randomized Intervals

## Evasion Techniques
- **Break correlation windows**: Random 16-77 minute spacing prevents event clustering in hourly correlation rules
- **Dynamic seeding**: Time + PID ensures non-reproducible randomization across executions
- **Defeat pattern detection**: Irregular timing prevents SIEM rule matching for multi-event sequences

## Evades (Specific Mechanisms)
- **Elastic Security 8.x** - Default 6-minute detection windows (5min interval + 1min lookback); 16-77min spacing breaks threshold aggregation
- **Splunk ES Correlation** - Multi-event rules using 1-hour lookback windows; randomized spacing prevents temporal clustering
- **Microsoft Defender for Endpoint** - Process chain behavioral correlation; extended gaps disrupt parent-child timing analysis

## Code Sample
```python
import time, random, os

def dynamic_seed():
    seed = int(time.time() * 1000) ^ os.getpid()
    random.seed(seed)
    return seed

def get_random_interval(min_min=16, max_min=77):
    return random.randint(min_min * 60, max_min * 60)

# Execute operations with random delays
dynamic_seed()
for op in ["recon", "enum", "exec"]:
    execute_operation(op)
    delay = get_random_interval(16, 77)
    time.sleep(delay)  # Real delay, not demo
```

## References
- Evasion Engineering (Chow & LaSalvia), Chapter 2 - Listing 2-1
- Book: https://nostarch.com/evasion-engineering
- Author Code: https://github.com/dc401
- Elastic Detection Rules: https://www.elastic.co/guide/en/security/current/rules-ui-create.html
- Splunk Correlation Searches: https://docs.splunk.com/Documentation/ES/latest/Admin/Configurecorrelationsearches
- MS Defender Behavioral Detection: https://learn.microsoft.com/en-us/defender-endpoint/behavioral-blocking-containment
- SIEM Correlation Rules: https://cymulate.com/cybersecurity-glossary/siem-correlation-rules/
