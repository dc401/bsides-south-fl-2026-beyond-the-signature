# Entropy Anomaly Detection

## Overview
Detects custom low-entropy ciphers via Shannon entropy calculation. Identifies payloads encrypted with weak/custom algorithms that produce suspiciously low entropy values.

## Detection Method
- **Shannon Entropy**: Mathematical measure of randomness (0-8 scale)
- **Small Integer Detection**: Identifies custom cipher patterns
- **Classification**: LOW/BELOW_NORMAL/NORMAL/HIGH_ENTROPY

## How It Works
1. Calculates Shannon entropy of payload bytes
2. Compares against known baselines (Base64 ~5-6, strong crypto ~6-8)
3. Detects small integer patterns (custom cipher indicator)
4. Flags entropy <3.5 as suspicious (custom/weak cipher)

## Requirements
```bash
python3 -m venv venv
source venv/bin/activate
# No external dependencies - uses Python standard library
```

## Usage
```bash
python3 entropy_detector.py
```

## Expected Output
```
[DETECTION] Entropy Anomaly Detector

Low-Entropy Cipher        | Entropy: 2.85 | [!!! ALERT !!!]
                          | Very low (custom/weak cipher, NOT Base64/strong crypto)
                          | → small_integer_pattern: All bytes < 200, entropy 2.85

Base64 Encoded            | Entropy: 5.09 | [  OK  ]
                          | Moderate-high (normal code/text)
```

## Detection Capabilities
- ✓ Detects custom ciphers (entropy <3.5)
- ✓ Identifies small integer patterns
- ✓ Distinguishes from Base64 (entropy ~5-6)
- ✓ Catches weak substitution ciphers

## Evades Detection From
This detection script catches evasion techniques used against:
- Static signature scanners (Yara rules for Base64)
- Basic string analysis (doesn't match known encoding patterns)
- Antivirus heuristics (custom cipher not in signature DB)

## Precision/Recall Balance
- **Precision**: High (entropy threshold <3.5 well-tuned)
- **Recall**: High (catches custom ciphers reliably)
- **False Positives**: Low (normal text has entropy ~4-6)

## Entropy Reference Ranges
```
0.0 - 1.0: Single character repeated
1.0 - 3.0: Very low (suspicious custom cipher)
3.0 - 4.5: Low-moderate (plain text, simple encoding)
4.5 - 6.0: Moderate-high (Base64, normal code)
6.0 - 8.0: High (strong encryption, compressed data)
```

## Integration
Can be integrated with:
- Network traffic analysis (detect low-entropy payloads)
- File scanning pipelines (analyze suspicious executables)
- Email security gateways (detect encoded attachments)

## References
- Evasion Engineering (Chow & LaSalvia), Chapter 2
- Shannon entropy theory (Information Theory)
- Base64 entropy characteristics
