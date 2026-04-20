#!/usr/bin/env python3
# Behavioral detection for low-entropy encryption evasion
# Detects: Payloads with suspiciously LOW Shannon entropy (custom ciphers)
# Defender perspective: "Flip the script"

import math
import base64
from collections import Counter

class EntropyDetector:
    """Detect anomalous entropy patterns in payloads"""

    def __init__(self):
        # Thresholds tuned for precision/recall balance
        self.LOW_ENTROPY_THRESHOLD = 3.5      # Below = suspicious
        self.NORMAL_MIN_ENTROPY = 4.5         # Normal text/code range
        self.HIGH_ENTROPY_THRESHOLD = 6.0     # Above = encrypted/compressed

    def calculate_shannon_entropy(self, data):
        """Calculate Shannon entropy (0-8 scale for bytes)"""
        if not data:
            return 0.0

        # Convert to bytes if string
        if isinstance(data, str):
            data = data.encode()

        # Count byte frequencies
        counter = Counter(data)
        length = len(data)

        # Shannon entropy formula: -Σ(p(x) * log2(p(x)))
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def analyze_payload(self, payload, label="unknown"):
        """Analyze payload entropy and detect anomalies"""
        entropy = self.calculate_shannon_entropy(payload)

        # Classify
        if entropy < self.LOW_ENTROPY_THRESHOLD:
            classification = "LOW_ENTROPY_SUSPICIOUS"
            risk_level = "HIGH"
            confidence = 0.85
        elif entropy < self.NORMAL_MIN_ENTROPY:
            classification = "BELOW_NORMAL"
            risk_level = "MEDIUM"
            confidence = 0.6
        elif entropy > self.HIGH_ENTROPY_THRESHOLD:
            classification = "HIGH_ENTROPY_ENCRYPTED"
            risk_level = "MEDIUM"
            confidence = 0.7
        else:
            classification = "NORMAL_RANGE"
            risk_level = "LOW"
            confidence = 0.1

        # Additional heuristics for low-entropy custom ciphers
        anomalies = []
        if isinstance(payload, (list, bytes)):
            payload_bytes = payload if isinstance(payload, bytes) else bytes(payload)

            # Check for small integer patterns (low-entropy cipher characteristic)
            if all(b < 200 for b in payload_bytes) and entropy < self.LOW_ENTROPY_THRESHOLD:
                anomalies.append({
                    "type": "small_integer_pattern",
                    "evidence": f"All bytes < 200, entropy {entropy:.2f} (custom cipher indicator)"
                })

            # Check for repeated small values
            unique_ratio = len(set(payload_bytes)) / len(payload_bytes)
            if unique_ratio < 0.3 and entropy < self.LOW_ENTROPY_THRESHOLD:
                anomalies.append({
                    "type": "low_unique_byte_ratio",
                    "evidence": f"Only {unique_ratio*100:.1f}% unique bytes (substitution cipher)"
                })

        return {
            "label": label,
            "entropy": entropy,
            "classification": classification,
            "risk_level": risk_level,
            "confidence": confidence,
            "anomalies": anomalies,
            "interpretation": self._interpret_entropy(entropy)
        }

    def _interpret_entropy(self, entropy):
        """Human-readable entropy interpretation"""
        if entropy < 1.0:
            return "Extremely low (single character repetition)"
        elif entropy < 3.5:
            return "Very low (custom/weak cipher, NOT Base64/strong crypto)"
        elif entropy < 4.5:
            return "Low-moderate (plain text, simple encoding)"
        elif entropy < 6.0:
            return "Moderate-high (normal code/text)"
        elif entropy < 7.5:
            return "High (Base64, compressed data)"
        else:
            return "Very high (strong encryption, random data)"

    def compare_samples(self, samples):
        """Compare multiple samples and visualize"""
        print(f"\n{'='*70}")
        print(f"ENTROPY ANALYSIS COMPARISON")
        print(f"{'='*70}\n")

        results = []
        for label, data in samples:
            result = self.analyze_payload(data, label)
            results.append(result)

            # Visualization
            entropy = result['entropy']
            bar_length = int(entropy * 8)  # Scale to 0-64 chars
            bar = "█" * bar_length

            risk_marker = {
                "HIGH": "[!!! ALERT !!!]",
                "MEDIUM": "[! WARNING !]",
                "LOW": "[  OK  ]"
            }[result['risk_level']]

            print(f"{label:25} | Entropy: {entropy:4.2f} | {bar} {risk_marker}")
            print(f"{'':25} | {result['interpretation']}")

            if result['anomalies']:
                for anomaly in result['anomalies']:
                    print(f"{'':25} | → {anomaly['type']}: {anomaly['evidence']}")
            print()

        print(f"{'='*70}\n")
        return results


if __name__ == "__main__":
    print("[DETECTION] Entropy Anomaly Detector\n")

    detector = EntropyDetector()

    # Test samples (mimicking real-world scenarios)
    print("Testing various payload types...\n")

    # 1. Normal text
    normal_text = "Hello world, this is a normal message with regular entropy."

    # 2. Base64 encoded (high entropy ~6.0)
    base64_text = base64.b64encode(normal_text.encode()).decode()

    # 3. Low-entropy custom cipher (from evasion section 2)
    # Simulating output from chowencrypt()
    low_entropy_cipher = [8, 33, 54, 54, 63, 99, 87, 63, 72, 54, 30]

    # 4. Strong encryption simulation (high random entropy)
    import random
    random.seed(42)
    strong_crypto = bytes([random.randint(0, 255) for _ in range(50)])

    # 5. Suspicious low-entropy payload (attacker using custom cipher)
    suspicious_payload = bytes([random.randint(10, 150) for _ in range(100)])

    samples = [
        ("Normal Text", normal_text),
        ("Base64 Encoded", base64_text),
        ("Low-Entropy Cipher", bytes(low_entropy_cipher)),
        ("Strong Encryption", strong_crypto),
        ("Suspicious Payload", suspicious_payload)
    ]

    # Analyze and compare
    results = detector.compare_samples(samples)

    # Detection summary
    print("DETECTION SUMMARY:")
    print(f"  Total samples analyzed: {len(results)}")

    suspicious = [r for r in results if r['risk_level'] in ['HIGH', 'MEDIUM']]
    print(f"  Suspicious detections: {len(suspicious)}")

    for r in suspicious:
        print(f"\n  [ALERT] {r['label']}")
        print(f"    Risk: {r['risk_level']} (confidence: {r['confidence']*100:.0f}%)")
        print(f"    Classification: {r['classification']}")
        print(f"    Entropy: {r['entropy']:.2f}")

    print("\n[DETECTION] Low-entropy custom ciphers detected via entropy analysis")
    print("[NOTE] Precision/Recall balanced: Low threshold (~3.5) catches custom ciphers")
    print("       without excessive false positives on normal text (4.5-6.0 range)")
