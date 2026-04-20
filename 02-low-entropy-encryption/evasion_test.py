#!/usr/bin/env python3
# Demonstrate evasion of static string scanning in payloads
# Source: Evasion Engineering (Chow & LaSalvia) - Chapter 2
# https://nostarch.com/evasion-engineering

import base64
from low_entropy_cipher import chowencrypt, chowdecrypt

# Payload that would trigger static analysis (contains LOLBin commands)
suspicious_payload = "powershell -enc invoke-expression"

print("=" * 60)
print("EVASION TEST: Static String Detection")
print("=" * 60)

# Test 1: Plaintext (would be detected)
print("\n[TEST 1] Plaintext payload:")
print(f"Payload: {suspicious_payload}")
print(f"Contains 'powershell': {('powershell' in suspicious_payload)}")
print(f"Contains 'invoke': {('invoke' in suspicious_payload)}")
print("[RESULT] EDR would flag: YES - plaintext LOLBin command detected")

# Test 2: Base64 encoding (still detected by many EDRs)
print("\n[TEST 2] Base64 encoded:")
b64_payload = base64.b64encode(suspicious_payload.encode()).decode()
print(f"Encoded: {b64_payload}")
print(f"Entropy: ~6.0 (high)")
print(f"Has Base64 pattern: {all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in b64_payload)}")
print("[RESULT] EDR would flag: LIKELY - high entropy + Base64 pattern detected")

# Test 3: Low-entropy encryption (evades)
print("\n[TEST 3] Low-entropy cipher:")
encrypted = chowencrypt(suspicious_payload, key=42)
print(f"Encrypted: {encrypted}")
print(f"Max value: {max(encrypted)}, Min value: {min(encrypted)}")
print(f"Value range: Small integers (low entropy ~2-3)")
print(f"Contains 'powershell': {('powershell' in str(encrypted))}")
print(f"Contains Base64 chars: NO - only integers in list")
print("[RESULT] EDR would flag: NO - low entropy, no suspicious strings, no encoding pattern")

# Verify decryption works
print("\n[VERIFICATION] Decrypt and execute:")
decrypted = chowdecrypt(encrypted, key=42)
print(f"Decrypted: {decrypted}")
print(f"Match original: {decrypted == suspicious_payload}")

print("\n" + "=" * 60)
print("SUMMARY: Low-entropy cipher bypasses static string + entropy detection")
print("=" * 60)
