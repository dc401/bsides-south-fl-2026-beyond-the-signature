#!/bin/bash
# Demo: Convert binary to hex, encrypt with low-entropy cipher
# Source: Evasion Engineering (Chow & LaSalvia) - Chapter 2, Listing 2-4
# https://nostarch.com/evasion-engineering

echo "[INFO] Demo: Low-Entropy Encryption Pipeline"
echo ""

# Create sample binary file
echo "Hello World" > /tmp/sample.txt

echo "[1] Original text:"
cat /tmp/sample.txt
echo ""

echo "[2] Convert to hex:"
xxd -p /tmp/sample.txt | tr -d '\n'
echo ""
echo ""

echo "[3] Encrypt hex with low-entropy cipher:"
xxd -p /tmp/sample.txt | tr -d '\n' | python3 hex_cipher.py
echo ""

# Cleanup
rm /tmp/sample.txt

echo "[INFO] Encrypted payload contains small integers (low entropy)"
echo "[INFO] Evades EDR entropy scanners looking for Base64/hex patterns"
