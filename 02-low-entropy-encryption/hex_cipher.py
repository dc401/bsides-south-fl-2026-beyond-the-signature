#!/usr/bin/env python3
# Low-entropy hex encryption for binary payloads
# Source: Evasion Engineering (Chow & LaSalvia) - Chapter 2, Listing 2-5
# https://nostarch.com/evasion-engineering

import sys
from random import randint

def hex_encrypt(hex_input, key=10):
    """Convert hex string to integers and encrypt with low-entropy cipher"""
    # Convert hex pairs to integers (e.g., 'FF' -> 255)
    hex_bytes = [int(hex_input[i:i+2], 16) for i in range(0, len(hex_input), 2)
                 if len(hex_input[i:i+2]) == 2]

    # Generate random IV
    iv = randint(311, 457)
    composite_key = iv + int(key)

    cipher = [iv]
    for byte in hex_bytes:
        encrypted = (3 * byte) + composite_key
        cipher.append(encrypted)

    return cipher

def hex_decrypt(cipher_list, key=10):
    """Decrypt cipher and return hex string"""
    # Extract IV and rebuild composite key
    iv = cipher_list[0]
    composite_key = iv + int(key)

    decrypted = []
    for value in cipher_list[1:]:
        original = int((value - composite_key) / 3)
        decrypted.append(original)

    # Convert back to hex string
    return ''.join([format(b, '02x') for b in decrypted])

if __name__ == "__main__":
    # Read from stdin (for pipeline usage)
    hex_input = sys.stdin.read().strip()

    # Encrypt
    encrypted = hex_encrypt(hex_input)
    print(f"Encrypted: {encrypted}")

    # Decrypt
    decrypted = hex_decrypt(encrypted)
    print(f"Decrypted hex: {decrypted}")
