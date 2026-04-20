#!/usr/bin/env python3
# Low-entropy encryption using custom substitution cipher
# Source: Evasion Engineering (Chow & LaSalvia) - Chapter 2, Listing 2-2
# https://nostarch.com/evasion-engineering

def chowencrypt(cleartext, key):
    """Encrypt using low-entropy substitution cipher"""
    # Character mapping for common text and CLI chars
    encodeddict = {
        'a': 1, 'b': 2, 'c': 3, 'd': 4,
        'e': 5, 'f': 6, 'g': 7, 'h': 8,
        'i': 9, 'j': 10, 'k': 11, 'l': 12,
        'm': 13, 'n': 14, 'o': 15, 'p': 16,
        'q': 17, 'r': 18, 's': 19, 't': 20,
        'u': 21, 'v': 22, 'w': 23, 'x': 24,
        'y': 25, 'z': 26, ' ': 27, '.': 28,
        ',': 29, '!': 30, '?': 31, '-': 32
    }

    # Prepend initialization vector (first char)
    cipherstream = [encodeddict[cleartext[0]]]

    # Composite key from IV + user key
    compositekey = encodeddict[cleartext[0]] + int(key)

    # Encrypt each character: (3 * char_value) + compositekey
    for i in range(1, len(cleartext)):
        if cleartext[i] in encodeddict:
            encryptedbyte = (3 * encodeddict[cleartext[i]]) + compositekey
            cipherstream.append(encryptedbyte)

    return cipherstream

def chowdecrypt(cipherstream, key):
    """Decrypt low-entropy cipher"""
    # Reverse character mapping
    decodeddict = {v: k for k, v in {
        'a': 1, 'b': 2, 'c': 3, 'd': 4,
        'e': 5, 'f': 6, 'g': 7, 'h': 8,
        'i': 9, 'j': 10, 'k': 11, 'l': 12,
        'm': 13, 'n': 14, 'o': 15, 'p': 16,
        'q': 17, 'r': 18, 's': 19, 't': 20,
        'u': 21, 'v': 22, 'w': 23, 'x': 24,
        'y': 25, 'z': 26, ' ': 27, '.': 28,
        ',': 29, '!': 30, '?': 31, '-': 32
    }.items()}

    # Extract IV and rebuild composite key
    iv = cipherstream[0]
    compositekey = iv + int(key)

    decrypted = []
    # Decrypt: (encrypted_value - compositekey) / 3
    for value in cipherstream[1:]:
        original = int((value - compositekey) / 3)
        if original in decodeddict:
            decrypted.append(decodeddict[original])

    # Rebuild string with IV
    decryptedtext = decodeddict[iv] + ''.join(decrypted)
    return decryptedtext

if __name__ == "__main__":
    # Demo payload
    cleartext = "hello world"
    key = 10

    print(f"[INFO] Cleartext: {cleartext}")
    print(f"[INFO] Key: {key}")

    # Encrypt
    encrypted = chowencrypt(cleartext, key)
    print(f"[INFO] Encrypted: {encrypted}")

    # Decrypt
    decrypted = chowdecrypt(encrypted, key)
    print(f"[INFO] Decrypted: {decrypted}")

    # Show low entropy characteristic
    print(f"\n[INFO] Encrypted values are small integers (low entropy)")
    print(f"[INFO] Max value: {max(encrypted)}, Min value: {min(encrypted)}")
