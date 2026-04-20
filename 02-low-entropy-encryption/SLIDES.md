# Low-Entropy Encryption - Custom Cipher

## Evasion Techniques
- **Bypass entropy scanners**: Custom substitution cipher maintains 1-4 Shannon entropy vs Base64 (~6.0) and strong crypto (~8.0)
- **Avoid encoding signatures**: Small integer values (300-700 range) lack Base64/hex character patterns (A-Z, 0-9, +, /)
- **Defeat static analysis**: Arithmetic encryption (3x + key) produces low-randomness output, evading entropy threshold alerts

## Evades (Specific Mechanisms)
- **CrowdStrike Falcon** - Static entropy analysis flags high-entropy shellcode in binaries; low-entropy cipher produces small integers below detection threshold
- **Microsoft Defender AMSI** - Scans obfuscated PowerShell for high entropy patterns; substitution cipher maintains human-language-like entropy profile
- **Generic EDR scanners** - Detect Base64 (~6.0 entropy) and hexadecimal encoding; custom cipher avoids standard encoding signatures

## Code Sample (Text)
```python
def chowencrypt(cleartext, key):
    encodeddict = {'a': 1, 'b': 2, 'c': 3, ...}  # Char mapping
    cipherstream = [encodeddict[cleartext[0]]]   # IV
    compositekey = encodeddict[cleartext[0]] + int(key)
    
    for i in range(1, len(cleartext)):
        encrypted = (3 * encodeddict[cleartext[i]]) + compositekey
        cipherstream.append(encrypted)
    return cipherstream

# "hello world" -> [8, 33, 54, 54, 63, 99, 87, 63, 72, 54, 30]
# Max: 99, Min: 8 (low entropy vs Base64 high entropy)
```

## Code Sample (Binary/Hex)
```python
# Convert binary -> hex -> low-entropy cipher
echo "Hello World" | xxd -p | tr -d '\n' | python3 hex_cipher.py

# Output: [326, 552, 639, 660, ...]  # Small integers, low entropy
# Evades: EDR scanners looking for Base64 or hex-encoded payloads
```

## References
- Evasion Engineering (Chow & LaSalvia), Chapter 2 - Listings 2-2, 2-3, 2-5
- Book: https://nostarch.com/evasion-engineering
- Author Code: https://github.com/dc401
- Entropy Detection Research: https://pmc.ncbi.nlm.nih.gov/articles/PMC8871499/
- CrowdStrike Entropy Evasion: https://redsiege.com/blog/2023/04/evading-crowdstrike-falcon-using-entropy/
- MS Defender AMSI: https://learn.microsoft.com/en-us/defender-endpoint/amsi-on-mdav
- Ransomware Detection Limits: https://link.springer.com/chapter/10.1007/978-3-030-36802-9_20
