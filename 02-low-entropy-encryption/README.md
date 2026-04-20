# Low-Entropy Encryption - Custom Cipher

## Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (none required)
pip install -r requirements.txt

# Run text cipher example
python3 low_entropy_cipher.py

# Run hex cipher example (for binary payloads)
echo "48656c6c6f" | python3 hex_cipher.py

# Run full demo
./demo.sh
```

## What This Evades
Bypasses EDR entropy detection that flags high-entropy encoded/encrypted payloads:
- CrowdStrike Falcon (static entropy analysis)
- Microsoft Defender AMSI (obfuscated script detection)
- Generic EDR scanners (Base64/hex pattern matching)

## How It Works
- Uses custom substitution cipher with arithmetic encryption (3x + key)
- Produces small integer values (Shannon entropy 1-4 vs Base64 ~6.0)
- Avoids standard encoding signatures (Base64, hexadecimal)
- Maintains low-randomness output below EDR detection thresholds

## Files
- `low_entropy_cipher.py` - Text-based low-entropy cipher
- `hex_cipher.py` - Binary/hex payload encryption
- `demo.sh` - Full pipeline demo (binary -> hex -> encrypted)

## Reference
Evasion Engineering, Chapter 2 - Listings 2-2, 2-3, 2-5  
https://nostarch.com/evasion-engineering
