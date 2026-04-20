#!/usr/bin/env python3
# Static analysis for evasive binaries
# Automated detection for analyst triage and investigation
# Detects: Go binaries, low-entropy crypto, custom shells, network exfil

import re
import os
import math
import subprocess
from collections import Counter

class StaticBinaryAnalyzer:
    """
    Automated static analysis for suspicious binaries
    Purpose: Triage and provide investigation leads for analysts
    """

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.binary_size = os.path.getsize(binary_path)
        self.strings_output = None
        self.symbols_output = None
        self.indicators = []
        self.risk_score = 0

    def extract_strings(self, min_length=4):
        """Extract printable strings from binary"""
        try:
            # Use strings command
            result = subprocess.run(
                ['strings', '-n', str(min_length), self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            self.strings_output = result.stdout.split('\n')
            return self.strings_output
        except Exception as e:
            print(f"[WARN] String extraction failed: {e}")
            return []

    def extract_symbols(self):
        """Extract symbols using nm or go tool"""
        try:
            # Try nm first
            result = subprocess.run(
                ['nm', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                self.symbols_output = result.stdout
                return self.symbols_output

            # Fallback to go tool nm if available
            result = subprocess.run(
                ['go', 'tool', 'nm', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            self.symbols_output = result.stdout
            return self.symbols_output

        except Exception as e:
            print(f"[WARN] Symbol extraction failed: {e}")
            return ""

    def detect_go_binary(self):
        """Detect Go binary signatures (Section 7)"""
        if not self.strings_output:
            self.extract_strings()

        go_indicators = [
            "go.buildid",
            "runtime.main",
            "runtime.goexit",
            "type..hash"
        ]

        found = []
        for indicator in go_indicators:
            if any(indicator in s for s in self.strings_output):
                found.append(indicator)

        if len(found) >= 2:
            self.indicators.append({
                "type": "go_binary",
                "confidence": 0.95,
                "evidence": f"Found {len(found)} Go signatures: {', '.join(found[:3])}",
                "severity": "INFO"
            })
            self.risk_score += 10  # Go binary itself not malicious, but context matters

        return len(found) >= 2

    def detect_stripped_binary(self):
        """Detect stripped symbols (suspicious for legitimate software)"""
        try:
            # Get symbols with nm
            result = subprocess.run(
                ['nm', self.binary_path],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Count symbols
            symbol_lines = [l for l in result.stdout.split('\n') if l.strip()]
            symbol_count = len(symbol_lines)

            # Stripped Go binaries: <200 symbols (only external C libs)
            # Normal Go binaries: 1000s of symbols
            if symbol_count < 200:
                self.indicators.append({
                    "type": "stripped_symbols",
                    "confidence": 0.75,
                    "evidence": f"Only {symbol_count} symbols (normal: >1000). Legitimate software retains symbols for debugging.",
                    "severity": "MEDIUM"
                })
                self.risk_score += 30

        except Exception as e:
            pass  # Skip if tools not available

    def detect_encryption_functions(self):
        """Detect low-entropy encryption patterns (Section 2)"""
        if not self.strings_output:
            self.extract_strings()

        # Look for CUSTOM (main package) encryption function names
        # Exclude Go runtime internal functions (slices., runtime., crypto/*)
        crypto_patterns = [
            r"main\.\w*encrypt",
            r"main\.\w*cipher",
            r"main\.chowEncrypt",  # Unobfuscated name
            r"main\.e[0-9]+",      # Obfuscated encryption (e1, e2, etc.)
            r"main\.\w*xor(?!shift)",  # User XOR, not runtime xorshift
        ]

        found_crypto = []
        for pattern in crypto_patterns:
            matches = [s for s in self.strings_output if re.search(pattern, s, re.IGNORECASE)]
            if matches:
                found_crypto.extend(matches[:2])  # Limit to 2 per pattern

        if found_crypto:
            self.indicators.append({
                "type": "custom_encryption",
                "confidence": 0.75,
                "evidence": f"Custom encryption functions: {', '.join(found_crypto[:3])}",
                "severity": "MEDIUM"
            })
            self.risk_score += 30

        # Check for arithmetic operations typical of simple ciphers
        arithmetic_patterns = [
            r"\* 3",  # Our 3x cipher
            r"\+ \d+",  # Key addition
            r"% 256"  # Modulo for char wrapping
        ]

        # Read binary as bytes for pattern matching
        with open(self.binary_path, 'rb') as f:
            binary_data = f.read()
            binary_str = str(binary_data)

        cipher_indicators = 0
        for pattern in arithmetic_patterns:
            if re.search(pattern, binary_str):
                cipher_indicators += 1

        if cipher_indicators >= 2:
            self.indicators.append({
                "type": "simple_cipher_pattern",
                "confidence": 0.70,
                "evidence": f"Arithmetic patterns consistent with simple cipher (found {cipher_indicators} patterns)",
                "severity": "MEDIUM"
            })
            self.risk_score += 25

    def detect_custom_shell_functions(self):
        """Detect custom shell implementations (Section 3)"""
        if not self.strings_output:
            self.extract_strings()

        # Custom function patterns (including obfuscated names)
        # Look for: main.customX or main.fnX patterns
        custom_patterns = [
            r"main\.custom\w+",  # Original unobfuscated
            r"main\.fn[0-9]+",   # Obfuscated numeric (fn1, fn2, etc.)
        ]

        found_funcs = []
        for pattern in custom_patterns:
            matches = [s for s in self.strings_output if re.search(pattern, s)]
            for match in matches:
                # Extract just the function name
                func_match = re.search(pattern, match)
                if func_match:
                    func_name = func_match.group(0).replace("main.", "")
                    if func_name not in found_funcs:
                        found_funcs.append(func_name)

        # Only flag if multiple custom functions found (not just 1-2 helpers)
        if len(found_funcs) >= 3:
            self.indicators.append({
                "type": "custom_shell_functions",
                "confidence": 0.85,
                "evidence": f"Multiple custom functions: {', '.join(found_funcs[:5])}",
                "severity": "HIGH"
            })
            self.risk_score += 45

        # Look for /proc access (must be with cmdline, not just Go runtime)
        proc_access = [s for s in self.strings_output if "/proc/" in s and "cmdline" in s]

        if proc_access:
            self.indicators.append({
                "type": "proc_filesystem_access",
                "confidence": 0.75,
                "evidence": f"/proc enumeration detected (ps alternative)",
                "severity": "MEDIUM"
            })
            self.risk_score += 20

        # Look for DIRECT syscall usage in main package (not Go runtime)
        syscall_patterns = ["main.customWhoami", "syscall.Getuid", "syscall.Getgid"]
        syscall_usage = [s for s in self.strings_output if any(p in s for p in syscall_patterns)]

        # Only flag if multiple custom syscalls found (not just Go runtime)
        if len(syscall_usage) >= 2:
            self.indicators.append({
                "type": "direct_syscalls",
                "confidence": 0.80,
                "evidence": f"Direct syscall usage (avoiding LOLBins)",
                "severity": "MEDIUM"
            })
            self.risk_score += 25

    def detect_network_exfiltration(self):
        """Detect network exfiltration patterns"""
        if not self.strings_output:
            self.extract_strings()

        # Localhost connections (suspicious for exfil)
        localhost_patterns = ["127.0.0.1:443", "localhost:443"]
        localhost_found = any(any(p in s for p in localhost_patterns) for s in self.strings_output)

        if localhost_found:
            self.indicators.append({
                "type": "localhost_exfiltration",
                "confidence": 0.85,
                "evidence": "Connection to 127.0.0.1:443 (local C2 simulation)",
                "severity": "HIGH"
            })
            self.risk_score += 40

        # External IP check services
        external_check = ["ifconfig.me", "ipify", "icanhazip"]
        external_found = [s for s in self.strings_output if any(p in s for p in external_check)]

        if external_found:
            self.indicators.append({
                "type": "external_ip_check",
                "confidence": 0.70,
                "evidence": f"External IP enumeration: {external_found[0][:50]}",
                "severity": "MEDIUM"
            })
            self.risk_score += 20

        # Network function usage
        net_functions = ["net.Dial", "net.Interfaces", "net.Addrs"]
        net_found = [s for s in self.strings_output if any(p in s for p in net_functions)]

        if len(net_found) >= 2:
            self.indicators.append({
                "type": "network_enumeration",
                "confidence": 0.75,
                "evidence": f"Network enumeration functions: {len(net_found)} found",
                "severity": "MEDIUM"
            })
            self.risk_score += 20

    def detect_timing_evasion(self):
        """Detect timing delay patterns (Section 1)"""
        if not self.strings_output:
            self.extract_strings()

        # Look for CUSTOM delay functions (main package)
        delay_patterns = [
            "main.randomDelay",
            "randomDelaySeconds"
        ]

        delay_found = []
        for pattern in delay_patterns:
            matches = [s for s in self.strings_output if pattern in s]
            if matches:
                delay_found.extend(matches[:2])

        # Only flag if custom delay functions found (not just Go time.Sleep)
        if delay_found:
            self.indicators.append({
                "type": "timing_delays",
                "confidence": 0.70,
                "evidence": f"Timing delay functions: {', '.join(delay_found[:2])}",
                "severity": "MEDIUM"
            })
            self.risk_score += 25

        # Look for random number generation (for jitter)
        rng_patterns = ["rand.Seed", "rand.Intn", "time.Now"]
        rng_found = [s for s in self.strings_output if any(p in s for p in rng_patterns)]

        if len(rng_found) >= 2:
            self.indicators.append({
                "type": "random_jitter",
                "confidence": 0.65,
                "evidence": f"RNG for timing jitter: {len(rng_found)} indicators",
                "severity": "LOW"
            })
            self.risk_score += 15

    def detect_reconnaissance_patterns(self):
        """Detect reconnaissance activity indicators"""
        if not self.strings_output:
            self.extract_strings()

        recon_keywords = [
            "whoami", "uid=", "gid=",
            "Process", "enumerate",
            "interface", "ifconfig",
            "RECON", "reconnaissance"
        ]

        recon_found = []
        for keyword in recon_keywords:
            if any(keyword in s for s in self.strings_output):
                recon_found.append(keyword)

        if len(recon_found) >= 3:
            self.indicators.append({
                "type": "reconnaissance_activity",
                "confidence": 0.80,
                "evidence": f"Reconnaissance keywords: {', '.join(recon_found[:4])}",
                "severity": "HIGH"
            })
            self.risk_score += 35

    def analyze_binary_entropy(self, chunk_size=1024):
        """Analyze actual binary data for low-entropy encrypted sections"""
        try:
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()

            # Sample chunks from the binary
            num_chunks = min(100, len(binary_data) // chunk_size)
            low_entropy_chunks = 0

            for i in range(num_chunks):
                offset = (i * len(binary_data)) // num_chunks
                chunk = binary_data[offset:offset+chunk_size]

                if len(chunk) < 100:
                    continue

                # Calculate byte entropy
                counter = Counter(chunk)
                length = len(chunk)
                entropy = -sum((count / length) * math.log2(count / length)
                             for count in counter.values() if count > 0)

                # Low entropy in binary data = weak crypto or obfuscation
                if entropy < 3.0:
                    low_entropy_chunks += 1

            if low_entropy_chunks > num_chunks * 0.1:  # >10% low entropy
                self.indicators.append({
                    "type": "low_entropy_binary_sections",
                    "confidence": 0.80,
                    "evidence": f"{low_entropy_chunks}/{num_chunks} sections with low entropy (weak crypto)",
                    "severity": "MEDIUM"
                })
                self.risk_score += 30

        except Exception as e:
            print(f"[WARN] Binary entropy analysis failed: {e}")

    def detect_simple_cipher_patterns(self):
        """Detect simple cipher patterns in compiled code"""
        try:
            with open(self.binary_path, 'rb') as f:
                binary_data = f.read()

            # Look for arithmetic patterns typical of simple ciphers
            # Pattern 1: Multiply by 3 (our cipher uses * 3)
            # Pattern 2: Add constant (our cipher uses + key)
            # Pattern 3: Modulo 256 (character wrapping)

            suspicious_patterns = 0

            # Search for byte patterns that indicate arithmetic on characters
            # IMUL (multiply) followed by ADD (addition) - x86_64 pattern
            # This is a simplified heuristic
            mul_pattern = b'\x69'  # IMUL instruction prefix
            add_pattern = b'\x83\xC0'  # ADD to register

            # Count occurrences
            if binary_data.count(mul_pattern) > 10:
                suspicious_patterns += 1

            if binary_data.count(add_pattern) > 10:
                suspicious_patterns += 1

            # Look for modulo 256 operation (AND 0xFF)
            and_255 = b'\x25\xFF\x00\x00\x00'  # AND EAX, 0xFF
            if binary_data.count(and_255) > 5:
                suspicious_patterns += 1

            if suspicious_patterns >= 2:
                self.indicators.append({
                    "type": "simple_cipher_bytecode",
                    "confidence": 0.70,
                    "evidence": f"Arithmetic patterns in compiled code ({suspicious_patterns} indicators)",
                    "severity": "MEDIUM"
                })
                self.risk_score += 25

        except Exception as e:
            print(f"[WARN] Cipher pattern analysis failed: {e}")

    def analyze(self):
        """Run all detection checks"""
        print(f"\n[STATIC ANALYSIS] {os.path.basename(self.binary_path)}")
        print(f"[INFO] Binary size: {self.binary_size:,} bytes")

        # Extract data
        print("[INFO] Extracting strings...")
        self.extract_strings()
        print(f"[INFO] Found {len(self.strings_output)} strings")

        # Run detections
        print("\n[DETECTION] Running analysis modules...")

        self.detect_go_binary()
        self.detect_stripped_binary()
        self.detect_encryption_functions()
        self.detect_simple_cipher_patterns()
        self.analyze_binary_entropy()
        self.detect_custom_shell_functions()
        self.detect_network_exfiltration()
        self.detect_timing_evasion()
        self.detect_reconnaissance_patterns()

        # Generate report
        return self.generate_report()

    def generate_llm_prompt(self, classification):
        """Generate LLM-assisted analysis prompt and tool recommendations"""
        print("\n[LLM-ASSISTED ANALYSIS]\n")
        print("For deeper analysis, gather additional raw data using these tools:\n")

        print("Go-Specific Decompilation Tools:")
        print("  1. Ghidra with GoReSym plugin:")
        print("     - Download: https://github.com/mandiant/GoReSym")
        print("     - Purpose: Recover Go function names, types, and interfaces")
        print("     - Command: GoReSym -t -d -p <binary> > symbols.txt")
        print("")
        print("  2. IDA Pro with golang_loader_assist:")
        print("     - Download: https://github.com/strazzere/golang_loader_assist")
        print("     - Purpose: Parse Go runtime metadata, restore function names")
        print("")
        print("  3. Redress (Go reverse engineering tool):")
        print("     - Install: go install github.com/goretk/redress@latest")
        print("     - Command: redress -pkg -interface -type <binary>")
        print("")
        print("  4. go-reversing-toolkit:")
        print("     - Command: strings -n 10 <binary> | grep 'main\\.'")
        print("     - Command: objdump -d <binary> > disassembly.txt")
        print("")

        print("After gathering raw data, copy this prompt to an LLM:\n")
        print("-" * 70)
        print("COPY BELOW THIS LINE")
        print("-" * 70)
        print()

        # Generate structured prompt
        prompt = f"""I need help analyzing a suspicious Go binary. Here are the automated static analysis findings:

BINARY INFORMATION:
- File: {os.path.basename(self.binary_path)}
- Size: {self.binary_size:,} bytes
- Risk Score: {self.risk_score}/100
- Classification: {classification}

INDICATORS FOUND ({len(self.indicators)} total):
"""

        # Add indicators grouped by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            severity_indicators = [i for i in self.indicators if i['severity'] == severity]
            if severity_indicators:
                prompt += f"\n{severity} Severity:\n"
                for indicator in severity_indicators:
                    prompt += f"  - {indicator['type']} (confidence: {indicator['confidence']*100:.0f}%)\n"
                    prompt += f"    Evidence: {indicator['evidence']}\n"

        prompt += "\nRAW DATA AVAILABLE:\n"
        prompt += "- Full strings output (attach as separate file)\n"
        prompt += "- Symbol table (attach if available)\n"
        prompt += "- Disassembly output (attach if available)\n"
        prompt += "- GoReSym recovered symbols (attach if available)\n"

        prompt += "\nANALYSIS QUESTIONS:\n"
        question_num = 1

        if any(i['type'] in ['custom_encryption', 'simple_cipher_bytecode'] for i in self.indicators):
            prompt += f"{question_num}. Encryption/Obfuscation Analysis:\n"
            prompt += "   - Based on bytecode patterns found (IMUL, ADD, AND operations), can you infer the encryption algorithm?\n"
            prompt += "   - What are the likely constants (multiplier, key, modulo values)?\n"
            prompt += "   - How would I decrypt data encrypted with this algorithm?\n"
            prompt += "   - Where in the disassembly should I look for encryption keys?\n"
            question_num += 1

        if any(i['type'] == 'custom_shell_functions' for i in self.indicators):
            prompt += f"{question_num}. Custom Function Analysis:\n"
            prompt += "   - Based on strings/symbols, what custom functions exist (main.fn*, main.custom*)?\n"
            prompt += "   - What might each function do based on:\n"
            prompt += "     * Syscall patterns (syscall.Getuid, syscall.Open, etc.)\n"
            prompt += "     * File access patterns (/proc, /sys, registry paths)\n"
            prompt += "     * Network function calls (net.Dial, net.Interfaces)\n"
            prompt += "   - Are these legitimate admin tools or reconnaissance functions?\n"
            question_num += 1

        if any(i['type'] in ['localhost_exfiltration', 'external_ip_check', 'network_enumeration'] for i in self.indicators):
            prompt += f"{question_num}. Network Activity Analysis:\n"
            prompt += "   - What network destinations were found in strings (IPs, domains, ports)?\n"
            prompt += "   - Which destinations are likely:\n"
            prompt += "     * C2 channels (especially localhost, unusual ports)\n"
            prompt += "     * Reconnaissance/enumeration (IP check services)\n"
            prompt += "     * Legitimate services\n"
            prompt += "   - What data might be exfiltrated based on custom functions?\n"
            question_num += 1

        if any(i['type'] in ['timing_delays', 'random_jitter'] for i in self.indicators):
            prompt += f"{question_num}. Evasion Technique Analysis:\n"
            prompt += "   - What timing/delay functions exist?\n"
            prompt += "   - Are delays randomized (correlation evasion) or fixed (scheduling)?\n"
            prompt += "   - What other evasion techniques might be present?\n"
            question_num += 1

        prompt += f"{question_num}. Attack Workflow Reconstruction:\n"
        prompt += "   - Based on all indicators, what is the likely attack sequence?\n"
        prompt += "   - What data is being collected?\n"
        prompt += "   - How is it being obfuscated/encrypted?\n"
        prompt += "   - Where is it being sent?\n"
        prompt += "   - What is the operational intent (reconnaissance, persistence, exfiltration)?\n"
        question_num += 1

        prompt += f"{question_num}. Reverse Engineering Guidance:\n"
        prompt += "   - What should I look for in the disassembly to confirm these hypotheses?\n"
        prompt += "   - Specific function addresses to examine (main.*, runtime.*)\n"
        prompt += "   - Key variable assignments (constants, keys, addresses)\n"
        prompt += "   - Cross-references to follow (callers/callees)\n"
        prompt += "   - Ghidra/IDA specific actions to take\n"

        prompt += "\nPlease provide:\n"
        prompt += "- Step-by-step reverse engineering guidance\n"
        prompt += "- Specific addresses/offsets to examine in Ghidra/IDA\n"
        prompt += "- Likely decryption keys and algorithms (if applicable)\n"
        prompt += "- IOCs for detection rules (IPs, domains, file paths, registry keys, function names)\n"
        prompt += "- YARA/Sigma rules for automated detection\n"
        prompt += "- Recommended containment and remediation actions\n"

        print(prompt)
        print("-" * 70)
        print("END OF PROMPT")
        print("-" * 70)
        print()

    def generate_report(self):
        """Generate analyst-friendly report"""
        print(f"\n{'='*70}")
        print(f"STATIC ANALYSIS REPORT")
        print(f"{'='*70}\n")

        print(f"Binary: {os.path.basename(self.binary_path)}")
        print(f"Size: {self.binary_size:,} bytes")
        print(f"Risk Score: {self.risk_score}/100")

        # Classify
        if self.risk_score >= 150:
            classification = "CRITICAL"
        elif self.risk_score >= 100:
            classification = "HIGH"
        elif self.risk_score >= 50:
            classification = "MEDIUM"
        else:
            classification = "LOW"

        print(f"Classification: {classification}\n")

        if self.indicators:
            print(f"[INDICATORS] {len(self.indicators)} findings:\n")

            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_indicators = sorted(self.indicators, key=lambda x: severity_order.get(x['severity'], 5))

            for idx, indicator in enumerate(sorted_indicators, 1):
                print(f"{idx}. [{indicator['severity']}] {indicator['type']}")
                print(f"   Confidence: {indicator['confidence']*100:.0f}%")
                print(f"   Evidence: {indicator['evidence']}")
                print()

            # Analyst recommendations
            print(f"[ANALYST RECOMMENDATIONS]\n")

            if any(i['type'] == 'custom_shell_functions' for i in self.indicators):
                print("- Reverse engineer custom shell functions for capabilities")

            if any(i['type'] == 'custom_encryption' for i in self.indicators):
                print("- Analyze encryption implementation (likely weak/custom)")

            if any(i['type'] == 'localhost_exfiltration' for i in self.indicators):
                print("- Check network logs for actual C2 connections")

            if any(i['type'] == 'timing_delays' for i in self.indicators):
                print("- Review execution timeline for correlation evasion")

            if any(i['type'] == 'go_binary' for i in self.indicators):
                print("- Use Go-specific reverse engineering tools (IDA, Ghidra with Go plugin)")

            print("\n[NEXT STEPS]")
            print("1. Dynamic analysis in sandbox environment")
            print("2. Network traffic capture (PCAP)")
            print("3. Full reverse engineering with Ghidra/IDA")
            print("4. Memory dump analysis during execution")
            print("5. Compare with known malware families")

            # LLM-assisted analysis section
            self.generate_llm_prompt(classification)

        else:
            print("[INFO] No suspicious indicators found")
            print("[NOTE] Low risk, but manual review recommended")

        print(f"\n{'='*70}\n")

        return {
            "risk_score": self.risk_score,
            "classification": classification,
            "indicators": self.indicators
        }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 static_analyzer.py <binary_path>")
        print("Example: python3 static_analyzer.py ../evasive_recon")
        sys.exit(1)

    binary_path = sys.argv[1]

    if not os.path.exists(binary_path):
        print(f"[ERROR] Binary not found: {binary_path}")
        sys.exit(1)

    # Run analysis
    analyzer = StaticBinaryAnalyzer(binary_path)
    result = analyzer.analyze()

    # Exit code based on risk
    if result['classification'] in ['CRITICAL', 'HIGH']:
        sys.exit(1)  # Alert
    else:
        sys.exit(0)  # No alert
