#!/usr/bin/env python3
"""
Example workflows for Ghidra-Claude integration
Demonstrates various reverse engineering analysis patterns
"""

import json
import sys
from pathlib import Path
from typing import Dict, List
from ghidra_claude_bridge import GhidraClaudeBridge, AnalysisType, create_claude_prompt


class WorkflowExamples:
    """Collection of example analysis workflows"""

    def __init__(self, ghidra_path: str):
        self.bridge = GhidraClaudeBridge(ghidra_path)

    def malware_analysis_workflow(self, binary_path: str) -> Dict:
        """
        Complete malware analysis workflow
        1. Extract indicators of compromise
        2. Identify anti-analysis techniques
        3. Find C2 communication patterns
        4. Detect persistence mechanisms
        """
        print(f"\n[*] Starting malware analysis for: {binary_path}")

        # Run initial analysis
        analysis = self.bridge.analyze_binary(binary_path, AnalysisType.MALWARE_INDICATORS)

        # Create specialized prompts for different aspects
        prompts = {
            "iocs": self._create_ioc_prompt(analysis),
            "anti_analysis": self._create_anti_analysis_prompt(analysis),
            "c2_comms": self._create_c2_prompt(analysis),
            "persistence": self._create_persistence_prompt(analysis)
        }

        return {
            "binary": binary_path,
            "workflow": "malware_analysis",
            "prompts": prompts,
            "ghidra_data": analysis
        }

    def vulnerability_assessment_workflow(self, binary_path: str) -> Dict:
        """
        Security vulnerability assessment workflow
        1. Identify unsafe functions
        2. Find buffer overflow candidates
        3. Detect format string vulnerabilities
        4. Check for race conditions
        """
        print(f"\n[*] Starting vulnerability assessment for: {binary_path}")

        analysis = self.bridge.analyze_binary(binary_path, AnalysisType.VULNERABILITY_SCAN)

        # Extract vulnerable patterns
        vulnerable_functions = self._find_vulnerable_functions(analysis)
        buffer_overflow_candidates = self._find_buffer_overflows(analysis)
        format_string_vulns = self._find_format_strings(analysis)

        prompts = {
            "vulnerable_functions": self._create_vuln_function_prompt(vulnerable_functions),
            "buffer_overflows": self._create_buffer_overflow_prompt(buffer_overflow_candidates),
            "format_strings": self._create_format_string_prompt(format_string_vulns),
            "general_assessment": create_claude_prompt(analysis)
        }

        return {
            "binary": binary_path,
            "workflow": "vulnerability_assessment",
            "prompts": prompts,
            "findings": {
                "vulnerable_functions": vulnerable_functions,
                "buffer_overflow_candidates": buffer_overflow_candidates,
                "format_string_vulnerabilities": format_string_vulns
            }
        }

    def crypto_implementation_review(self, binary_path: str) -> Dict:
        """
        Cryptographic implementation review workflow
        1. Identify crypto algorithms
        2. Check key management
        3. Find hardcoded secrets
        4. Assess random number generation
        """
        print(f"\n[*] Starting crypto review for: {binary_path}")

        analysis = self.bridge.analyze_binary(binary_path, AnalysisType.CRYPTO_IDENTIFICATION)

        crypto_functions = self._identify_crypto_functions(analysis)
        key_operations = self._find_key_operations(analysis)
        hardcoded_secrets = self._find_hardcoded_secrets(analysis)

        prompts = {
            "crypto_algorithms": self._create_crypto_algo_prompt(crypto_functions),
            "key_management": self._create_key_mgmt_prompt(key_operations),
            "hardcoded_secrets": self._create_secrets_prompt(hardcoded_secrets),
            "rng_assessment": self._create_rng_prompt(analysis)
        }

        return {
            "binary": binary_path,
            "workflow": "crypto_review",
            "prompts": prompts,
            "findings": {
                "crypto_functions": crypto_functions,
                "key_operations": key_operations,
                "potential_secrets": hardcoded_secrets
            }
        }

    def protocol_reverse_engineering(self, binary_path: str) -> Dict:
        """
        Network protocol reverse engineering workflow
        1. Identify network functions
        2. Find protocol handlers
        3. Extract message formats
        4. Map state machines
        """
        print(f"\n[*] Starting protocol analysis for: {binary_path}")

        analysis = self.bridge.analyze_binary(binary_path, AnalysisType.PROTOCOL_ANALYSIS)

        network_functions = self._find_network_functions(analysis)
        protocol_handlers = self._find_protocol_handlers(analysis)
        message_structures = self._extract_message_structures(analysis)

        prompts = {
            "network_functions": self._create_network_prompt(network_functions),
            "protocol_handlers": self._create_protocol_handler_prompt(protocol_handlers),
            "message_formats": self._create_message_format_prompt(message_structures),
            "state_machine": self._create_state_machine_prompt(analysis)
        }

        return {
            "binary": binary_path,
            "workflow": "protocol_reverse_engineering",
            "prompts": prompts,
            "findings": {
                "network_functions": network_functions,
                "protocol_handlers": protocol_handlers,
                "message_structures": message_structures
            }
        }

    # Helper methods for finding specific patterns

    def _find_vulnerable_functions(self, analysis: Dict) -> List[Dict]:
        """Find potentially vulnerable functions"""
        vulnerable = []
        dangerous_funcs = [
            "strcpy", "strcat", "sprintf", "vsprintf", "gets",
            "scanf", "fscanf", "sscanf", "vscanf", "vfscanf",
            "vsscanf", "strtok", "strtok_r", "strncpy", "strncat"
        ]

        functions = analysis.get("context", {}).get("relevant_functions", [])
        for func in functions:
            name = func.get("name", "").lower()
            if any(df in name for df in dangerous_funcs):
                vulnerable.append(func)

            # Check for dangerous patterns in decompiled code
            decompiled = func.get("decompiled_code", "")
            if decompiled:
                for df in dangerous_funcs:
                    if df in decompiled:
                        vulnerable.append(func)
                        break

        return vulnerable

    def _find_buffer_overflows(self, analysis: Dict) -> List[Dict]:
        """Find potential buffer overflow candidates"""
        candidates = []
        functions = analysis.get("context", {}).get("relevant_functions", [])

        for func in functions:
            decompiled = func.get("decompiled_code", "")
            if not decompiled:
                continue

            # Look for stack buffer operations
            if ("char " in decompiled and "[" in decompiled and "]" in decompiled):
                if any(pattern in decompiled for pattern in ["strcpy", "strcat", "gets", "scanf"]):
                    candidates.append({
                        "function": func.get("name"),
                        "address": func.get("address"),
                        "reason": "Stack buffer with unsafe operation"
                    })

        return candidates

    def _find_format_strings(self, analysis: Dict) -> List[Dict]:
        """Find format string vulnerabilities"""
        vulnerabilities = []
        functions = analysis.get("context", {}).get("relevant_functions", [])

        for func in functions:
            decompiled = func.get("decompiled_code", "")
            if not decompiled:
                continue

            # Look for printf family functions with non-literal format strings
            printf_funcs = ["printf", "fprintf", "sprintf", "snprintf", "vprintf"]
            for pf in printf_funcs:
                if pf in decompiled:
                    # Simple heuristic - would need more sophisticated analysis
                    vulnerabilities.append({
                        "function": func.get("name"),
                        "address": func.get("address"),
                        "type": pf
                    })

        return vulnerabilities

    def _identify_crypto_functions(self, analysis: Dict) -> List[Dict]:
        """Identify cryptographic functions"""
        crypto_funcs = []
        crypto_indicators = [
            "aes", "des", "rsa", "sha", "md5", "hmac", "encrypt", "decrypt",
            "cipher", "hash", "sign", "verify", "key", "iv", "nonce"
        ]

        functions = analysis.get("context", {}).get("relevant_functions", [])
        for func in functions:
            name = func.get("name", "").lower()
            if any(ci in name for ci in crypto_indicators):
                crypto_funcs.append(func)

        return crypto_funcs

    def _find_key_operations(self, analysis: Dict) -> List[Dict]:
        """Find key generation and management operations"""
        key_ops = []
        key_patterns = ["generat", "derive", "import", "export", "store", "load"]

        functions = analysis.get("context", {}).get("relevant_functions", [])
        for func in functions:
            name = func.get("name", "").lower()
            if "key" in name and any(kp in name for kp in key_patterns):
                key_ops.append(func)

        return key_ops

    def _find_hardcoded_secrets(self, analysis: Dict) -> List[Dict]:
        """Find potential hardcoded secrets"""
        secrets = []
        strings = analysis.get("binary_info", {}).get("strings", [])

        # Look for high-entropy strings that might be keys
        for string_data in strings:
            value = string_data.get("value", "")
            # Simple heuristics for potential secrets
            if len(value) in [16, 24, 32, 64, 128]:  # Common key sizes
                if all(c in "0123456789abcdefABCDEF" for c in value):
                    secrets.append({
                        "type": "hex_string",
                        "value": value,
                        "address": string_data.get("address")
                    })
            elif len(value) > 20 and value.endswith("="):  # Possible base64
                secrets.append({
                    "type": "base64_candidate",
                    "value": value[:50] + "..." if len(value) > 50 else value,
                    "address": string_data.get("address")
                })

        return secrets

    def _find_network_functions(self, analysis: Dict) -> List[Dict]:
        """Find network-related functions"""
        network_funcs = []
        network_indicators = [
            "socket", "connect", "bind", "listen", "accept", "send", "recv",
            "sendto", "recvfrom", "select", "poll", "epoll", "http", "tcp", "udp"
        ]

        functions = analysis.get("context", {}).get("relevant_functions", [])
        for func in functions:
            name = func.get("name", "").lower()
            if any(ni in name for ni in network_indicators):
                network_funcs.append(func)

        return network_funcs

    def _find_protocol_handlers(self, analysis: Dict) -> List[Dict]:
        """Find protocol handler functions"""
        handlers = []
        handler_patterns = ["handle", "process", "parse", "dispatch", "on_", "recv_"]

        functions = analysis.get("context", {}).get("relevant_functions", [])
        for func in functions:
            name = func.get("name", "").lower()
            if any(hp in name for hp in handler_patterns):
                if "packet" in name or "message" in name or "request" in name:
                    handlers.append(func)

        return handlers

    def _extract_message_structures(self, analysis: Dict) -> List[Dict]:
        """Extract potential message structure definitions"""
        structures = []
        # This would require more sophisticated analysis of data structures
        # For now, return placeholder
        return structures

    # Prompt creation methods

    def _create_ioc_prompt(self, analysis: Dict) -> str:
        return f"""Analyze this binary for Indicators of Compromise (IOCs):

Binary: {analysis.get('binary_info', {}).get('name')}
Architecture: {analysis.get('binary_info', {}).get('architecture')}

Please identify:
1. Network indicators (IPs, domains, URLs)
2. File system indicators (paths, filenames)
3. Registry keys (for Windows binaries)
4. Mutex names
5. Process names
6. Service names

Focus on strings and function names that might indicate malicious behavior."""

    def _create_anti_analysis_prompt(self, analysis: Dict) -> str:
        return """Identify anti-analysis and evasion techniques:

1. Anti-debugging checks (IsDebuggerPresent, CheckRemoteDebuggerPresent)
2. Anti-VM detection (CPUID checks, timing checks)
3. Code obfuscation patterns
4. Encrypted/packed sections
5. Process injection techniques
6. API hooking methods

Examine function names and code patterns for these techniques."""

    def _create_c2_prompt(self, analysis: Dict) -> str:
        return """Analyze Command & Control (C2) communication patterns:

1. Network communication functions
2. Data encoding/encryption before transmission
3. Command parsing and dispatch mechanisms
4. Beacon intervals or sleep patterns
5. Protocol identification (HTTP, HTTPS, DNS, custom)
6. Data exfiltration methods

Look for patterns that indicate remote control capabilities."""

    def _create_persistence_prompt(self, analysis: Dict) -> str:
        return """Identify persistence mechanisms:

1. Registry modifications (Run keys, services)
2. Scheduled task creation
3. Service installation
4. DLL hijacking setup
5. Startup folder modifications
6. Boot sector modifications
7. Rootkit behaviors

Analyze functions that interact with system persistence points."""

    def _create_vuln_function_prompt(self, vulnerable_functions: List[Dict]) -> str:
        prompt = "Analyze these potentially vulnerable functions for security issues:\n\n"
        for func in vulnerable_functions[:5]:
            prompt += f"Function: {func.get('name')} at {func.get('address')}\n"
            if func.get('decompiled_code'):
                prompt += f"Code snippet:\n```c\n{func['decompiled_code'][:500]}\n```\n\n"
        prompt += "\nIdentify specific vulnerabilities and exploitation potential."
        return prompt

    def _create_buffer_overflow_prompt(self, candidates: List[Dict]) -> str:
        prompt = "Analyze these potential buffer overflow candidates:\n\n"
        for candidate in candidates[:5]:
            prompt += f"- Function: {candidate['function']} at {candidate['address']}\n"
            prompt += f"  Reason: {candidate['reason']}\n\n"
        prompt += "\nAssess exploitability and suggest mitigations."
        return prompt

    def _create_format_string_prompt(self, vulns: List[Dict]) -> str:
        prompt = "Review these potential format string vulnerabilities:\n\n"
        for vuln in vulns[:5]:
            prompt += f"- Function: {vuln['function']} using {vuln['type']}\n"
        prompt += "\nDetermine if user-controlled format strings are possible."
        return prompt

    def _create_crypto_algo_prompt(self, crypto_functions: List[Dict]) -> str:
        prompt = "Identify cryptographic algorithms in these functions:\n\n"
        for func in crypto_functions[:5]:
            prompt += f"- {func.get('name')} at {func.get('address')}\n"
        prompt += "\nDetermine algorithm types, key sizes, and modes of operation."
        return prompt

    def _create_key_mgmt_prompt(self, key_operations: List[Dict]) -> str:
        prompt = "Analyze key management in these functions:\n\n"
        for func in key_operations[:5]:
            prompt += f"- {func.get('name')}\n"
        prompt += "\nAssess key generation, storage, and handling security."
        return prompt

    def _create_secrets_prompt(self, secrets: List[Dict]) -> str:
        prompt = "Review these potential hardcoded secrets:\n\n"
        for secret in secrets[:10]:
            prompt += f"- Type: {secret['type']} at {secret['address']}\n"
            prompt += f"  Value: {secret['value']}\n\n"
        prompt += "\nDetermine if these are actual secrets and their purpose."
        return prompt

    def _create_rng_prompt(self, analysis: Dict) -> str:
        return """Analyze random number generation:

1. Identify RNG functions (rand, random, CryptGenRandom)
2. Check for proper seeding
3. Assess entropy sources
4. Identify predictable patterns
5. Check for cryptographic vs non-cryptographic RNG

Determine if RNG is suitable for security purposes."""

    def _create_network_prompt(self, network_functions: List[Dict]) -> str:
        prompt = "Analyze network communication in these functions:\n\n"
        for func in network_functions[:5]:
            prompt += f"- {func.get('name')}\n"
        prompt += "\nIdentify protocols, data formats, and security measures."
        return prompt

    def _create_protocol_handler_prompt(self, handlers: List[Dict]) -> str:
        prompt = "Analyze these protocol handler functions:\n\n"
        for handler in handlers[:5]:
            prompt += f"- {handler.get('name')}\n"
        prompt += "\nDetermine message types, parsing logic, and state transitions."
        return prompt

    def _create_message_format_prompt(self, structures: List[Dict]) -> str:
        return """Identify message and packet formats:

1. Header structures
2. Field types and sizes
3. Endianness considerations
4. Checksums or integrity checks
5. Encryption/compression indicators

Reconstruct protocol data structures."""

    def _create_state_machine_prompt(self, analysis: Dict) -> str:
        return """Map protocol state machine:

1. Identify states (connected, authenticated, idle, etc.)
2. Find state transition functions
3. Determine trigger events
4. Map error states and recovery
5. Identify timeout handling

Create a state diagram of the protocol flow."""


def demo_workflow(binary_path: str, ghidra_path: str, workflow_type: str = "malware"):
    """Demonstrate a specific workflow"""
    examples = WorkflowExamples(ghidra_path)

    workflows = {
        "malware": examples.malware_analysis_workflow,
        "vulnerability": examples.vulnerability_assessment_workflow,
        "crypto": examples.crypto_implementation_review,
        "protocol": examples.protocol_reverse_engineering
    }

    if workflow_type not in workflows:
        print(f"Unknown workflow: {workflow_type}")
        print(f"Available: {', '.join(workflows.keys())}")
        return

    # Run selected workflow
    result = workflows[workflow_type](binary_path)

    # Save results
    output_path = Path(f"{Path(binary_path).stem}_{workflow_type}_analysis.json")
    with open(output_path, 'w') as f:
        # Convert to JSON-serializable format
        json_result = {
            "binary": str(result["binary"]),
            "workflow": result["workflow"],
            "prompts": result["prompts"]
        }
        if "findings" in result:
            json_result["findings"] = result["findings"]

        json.dump(json_result, f, indent=2, default=str)

    print(f"\n[+] Analysis complete! Results saved to: {output_path}")
    print("\n[+] Claude prompts generated for:")
    for prompt_name in result["prompts"].keys():
        print(f"    - {prompt_name}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ghidra-Claude Workflow Examples")
    parser.add_argument("binary", help="Binary file to analyze")
    parser.add_argument(
        "--workflow",
        choices=["malware", "vulnerability", "crypto", "protocol"],
        default="malware",
        help="Workflow type to execute"
    )
    parser.add_argument(
        "--ghidra-path",
        default=r"C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV",
        help="Path to Ghidra installation"
    )

    args = parser.parse_args()
    demo_workflow(args.binary, args.ghidra_path, args.workflow)