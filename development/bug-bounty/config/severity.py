"""
CVSS helpers and severity classification for findings.
References: CVSS v3.1 scoring guide + NVD severity thresholds.
"""

from dataclasses import dataclass
from typing import Optional


# NVD CVSS v3.x severity thresholds
SEVERITY_THRESHOLDS = {
    "Critical": (9.0, 10.0),
    "High": (7.0, 8.9),
    "Medium": (4.0, 6.9),
    "Low": (0.1, 3.9),
    "Informational": (0.0, 0.0),
}

# Common CWE references
CWE_MAP = {
    "sqli": ("CWE-89", "SQL Injection"),
    "xss": ("CWE-79", "Cross-site Scripting"),
    "ssrf": ("CWE-918", "Server-Side Request Forgery"),
    "idor": ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "bac": ("CWE-284", "Improper Access Control"),
    "rce": ("CWE-78", "OS Command Injection"),
    "lfi": ("CWE-22", "Path Traversal"),
    "xxe": ("CWE-611", "Improper Restriction of XML External Entity Reference"),
    "csrf": ("CWE-352", "Cross-Site Request Forgery"),
    "rop": ("CWE-119", "Buffer Errors / Memory Corruption"),
    "jwt": ("CWE-347", "Improper Verification of Cryptographic Signature"),
    "open_redirect": ("CWE-601", "URL Redirection to Untrusted Site"),
    "mass_assignment": ("CWE-915", "Improperly Controlled Modification of Object Attributes"),
    "prompt_injection": ("CWE-1336", "Improper Neutralization of Special Elements in Template Engine"),
    "model_extraction": ("CWE-200", "Exposure of Sensitive Information"),
    "insecure_deserialization": ("CWE-502", "Deserialization of Untrusted Data"),
    "auth_bypass": ("CWE-287", "Improper Authentication"),
    "rate_limit": ("CWE-770", "Allocation of Resources Without Limits"),
    "info_disclosure": ("CWE-200", "Exposure of Sensitive Information"),
    "broken_crypto": ("CWE-327", "Use of a Broken/Risky Cryptographic Algorithm"),
}

# OWASP Top 10 (2021) mapping
OWASP_MAP = {
    "auth_bypass": "A07:2021 - Identification and Authentication Failures",
    "jwt": "A02:2021 - Cryptographic Failures",
    "sqli": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "idor": "A01:2021 - Broken Access Control",
    "bac": "A01:2021 - Broken Access Control",
    "rce": "A03:2021 - Injection",
    "lfi": "A01:2021 - Broken Access Control",
    "xxe": "A05:2021 - Security Misconfiguration",
    "csrf": "A01:2021 - Broken Access Control",
    "mass_assignment": "A08:2021 - Software and Data Integrity Failures",
    "open_redirect": "A01:2021 - Broken Access Control",
    "info_disclosure": "A02:2021 - Cryptographic Failures",
    "insecure_deserialization": "A08:2021 - Software and Data Integrity Failures",
    "broken_crypto": "A02:2021 - Cryptographic Failures",
    "rate_limit": "A04:2021 - Insecure Design",
    "prompt_injection": "LLM01:2025 - Prompt Injection",
    "model_extraction": "LLM10:2025 - Unbounded Consumption",
}


def severity_label(cvss_score: float) -> str:
    if cvss_score == 0.0:
        return "Informational"
    for label, (lo, hi) in SEVERITY_THRESHOLDS.items():
        if label == "Informational":
            continue
        if lo <= cvss_score <= hi:
            return label
    return "Unknown"


def cvss_vector_prompt(vuln_type: str) -> str:
    """Return a suggested CVSS v3.1 base vector for common vuln types."""
    vectors = {
        "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      # 9.8 Critical
        "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",        # 10.0 Critical
        "ssrf": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",       # 8.5 High
        "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",        # 6.1 Medium
        "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",       # 8.1 High
        "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",       # 6.5 Medium
        "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1 Medium
        "jwt": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",        # 7.4 High
        "auth_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1 Critical
        "lfi": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",        # 6.5 Medium
        "rop": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",        # 7.0 High
        "prompt_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",  # 10.0 Critical
        "rate_limit": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",  # 5.3 Medium
        "info_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 5.3 Medium
    }
    return vectors.get(vuln_type, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")


def lookup_cwe(vuln_type: str) -> tuple[str, str]:
    return CWE_MAP.get(vuln_type, ("CWE-?", "Unknown vulnerability type"))


def lookup_owasp(vuln_type: str) -> str:
    return OWASP_MAP.get(vuln_type, "OWASP Reference: See https://owasp.org/Top10/")
