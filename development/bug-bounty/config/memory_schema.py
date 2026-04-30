"""
Memory graph entity templates for the bug bounty workflow.
These map to mcp__memory__* operations used throughout the phases.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime


@dataclass
class ScopeRecord:
    target: str
    program: str
    scope_urls: List[str]
    out_of_scope: List[str]
    auth_type: str  # program | ctf | lab | written
    notes: str
    initialized_at: str


@dataclass
class TargetEntity:
    """Maps to a memory graph entity for the target."""
    name: str
    entity_type: str = "Target"
    domain: str = ""
    ip_range: str = ""
    tech_stack: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    notes: str = ""

    def to_memory_entity(self) -> dict:
        """Format for mcp__memory__create_entities."""
        observations = []
        if self.domain:
            observations.append(f"Domain: {self.domain}")
        if self.ip_range:
            observations.append(f"IP range: {self.ip_range}")
        for tech in self.tech_stack:
            observations.append(f"Tech: {tech}")
        for port in self.open_ports:
            observations.append(f"Port: {port}")
        for cve in self.cves:
            observations.append(f"CVE: {cve}")
        if self.notes:
            observations.append(f"Notes: {self.notes}")
        return {
            "name": self.name,
            "entityType": self.entity_type,
            "observations": observations,
        }


@dataclass
class Finding:
    """Represents a single vulnerability finding."""
    id: str
    title: str
    target: str
    severity: str       # Critical | High | Medium | Low | Informational
    cvss_score: float
    cvss_vector: str
    cwe: str            # e.g. CWE-79
    owasp: str          # e.g. A03:2021
    component: str
    description: str
    steps_to_reproduce: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence_files: List[str] = field(default_factory=list)
    poc_file: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    phase: str = ""     # phase3_web | phase3_api | phase3_ai | phase3_binary

    def to_dict(self) -> dict:
        return asdict(self)

    def to_memory_observation(self) -> dict:
        """Format for mcp__memory__add_observations."""
        return {
            "entityName": self.target,
            "contents": [
                f"FINDING [{self.severity}] {self.title}",
                f"CWE: {self.cwe} | OWASP: {self.owasp}",
                f"CVSS: {self.cvss_score} ({self.cvss_vector})",
                f"Impact: {self.impact}",
                f"PoC: {self.poc_file}" if self.poc_file else "PoC: pending",
            ],
        }

    def to_report_section(self) -> str:
        """Render finding as markdown section."""
        lines = [
            f"## [{self.severity}] {self.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | {self.severity} (CVSS {self.cvss_score}) |",
            f"| **CVSS Vector** | `{self.cvss_vector}` |",
            f"| **CWE** | {self.cwe} |",
            f"| **OWASP** | {self.owasp} |",
            f"| **Component** | {self.component} |",
            f"| **Discovered** | {self.discovered_at[:10]} |",
            "",
            "### Description",
            "",
            self.description,
            "",
            "### Steps to Reproduce",
            "",
        ]
        for i, step in enumerate(self.steps_to_reproduce, 1):
            lines.append(f"{i}. {step}")
        lines += [
            "",
            "### Impact",
            "",
            self.impact,
            "",
            "### Remediation",
            "",
            self.remediation,
            "",
        ]
        if self.references:
            lines.append("### References")
            lines.append("")
            for ref in self.references:
                lines.append(f"- {ref}")
            lines.append("")
        if self.evidence_files:
            lines.append("### Evidence")
            lines.append("")
            for ev in self.evidence_files:
                lines.append(f"- `{ev}`")
            lines.append("")
        return "\n".join(lines)
