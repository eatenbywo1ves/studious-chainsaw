"""
Phase 5 — Report Generation
=============================
Aggregates all findings from the findings/ directory and produces:
  - Executive summary (1 page)
  - Technical findings (per finding: severity, repro, impact, fix)
  - Evidence appendix
  - HackerOne/Bugcrowd submission template per finding

Agents used:
  - security-auditor     → CVSS review, OWASP mapping, remediation
  - compliance-specialist → CWE IDs, regulatory impact
  - technical-writer     → executive summary + submission copy
"""

import json
from pathlib import Path
from datetime import datetime

from config.severity import severity_label


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Informational": "⚪",
}


def run_report_generation(target: str, output_dir: Path) -> None:
    report_dir = output_dir / "reports"
    report_dir.mkdir(exist_ok=True)

    print(f"\n[PHASE 5] Report Generation — {target}")
    print("=" * 60)

    # Load scope
    scope = _load_scope(output_dir)

    # Load all findings
    findings = _load_findings(output_dir)
    if not findings:
        print("[WARN] No findings found. Run phases 3/4 first.")
        print(f"       Expected findings in: {output_dir}/findings/")
        return

    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Informational"), 99))

    print(f"\n  Loaded {len(findings)} finding(s):")
    for f in findings_sorted:
        sev = f.get("severity", "Unknown")
        print(f"    [{sev:14s}] {f.get('title', f.get('id'))}")

    # 1. Full technical report (Markdown)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_md = _generate_full_report(target, scope, findings_sorted)
    report_file = report_dir / f"security_report_{timestamp}.md"
    report_file.write_text(report_md)
    print(f"\n[OK] Full report     → {report_file}")

    # 2. Executive summary
    exec_summary = _generate_executive_summary(target, scope, findings_sorted)
    exec_file = report_dir / f"executive_summary_{timestamp}.md"
    exec_file.write_text(exec_summary)
    print(f"[OK] Exec summary    → {exec_file}")

    # 3. Per-finding HackerOne/Bugcrowd submission templates
    submissions_dir = report_dir / "submissions"
    submissions_dir.mkdir(exist_ok=True)
    for finding in findings_sorted:
        sub = _generate_submission_template(finding, scope)
        sub_file = submissions_dir / f"{finding.get('id', 'unknown')}_submission.md"
        sub_file.write_text(sub)
    print(f"[OK] Submissions     → {submissions_dir}/ ({len(findings_sorted)} files)")

    # 4. JSON summary for programmatic use
    summary_json = _generate_summary_json(target, scope, findings_sorted)
    json_file = report_dir / f"findings_summary_{timestamp}.json"
    json_file.write_text(json.dumps(summary_json, indent=2))
    print(f"[OK] JSON summary    → {json_file}")

    # 5. Agent prompts for report polishing
    agent_prompts = _generate_report_agent_prompts(target, findings_sorted, report_file)
    agent_file = report_dir / "report_agent_prompts.md"
    agent_file.write_text(agent_prompts)
    print(f"[OK] Agent prompts   → {agent_file}")

    _print_summary(findings_sorted, report_dir)


def _load_scope(output_dir: Path) -> dict:
    scope_file = output_dir / "scope.json"
    if scope_file.exists():
        return json.loads(scope_file.read_text())
    return {"target": str(output_dir.name), "program": "Unknown", "auth_type": "unknown"}


def _load_findings(output_dir: Path) -> list[dict]:
    findings_dir = output_dir / "findings"
    if not findings_dir.exists():
        return []
    findings = []
    for f in findings_dir.glob("*.json"):
        try:
            findings.append(json.loads(f.read_text()))
        except Exception:
            pass
    return findings


def _generate_full_report(target: str, scope: dict, findings: list[dict]) -> str:
    critical = [f for f in findings if f.get("severity") == "Critical"]
    high = [f for f in findings if f.get("severity") == "High"]
    medium = [f for f in findings if f.get("severity") == "Medium"]
    low = [f for f in findings if f.get("severity") == "Low"]
    info = [f for f in findings if f.get("severity") == "Informational"]

    lines = [
        f"# Security Assessment Report",
        f"",
        f"**Target:** {target}",
        f"**Program:** {scope.get('program', 'N/A')}",
        f"**Authorization:** {scope.get('auth_type', 'N/A')}",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}",
        f"**Total Findings:** {len(findings)}",
        f"",
        "---",
        "",
        "## Risk Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {len(critical)} |",
        f"| 🟠 High | {len(high)} |",
        f"| 🟡 Medium | {len(medium)} |",
        f"| 🔵 Low | {len(low)} |",
        f"| ⚪ Informational | {len(info)} |",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    for finding in findings:
        lines.append(_render_finding(finding))
        lines.append("---")
        lines.append("")

    lines += [
        "## Evidence Appendix",
        "",
        "Screenshots and request/response logs are stored in the `output/` directory:",
        "",
    ]
    for finding in findings:
        fid = finding.get("id", "unknown")
        lines.append(f"- **{finding.get('title')}** → `output/exploits/{fid}/`")

    lines += [
        "",
        "---",
        "",
        "## Methodology",
        "",
        "This assessment followed a structured bug bounty methodology:",
        "",
        "1. **Phase 1 — Recon:** Passive OSINT, tech fingerprinting, CVE research",
        "2. **Phase 2 — Surface Mapping:** Endpoint enumeration, auth boundary identification",
        "3. **Phase 3 — Testing:** OWASP Top 10, API security, AI/ML, binary analysis",
        "4. **Phase 4 — Exploitation:** PoC development, impact validation",
        "5. **Phase 5 — Reporting:** CVSS scoring, CWE mapping, remediation guidance",
        "",
        "All testing was conducted within the authorized scope.",
        "",
        "---",
        "",
        f"*Report generated: {datetime.utcnow().isoformat()}*",
    ]

    return "\n".join(lines)


def _render_finding(finding: dict) -> str:
    sev = finding.get("severity", "Unknown")
    emoji = SEVERITY_EMOJI.get(sev, "⚫")
    lines = [
        f"## {emoji} [{sev}] {finding.get('title', 'Untitled')}",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Severity** | {sev} |",
        f"| **CVSS Score** | {finding.get('cvss_score', 'N/A')} |",
        f"| **CVSS Vector** | `{finding.get('cvss_vector', 'N/A')}` |",
        f"| **CWE** | [{finding.get('cwe', 'N/A')}](https://cwe.mitre.org/data/definitions/{finding.get('cwe','0').replace('CWE-','')}.html) |",
        f"| **OWASP** | {finding.get('owasp', 'N/A')} |",
        f"| **Component** | `{finding.get('component', 'N/A')}` |",
        f"| **Discovered** | {finding.get('discovered_at', 'N/A')[:10]} |",
        "",
        "### Description",
        "",
        finding.get("description", "_No description provided._"),
        "",
        "### Steps to Reproduce",
        "",
    ]
    for i, step in enumerate(finding.get("steps_to_reproduce", []), 1):
        lines.append(f"{i}. {step}")
    lines += [
        "",
        "### Impact",
        "",
        finding.get("impact", "_No impact statement provided._"),
        "",
        "### Remediation",
        "",
        finding.get("remediation", "_No remediation provided._"),
        "",
    ]
    refs = finding.get("references", [])
    if refs:
        lines += ["### References", ""]
        for ref in refs:
            lines.append(f"- {ref}")
        lines.append("")
    poc = finding.get("poc_file", "")
    if poc:
        lines += [f"### PoC", f"", f"`{poc}`", ""]
    return "\n".join(lines)


def _generate_executive_summary(target: str, scope: dict, findings: list[dict]) -> str:
    critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    has_critical = critical_count > 0
    has_high = high_count > 0

    risk_level = "Critical" if has_critical else "High" if has_high else "Medium" if findings else "Low"

    top_findings = findings[:3]

    return f"""# Executive Summary

**Target:** {target}
**Program:** {scope.get('program', 'N/A')}
**Assessment Date:** {datetime.utcnow().strftime('%Y-%m-%d')}
**Overall Risk:** **{risk_level}**

---

## Overview

A security assessment of **{target}** identified **{len(findings)} vulnerability(ies)**,
including {critical_count} Critical and {high_count} High severity issues.

{'**Immediate remediation is required for critical findings.**' if has_critical else ''}

## Risk Distribution

| Severity | Count | Action |
|----------|-------|--------|
| Critical | {critical_count} | Immediate fix required |
| High | {high_count} | Fix within 7 days |
| Medium | {sum(1 for f in findings if f.get('severity') == 'Medium')} | Fix within 30 days |
| Low | {sum(1 for f in findings if f.get('severity') == 'Low')} | Fix at next release |
| Informational | {sum(1 for f in findings if f.get('severity') == 'Informational')} | Review recommended |

## Key Findings

{chr(10).join(f"- **[{f.get('severity')}]** {f.get('title')}: {f.get('impact', 'See full report.')[:100]}" for f in top_findings)}

## Business Impact

{_infer_business_impact(findings)}

## Recommended Actions

1. Address all Critical findings immediately before next deployment
2. Schedule High findings for patching within one sprint
3. Implement secure coding training for identified injection vulnerabilities
4. Conduct follow-up assessment after remediation

---
*Full technical details in the accompanying Security Assessment Report.*
"""


def _infer_business_impact(findings: list[dict]) -> str:
    impacts = [f.get("impact", "") for f in findings if f.get("impact")]
    if not impacts:
        return "See individual finding impact statements in the full report."
    return " ".join(impacts[:2])[:400] + ("..." if sum(len(i) for i in impacts[:2]) > 400 else "")


def _generate_submission_template(finding: dict, scope: dict) -> str:
    return f"""# {finding.get('title')} — Submission Template

Platform: {scope.get('program', 'HackerOne / Bugcrowd')}
Finding ID: {finding.get('id')}

---

## Title

{finding.get('title')}

## Severity

{finding.get('severity')} — CVSS {finding.get('cvss_score')} — `{finding.get('cvss_vector')}`

## Weakness Type

{finding.get('cwe')} — {finding.get('cwe_name', '')}

## Asset

{finding.get('component', 'N/A')}

## Description

{finding.get('description', '')}

## Steps to Reproduce

{chr(10).join(f"{i+1}. {s}" for i, s in enumerate(finding.get('steps_to_reproduce', [])))}

## Impact

{finding.get('impact', '')}

## Supporting Material / References

- PoC script: `{finding.get('poc_file', 'See exploits directory')}`
- Screenshots: See evidence appendix
- OWASP: {finding.get('owasp', 'N/A')}
- CWE: {finding.get('cwe', 'N/A')}

## Recommended Fix

{finding.get('remediation', '')}

---

*Discovered: {finding.get('discovered_at', 'N/A')[:10]}*
"""


def _generate_summary_json(target: str, scope: dict, findings: list[dict]) -> dict:
    return {
        "target": target,
        "program": scope.get("program"),
        "auth_type": scope.get("auth_type"),
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "severity_counts": {
            "Critical": sum(1 for f in findings if f.get("severity") == "Critical"),
            "High": sum(1 for f in findings if f.get("severity") == "High"),
            "Medium": sum(1 for f in findings if f.get("severity") == "Medium"),
            "Low": sum(1 for f in findings if f.get("severity") == "Low"),
            "Informational": sum(1 for f in findings if f.get("severity") == "Informational"),
        },
        "findings": [
            {
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cvss_score": f.get("cvss_score"),
                "cwe": f.get("cwe"),
                "owasp": f.get("owasp"),
                "component": f.get("component"),
            }
            for f in findings
        ],
    }


def _generate_report_agent_prompts(target: str, findings: list[dict], report_file: Path) -> str:
    finding_titles = "\n".join(f"- [{f.get('severity')}] {f.get('title')}" for f in findings)
    top5_titles = "\n".join(
        f"[{f.get('severity')}] {f.get('title')}" for f in findings[:5]
    )
    return f"""# Report Agent Prompts — {target}

Use these with the specified agents in Claude Code to polish the report.

---

## 1. security-auditor Agent — CVSS Review

```
Review the following security findings and verify/improve:
1. CVSS v3.1 vector accuracy for each finding
2. OWASP Top 10 2021 mapping
3. CWE assignment
4. Remediation recommendations (with code examples where possible)

Findings:
{finding_titles}

Full report: {report_file}

For each finding, confirm or correct the CVSS vector and provide:
- Precise environmental score justification
- Specific remediation code snippet
- Links to relevant OWASP/NIST guidance
```

---

## 2. compliance-specialist Agent — Regulatory Mapping

```
Map the following security findings to regulatory frameworks:

Findings:
{finding_titles}

For each finding, provide:
- CWE ID confirmation
- Relevant regulatory impact (GDPR, PCI DSS, SOC2, HIPAA as applicable)
- Whether this would constitute a reportable breach
- Priority based on compliance requirements

Target: {target}
```

---

## 3. technical-writer Agent — Executive Summary

```
Review and improve the executive summary for this security report.
The audience is non-technical stakeholders (CISO, executives, legal).

Key requirements:
- Plain English (no jargon)
- Business risk framing (not CVE numbers)
- Clear action items with timeline
- 1 page maximum

Findings to summarize:
{finding_titles}

Current executive summary is in: {report_file.parent}/executive_summary_*.md
```

---

## 4. Memory Graph Update

After agents complete their review:

```python
# Update memory graph with final report location
mcp__memory__add_observations(
  entityName="{target}",
  contents=[
    "REPORT GENERATED: {report_file.name}",
    "Total findings: {len(findings)}",
    "{top5_titles}",
    "Report path: {report_file}"
  ]
)
```
"""


def _print_summary(findings: list[dict], report_dir: Path) -> None:
    print(f"\n[PHASE 5 SUMMARY]")
    print(f"  Total findings  : {len(findings)}")
    by_sev = {}
    for f in findings:
        s = f.get("severity", "Unknown")
        by_sev[s] = by_sev.get(s, 0) + 1
    for sev, count in sorted(by_sev.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99)):
        emoji = SEVERITY_EMOJI.get(sev, "⚫")
        print(f"    {emoji} {sev:14s}: {count}")
    print(f"\n[FILES]")
    for f in sorted(report_dir.iterdir()):
        if f.is_file():
            print(f"  {f}")
    print(f"\n[NEXT] Polish report using report_agent_prompts.md")
    print(f"[NEXT] Submit individual findings from reports/submissions/")
    print(f"[NEXT] Store final report in memory graph (see agent_prompts.md)\n")
