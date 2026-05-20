# Template: Claude Code Agent Definition

**Location:** `.claude/agents/<agent-name>/AGENT.md`

**Purpose:** Define a specialized security testing agent for Claude Code integration

---

## Template

```markdown
---
name: [Agent Display Name]
description: [Detailed description of what this agent tests, OWASP/MITRE coverage, and when to use it. Be specific about capabilities and use cases.]
allowed-tools:
  - Bash
  - Read
  - Write
  # Add only tools this agent needs
---

# [Agent Name] Security Agent

## Purpose

[1-2 sentences describing the agent's purpose]

## OWASP/MITRE Coverage

- **OWASP [Reference]**: [Description]
- **MITRE [Reference]**: [Description]
- **Related**: [Other standards]

## Testing Methodology

### Phase 1: Analysis (Passive)

[Describe passive testing approach]

1. **Test Category 1**
   ```
   [Example test or payload]
   ```

2. **Test Category 2**
   ```
   [Example test or payload]
   ```

### Phase 2: Exploitation (Active Validation)

If vulnerability detected:

1. [Validation step 1]
2. [Validation step 2]
3. [Evidence collection]

### Phase 3: Reporting

Generate findings with:
- Vulnerable endpoints
- Successful payloads
- Evidence (request/response pairs)
- Severity assessment
- Remediation recommendations

## CTF Challenge Mapping

- **[Challenge Name]**: [Attack type]

## Integration with Python Implementation

This agent wraps the Python implementation:

```bash
cd development/ml-sectest-framework
python -c "
from agents import [PythonAgentClass]
from core.base_agent import AgentContext

agent = [PythonAgentClass]()
context = AgentContext(
    target_url='<target>',
    challenge_name='[Test Name]',
    difficulty_level='[Easy/Medium/Hard]',
    owasp_reference='[OWASP Reference]'
)

results = agent.execute(context)
for result in results:
    print(f'{result.status}: {result.vulnerability_type}')
"
```

## Example Output

```
🔍 [Agent Name] - Test Results

Target: http://localhost:8000
Tests Performed: X
Vulnerabilities Found: Y

Critical Findings:
  1. [Finding Type] - CONFIRMED
     Payload: "[payload]"
     Response: "[response]"
     Severity: [CRITICAL/HIGH/MEDIUM/LOW]

Recommendations:
  - [Recommendation 1]
  - [Recommendation 2]

OWASP Reference: [URL]
MITRE ATLAS: [URL]
```

## Usage

### Natural Language Invocation

```bash
claude "Test [target] for [vulnerability type]"
claude "Use the [agent name] on [target]"
```

### Slash Command

```bash
claude /scan-target [target]
# (Will automatically invoke this agent for appropriate targets)
```

### Direct Python

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan [target] --agents [agent_id]
```

## Notes

- **Non-destructive testing**: Payloads designed to prove vulnerability without harm
- **Timeout protection**: [X]-second timeout per request
- **Rate limiting**: Respects target rate limits automatically
- **Evidence collection**: Full request/response pairs captured
```

---

## Field Guide

### name
- Display name shown to user
- Should be descriptive and professional
- Example: "Prompt Injection Tester", "Edward Teller (Fusion Chain Coordinator)"

### description
- **Critical for discoverability!**
- Claude uses this to decide when to invoke the agent
- Include:
  - What it tests
  - OWASP/MITRE references
  - When to use it
  - Key capabilities
- **Be specific** (not "helps with security" but "Tests for LLM prompt injection vulnerabilities...")

### allowed-tools
- Minimum tools needed for this agent
- Common tools:
  - `Bash`: Run Python scripts, execute commands
  - `Read`: Read files (payloads, configs)
  - `Write`: Write reports, evidence
  - `Task`: Spawn other agents (for coordinators only)

### Integration Section
- **Always reference Python implementation**
- Never duplicate Python logic in Markdown
- Show how to invoke the underlying Python code

### Example Output
- Show realistic output format
- Include severity indicators (🔴🟠🟡🟢)
- Reference OWASP/MITRE standards

---

## Example: Filled Template

See `.claude/agents/prompt-injection/AGENT.md` in the migration guide for a complete example.

---

## Checklist

Before committing your agent definition:

- [ ] YAML frontmatter is valid
- [ ] Description is specific and detailed (2-3 sentences minimum)
- [ ] allowed-tools includes only what's needed
- [ ] OWASP/MITRE references documented
- [ ] Integration section references Python implementation
- [ ] Example output shows realistic findings
- [ ] Usage examples include natural language, slash commands, and Python CLI
- [ ] Notes section covers safety and ethics

---

**Template Version:** 1.0
**Last Updated:** 2025-10-21
