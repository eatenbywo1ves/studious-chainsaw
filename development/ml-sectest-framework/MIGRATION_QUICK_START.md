# Claude Code Migration - Quick Start

**Time Required:** 30 minutes for basic setup

This is a condensed version of the full migration guide. For complete details, see `CLAUDE_CODE_MIGRATION_GUIDE.md`.

---

## Quick Setup (30 Minutes)

### Step 1: Create Directory Structure (5 minutes)

```bash
cd development/ml-sectest-framework

# Create .claude/ structure
mkdir -p .claude/agents
mkdir -p .claude/skills
mkdir -p .claude/commands
```

### Step 2: Add Your First Skill (10 minutes)

Create `.claude/skills/vulnerability-scanning/SKILL.md`:

```markdown
---
name: vulnerability-scanning
description: Core vulnerability scanning for ML/AI systems. Tests for OWASP Top 10 ML/LLM vulnerabilities including prompt injection, model inversion, data poisoning, and more. Use when testing ML applications for security issues.
allowed-tools:
  - Read
  - Bash
  - Write
---

# Vulnerability Scanning Skill

Provides automated security testing capabilities for ML/AI applications.

## Usage

This skill wraps the ML-SecTest Python framework:

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan <target> --parallel --format both
```

## Coverage

- Prompt Injection (OWASP LLM01)
- Model Inversion (OWASP ML03)
- Data Poisoning (OWASP ML02)
- Model Extraction (OWASP LLM10)
- Serialization Exploits (OWASP LLM05)
- Adversarial Attacks
```

### Step 3: Add Your First Command (10 minutes)

Create `.claude/commands/scan-target.md`:

```markdown
You are performing a security assessment using ML-SecTest.

**Target:** $ARGUMENTS

## Workflow

1. Run scan:
   ```bash
   cd development/ml-sectest-framework
   python ml_sectest.py scan $ARGUMENTS --parallel --format both
   ```

2. Show results summary

3. Provide recommendations

## Output Format

```
🔍 Security Assessment

Target: $ARGUMENTS
Findings:
  🔴 CRITICAL: X
  🟠 HIGH: X
  🟡 MEDIUM: X

[Details...]
```
```

### Step 4: Add Your First Agent (5 minutes)

Create `.claude/agents/prompt-injection/AGENT.md`:

```markdown
---
name: Prompt Injection Tester
description: Tests for LLM prompt injection vulnerabilities (OWASP LLM01). Use when scanning LLM applications.
allowed-tools:
  - Bash
  - Read
---

# Prompt Injection Agent

Tests LLM applications for instruction override vulnerabilities.

## Usage

```bash
cd development/ml-sectest-framework
python ml_sectest.py scan <target> --agents prompt_injection_001
```

## OWASP Coverage

- OWASP LLM01: Prompt Injection
- MITRE AML.T0051: LLM Prompt Injection
```

### Step 5: Test It! (5 minutes)

```bash
# Test slash command
claude /scan-target http://localhost:8000

# Test natural language
claude "Test localhost:8000 for security vulnerabilities"

# Test agent invocation
claude "Use the prompt injection tester on localhost:8000"
```

---

## What You Get

✅ Natural language security scanning
✅ Custom slash commands
✅ Auto-discovered agents and skills
✅ 100% backward compatibility with Python CLI

## Full Python CLI Still Works

```bash
# All existing commands work exactly as before
python ml_sectest.py scan http://localhost:8000
python ml_sectest.py test-challenge vault
python ml_sectest.py batch-scan --input targets.csv
```

---

## Next Steps

1. Read full guide: `CLAUDE_CODE_MIGRATION_GUIDE.md`
2. Add more skills from Phase 2
3. Add more commands from Phase 3
4. Convert remaining agents from Phase 4

## Rollback

If needed, simply:
```bash
git rm -rf .claude/
```

No Python code is modified, so rollback is instant.

---

**Total Time:** 30 minutes for basic setup, 6-10 hours for full migration
