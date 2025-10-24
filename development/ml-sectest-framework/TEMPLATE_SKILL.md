# Template: Claude Code Skill Definition

**Location:** `.claude/skills/<skill-name>/SKILL.md`

**Purpose:** Define a reusable capability that Claude can invoke when needed

---

## Template

```markdown
---
name: [skill-identifier-lowercase]
description: [Detailed description of what this skill provides, when to use it, and key capabilities. Include specific use cases and trigger keywords.]
allowed-tools:
  - Read
  - Write
  # Add only tools this skill needs
---

# [Skill Display Name] Skill

## Purpose

[1-2 sentences describing what this skill provides]

## Capabilities

### 1. [Capability Name]

[Description of first capability]

Example:
```[language]
[Code example or usage]
```

### 2. [Capability Name]

[Description of second capability]

### 3. [Capability Name]

[Description of third capability]

## Usage

This skill is automatically invoked when:

- [Trigger condition 1]
- [Trigger condition 2]
- [Trigger condition 3]

## Integration with Python Implementation

[How this skill wraps/uses the Python code]

Example:
```bash
cd development/ml-sectest-framework
[command to invoke underlying functionality]
```

Or:
```python
from [module] import [Class]

[usage example]
```

## Example Workflow

```bash
# User request
claude "[example request that triggers this skill]"

# Behind the scenes:
# 1. [Step 1]
# 2. [Step 2]
# 3. [Step 3]
```

## Templates

Supporting templates in `templates/`:

- `[template1].json`: [Description]
- `[template2].html`: [Description]
```

---

## Field Guide

### name
- Lowercase with hyphens (slug format)
- Should be concise but descriptive
- Examples: "vulnerability-scanning", "report-generation", "payload-crafting"

### description
- **Critical for automatic invocation!**
- Claude reads this to decide when to use the skill
- Include:
  - What it provides
  - When to use it
  - Key capabilities
  - Trigger keywords
- **Be very specific** about use cases

### allowed-tools
- Minimum tools needed
- Skills typically need fewer tools than agents
- Common combinations:
  - Read-only: `[Read]`
  - Report generation: `[Read, Write]`
  - Execution: `[Read, Bash]`

### Capabilities Section
- Break down into 3-5 discrete capabilities
- Show concrete examples for each
- Code snippets help understanding

### Usage Section
- **Critical:** List trigger conditions
- These are the phrases/scenarios that cause Claude to invoke this skill
- Examples:
  - "when testing ML applications for security"
  - "when generating reports"
  - "when user mentions payloads or test cases"

### Integration Section
- Show how skill wraps Python code
- Provide runnable examples
- Don't duplicate logic, just reference it

---

## Skill vs Agent vs Command

| Aspect | Skill | Agent | Command |
|--------|-------|-------|---------|
| Invocation | Automatic (Claude decides) | Automatic (Claude delegates) | Manual (/command) |
| Scope | Reusable capability | Specialized task | User workflow |
| Delegation | No (skill is used) | Yes (agent is invoked) | No (command is followed) |
| Tools | Limited subset | Full toolset | Varies by command |

**Example:**
- **Skill**: "vulnerability-scanning" (provides scanning capability)
- **Agent**: "prompt-injection" (tests for specific vulnerability)
- **Command**: "/scan-target" (user-initiated workflow)

An **agent** might use a **skill** to accomplish its task, and a **command** might invoke an **agent** that uses a **skill**.

---

## Example: Filled Template

See `.claude/skills/vulnerability-scanning/SKILL.md` in the migration guide for a complete example.

---

## Supporting Files

Skills can have supporting files in their directory:

```
.claude/skills/my-skill/
├── SKILL.md              # Required: Skill definition
├── templates/            # Optional: Templates
│   ├── template1.json
│   └── template2.html
├── configs/              # Optional: Configurations
│   └── defaults.yaml
└── data/                 # Optional: Reference data
    └── patterns.json
```

Reference these in your SKILL.md:

```markdown
## Templates

Supporting templates in `templates/`:

- `report-template.html`: HTML report structure
- `finding-schema.json`: JSON schema for findings
```

---

## Checklist

Before committing your skill definition:

- [ ] YAML frontmatter is valid
- [ ] Name is lowercase-with-hyphens
- [ ] Description includes specific use cases and trigger keywords
- [ ] allowed-tools includes only what's needed
- [ ] Capabilities section breaks down 3-5 discrete functions
- [ ] Usage section lists clear trigger conditions
- [ ] Integration section references Python implementation
- [ ] Example workflow shows concrete usage
- [ ] Supporting files created (if applicable)

---

## Tips for Great Skills

1. **Make skills focused**: One skill = one cohesive capability
2. **Be trigger-rich**: Include many synonyms and use cases in description
3. **Show examples**: Concrete examples > abstract descriptions
4. **Reference, don't duplicate**: Point to Python code, don't recreate it
5. **Think reusability**: Skills should be useful across multiple agents

---

**Template Version:** 1.0
**Last Updated:** 2025-10-21
