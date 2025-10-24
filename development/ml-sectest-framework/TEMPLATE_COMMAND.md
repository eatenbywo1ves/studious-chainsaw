# Template: Claude Code Slash Command

**Location:** `.claude/commands/<command-name>.md`

**Purpose:** Define a user-invocable workflow using slash command syntax

---

## Template

```markdown
You are [performing task description].

**[Input Label]:** $ARGUMENTS

## [Task Name] Workflow

1. **[Step 1 Name]**

   [Description]

   ```bash
   [command or code]
   ```

2. **[Step 2 Name]**

   [Description]

   ```bash
   [command or code]
   ```

3. **[Step 3 Name]**

   [Description]

4. **[Final Step Name]**

   Format as:
   ```
   [Expected output format]

   [Example output structure]
   ```

## Notes

- [Important note 1]
- [Important note 2]
- [Skills to use: skill-name]
- [Agents to invoke: agent-name]
```

---

## Field Guide

### Command Name (Filename)

- Filename: `<command-name>.md` (lowercase with hyphens)
- Invoked as: `/command-name`
- Examples:
  - `scan-target.md` → `/scan-target`
  - `test-challenge.md` → `/test-challenge`
  - `generate-report.md` → `/generate-report`

### First Line (Task Description)

Start with: "You are [doing something]..."

Examples:
- "You are performing a comprehensive security assessment..."
- "You are testing an ML CTF challenge..."
- "You are generating a professional security report..."

This sets the context for Claude.

### $ARGUMENTS Placeholder

- Represents user input after the command
- Format: `/command-name <arguments>`
- Examples:
  - `/scan-target http://localhost:8000` → `$ARGUMENTS = "http://localhost:8000"`
  - `/test-challenge vault` → `$ARGUMENTS = "vault"`

Reference it in your workflow:
```markdown
**Target URL:** $ARGUMENTS

python ml_sectest.py scan $ARGUMENTS
```

### Workflow Section

Break down the task into clear steps:

1. **Numbered steps** for sequential workflows
2. **Code blocks** for commands to execute
3. **Descriptions** explaining what each step does

### Output Format

Always specify expected output format:

```markdown
Format as:
```
🔍 [Title]

[Summary statistics]

[Detailed findings]

[Recommendations]
```
```

This ensures consistent, professional output.

### Notes Section

Include:
- Which skills to use
- Which agents to invoke
- Important considerations
- Edge cases to handle

---

## Command Patterns

### Pattern 1: Scan/Test Target

```markdown
You are performing [type] testing.

**Target:** $ARGUMENTS

## Workflow

1. **Initialize**
   ```bash
   cd development/ml-sectest-framework
   ```

2. **Execute Scan**
   ```bash
   python ml_sectest.py scan $ARGUMENTS [flags]
   ```

3. **Analyze Results**
   [Analysis steps]

4. **Present Findings**
   [Output format]

## Notes
- Use vulnerability-scanning skill
- Invoke appropriate agents automatically
```

### Pattern 2: Process File/Data

```markdown
You are processing [data type].

**Input File:** $ARGUMENTS

## Workflow

1. **Validate Input**
   ```bash
   file $ARGUMENTS
   head $ARGUMENTS
   ```

2. **Process Data**
   [Processing steps]

3. **Generate Output**
   [Output steps]

## Notes
- Support CSV, JSON, TXT formats
- Validate before processing
```

### Pattern 3: Generate Report

```markdown
You are generating [report type].

**Source:** $ARGUMENTS

## Workflow

1. **Load Data**
   ```bash
   cat $ARGUMENTS
   ```

2. **Parse Results**
   [Parsing steps]

3. **Generate Report**
   [Report generation]

4. **Save Output**
   ```bash
   [Save command]
   ```

## Notes
- Use security-reporting skill
- Support HTML and JSON formats
```

### Pattern 4: Coordinate Multi-Step Attack

```markdown
You are coordinating [attack type].

**Configuration:** $ARGUMENTS

## Workflow

1. **Load Configuration**
   [Config loading]

2. **Execute Stages**
   Stage 1: [Description]
   Stage 2: [Description]
   Stage 3: [Description]

3. **Analyze Results**
   [Analysis]

4. **Report Findings**
   [Reporting]

## Notes
- Use game-theoretic-optimization skill
- Invoke edward-teller agent for fusion chains
```

---

## Example: Filled Template

```markdown
You are performing a comprehensive security assessment using the ML-SecTest framework.

**Target URL:** $ARGUMENTS

## Assessment Workflow

1. **Initialize Framework**
   ```bash
   cd development/ml-sectest-framework
   ```

2. **Run Security Scan**
   ```bash
   python ml_sectest.py scan $ARGUMENTS --parallel --format both
   ```

3. **Analyze Results**
   - Load generated reports from `reports/`
   - Summarize findings by severity
   - Map vulnerabilities to OWASP/MITRE

4. **Present Findings**

   Format as:
   ```
   🔍 Security Assessment Complete

   Target: $ARGUMENTS
   Duration: X.X seconds

   Findings:
     🔴 CRITICAL: X vulnerabilities
     🟠 HIGH: X vulnerabilities
     🟡 MEDIUM: X vulnerabilities
     🟢 LOW: X vulnerabilities

   Critical Issues:
     1. [Type] (OWASP/MITRE) - Description

   Recommendations:
     - Prioritized steps

   Full Report: reports/scan_TIMESTAMP.html
   ```

## Notes

- Use vulnerability-scanning skill for payload generation
- Use security-reporting skill for final report
- Use game-theoretic-optimization if multiple agents needed
```

---

## Advanced: Dynamic Arguments

For multiple arguments, use clear labels:

```markdown
**Target:** First word of $ARGUMENTS
**Options:** Remaining words of $ARGUMENTS

Parse arguments:
```bash
TARGET=$(echo "$ARGUMENTS" | awk '{print $1}')
OPTIONS=$(echo "$ARGUMENTS" | awk '{$1=""; print $0}')
```
```

Or use named arguments in usage:

```bash
# Usage: /scan-target <url> [--parallel] [--format json]
claude /scan-target http://localhost:8000 --parallel --format json
```

---

## Checklist

Before committing your command:

- [ ] Filename is lowercase-with-hyphens.md
- [ ] First line sets task context ("You are...")
- [ ] $ARGUMENTS placeholder used appropriately
- [ ] Workflow broken into clear numbered steps
- [ ] Code blocks show exact commands to run
- [ ] Output format specified explicitly
- [ ] Notes section references skills/agents to use
- [ ] Example usage documented

---

## Testing Your Command

1. **Save command**: `.claude/commands/my-command.md`

2. **Test invocation**:
   ```bash
   claude /my-command test-argument
   ```

3. **Verify**:
   - Claude follows workflow steps
   - Output matches specified format
   - Skills/agents invoked correctly

4. **Iterate**:
   - Refine based on results
   - Add edge case handling
   - Improve output formatting

---

## Tips for Great Commands

1. **Be specific**: Clear, numbered steps
2. **Show commands**: Exact bash/Python to run
3. **Format output**: Specify structure explicitly
4. **Handle errors**: Note edge cases in Notes section
5. **Reference skills**: Leverage existing skills/agents
6. **Test thoroughly**: Try with various inputs

---

**Template Version:** 1.0
**Last Updated:** 2025-10-21
