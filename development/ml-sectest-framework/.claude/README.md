# Claude Code Integration

This directory contains Claude Code-compatible definitions for the ML-SecTest framework.

## Structure

- **agents/**: Specialized security testing agents (Markdown definitions)
- **skills/**: Reusable capabilities for vulnerability analysis
- **commands/**: Custom slash commands for common workflows

## Usage

### Natural Language Invocation

Instead of CLI commands, you can use natural language:

```
"Scan localhost:8000 for prompt injection vulnerabilities"
"Test the Vault challenge"
"Run a fusion attack using the Trinity chain"
```

### Slash Commands

Quick access to common workflows:

```
/scan-target http://localhost:8000
/test-challenge vault
/batch-scan targets.csv
```

### Agents

Agents automatically delegate specialized tasks:

- **prompt-injection**: Tests for LLM prompt injection (OWASP LLM01)
- **model-inversion**: Tests for training data extraction (OWASP ML03)
- **edward-teller**: Multi-stage fusion attack coordinator

## Integration with Python Code

All `.claude/` definitions wrap the existing Python implementation in `agents/`, `core/`, and `utils/`. The Python code remains the authoritative implementation.

## Testing

Test agent invocation:
```bash
claude "Use the prompt injection agent to scan localhost:8000"
```

Test skill usage:
```bash
claude "Generate a security report from latest scan results"
```

Test commands:
```bash
claude /scan-target http://localhost:8000
```

## Documentation

See the parent directory for:
- `CLAUDE_CODE_MIGRATION_GUIDE.md` - Complete migration documentation
- `MIGRATION_QUICK_START.md` - 30-minute quick start guide
- `TEMPLATE_AGENT.md` - Template for creating new agents
- `TEMPLATE_SKILL.md` - Template for creating new skills
- `TEMPLATE_COMMAND.md` - Template for creating new commands
