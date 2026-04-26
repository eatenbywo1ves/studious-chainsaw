# Claude Code Agents - Quick Reference Card

**Updated:** October 29, 2025

---

## 🚀 Quick Access

| Need | Use This Agent | Command Example |
|------|----------------|-----------------|
| **TypeScript Help** | `typescript-pro` | Use typescript-pro agent to optimize my types |
| **Python Code** | `python-pro` | Use python-pro agent to refactor this code |
| **Security Audit** | `security-auditor` | Use security-auditor agent to review security |
| **API Design** | `backend-architect` | Use backend-architect agent to design REST API |
| **Database Schema** | `database-architect` | Use database-architect agent to design schema |
| **Frontend UI** | `frontend-developer` | Use frontend-developer agent to build component |
| **Testing** | `test-engineer` | Use test-engineer agent to write tests |
| **Bug Fixing** | `debugger` | Use debugger agent to diagnose this error |
| **Code Review** | `code-reviewer` | Use code-reviewer agent to review my PR |
| **Documentation** | `api-documenter` | Use api-documenter agent to generate API docs |
| **Performance** | `performance-engineer` | Use performance-engineer agent to optimize |
| **DevOps/CI/CD** | `deployment-engineer` | Use deployment-engineer agent to setup pipeline |

---

## 📋 All Available Agents

### Programming Languages
- `typescript-pro` - Advanced TypeScript (Sonnet)
- `python-pro` - Python expert (Sonnet)
- `javascript-pro` - Modern JavaScript (Sonnet)
- `golang-pro` - Go programming (Sonnet)
- `rust-pro` - Rust systems programming (Sonnet)

### Development Team
- `backend-architect` - Backend system design (Opus)
- `frontend-developer` - Frontend development (Sonnet)
- `fullstack-developer` - Full-stack development (Sonnet)

### DevOps & Infrastructure
- `deployment-engineer` - CI/CD automation (Sonnet)
- `cloud-architect` - Cloud architecture (Opus)
- `monitoring-specialist` - System monitoring (Sonnet)

### Security
- `security-auditor` - Security audit (Opus)
- `penetration-tester` - Penetration testing (Opus)
- `compliance-specialist` - Compliance & regulatory (Opus)

### Database
- `database-architect` - Database design (Opus)
- `database-optimizer` - Performance tuning (Sonnet)
- `supabase-schema-architect` - Supabase specialist (Sonnet)

### Testing & QA
- `test-engineer` - Test automation (Sonnet)
- `debugger` - Debugging specialist (Sonnet)
- `code-reviewer` - Code review expert (Sonnet)

### Performance
- `performance-engineer` - Performance optimization (Sonnet)
- `web-vitals-optimizer` - Web performance (Sonnet)

### AI & Prompts
- `ai-engineer` - LLM/RAG systems (Opus)
- `prompt-engineer` - Prompt optimization (Opus)

### Documentation
- `api-documenter` - API documentation (Sonnet)
- `technical-writer` - Technical writing (Sonnet)

---

## 💡 Common Workflows

### Full-Stack Feature
```
1. backend-architect → Design API
2. database-architect → Design schema
3. frontend-developer → Build UI
4. test-engineer → Write tests
5. security-auditor → Security review
6. code-reviewer → Final review
```

### Security Audit
```
1. security-auditor → Initial audit
2. penetration-tester → Vulnerability testing
3. compliance-specialist → Compliance check
4. code-reviewer → Code review
```

### Performance Optimization
```
1. performance-engineer → Profile and analyze
2. database-optimizer → Optimize queries
3. web-vitals-optimizer → Optimize frontend
4. code-reviewer → Review changes
```

---

## 🔧 Usage Patterns

### Pattern 1: Single Agent
```
"Use the typescript-pro agent to optimize my TypeScript types for better type inference"
```

### Pattern 2: Sequential Agents
```
"Use the backend-architect agent to design the API, then use the database-architect agent to design the schema"
```

### Pattern 3: Multi-Agent Workflow
```
"Use the following agents in sequence:
1. backend-architect for API design
2. database-architect for schema design
3. security-auditor for security review
4. test-engineer for test coverage"
```

---

## 📁 File Locations

| Resource | Location |
|----------|----------|
| **Agents** | `.claude/agents/` |
| **Commands** | `.claude/commands/` |
| **Main Guide** | `CLAUDE_CODE_PLUGIN_SYSTEM_GUIDE.md` |
| **Status Report** | `DEPLOYED_PLUGINS_STATUS_REPORT.md` |
| **Automation** | `.claude/plugin-deployment-automation.sh` |

---

## 🎯 Agent Selection Tips

### Choose Based On:
1. **Task Complexity** - Opus for complex architecture, Sonnet for implementation
2. **Expertise Needed** - Specialized agents for specific domains
3. **Workflow Stage** - Design → Implementation → Testing → Review

### Model Selection:
- **Opus** - Architecture, security, complex design decisions
- **Sonnet** - Implementation, optimization, testing, documentation

---

## ⚡ Quick Commands

```bash
# List all installed agents
ls -1 .claude/agents/*.md | sed 's/.*\///' | sed 's/\.md//'

# Check agent count
ls -la .claude/agents/*.md | wc -l

# View agent details
cat .claude/agents/typescript-pro.md

# Run automation script
./.claude/plugin-deployment-automation.sh verify
```

---

## 🔍 Troubleshooting

| Issue | Solution |
|-------|----------|
| Agent not found | Check spelling and use full category/name path |
| Wrong model used | Agents specify their model in YAML frontmatter |
| Agent not responding | Verify agent file exists in `.claude/agents/` |
| Multiple agents conflict | Use sequential workflow instead of parallel |

---

## 📞 Getting Help

1. **Check Agent Definition**: `cat .claude/agents/<agent-name>.md`
2. **Review Main Guide**: `CLAUDE_CODE_PLUGIN_SYSTEM_GUIDE.md`
3. **Check Status Report**: `DEPLOYED_PLUGINS_STATUS_REPORT.md`
4. **Run Verification**: `./.claude/plugin-deployment-automation.sh verify`

---

**Last Updated:** October 29, 2025
**Total Agents:** 25+
**System Status:** 🟢 Operational
