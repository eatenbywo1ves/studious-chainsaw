# Documentation Freeze - Quick Reference Card

**Active:** 2025-10-14 to 2025-10-28 (14 days)

---

## ⚡ Quick Commands

### Daily Workflow
```bash
# Start your day - pick ONE core project
cd development/ml-sectest-framework   # Option 1
cd development/saas                    # Option 2
cd development/GhidraGo                # Option 3
cd projects/platform/mcp-gateway       # Option 4

# Work for minimum 4 hours before switching
```

### Check Freeze Status
```bash
# See if you have any forbidden files
git status | grep -E "(PLAN|STATUS|ANALYSIS|ROADMAP|CLEANUP)"

# Clean up forbidden files (add to gitignore instead of tracking)
git add .gitignore
git status
```

### Using GitHub Instead of Markdown
```bash
# Create an issue instead of a planning doc
gh issue create --title "Feature: Add X" --body "Implementation plan..."

# Create a discussion instead of analysis doc
gh discussion create --title "Analysis: Performance" --body "..."

# Check project board instead of status docs
gh project list
```

---

## 🎯 The 4 Core Projects

| # | Project | Path | Focus This Week |
|---|---------|------|-----------------|
| 1 | **ML Security** | `ml-sectest-framework/` | Fix 3 failing tests, deploy v1.0 |
| 2 | **SaaS Platform** | `saas/` | Build first customer feature |
| 3 | **GhidraGo** | `GhidraGo/` | Bug fixes only (stable release) |
| 4 | **MCP Gateway** | `mcp-gateway/` | Production stability testing |

---

## ❌ Forbidden Actions

**DO NOT:**
- Create files matching: `*PLAN*.md`, `*STATUS*.md`, `*ANALYSIS*.md`, etc.
- Add new root-level `.md` files (except CHANGELOG)
- Start work on archived projects
- Context-switch more than 2x per day

---

## ✅ Allowed Actions

**DO:**
- Update existing `README.md` (1 per project)
- Write code comments and docstrings
- Create GitHub Issues/PRs/Discussions
- Update `CHANGELOG.md` for releases
- Fix critical bugs in archived projects

---

## 📊 Track Your Progress

### Daily (End of Day)
- [ ] How many hours in single project?
- [ ] Did I create any forbidden docs? (should be 0)
- [ ] Feature commits today: ___
- [ ] Context switches today: ___ (max 2)

### Weekly (Friday)
- [ ] Feature commits this week: ___
- [ ] Doc commits this week: ___ (should be <5)
- [ ] Ratio: ___ : 1 (target 4:1 feature:doc)
- [ ] Tests added: ___
- [ ] GitHub issues closed: ___

---

## 🚨 If You Break the Freeze

1. **Acknowledge it** - Don't hide violations
2. **Delete the file** - Or add to `.gitignore`
3. **Use GitHub** - Issues/Discussions instead
4. **Update metrics** - Track freeze violations

**Philosophy:** The freeze isn't about perfection, it's about breaking the recursive cleanup habit.

---

## 🔧 Emergency Override

If you MUST create a forbidden doc (very rare):

```bash
# Override pre-commit hook (use sparingly!)
git commit --no-verify -m "Critical: security disclosure doc"

# But seriously consider: can this go in GitHub Issues instead?
```

---

## 📈 Success Looks Like

After 2 weeks:
- ✅ Shipped v1.0 of ML Security Framework
- ✅ SaaS platform has 1-2 new customer features
- ✅ No untracked root-level `.md` files
- ✅ Feature:Doc ratio is 3:1 or better
- ✅ You feel less stressed about organization

---

## 🎓 Remember

> "The best documentation is working code and helpful tests"
> - Adapted from the Agile Manifesto

**Your creative energy is better spent building the Edward Teller Agent's next fusion chain than writing another cleanup plan.**

---

For full details, see [CORE_PROJECTS.md](CORE_PROJECTS.md)
