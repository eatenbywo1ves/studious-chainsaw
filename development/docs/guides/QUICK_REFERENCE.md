# ⚡ VS Code + Claude Code Quick Reference

## 🚀 Getting Started

```bash
# Open VS Code in development directory
code ~/development

# Start development environment
./scripts/dev-start.sh all

# Open Claude workflow helper
./scripts/claude-workflow.sh
```

---

## ⌨️ Essential Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Toggle Terminal | `` Ctrl+` `` |
| Start Claude | `Ctrl+Shift+C` |
| Command Palette | `Ctrl+Shift+P` |
| Fix Linting | `Ctrl+Alt+L` |
| Fix Types | `Ctrl+Alt+T` |
| Review Status | `Ctrl+Alt+S` |

---

## 🔧 Most Used Aliases

### Navigation
```bash
dev          # Go to ~/development
saas         # Go to SaaS project
mlsec        # Go to ML SecTest
```

### Git
```bash
gs           # git status
gaa          # git add --all
gc "msg"     # git commit -m "msg"
gp           # git push
status       # Enhanced git status
```

### Development
```bash
saas-dev     # Start SaaS server
mlsec-dev    # Start ML SecTest
test         # Run tests
lint         # Check code quality
format       # Format code
```

### Claude
```bash
c            # Start Claude
clint        # Fix linting
ctypecheck   # Fix types
cstatus      # Review status
cfix         # Fix errors
```

### Docker
```bash
dcup         # Start containers
dcdown       # Stop containers
dclogs       # View logs
dclean       # Clean everything
```

---

## 🎯 Common Workflows

### 1. Start Working
```bash
code ~/development/saas
saas-dev
```

### 2. Fix Code Issues
```bash
lint                    # Check issues
clint                   # Let Claude fix
```

### 3. Git Workflow
```bash
gs                      # Check status
gaa                     # Stage all
gc "commit message"     # Commit
gp                      # Push
```

### 4. Run Tests
```bash
test                    # Run all tests
ctest "module name"     # Write/fix tests
```

### 5. Deploy
```bash
dcbuild                 # Build containers
dcup                    # Start services
dclogs                  # Watch logs
```

---

## 🎨 VS Code Tasks

Press `Ctrl+Shift+P`, type "Run Task":

- **Start Development Environment**
- **Start SaaS Dev Server**
- **Start ML SecTest Server**
- **Run Tests**
- **Format Code**
- **Claude: Fix Linting**
- **Claude Workflow Helper**

---

## 💡 Pro Tips

1. **Tab Completion**: Type partial command + Tab
2. **History Search**: `Ctrl+R` then type to search
3. **Chain Commands**: `test && format && gc "fixed"`
4. **Background Jobs**: Add `&` to run in background
5. **Quick Status**: Type `envinfo` for full status

---

## 🆘 Help Commands

```bash
alias               # List all aliases
envinfo            # Environment status
status             # Git status
./scripts/claude-workflow.sh  # Interactive helper
```

---

## 📍 Important Paths

```
~/development/               # Main workspace
  ├── saas/                 # SaaS API project
  ├── ml-sectest-framework/ # ML Security Testing
  ├── security/             # Security tools
  ├── scripts/              # Helper scripts
  └── .vscode/              # VS Code config
```

---

**Full Guide**: `~/development/TERMINAL_GUIDE.md`
