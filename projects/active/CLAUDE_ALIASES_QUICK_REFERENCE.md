# Claude Code Aliases Quick Reference

## 🚀 How to Use Aliases in Claude Code

### Method 1: Git Aliases (Persistent & Recommended)
These are already configured and work immediately:

| Alias | Full Command | Description |
|-------|--------------|-------------|
| `git st` | `git status` | Check repository status |
| `git co` | `git checkout` | Switch branches/files |
| `git br` | `git branch` | List/manage branches |
| `git ci` | `git commit` | Commit changes |
| `git aa` | `git add --all` | Stage all changes |
| `git lg` | `git log --graph --pretty...` | Beautiful log graph |
| `git last` | `git log -1 HEAD` | Show last commit |
| `git unstage` | `git reset HEAD --` | Unstage files |

### Method 2: Shell Aliases (Session-based)
Run this at the start of each session:
```bash
source /c/Users/Corbin/development/.claude_aliases
```

Then you can use shortcuts like:
- `gs` → git status
- `dev` → cd to development folder  
- `pyshared` → Python with shared modules
- `ll` → detailed file listing

### Method 3: Inline Aliases (One-liners)
Use directly in commands:
```bash
# Define and use in same line
alias ll='ls -la' && ll

# Or source aliases and run command
source /c/Users/Corbin/development/.claude_aliases && gs
```

## 📝 Examples

### Using Git Aliases
```bash
# Check status
git st

# Stage all changes
git aa

# Commit with message
git ci -m "Add new feature"

# View pretty log
git lg
```

### Using Shell Aliases (after sourcing)
```bash
# Source the aliases
source /c/Users/Corbin/development/.claude_aliases

# Navigate quickly
dev        # Go to development folder
shared     # Go to shared folder

# Python shortcuts
pyshared api_gateway.py    # Run with PYTHONPATH set
```

### Custom Functions Available
After sourcing `.claude_aliases`:

- `mkcd dirname` - Create and enter directory
- `gcommit "message"` - Add all and commit
- `ff pattern` - Find files matching pattern
- `fd pattern` - Find directories matching pattern
- `extract file.zip` - Extract any archive
- `pyserver 8080` - Start Python HTTP server

## 💡 Pro Tips

1. **Git aliases are permanent** - Once set, they work in every session
2. **Create project-specific aliases** - Add a `.aliases` file to your project
3. **Chain commands** - Use `&&` to run multiple commands: `git aa && git ci -m "Update"`
4. **View all Git aliases**: `git config --get-regexp alias`
5. **Remove a Git alias**: `git config --global --unset alias.name`

## 🔧 Adding New Aliases

### Add a Git Alias
```bash
git config --global alias.newname 'command'
```

### Add to Shell Aliases
Edit `/c/Users/Corbin/development/.claude_aliases` and re-source it.

## 📌 Most Useful for Your Workflow

Based on your projects, these aliases will save you the most time:

1. **Git workflow**: `git st`, `git aa`, `git ci -m "..."`
2. **Python development**: `pyshared`, `apigate`, `observatory`
3. **Navigation**: `dev`, `shared`, `ll`
4. **Docker**: `dc up`, `dc down`, `dkps`

---

Remember: Git aliases work immediately, shell aliases need sourcing each session!