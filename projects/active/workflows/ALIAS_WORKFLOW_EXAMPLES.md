# Real-World Alias Workflow Examples

## 🎯 Example 1: Quick Git Workflow
```bash
# Without aliases (45 keystrokes)
git status
git add --all  
git commit -m "Fix bug"
git push

# With aliases (25 keystrokes)
git st
git aa
git ci -m "Fix bug"
git push
```

## 🎯 Example 2: Python Development Session
```bash
# Start your Claude Code session
source /c/Users/Corbin/development/claude-startup.sh

# Navigate to shared modules (using alias)
shared

# Run your API gateway with proper path (using alias)
pyshared api_gateway.py

# Or use the specific alias
apigate
```

## 🎯 Example 3: Project Setup & Navigation
```bash
# Source aliases
source /c/Users/Corbin/development/.claude_aliases

# Create and enter new project (using function)
mkcd my-new-project

# Initialize git and make first commit
git init
echo "# My Project" > README.md
git aa
git ci -m "Initial commit"

# Find all Python files (using function)
ff "*.py"

# Find all test directories (using function)
fd test
```

## 🎯 Example 4: Combined Commands
```bash
# Check status, add all, and commit in one line
git st && git aa && git ci -m "Update features"

# Navigate to dev and list files
source /c/Users/Corbin/development/.claude_aliases && dev && ll

# Start Python server after navigating
dev && pyserver 8080
```

## 🎯 Example 5: Your Specific Projects
```bash
# Working with your Observatory project
source /c/Users/Corbin/development/claude-startup.sh
observatory  # Runs the enhanced observatory adapter

# Working with API Gateway
apigate  # Runs api_gateway.py with correct PYTHONPATH

# Check metrics
metrics  # Runs api_gateway_metrics.py
```

## 🎯 Example 6: Docker Development
```bash
# After sourcing aliases
dc up -d      # Start containers in background
dclf          # Follow logs
dkps          # Check running containers
dc down       # Stop everything
```

## 🎯 Example 7: File Management
```bash
# Using the sourced aliases
ll            # Detailed listing
lt            # List by time modified
lsize         # List by size
tree          # Tree view with colors
```

## 🔥 Power User Combos

### Quick commit and push
```bash
git aa && git ci -m "Update" && git push
```

### Navigate and run
```bash
dev && ll && pyshared main.py
```

### Clean and rebuild
```bash
clean && build && test
```

### Full project setup
```bash
mkcd new-project && git init && echo "# Project" > README.md && git aa && git ci -m "Init"
```

## 💡 Tips for Maximum Efficiency

1. **Start every session with:**
   ```bash
   source /c/Users/Corbin/development/claude-startup.sh
   ```

2. **Most used Git aliases:**
   - `git st` - Check what's changed
   - `git aa` - Stage everything  
   - `git ci -m "msg"` - Commit
   - `git lg` - Beautiful log

3. **Navigation shortcuts save the most time:**
   - `dev` - Jump to development
   - `..` - Go up one level
   - `ll` - See everything in directory

4. **Your project-specific winners:**
   - `pyshared` - Python with your modules
   - `apigate` - Run API gateway
   - `observatory` - Run observatory adapter

## 📊 Time Saved

Based on typical usage:
- Git aliases: Save ~20 keystrokes per commit
- Navigation aliases: Save ~15 keystrokes per directory change  
- Python aliases: Save ~40 keystrokes per run
- **Daily total: ~500+ keystrokes saved = 5-10 minutes**
- **Weekly: 25-50 minutes saved**
- **Monthly: 2-3 hours saved!**

## 🚀 Quick Start Checklist

- [ ] Git aliases are configured (permanent)
- [ ] Created `.claude_aliases` file
- [ ] Created `claude-startup.sh` script
- [ ] Created quick reference guide
- [ ] Know how to source aliases each session

Remember: The key is consistency - use them every time!