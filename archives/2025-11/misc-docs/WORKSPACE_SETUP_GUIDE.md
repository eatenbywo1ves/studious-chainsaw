# Workspace Setup Guide

## Overview

Your `development` and `projects` directories are currently part of a **monorepo** rooted at `C:\Users\Corbin`. This document explains the current setup and provides recommendations.

---

## Current Structure

```
C:\Users\Corbin\                     (Git Repo Root)
├── development\                     🐍 Python/Infrastructure
│   ├── saas\                        SaaS platform
│   ├── ml-sectest-framework\        ML security testing
│   ├── Ghidra tools\                Reverse engineering
│   ├── kubernetes\                  K8s configs
│   ├── .claude\                     Claude config (MCP servers)
│   └── mcp-servers\                 Financial + utilities MCP
│
└── projects\                        🌐 Node.js/TypeScript
    ├── financial-apps\              Financial applications
    ├── genetic-simulation\          Genetic algorithms
    ├── platform\                    Platform code
    ├── .claude\                     Claude config (permissions)
    └── mcp-servers\                 Financial analysis MCP servers
```

---

## ✅ What's Been Done

### 1. Created Multi-Root VS Code Workspace
**File:** `C:\Users\Corbin\corbin-workspace.code-workspace`

This workspace includes both directories with:
- Separate views for each project
- Language-specific settings (Python/TypeScript)
- Recommended extensions
- Debug configurations for both stacks
- Intelligent file exclusions

**Usage:**
```bash
# Open workspace from anywhere
workspace
# or
ws
# or
code ~/corbin-workspace.code-workspace
```

### 2. Updated Bash Aliases
**File:** `C:\Users\Corbin\development\.bash_aliases`

New navigation shortcuts:
```bash
# Development (Python)
dev      # → ~/development
saas     # → ~/development/saas
mlsec    # → ~/development/ml-sectest-framework

# Projects (Node.js)
proj     # → ~/projects
finance  # → ~/projects/financial-apps
genetic  # → ~/projects/genetic-simulation

# Workspace
workspace  # Opens VS Code workspace
ws         # Short alias
```

### 3. Analysis Complete
- ✅ MCP servers are project-specific (no duplication)
- ✅ Claude configs are different (no conflicts)
- ✅ Other shared directories are project-specific
- ✅ No symbolic links needed

---

## 🎯 Recommendations

### Option A: Keep Current Monorepo (Easiest)
**Status:** Already set up!

**Pros:**
- No migration needed
- Everything already works
- Single git history

**Cons:**
- Entire home directory is tracked
- Risk of accidentally committing personal files
- Large repository size

**If choosing this:** Create a comprehensive `.gitignore` at `~/` to exclude personal files.

---

### Option B: Restructure into Separate Repos (Recommended) ⭐

Create independent repositories:

```
C:\Users\Corbin\
├── workspace\                        New directory
│   ├── development\                  Git Repo #1
│   └── projects\                     Git Repo #2
```

**Migration Steps:**

#### Step 1: Backup everything
```bash
# Backup current state
cd ~
tar -czf backup-$(date +%Y%m%d).tar.gz development/ projects/
```

#### Step 2: Initialize separate repos
```bash
# Create workspace directory
mkdir -p ~/workspace

# Initialize development repo
cp -r ~/development ~/workspace/development
cd ~/workspace/development
git init
git remote add origin <your-development-repo-url>
git add .
git commit -m "Initial commit: Development workspace"

# Initialize projects repo
cp -r ~/projects ~/workspace/projects
cd ~/workspace/projects
git init
git remote add origin <your-projects-repo-url>
git add .
git commit -m "Initial commit: Projects workspace"
```

#### Step 3: Update workspace file
```bash
# Edit corbin-workspace.code-workspace
# Change paths from "development" to "workspace/development"
# Change paths from "projects" to "workspace/projects"
```

#### Step 4: Update aliases
```bash
# Update .bash_aliases
alias dev='cd ~/workspace/development'
alias proj='cd ~/workspace/projects'
```

**Pros:**
- Clean separation of concerns
- Smaller repos (faster operations)
- No risk of tracking home directory
- Proper git workflows for each

**Cons:**
- Requires migration effort
- Need to manage two repos

---

### Option C: Submodules Approach (Advanced)

Convert current structure to use git submodules:

```bash
cd ~
git init parent-repo
git submodule add <dev-url> development
git submodule add <proj-url> projects
```

**Pros:**
- Single workspace with independent repos
- Share common configs in parent

**Cons:**
- Submodules can be complex
- Requires understanding of git submodules

---

## 📋 Action Items

### Immediate (Already Done ✅)
- [x] Create multi-root workspace
- [x] Update bash aliases
- [x] Analyze directory overlap

### Short Term (Recommended)
- [ ] **Choose an option above**
- [ ] Create comprehensive `.gitignore` for home directory
- [ ] Document project dependencies
- [ ] Set up pre-commit hooks for each repo

### Long Term
- [ ] Set up CI/CD for each project
- [ ] Configure automatic backups
- [ ] Document development workflows
- [ ] Create project-specific README files

---

## 🚀 Quick Start

### Using the New Setup

1. **Open workspace:**
   ```bash
   ws
   ```

2. **Navigate to projects:**
   ```bash
   dev      # Development (Python)
   proj     # Projects (Node.js)
   saas     # SaaS project
   finance  # Financial apps
   ```

3. **Check current status:**
   ```bash
   status      # Git status + recent commits
   envinfo     # Environment info
   ```

4. **Start development:**
   ```bash
   # Development (Python)
   cd ~/development/saas
   source venv/bin/activate
   python main.py

   # Projects (Node.js)
   cd ~/projects
   npm install
   npm run dev
   ```

---

## 🔧 Configuration Files

### Workspace Config
`C:\Users\Corbin\corbin-workspace.code-workspace`
- Multi-root workspace with both directories
- Language-specific settings
- Debug configurations

### Bash Aliases
`C:\Users\Corbin\development\.bash_aliases`
- Navigation shortcuts
- Git workflows
- Docker/Kubernetes helpers
- Testing shortcuts

### Claude Configs
- `development\.claude\settings.local.json` - MCP server config
- `projects\.claude\settings.local.json` - Permission config

---

## 📊 Current Git Status

**Repository:** `C:\Users\Corbin`
**Branch:** `feat/todo-deployment-phase-1`
**Status:** 2 commits ahead of origin

**Modified files:**
- `docker-compose.yml` (development)
- `KEY_INSIGHTS.md` (Insights)

**Untracked files:** ~40 new files in development/saas

---

## 🆘 Troubleshooting

### Issue: Git tracks entire home directory
**Solution:** Choose Option B (restructure) or create comprehensive `.gitignore`

### Issue: VS Code slow with large workspace
**Solution:** Update `files.exclude` in workspace settings to exclude more directories

### Issue: Different Python/Node versions needed
**Solution:** Use `venv` for Python, `nvm` for Node.js (already set up)

---

## 📚 Resources

- [VS Code Multi-Root Workspaces](https://code.visualstudio.com/docs/editor/multi-root-workspaces)
- [Git Submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules)
- [Bash Aliases Guide](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)

---

## 📞 Next Steps

**Recommended Path:**
1. Use the new workspace setup for 1-2 weeks
2. Evaluate if current monorepo works for you
3. If issues arise, migrate to Option B (separate repos)
4. Document any project-specific workflows

**Questions to Consider:**
- Do you want separate git histories for each project?
- Do you need to share commits between projects?
- How often do you work on both simultaneously?

---

*Generated: 2025-10-29*
*Last Updated: 2025-10-29*
