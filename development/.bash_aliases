#!/bin/bash
# Custom Aliases for Development Workflow
# Auto-loaded in VS Code integrated terminal

# ============================================================
# NAVIGATION SHORTCUTS
# ============================================================
# Development directory (Python/Infrastructure)
alias dev='cd ~/development'
alias saas='cd ~/development/saas'
alias mlsec='cd ~/development/ml-sectest-framework'
alias sec='cd ~/development/security'
alias docs='cd ~/development/docs'
alias k8s='cd ~/development/kubernetes'
alias scripts='cd ~/development/scripts'

# Projects directory (Node.js/TypeScript)
alias proj='cd ~/projects'
alias projdocs='cd ~/projects/docs'
alias finance='cd ~/projects/financial-apps'
alias genetic='cd ~/projects/genetic-simulation'

# Workspace shortcuts
alias workspace='code ~/corbin-workspace.code-workspace'
alias ws='code ~/corbin-workspace.code-workspace'

# Quick directory listing
alias l='ls -lah'
alias ll='ls -lh'
alias la='ls -A'
alias tree='tree -C -L 2'

# ============================================================
# GIT WORKFLOW SHORTCUTS
# ============================================================
alias gs='git status'
alias ga='git add'
alias gaa='git add --all'
alias gc='git commit -m'
alias gp='git push'
alias gpl='git pull'
alias gd='git diff'
alias gl='git log --oneline --graph --decorate -10'
alias gb='git branch'
alias gco='git checkout'
alias gcb='git checkout -b'
alias gst='git stash'
alias gstp='git stash pop'

# Git helpers
alias uncommit='git reset --soft HEAD~1'
alias gdiff='git diff HEAD'
alias gclean='git clean -fd'

# ============================================================
# PYTHON DEVELOPMENT
# ============================================================
alias py='python'
alias py3='python3'
alias pip='python -m pip'
alias venv='python -m venv'

# Virtual environment shortcuts
alias activate='source venv/bin/activate'
alias deactivate='deactivate'
alias mkvenv='python -m venv venv && source venv/bin/activate && pip install --upgrade pip'

# Python tools
alias pytest='python -m pytest'
alias black='python -m black'
alias ruff='python -m ruff'
alias mypy='python -m mypy'

# Quick linting
alias lint='ruff check . && mypy .'
alias format='black . && ruff check --fix .'

# ============================================================
# DOCKER & CONTAINERS
# ============================================================
alias d='docker'
alias dc='docker-compose'
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias drm='docker rm'
alias drmi='docker rmi'
alias dstop='docker stop $(docker ps -q)'
alias dclean='docker system prune -af'

# Docker compose shortcuts
alias dcup='docker-compose up -d'
alias dcdown='docker-compose down'
alias dclogs='docker-compose logs -f'
alias dcrestart='docker-compose restart'
alias dcbuild='docker-compose build'

# ============================================================
# KUBERNETES SHORTCUTS
# ============================================================
alias k='kubectl'
alias kgp='kubectl get pods'
alias kgs='kubectl get services'
alias kgd='kubectl get deployments'
alias kdesc='kubectl describe'
alias klogs='kubectl logs -f'
alias kexec='kubectl exec -it'
alias kns='kubectl config set-context --current --namespace'

# ============================================================
# DEVELOPMENT SERVERS
# ============================================================
# Start SaaS API server
alias saas-dev='cd ~/development/saas && source venv/bin/activate && uvicorn app.main:app --reload --port 8000'
alias saas-prod='cd ~/development/saas && source venv/bin/activate && uvicorn app.main:app --host 0.0.0.0 --port 8000'

# Start ML SecTest framework
alias mlsec-dev='cd ~/development/ml-sectest-framework && source venv/bin/activate && uvicorn app.main:app --reload --port 8081'

# Load testing
alias loadtest='cd ~/development/saas/tests/performance && locust'

# ============================================================
# TESTING SHORTCUTS
# ============================================================
alias test='pytest -v'
alias testcov='pytest --cov=. --cov-report=html'
alias testwatch='pytest-watch'
alias testfast='pytest -x --ff'  # Stop on first failure, run last failures first

# ============================================================
# CLAUDE CODE INTEGRATION
# ============================================================
alias c='claude'
alias cplan='claude --model opusplan'
alias copus='claude --model opus'
alias cthink='claude "think about"'
alias cfix='claude "fix the errors in"'
alias ctest='claude "write tests for"'
alias crefactor='claude "refactor"'
alias cdocs='claude "document"'

# Quick Claude commands
alias cstatus='claude "review our current status and check for any incomplete tasks"'
alias clint='claude "fix all linting errors"'
alias ctypecheck='claude "fix all type checking errors"'
alias csec='claude "perform security audit on"'

# ============================================================
# PROJECT-SPECIFIC HELPERS
# ============================================================
# SaaS project
alias saas-setup='cd ~/development/saas && mkvenv && pip install -r requirements-saas.txt'
alias saas-test='cd ~/development/saas && pytest tests/'
alias saas-db='cd ~/development/saas && alembic upgrade head'

# ML SecTest project
alias mlsec-setup='cd ~/development/ml-sectest-framework && mkvenv && pip install -r requirements.txt'
alias mlsec-test='cd ~/development/ml-sectest-framework && pytest tests/'
alias mlsec-scan='cd ~/development/ml-sectest-framework && python ml_sectest.py scan'

# ============================================================
# SYSTEM UTILITIES
# ============================================================
alias cls='clear'
alias h='history'
alias ports='netstat -tulanp'
alias psg='ps aux | grep -v grep | grep -i -e VSZ -e'
alias myip='curl -s ifconfig.me'

# Disk usage
alias diskspace='du -h --max-depth=1 | sort -hr'
alias freespace='df -h'

# ============================================================
# PRODUCTIVITY HELPERS
# ============================================================
# Quick notes
alias note='code ~/development/NOTES.md'
alias todo='code ~/development/TODO.md'
alias daily='code ~/development/daily-briefings/$(date +%Y-%m-%d).md'

# Project status
status() {
    echo "=== Git Status ==="
    git status -sb
    echo ""
    echo "=== Recent Commits ==="
    git log --oneline -5
    echo ""
    echo "=== Branch Info ==="
    git branch -v
}

# Create new feature branch
feature() {
    if [ -z "$1" ]; then
        echo "Usage: feature <branch-name>"
        return 1
    fi
    git checkout -b "feat/$1"
}

# Create new fix branch
fix() {
    if [ -z "$1" ]; then
        echo "Usage: fix <branch-name>"
        return 1
    fi
    git checkout -b "fix/$1"
}

# Quick commit with timestamp
qc() {
    git add .
    git commit -m "${1:-Quick commit at $(date +%H:%M)}"
}

# ============================================================
# ENVIRONMENT HELPERS
# ============================================================
# Show environment info
envinfo() {
    echo "=== Python Version ==="
    python --version
    echo ""
    echo "=== Virtual Environment ==="
    echo "VIRTUAL_ENV: ${VIRTUAL_ENV:-Not activated}"
    echo ""
    echo "=== Git Branch ==="
    git branch --show-current 2>/dev/null || echo "Not a git repository"
    echo ""
    echo "=== Docker Status ==="
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Docker not running"
}

# Load project-specific environment
loadenv() {
    if [ -f .env ]; then
        export $(cat .env | grep -v '^#' | xargs)
        echo "[OK] Loaded .env file"
    else
        echo "[ERROR] No .env file found"
    fi
}

# ============================================================
# BANNER (Only show in interactive shells, not in scripts)
# ============================================================
if [ -t 1 ] && [ -z "$CLAUDE_CODE_EXEC" ]; then
    echo ""
    echo "Development Environment Ready!"
    echo "Working directory: $(pwd)"
    echo "Custom aliases loaded (type 'alias' to see all)"
    echo ""
    echo "Quick Commands:"
    echo "  dev, saas, mlsec, sec  - Navigate to projects"
    echo "  c, cplan, copus        - Claude Code shortcuts"
    echo "  dcup, dcdown           - Docker Compose"
    echo "  test, lint, format     - Testing & Code Quality"
    echo "  status, envinfo        - Project status"
    echo ""
fi
