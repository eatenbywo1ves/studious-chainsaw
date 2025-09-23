# Claude Code Aliases Guide

## Shell Aliases for Claude Code

### 1. Basic Shell Aliases
You can create shell aliases that work within Claude Code sessions. These can be defined in your shell configuration files or set temporarily in a session.

### 2. Git Aliases
Git aliases are particularly useful when working with Claude Code for version control operations.

### 3. Project-Specific Aliases
Create project-specific aliases that can be sourced when working on particular projects.

## Examples

### Common Development Aliases
```bash
# Navigation aliases
alias dev='cd /c/Users/Corbin/development'
alias shared='cd /c/Users/Corbin/development/shared'
alias ll='ls -la'
alias ..='cd ..'
alias ...='cd ../..'

# Git aliases (shell level)
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline -10'
alias gd='git diff'

# Python development
alias py='python'
alias pyshared='PYTHONPATH="/c/Users/Corbin/development/shared" python'
alias venv='python -m venv'
alias activate='source venv/bin/activate'

# npm/node aliases
alias ni='npm install'
alias nr='npm run'
alias nrd='npm run dev'
alias nrb='npm run build'

# Docker aliases
alias dc='docker-compose'
alias dcu='docker-compose up'
alias dcd='docker-compose down'
alias dps='docker ps'
```

### Git Config Aliases
These are stored in your git configuration and work across all tools:
```bash
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.ci commit
git config --global alias.st status
git config --global alias.unstage 'reset HEAD --'
git config --global alias.last 'log -1 HEAD'
git config --global alias.visual '!gitk'
```

### Project-Specific Alias File
Create a `.aliases` file in your project root:
```bash
# Project-specific aliases
alias test='npm test'
alias build='npm run build'
alias start='npm start'
alias lint='npm run lint'
alias format='npm run format'
```

## How to Use Aliases in Claude Code

1. **Temporary aliases** - Set them at the beginning of your session
2. **Persistent aliases** - Add them to your shell configuration files
3. **Project aliases** - Source them when working on specific projects

## Setting Up Aliases

### Option 1: Create a personal aliases file
```bash
# Create aliases file
echo '# My Claude Code Aliases' > ~/.claude_aliases

# Add aliases
echo "alias ll='ls -la'" >> ~/.claude_aliases
echo "alias gs='git status'" >> ~/.claude_aliases

# Source in your session
source ~/.claude_aliases
```

### Option 2: Use git aliases globally
```bash
# Set up common git aliases
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.ci commit
git config --global alias.st status
```

### Option 3: Project-specific setup script
Create a `setup.sh` in your project that sets up all needed aliases when sourced.