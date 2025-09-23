#!/bin/bash
# ============================================
# Bash Aliases Configuration
# ============================================
# To use these aliases, source this file in your .bashrc:
# echo "source ~/development/bash_aliases.sh" >> ~/.bashrc
# Or manually: source ~/development/bash_aliases.sh

# ============================================
# Navigation Aliases
# ============================================
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias ~='cd ~'
alias -- -='cd -'  # Go to previous directory

# Quick directory access
alias dev='cd ~/development'
alias proj='cd ~/projects'
alias dl='cd ~/Downloads'
alias docs='cd ~/Documents'
alias desk='cd ~/Desktop'

# ============================================
# Listing Files
# ============================================
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias lt='ls -ltr'  # Sort by modification time, oldest first
alias lh='ls -lh'   # Human readable sizes
alias ld='ls -ld */' # List only directories

# ============================================
# Git Aliases
# ============================================
alias g='git'
alias gs='git status'
alias ga='git add'
alias gaa='git add --all'
alias gc='git commit -m'
alias gca='git commit -am'
alias gp='git push'
alias gl='git pull'
alias glog='git log --oneline --graph --decorate'
alias gd='git diff'
alias gb='git branch'
alias gco='git checkout'
alias gcb='git checkout -b'
alias gm='git merge'
alias gr='git remote -v'
alias gst='git stash'
alias gstp='git stash pop'
alias greset='git reset --hard HEAD'
alias gclean='git clean -fd'

# ============================================
# File Operations
# ============================================
alias cp='cp -iv'     # Interactive and verbose
alias mv='mv -iv'     # Interactive and verbose
alias rm='rm -i'      # Interactive (confirm before delete)
alias mkdir='mkdir -pv' # Create parent dirs as needed, verbose

# ============================================
# System Information
# ============================================
alias df='df -h'      # Human readable disk space
alias du='du -h'      # Human readable disk usage
alias free='free -h'  # Human readable memory
alias ps='ps aux'     # All processes
alias top='top -o %CPU' # Sort by CPU usage
alias ports='netstat -tuln' # Show listening ports

# ============================================
# Search & Find
# ============================================
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias find='find . -name'
alias ff='find . -type f -name'  # Find files
alias fd='find . -type d -name'  # Find directories

# ============================================
# Python Aliases
# ============================================
alias py='python'
alias py3='python3'
alias pip='pip3'
alias venv='python -m venv'
alias activate='source venv/bin/activate 2>/dev/null || source venv/Scripts/activate'
alias pipreq='pip freeze > requirements.txt'
alias pipinst='pip install -r requirements.txt'

# ============================================
# Node.js / npm Aliases
# ============================================
alias ni='npm install'
alias ns='npm start'
alias nt='npm test'
alias nb='npm run build'
alias nrd='npm run dev'
alias nrs='npm run serve'

# ============================================
# Docker Aliases
# ============================================
alias d='docker'
alias dc='docker-compose'
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias dexec='docker exec -it'
alias dlogs='docker logs -f'
alias dstop='docker stop $(docker ps -q)'
alias drm='docker rm $(docker ps -aq)'
alias drmi='docker rmi $(docker images -q)'

# ============================================
# Utility Aliases
# ============================================
alias c='clear'
alias h='history'
alias hgrep='history | grep'
alias path='echo -e ${PATH//:/\\n}' # Print PATH on separate lines
alias reload='source ~/.bashrc'
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias week='date +%V'
alias myip='curl -s ifconfig.me'
alias localip='ipconfig | grep -A 2 "Wireless LAN adapter Wi-Fi" | grep "IPv4"'

# ============================================
# Safety Aliases
# ============================================
alias wget='wget -c'  # Continue partial downloads
alias df='df -h'      # Human readable
alias free='free -m'  # Show in MB

# ============================================
# Windows-specific (Git Bash)
# ============================================
alias cls='clear'
alias dir='ls -la'
alias copy='cp'
alias move='mv'
alias del='rm'
alias md='mkdir'
alias rd='rmdir'
alias where='which'

# ============================================
# Custom Functions as Aliases
# ============================================
# Create directory and cd into it
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# Git commit with message
gcommit() {
    git add -A && git commit -m "$1"
}

# Extract various archive formats
extract() {
    if [ -f $1 ]; then
        case $1 in
            *.tar.bz2)   tar xjf $1   ;;
            *.tar.gz)    tar xzf $1   ;;
            *.bz2)       bunzip2 $1   ;;
            *.rar)       unrar x $1   ;;
            *.gz)        gunzip $1    ;;
            *.tar)       tar xf $1    ;;
            *.tbz2)      tar xjf $1   ;;
            *.tgz)       tar xzf $1   ;;
            *.zip)       unzip $1     ;;
            *.Z)         uncompress $1;;
            *.7z)        7z x $1      ;;
            *)           echo "'$1' cannot be extracted" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}

# Quick backup of a file
backup() {
    cp "$1" "$1.backup.$(date +%Y%m%d_%H%M%S)"
}

# Show the size of directories in current location
dirsize() {
    du -h --max-depth=1 | sort -rh
}

# ============================================
# Claude Code Specific
# ============================================
alias claude='claude'
alias cauth='claude auth status'
alias chelp='claude --help'

# ============================================
# Shortcuts for common typos
# ============================================
alias sl='ls'
alias gti='git'
alias gitst='git status'
alias pdw='pwd'
alias cler='clear'
alias clera='clear'

echo "✓ Bash aliases loaded successfully!"
echo "Type 'alias' to see all available aliases"