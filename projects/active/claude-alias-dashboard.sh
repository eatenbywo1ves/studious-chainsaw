#!/bin/bash
# Claude Code Alias Dashboard - Interactive alias helper
# Usage: source this or run: bash claude-alias-dashboard.sh

# Colors for better visibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

clear
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${WHITE}           🚀 CLAUDE CODE ALIAS DASHBOARD 🚀                ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to check if we're in a git repo
in_git_repo() {
    git rev-parse --git-dir > /dev/null 2>&1
}

# Function to check if Python files exist
has_python_files() {
    ls *.py 2>/dev/null | head -1 > /dev/null
}

# Function to check if Node.js project
has_node_project() {
    [ -f "package.json" ]
}

# Function to check if Docker files exist
has_docker() {
    [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ] || [ -f "Dockerfile" ]
}

# Context-aware suggestions
echo -e "${GREEN}📍 Current Directory:${NC} $(pwd)"
echo -e "${GREEN}📊 Context Analysis:${NC}"
echo ""

# Git context
if in_git_repo; then
    echo -e "${YELLOW}🔧 Git Repository Detected!${NC}"
    echo -e "  ${BLUE}Recommended aliases:${NC}"
    echo -e "    ${WHITE}git st${NC}         - Check status"
    echo -e "    ${WHITE}git aa${NC}         - Stage all changes"
    echo -e "    ${WHITE}git ci -m '...'${NC} - Commit with message"
    echo -e "    ${WHITE}git lg${NC}         - View pretty log"
    echo -e "    ${WHITE}git last${NC}       - Show last commit"
    
    # Show current branch
    BRANCH=$(git branch --show-current 2>/dev/null)
    if [ -n "$BRANCH" ]; then
        echo -e "  ${PURPLE}Current branch:${NC} $BRANCH"
    fi
    echo ""
fi

# Python context
if has_python_files; then
    echo -e "${YELLOW}🐍 Python Project Detected!${NC}"
    echo -e "  ${BLUE}Recommended aliases:${NC}"
    echo -e "    ${WHITE}py${NC}          - Run Python"
    echo -e "    ${WHITE}pyshared${NC}    - Python with shared modules"
    echo -e "    ${WHITE}venv${NC}        - Create virtual environment"
    echo -e "    ${WHITE}activate${NC}    - Activate venv"
    echo -e "    ${WHITE}pipreq${NC}      - Generate requirements.txt"
    
    # Check for your specific scripts
    if [ -f "api_gateway.py" ]; then
        echo -e "    ${WHITE}apigate${NC}     - Run API Gateway"
    fi
    if [ -f "enhanced_observatory_adapter.py" ]; then
        echo -e "    ${WHITE}observatory${NC} - Run Observatory Adapter"
    fi
    echo ""
fi

# Node.js context
if has_node_project; then
    echo -e "${YELLOW}📦 Node.js Project Detected!${NC}"
    echo -e "  ${BLUE}Recommended aliases:${NC}"
    echo -e "    ${WHITE}ni${NC}          - npm install"
    echo -e "    ${WHITE}nrd${NC}         - npm run dev"
    echo -e "    ${WHITE}nrb${NC}         - npm run build"
    echo -e "    ${WHITE}nrt${NC}         - npm run test"
    echo ""
fi

# Docker context
if has_docker; then
    echo -e "${YELLOW}🐳 Docker Configuration Detected!${NC}"
    echo -e "  ${BLUE}Recommended aliases:${NC}"
    echo -e "    ${WHITE}dc up${NC}       - Start containers"
    echo -e "    ${WHITE}dc down${NC}     - Stop containers"
    echo -e "    ${WHITE}dkps${NC}        - List running containers"
    echo -e "    ${WHITE}dclf${NC}        - Follow container logs"
    echo ""
fi

# Quick Stats
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}📈 Quick Stats:${NC}"

# Count aliases
ALIAS_COUNT=$(alias 2>/dev/null | wc -l)
echo -e "  • Total aliases available: ${WHITE}$ALIAS_COUNT${NC}"

# Git aliases
GIT_ALIAS_COUNT=$(git config --get-regexp alias 2>/dev/null | wc -l)
echo -e "  • Git aliases configured: ${WHITE}$GIT_ALIAS_COUNT${NC}"

# Show if PYTHONPATH is set
if [ -n "$PYTHONPATH" ]; then
    echo -e "  • Python shared modules: ${GREEN}✓ Configured${NC}"
else
    echo -e "  • Python shared modules: ${RED}✗ Not set${NC}"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}🎯 Most Useful Aliases for You:${NC}"
echo ""

# Create a two-column layout
echo -e "${BLUE}Navigation:${NC}                    ${BLUE}Git Workflow:${NC}"
echo -e "  ${WHITE}dev${NC}    → development/          ${WHITE}git st${NC}  → status"
echo -e "  ${WHITE}shared${NC} → shared/               ${WHITE}git aa${NC}  → add all"
echo -e "  ${WHITE}ll${NC}     → list detailed         ${WHITE}git ci${NC}  → commit"
echo -e "  ${WHITE}..${NC}     → up one level          ${WHITE}git lg${NC}  → pretty log"
echo ""
echo -e "${BLUE}Python Development:${NC}            ${BLUE}Utilities:${NC}"
echo -e "  ${WHITE}pyshared${NC} → Python w/ modules   ${WHITE}mkcd${NC}    → make & enter dir"
echo -e "  ${WHITE}apigate${NC}  → API Gateway         ${WHITE}ff${NC}      → find files"
echo -e "  ${WHITE}metrics${NC}  → Gateway metrics     ${WHITE}extract${NC} → unzip anything"
echo ""

# Interactive section
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}💡 Quick Actions:${NC}"
echo -e "  • Type ${WHITE}alias${NC} to see all available aliases"
echo -e "  • Type ${WHITE}claude-help${NC} for more help"
echo -e "  • View docs: ${WHITE}cat \$CLAUDE_WORKSPACE/CLAUDE_ALIASES_QUICK_REFERENCE.md${NC}"
echo ""

# Suggestion based on time of day
HOUR=$(date +%H)
if [ $HOUR -lt 12 ]; then
    echo -e "${YELLOW}☕ Good morning!${NC} Start with ${WHITE}git st${NC} to check your repo status"
elif [ $HOUR -lt 17 ]; then
    echo -e "${YELLOW}☀️ Good afternoon!${NC} Use ${WHITE}git lg${NC} to review today's commits"
else
    echo -e "${YELLOW}🌙 Good evening!${NC} Use ${WHITE}git today${NC} to see what you accomplished"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

# Function to show specific alias group
show_alias_group() {
    case $1 in
        git)
            echo -e "${GREEN}Git Aliases:${NC}"
            git config --get-regexp alias | sed 's/alias\./  /g' | sed 's/ / → /g'
            ;;
        nav)
            echo -e "${GREEN}Navigation Aliases:${NC}"
            alias | grep -E "alias (dev|shared|ll|\.\.)" | sed 's/alias //g'
            ;;
        python)
            echo -e "${GREEN}Python Aliases:${NC}"
            alias | grep -E "alias (py|pip|venv)" | sed 's/alias //g'
            ;;
        *)
            echo "Usage: show_alias_group [git|nav|python]"
            ;;
    esac
}

# Export the function so it's available
export -f show_alias_group

echo -e "${WHITE}Tip: Run ${CYAN}show_alias_group git${WHITE} to see all git aliases${NC}"
echo ""