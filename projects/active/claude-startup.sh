#!/bin/bash
# Claude Code Session Startup Script
# Run this at the start of each session: source /c/Users/Corbin/development/claude-startup.sh

echo "🚀 Initializing Claude Code session..."

# Source custom aliases
source /c/Users/Corbin/development/.claude_aliases

# Set up some session variables
export PYTHONPATH="/c/Users/Corbin/development/shared:$PYTHONPATH"
export DEVELOPMENT_DIR="/c/Users/Corbin/development"

# Display current directory
echo "📁 Current directory: $(pwd)"

# Show git status if in a git repo
if git rev-parse --git-dir > /dev/null 2>&1; then
    echo ""
    echo "📊 Git Repository Status:"
    git st
fi

echo ""
echo "✅ Session ready! Quick tips:"
echo "  • Git aliases are available (git st, git lg, git aa, etc.)"
echo "  • Shell aliases loaded (type 'alias' to see all)"
echo "  • Custom functions available (mkcd, gcommit, ff, fd, extract)"
echo "  • PYTHONPATH includes shared modules"
echo ""
echo "📝 Quick reference: cat $DEVELOPMENT_DIR/CLAUDE_ALIASES_QUICK_REFERENCE.md"