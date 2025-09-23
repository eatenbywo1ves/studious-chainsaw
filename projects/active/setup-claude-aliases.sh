#!/bin/bash
# One-time setup script for Claude Code aliases
# Run this once: bash /c/Users/Corbin/development/setup-claude-aliases.sh

echo "🔧 Setting up Claude Code Aliases..."
echo "===================================="

# Detect home directory
HOME_DIR="$HOME"
if [ -z "$HOME_DIR" ]; then
    HOME_DIR="/c/Users/Corbin"
fi

# Detect shell configuration file
if [ -f "$HOME_DIR/.bashrc" ]; then
    SHELL_CONFIG="$HOME_DIR/.bashrc"
elif [ -f "$HOME_DIR/.bash_profile" ]; then
    SHELL_CONFIG="$HOME_DIR/.bash_profile"
else
    SHELL_CONFIG="$HOME_DIR/.bashrc"
    echo "Creating new .bashrc file..."
    touch "$SHELL_CONFIG"
fi

echo "📁 Home directory: $HOME_DIR"
echo "📄 Shell config file: $SHELL_CONFIG"

# Check if already configured
if grep -q "claude_aliases" "$SHELL_CONFIG" 2>/dev/null; then
    echo "⚠️  Claude aliases already configured in $SHELL_CONFIG"
    echo "    To reconfigure, remove the Claude section from $SHELL_CONFIG"
else
    # Add to shell configuration
    echo "" >> "$SHELL_CONFIG"
    echo "# Claude Code Aliases Configuration" >> "$SHELL_CONFIG"
    echo "# Added on $(date)" >> "$SHELL_CONFIG"
    echo "if [ -f /c/Users/Corbin/development/.claude_aliases ]; then" >> "$SHELL_CONFIG"
    echo "    source /c/Users/Corbin/development/.claude_aliases" >> "$SHELL_CONFIG"
    echo "fi" >> "$SHELL_CONFIG"
    echo "export PYTHONPATH=\"/c/Users/Corbin/development/shared:\$PYTHONPATH\"" >> "$SHELL_CONFIG"
    echo "export CLAUDE_WORKSPACE=\"/c/Users/Corbin/development\"" >> "$SHELL_CONFIG"
    
    echo "✅ Added Claude aliases to $SHELL_CONFIG"
fi

# Configure Git aliases (these are global and permanent)
echo ""
echo "🔧 Configuring Git aliases..."

git config --global alias.st 'status'
git config --global alias.co 'checkout'
git config --global alias.br 'branch'
git config --global alias.ci 'commit'
git config --global alias.aa 'add --all'
git config --global alias.unstage 'reset HEAD --'
git config --global alias.last 'log -1 HEAD'
git config --global alias.lg "log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit"
git config --global alias.today "log --since=midnight --oneline"
git config --global alias.yesterday "log --since=yesterday.midnight --until=midnight --oneline"

echo "✅ Git aliases configured"

# Create a desktop shortcut script (optional)
DESKTOP_SCRIPT="/c/Users/Corbin/Desktop/claude-dev.sh"
if [ -d "/c/Users/Corbin/Desktop" ]; then
    cat > "$DESKTOP_SCRIPT" << 'EOF'
#!/bin/bash
# Quick launcher for Claude development environment
cd /c/Users/Corbin/development
source /c/Users/Corbin/development/.claude_aliases
echo "🚀 Claude development environment ready!"
exec bash
EOF
    chmod +x "$DESKTOP_SCRIPT" 2>/dev/null
    echo "✅ Created desktop launcher: $DESKTOP_SCRIPT"
fi

# Test the configuration
echo ""
echo "🧪 Testing configuration..."
echo "============================"

# Source and test
source /c/Users/Corbin/development/.claude_aliases 2>/dev/null

# Test Git aliases
echo -n "Git aliases: "
if git st --version >/dev/null 2>&1; then
    echo "✅ Working"
else
    echo "⚠️  Need to restart shell"
fi

# Show summary
echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo ""
echo "✨ What's been configured:"
echo "  • Shell aliases in: /c/Users/Corbin/development/.claude_aliases"
echo "  • Git aliases (global)"
echo "  • PYTHONPATH for shared modules"
echo "  • Quick access functions"
echo ""
echo "📝 Next steps:"
echo "  1. Restart your terminal or run: source $SHELL_CONFIG"
echo "  2. Your aliases will now load automatically!"
echo "  3. Type 'alias' to see all available shortcuts"
echo ""
echo "🚀 Quick test commands to try:"
echo "  git st          # Git status"
echo "  git lg          # Pretty log"
echo "  dev             # Go to development folder"
echo "  claude-help     # Show help"
echo ""
echo "📚 Documentation:"
echo "  • Quick Reference: /c/Users/Corbin/development/CLAUDE_ALIASES_QUICK_REFERENCE.md"
echo "  • Examples: /c/Users/Corbin/development/ALIAS_WORKFLOW_EXAMPLES.md"