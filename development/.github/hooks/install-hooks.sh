#!/bin/bash
#
# Install documentation freeze hooks
# Run this script to activate the pre-commit hook
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔧 Installing Documentation Freeze Hooks..."

# Set git hooks path
git config core.hooksPath "$SCRIPT_DIR"

# Make hooks executable
chmod +x "$SCRIPT_DIR/pre-commit"

echo "✅ Hooks installed successfully!"
echo ""
echo "Documentation Freeze is now active until 2025-10-28"
echo "See ../CORE_PROJECTS.md for details"
