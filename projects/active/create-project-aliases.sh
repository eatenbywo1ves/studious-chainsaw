#!/bin/bash
# Script to create project-specific aliases
# Usage: source this script in any project directory

PROJECT_DIR=$(pwd)
PROJECT_NAME=$(basename "$PROJECT_DIR")
ALIAS_FILE="$PROJECT_DIR/.project-aliases"

echo "Creating aliases for project: $PROJECT_NAME"

# Create project-specific aliases file
cat > "$ALIAS_FILE" << 'EOF'
# Project-specific aliases
# Source this file: source .project-aliases

# Project navigation
alias root='cd $(git rev-parse --show-toplevel 2>/dev/null || pwd)'
alias src='cd src 2>/dev/null || echo "No src directory"'
alias tests='cd tests 2>/dev/null || cd test 2>/dev/null || echo "No test directory"'

# Project-specific build commands
alias build='if [ -f package.json ]; then npm run build; elif [ -f Makefile ]; then make; elif [ -f setup.py ]; then python setup.py build; else echo "No build system detected"; fi'
alias test='if [ -f package.json ]; then npm test; elif [ -f pytest.ini ] || [ -f tests/ ]; then pytest; elif [ -f Makefile ]; then make test; else echo "No test system detected"; fi'
alias run='if [ -f package.json ]; then npm start; elif [ -f main.py ]; then python main.py; elif [ -f app.py ]; then python app.py; else echo "No run command detected"; fi'

# Git workflow for this project
alias save='git add -A && git commit -m'
alias sync='git pull && git push'
alias wip='git add -A && git commit -m "WIP: Work in progress"'
alias amend='git add -A && git commit --amend --no-edit'

# Project cleanup
alias clean='find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null; find . -type f -name "*.pyc" -delete 2>/dev/null; rm -rf node_modules 2>/dev/null; rm -rf dist build 2>/dev/null'

echo "Project aliases loaded for: $(basename $(pwd))"
EOF

echo "✅ Created $ALIAS_FILE"
echo "To use: source .project-aliases"

# Auto-source if created successfully
if [ -f "$ALIAS_FILE" ]; then
    source "$ALIAS_FILE"
fi