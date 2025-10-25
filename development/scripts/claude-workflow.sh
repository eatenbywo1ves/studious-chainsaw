#!/bin/bash
# Claude Code Workflow Helper
# Quick shortcuts for common Claude Code tasks

DEV_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DEV_ROOT"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}"
}

# Show menu
show_menu() {
    print_header "🤖 Claude Code Workflow Helper"
    echo ""
    echo "Select a workflow:"
    echo ""
    echo "  1) 🐛 Fix linting errors"
    echo "  2) 🔍 Fix type checking errors"
    echo "  3) 🧪 Run tests and fix failures"
    echo "  4) 📝 Add documentation"
    echo "  5) 🔄 Refactor code"
    echo "  6) 🔒 Security audit"
    echo "  7) 📊 Review project status"
    echo "  8) 🎯 Custom prompt"
    echo "  9) 🚀 Deploy workflow"
    echo "  0) ❌ Exit"
    echo ""
    read -p "Enter choice [0-9]: " choice
    echo ""
}

# Workflow implementations
fix_linting() {
    print_header "🐛 Running Linting Check & Fix"
    echo "Running ruff check..."
    ruff check . || true
    echo ""
    read -p "Run Claude to fix issues? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        claude "Fix all linting errors found by ruff. Make sure to follow best practices and maintain code style."
    fi
}

fix_typecheck() {
    print_header "🔍 Running Type Check"
    echo "Running mypy..."
    mypy . || true
    echo ""
    read -p "Run Claude to fix type errors? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        claude "Fix all type checking errors found by mypy. Add proper type hints where missing."
    fi
}

run_tests() {
    print_header "🧪 Running Tests"
    echo "Running pytest..."
    pytest -v || true
    echo ""
    read -p "Run Claude to fix test failures? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        claude "Fix all failing tests. Ensure tests pass and maintain good test coverage."
    fi
}

add_docs() {
    print_header "📝 Add Documentation"
    read -p "Enter file or directory to document: " target
    if [ -z "$target" ]; then
        target="."
    fi
    claude "Add comprehensive documentation to $target including docstrings, type hints, and comments."
}

refactor_code() {
    print_header "🔄 Refactor Code"
    read -p "Enter file or directory to refactor: " target
    if [ -z "$target" ]; then
        echo "Please specify a file or directory."
        return
    fi
    claude "Refactor $target to improve code quality, readability, and maintainability. Follow best practices."
}

security_audit() {
    print_header "🔒 Security Audit"
    read -p "Audit specific file/directory (leave blank for full project): " target
    if [ -z "$target" ]; then
        target="."
    fi
    claude --model opusplan "Perform a thorough security audit of $target. Check for vulnerabilities, security best practices, and potential issues."
}

review_status() {
    print_header "📊 Project Status Review"

    echo "Git Status:"
    git status -sb
    echo ""

    echo "Recent Commits:"
    git log --oneline -5
    echo ""

    echo "TODO Items:"
    grep -r "TODO" --include="*.py" --include="*.md" . 2>/dev/null | head -10 || echo "No TODOs found"
    echo ""

    read -p "Run Claude to review and organize? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        claude "Review our current project status, check for incomplete tasks, and suggest next steps."
    fi
}

custom_prompt() {
    print_header "🎯 Custom Claude Prompt"
    echo "Enter your prompt (press Ctrl+D when done):"
    echo ""

    # Read multi-line input
    prompt=$(cat)

    if [ -n "$prompt" ]; then
        claude "$prompt"
    else
        echo "No prompt entered."
    fi
}

deploy_workflow() {
    print_header "🚀 Deployment Workflow"
    echo "Select deployment target:"
    echo "  1) Docker build and test"
    echo "  2) Kubernetes deployment"
    echo "  3) Production readiness check"
    echo ""
    read -p "Enter choice [1-3]: " deploy_choice

    case $deploy_choice in
        1)
            claude "Help me build and test Docker containers. Check Dockerfiles, build images, and validate containers."
            ;;
        2)
            claude "Review Kubernetes manifests and help deploy to cluster. Ensure configurations are correct."
            ;;
        3)
            claude "Perform a production readiness check. Review code quality, tests, documentation, security, and deployment configurations."
            ;;
        *)
            echo "Invalid choice"
            ;;
    esac
}

# Main loop
while true; do
    show_menu

    case $choice in
        1) fix_linting ;;
        2) fix_typecheck ;;
        3) run_tests ;;
        4) add_docs ;;
        5) refactor_code ;;
        6) security_audit ;;
        7) review_status ;;
        8) custom_prompt ;;
        9) deploy_workflow ;;
        0) echo "Goodbye! 👋"; exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
    clear
done
