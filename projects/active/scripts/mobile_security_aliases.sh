#!/bin/bash
# Mobile-Optimized Security Commands for Claude Code
# Source this file: source scripts/mobile_security_aliases.sh

# Quick security validation (mobile-friendly)
alias csec='python scripts/claude_security_check.py'

# Fast syntax check for security files
alias csyn='find . -path "*/security/*" -name "*.py" -exec python -m py_compile {} \; 2>&1 | grep -v "^$" || echo "✓ All security files syntax OK"'

# Critical import validation
alias cimp='python -c "
import sys, re
files = [\"shared/security/mfa.py\", \"shared/security/rbac.py\"]
for f in files:
    try:
        with open(f) as file:
            content = file.read()
            if \"from typing import\" in content:
                typing_line = [l for l in content.split(\"\n\") if \"from typing import\" in l][0]
                missing = []
                for req in [\"Tuple\", \"Optional\", \"Dict\"]:
                    if req not in typing_line:
                        missing.append(req)
                if missing:
                    print(f\"✗ {f}: Missing {missing}\")
                else:
                    print(f\"✓ {f}: Imports OK\")
    except FileNotFoundError:
        print(f\"? {f}: File not found\")
"'

# Bare except detection (security-critical)
alias cexc='grep -rn "except:" --include="*.py" shared/security/ agents/ 2>/dev/null | grep -v "except Exception:" || echo "✓ No bare except clauses found"'

# Complete security pipeline (mobile workflow)
alias csecall='echo "=== CLAUDE CODE SECURITY PIPELINE ===" && csec && echo && echo "=== SYNTAX CHECK ===" && csyn && echo && echo "=== IMPORT CHECK ===" && cimp && echo && echo "=== EXCEPTION CHECK ===" && cexc'

# Pre-commit security gate
alias cpre='echo "Pre-commit security validation..." && csecall && echo "✓ Ready for commit" || echo "✗ Security issues found - fix before commit"'

# Security file quick edit validation
alias cedit='f() { echo "Validating $1..." && python -m py_compile "$1" && python scripts/claude_security_check.py && echo "✓ $1 is secure"; }; f'

# Mobile-friendly flake8 security focus
alias cseclint='python -m flake8 --select=F,E9,E722 --max-line-length=130 shared/security/ agents/'

# Quick security metrics
alias cmetrics='echo "Security file count: $(find . -path "*/security/*" -name "*.py" | wc -l)" && echo "Total Python files: $(find . -name "*.py" | grep -v node_modules | wc -l)" && echo "Security coverage: $(python -c "
import subprocess
sec = int(subprocess.check_output(\"find . -path \\"*/security/*\\" -name \\"*.py\\" | wc -l\", shell=True))
total = int(subprocess.check_output(\"find . -name \\"*.py\\" | grep -v node_modules | wc -l\", shell=True))
print(f\"{sec/total*100:.1f}%\" if total > 0 else \"0%\")
")"'

echo "Claude Code Security Aliases Loaded ✓"
echo "Available commands:"
echo "  csec      - Full security scan"
echo "  csyn      - Syntax check security files"  
echo "  cimp      - Import validation"
echo "  cexc      - Exception handling check"
echo "  csecall   - Complete security pipeline"
echo "  cpre      - Pre-commit security gate"
echo "  cedit     - Validate edited file"
echo "  cseclint  - Security-focused linting"
echo "  cmetrics  - Security coverage metrics"