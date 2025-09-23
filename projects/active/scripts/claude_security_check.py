#!/usr/bin/env python3
"""
Claude Code Security Integration Script
Designed for mobile-friendly security validation workflow
"""

import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple


class SecurityValidator:
    """Security validation for Claude Code workflows"""

    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path.cwd()
        self.security_critical_paths = [
            "shared/security/",
            "agents/*/security/",
            "**/auth*.py",
            "**/mfa*.py",
            "**/rbac*.py",
        ]

    def validate_syntax_security(self, file_path: Path) -> Tuple[bool, str]:
        """Validate Python syntax for security-critical files"""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(file_path)],
                capture_output=True,
                text=True,
                cwd=self.project_root,
            )
            if result.returncode == 0:
                return True, "✓ Syntax valid"
            else:
                return False, f"✗ Syntax error: {result.stderr.strip()}"
        except Exception as e:
            return False, f"✗ Validation error: {e}"

    def check_critical_imports(self, file_path: Path) -> Tuple[bool, List[str]]:
        """Check for missing critical imports in security modules"""
        critical_imports = {
            "mfa.py": ["Tuple", "Optional", "Dict", "List"],
            "rbac.py": ["Tuple", "Optional", "Set", "Dict"],
            "auth": ["Optional", "Dict"],
        }

        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            filename = file_path.name.lower()
            for pattern, required_imports in critical_imports.items():
                if pattern in filename:
                    for import_name in required_imports:
                        if "from typing import" in content:
                            typing_line = [
                                line
                                for line in content.split("\n")
                                if "from typing import" in line
                            ][0]
                            if import_name not in typing_line:
                                issues.append(
                                    f"Missing {import_name} in typing imports"
                                )

            return len(issues) == 0, issues
        except Exception as e:
            return False, [f"Error checking imports: {e}"]

    def validate_exception_handling(self, file_path: Path) -> Tuple[bool, List[str]]:
        """Check for insecure exception handling patterns"""
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                if "except:" in line and "except Exception:" not in line:
                    issues.append(
                        f"Line {line_num}: Bare except clause (security risk)"
                    )

            return len(issues) == 0, issues
        except Exception as e:
            return False, [f"Error checking exceptions: {e}"]

    def run_security_scan(self) -> Dict[str, any]:
        """Comprehensive security scan for Claude Code workflows"""
        results = {
            "passed": True,
            "security_critical_files": [],
            "syntax_issues": [],
            "import_issues": [],
            "exception_issues": [],
            "summary": "",
        }

        # Find security-critical files
        security_files = []
        for pattern in self.security_critical_paths:
            security_files.extend(self.project_root.glob(pattern))

        security_files = [
            f for f in security_files if f.is_file() and f.suffix == ".py"
        ]
        results["security_critical_files"] = [str(f) for f in security_files]

        # Validate each security-critical file
        for file_path in security_files:
            # Syntax check
            syntax_ok, syntax_msg = self.validate_syntax_security(file_path)
            if not syntax_ok:
                results["syntax_issues"].append(f"{file_path}: {syntax_msg}")
                results["passed"] = False

            # Import check
            imports_ok, import_issues = self.check_critical_imports(file_path)
            if not imports_ok:
                for issue in import_issues:
                    results["import_issues"].append(f"{file_path}: {issue}")
                results["passed"] = False

            # Exception handling check
            exceptions_ok, exception_issues = self.validate_exception_handling(
                file_path
            )
            if not exceptions_ok:
                for issue in exception_issues:
                    results["exception_issues"].append(f"{file_path}: {issue}")
                results["passed"] = False

        # Generate summary
        total_issues = (
            len(results["syntax_issues"])
            + len(results["import_issues"])
            + len(results["exception_issues"])
        )

        if results["passed"]:
            results["summary"] = (
                f"✓ Security scan passed - {len(security_files)} files validated"
            )
        else:
            results["summary"] = f"✗ Security scan failed - {total_issues} issues found"

        return results


def main():
    """Main function for Claude Code integration"""
    validator = SecurityValidator()
    results = validator.run_security_scan()

    print("=" * 50)
    print("CLAUDE CODE SECURITY VALIDATION")
    print("=" * 50)
    print(results["summary"])
    print()

    if results["security_critical_files"]:
        print(
            f"Scanned {len(results['security_critical_files'])} security-critical files:"
        )
        for file_path in results["security_critical_files"]:
            print(f"  • {file_path}")
        print()

    if results["syntax_issues"]:
        print("SYNTAX ISSUES:")
        for issue in results["syntax_issues"]:
            print(f"  {issue}")
        print()

    if results["import_issues"]:
        print("IMPORT ISSUES:")
        for issue in results["import_issues"]:
            print(f"  {issue}")
        print()

    if results["exception_issues"]:
        print("EXCEPTION HANDLING ISSUES:")
        for issue in results["exception_issues"]:
            print(f"  {issue}")
        print()

    return 0 if results["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
