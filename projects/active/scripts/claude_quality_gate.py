#!/usr/bin/env python3
"""
Claude Code Quality Gate Integration
Automated security and quality validation for Claude Code workflows
"""

import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Tuple


class ClaudeQualityGate:
    """Quality gate specifically designed for Claude Code interactions"""

    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path.cwd()
        self.results = {
            "timestamp": time.time(),
            "passed": True,
            "security_score": 0,
            "quality_score": 0,
            "mobile_friendly": True,
            "checks": {},
        }

    def check_security_critical_files(self) -> Tuple[bool, Dict]:
        """Validate security-critical files are properly maintained"""
        security_files = ["shared/security/mfa.py", "shared/security/rbac.py"]

        results = {"files_checked": [], "issues": []}
        all_passed = True

        for file_path in security_files:
            full_path = self.project_root / file_path
            if not full_path.exists():
                results["issues"].append(f"Missing security file: {file_path}")
                all_passed = False
                continue

            results["files_checked"].append(file_path)

            # Check syntax
            syntax_result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(full_path)],
                capture_output=True,
                text=True,
            )

            if syntax_result.returncode != 0:
                results["issues"].append(f"Syntax error in {file_path}")
                all_passed = False

            # Check critical imports
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()

                if "from typing import" in content:
                    typing_imports = [
                        line
                        for line in content.split("\n")
                        if "from typing import" in line
                    ]
                    if typing_imports:
                        typing_line = typing_imports[0]
                        required = ["Tuple", "Optional", "Dict"]
                        for req in required:
                            if req not in typing_line:
                                results["issues"].append(
                                    f"Missing {req} import in {file_path}"
                                )
                                all_passed = False
            except Exception as e:
                results["issues"].append(f"Error reading {file_path}: {e}")
                all_passed = False

        return all_passed, results

    def check_automation_scripts(self) -> Tuple[bool, Dict]:
        """Validate our automation scripts are secure and functional"""
        script_files = [
            "scripts/claude_security_check.py",
            "scripts/fix_bare_except.py",
            "scripts/fix_fstrings.py",
            "scripts/fix_unused_variables.py",
        ]

        results = {"scripts_checked": [], "issues": []}
        all_passed = True

        for script_path in script_files:
            full_path = self.project_root / script_path
            if not full_path.exists():
                results["issues"].append(f"Missing script: {script_path}")
                all_passed = False
                continue

            results["scripts_checked"].append(script_path)

            # Syntax validation
            syntax_result = subprocess.run(
                [sys.executable, "-m", "py_compile", str(full_path)],
                capture_output=True,
                text=True,
            )

            if syntax_result.returncode != 0:
                results["issues"].append(f"Script syntax error: {script_path}")
                all_passed = False

        return all_passed, results

    def check_flake8_configuration(self) -> Tuple[bool, Dict]:
        """Validate flake8 configuration is security-appropriate"""
        flake8_config = self.project_root / ".flake8"
        results = {"config_found": False, "issues": []}

        if not flake8_config.exists():
            results["issues"].append("Missing .flake8 configuration")
            return False, results

        results["config_found"] = True

        try:
            with open(flake8_config, "r", encoding="utf-8") as f:
                config_content = f.read()

            # Check for security-appropriate settings
            required_settings = ["max-line-length", "exclude", "extend-ignore"]

            for setting in required_settings:
                if setting not in config_content:
                    results["issues"].append(f"Missing {setting} in .flake8")

            # Check for security-risky ignores
            risky_ignores = ["F401", "E999", "F811"]  # Don't ignore these
            for risky in risky_ignores:
                if f"extend-ignore = {risky}" in config_content:
                    results["issues"].append(f"Risky ignore: {risky}")

        except Exception as e:
            results["issues"].append(f"Error reading .flake8: {e}")
            return False, results

        return len(results["issues"]) == 0, results

    def check_mobile_optimization(self) -> Tuple[bool, Dict]:
        """Check for mobile-friendly command patterns"""
        mobile_files = [
            "scripts/mobile_security_aliases.sh",
            ".claude/claude_security_workflow.md",
        ]

        results = {"mobile_files": [], "issues": []}
        all_passed = True

        for file_path in mobile_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                results["mobile_files"].append(file_path)
            else:
                results["issues"].append(f"Missing mobile optimization: {file_path}")
                all_passed = False

        return all_passed, results

    def run_quality_gate(self) -> Dict:
        """Execute complete Claude Code quality gate"""
        print("Claude Code Quality Gate Starting...")
        print("=" * 50)

        # Security Critical Files Check
        print("1. Validating security-critical files...")
        sec_passed, sec_results = self.check_security_critical_files()
        self.results["checks"]["security_files"] = sec_results
        if not sec_passed:
            self.results["passed"] = False
            print(f"   X Security files: {len(sec_results['issues'])} issues")
        else:
            print(f"   OK Security files: {len(sec_results['files_checked'])} files OK")

        # Automation Scripts Check
        print("2. Validating automation scripts...")
        script_passed, script_results = self.check_automation_scripts()
        self.results["checks"]["automation_scripts"] = script_results
        if not script_passed:
            self.results["passed"] = False
            print(f"   X Scripts: {len(script_results['issues'])} issues")
        else:
            print(f"   OK Scripts: {len(script_results['scripts_checked'])} scripts OK")

        # Configuration Check
        print("3. Validating configuration...")
        config_passed, config_results = self.check_flake8_configuration()
        self.results["checks"]["configuration"] = config_results
        if not config_passed:
            self.results["passed"] = False
            print(f"   X Config: {len(config_results['issues'])} issues")
        else:
            print("   OK Configuration: .flake8 OK")

        # Mobile Optimization Check
        print("4. Validating mobile optimization...")
        mobile_passed, mobile_results = self.check_mobile_optimization()
        self.results["checks"]["mobile_optimization"] = mobile_results
        if not mobile_passed:
            self.results["mobile_friendly"] = False
            print(
                f"   WARNING Mobile: {len(mobile_results['issues'])} optimizations missing"
            )
        else:
            print(f"   OK Mobile: {len(mobile_results['mobile_files'])} files OK")

        # Calculate scores
        total_checks = 4
        passed_checks = sum([sec_passed, script_passed, config_passed, mobile_passed])
        self.results["security_score"] = int((passed_checks / total_checks) * 100)
        self.results["quality_score"] = self.results["security_score"]

        print("=" * 50)
        if self.results["passed"]:
            print("QUALITY GATE PASSED")
            print(f"   Security Score: {self.results['security_score']}%")
            print("   Ready for Claude Code development!")
        else:
            print("QUALITY GATE FAILED")
            print("   Issues found - review and fix before development")

        return self.results

    def print_detailed_results(self):
        """Print detailed results for issue resolution"""
        if not self.results["passed"]:
            print("\n" + "=" * 50)
            print("DETAILED ISSUES REPORT")
            print("=" * 50)

            for check_name, check_results in self.results["checks"].items():
                if "issues" in check_results and check_results["issues"]:
                    print(f"\n{check_name.upper()} ISSUES:")
                    for issue in check_results["issues"]:
                        print(f"  • {issue}")


def main():
    """Main function for Claude Code quality gate"""
    gate = ClaudeQualityGate()
    results = gate.run_quality_gate()

    if not results["passed"]:
        gate.print_detailed_results()
        print("\nRun individual checks to resolve issues:")
        print("  python scripts/claude_security_check.py")
        print("  source scripts/mobile_security_aliases.sh")
        return 1
    else:
        print("\nAll systems ready for secure Claude Code development!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
