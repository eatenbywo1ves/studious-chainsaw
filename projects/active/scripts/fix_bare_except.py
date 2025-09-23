#!/usr/bin/env python3
"""
Script to fix bare except clauses (E722)
Replaces bare 'except:' with 'except Exception:'
"""

import subprocess
from pathlib import Path


def get_bare_except_violations():
    """Get list of bare except violations from flake8"""
    result = subprocess.run(
        ["python", "-m", "flake8", "--select=E722", "."],
        capture_output=True,
        text=True,
        cwd=Path.cwd(),
    )

    violations = []
    for line in result.stdout.strip().split("\n"):
        if line and "E722" in line:
            # Parse: ./file.py:123:9: E722 do not use bare 'except'
            parts = line.split(":")
            if len(parts) >= 4:
                file_path = parts[0].lstrip(".\\/")
                line_num = int(parts[1])
                # Skip node_modules and other non-Python directories
                if "node_modules" not in file_path and "venv" not in file_path:
                    violations.append({"file": file_path, "line": line_num})

    return violations


def fix_bare_except_in_file(file_path, line_num):
    """Fix bare except in specific file and line"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if line_num <= len(lines):
            line = lines[line_num - 1]

            # Replace bare except with except Exception
            if "except:" in line:
                modified_line = line.replace("except:", "except Exception:")
                lines[line_num - 1] = modified_line

                with open(file_path, "w", encoding="utf-8") as f:
                    f.writelines(lines)

                return True
    except Exception as e:
        print(f"Error fixing {file_path}:{line_num} - {e}")
        return False

    return False


def main():
    """Main function"""
    print("Finding bare except violations...")
    violations = get_bare_except_violations()

    if not violations:
        print("No bare except violations found!")
        return

    print(f"Found {len(violations)} bare except violations")

    fixed = 0
    for violation in violations:
        file_path = violation["file"]
        line_num = violation["line"]

        print(f"Fixing {file_path}:{line_num}")

        if fix_bare_except_in_file(file_path, line_num):
            fixed += 1
        else:
            print(f"Failed to fix {file_path}:{line_num}")

    print(f"\nFixed {fixed}/{len(violations)} bare except violations")

    # Run flake8 again to check remaining issues
    print("\nChecking remaining E722 violations...")
    result = subprocess.run(
        ["python", "-m", "flake8", "--select=E722", "."], capture_output=True, text=True
    )

    remaining = len(
        [
            line
            for line in result.stdout.strip().split("\n")
            if line and "E722" in line and "node_modules" not in line
        ]
    )
    print(f"Remaining E722 violations: {remaining}")


if __name__ == "__main__":
    main()
