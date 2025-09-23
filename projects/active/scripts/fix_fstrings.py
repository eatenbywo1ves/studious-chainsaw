#!/usr/bin/env python3
"""
Script to fix f-string missing placeholders (F541)
Converts f-strings without placeholders to regular strings
"""

import re
import subprocess
from pathlib import Path


def get_fstring_violations():
    """Get list of f-string violations from flake8"""
    result = subprocess.run(
        ["python", "-m", "flake8", "--select=F541", "."],
        capture_output=True,
        text=True,
        cwd=Path.cwd(),
    )

    violations = []
    for line in result.stdout.strip().split("\n"):
        if line and "F541" in line:
            # Parse: ./file.py:123:9: F541 f-string is missing placeholders
            parts = line.split(":")
            if len(parts) >= 4:
                file_path = parts[0].lstrip(".\\/")
                line_num = int(parts[1])
                violations.append({"file": file_path, "line": line_num})

    return violations


def fix_fstring_in_file(file_path, line_num):
    """Fix f-string in specific file and line"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if line_num <= len(lines):
            line = lines[line_num - 1]

            # Convert f"string" to "string" and f'string' to 'string'
            # Handle various f-string patterns

            # Pattern 1: f"..." -> "..."
            modified_line = re.sub(r'\bf"([^"]*)"', r'"\1"', line)

            # Pattern 2: f'...' -> '...'
            modified_line = re.sub(r"\bf'([^']*)\'", r"'\1'", modified_line)

            # Pattern 3: f"""...""" -> """..."""
            modified_line = re.sub(
                r'\bf"""(.*?)"""', r'"""\1"""', modified_line, flags=re.DOTALL
            )

            # Pattern 4: f'''...''' -> '''...'''
            modified_line = re.sub(
                r"\bf'''(.*?)'''", r"'''\1'''", modified_line, flags=re.DOTALL
            )

            if modified_line != line:
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
    print("Finding f-string violations...")
    violations = get_fstring_violations()

    if not violations:
        print("No f-string violations found!")
        return

    print(f"Found {len(violations)} f-string violations")

    fixed = 0
    for violation in violations:
        file_path = violation["file"]
        line_num = violation["line"]

        print(f"Fixing {file_path}:{line_num}")

        if fix_fstring_in_file(file_path, line_num):
            fixed += 1
        else:
            print(f"Failed to fix {file_path}:{line_num}")

    print(f"\nFixed {fixed}/{len(violations)} f-string violations")

    # Run flake8 again to check remaining issues
    print("\nChecking remaining F541 violations...")
    result = subprocess.run(
        ["python", "-m", "flake8", "--select=F541", "."], capture_output=True, text=True
    )

    remaining = len(
        [line for line in result.stdout.strip().split("\n") if line and "F541" in line]
    )
    print(f"Remaining F541 violations: {remaining}")


if __name__ == "__main__":
    main()
