#!/usr/bin/env python3
"""
Script to fix unused variable violations (F841)
This script will either remove unused variables or prefix them with underscore
"""

import re
import subprocess
from pathlib import Path


def get_unused_variables():
    """Get list of unused variables from flake8"""
    result = subprocess.run(
        ["python", "-m", "flake8", "--select=F841", "."],
        capture_output=True,
        text=True,
        cwd=Path.cwd(),
    )

    violations = []
    for line in result.stdout.strip().split("\n"):
        if line and "F841" in line:
            # Parse: ./file.py:123:9: F841 local variable 'var_name' is assigned to but never used
            parts = line.split(":")
            if len(parts) >= 4:
                file_path = parts[0].lstrip(".\\/")
                line_num = int(parts[1])
                message = ":".join(parts[3:])

                # Extract variable name
                match = re.search(
                    r"local variable '(\w+)' is assigned to but never used", message
                )
                if match:
                    var_name = match.group(1)
                    violations.append(
                        {"file": file_path, "line": line_num, "variable": var_name}
                    )

    return violations


def fix_unused_variable(file_path, line_num, var_name):
    """Fix unused variable by prefixing with underscore"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if line_num <= len(lines):
            line = lines[line_num - 1]

            # Replace variable assignment with underscore prefix
            # Handle various patterns: var = ..., var, ... = ..., etc.

            # Pattern 1: Simple assignment "var = ..."
            if f"{var_name} = " in line:
                lines[line_num - 1] = line.replace(f"{var_name} = ", f"_{var_name} = ")

            # Pattern 2: Multiple assignment "var1, var2 = ..."
            elif f"{var_name}," in line or f", {var_name}" in line:
                lines[line_num - 1] = re.sub(f"\\b{var_name}\\b", f"_{var_name}", line)

            # Pattern 3: For loop "for var in ..."
            elif f"for {var_name} in " in line:
                lines[line_num - 1] = line.replace(
                    f"for {var_name} in ", f"for _{var_name} in "
                )

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

            return True
    except Exception as e:
        print(f"Error fixing {file_path}:{line_num} - {e}")
        return False

    return False


def main():
    """Main function"""
    print("Finding unused variables...")
    violations = get_unused_variables()

    if not violations:
        print("No unused variables found!")
        return

    print(f"Found {len(violations)} unused variables")

    fixed = 0
    for violation in violations:
        file_path = violation["file"]
        line_num = violation["line"]
        var_name = violation["variable"]

        print(f"Fixing {file_path}:{line_num} - variable '{var_name}'")

        if fix_unused_variable(file_path, line_num, var_name):
            fixed += 1
        else:
            print(f"Failed to fix {file_path}:{line_num}")

    print(f"\nFixed {fixed}/{len(violations)} unused variables")

    # Run flake8 again to check remaining issues
    print("\nChecking remaining F841 violations...")
    result = subprocess.run(
        ["python", "-m", "flake8", "--select=F841", "."], capture_output=True, text=True
    )

    remaining = len(
        [line for line in result.stdout.strip().split("\n") if line and "F841" in line]
    )
    print(f"Remaining F841 violations: {remaining}")


if __name__ == "__main__":
    main()
