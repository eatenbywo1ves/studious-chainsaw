#!/usr/bin/env python3
"""
Automated Whitespace Fixing Script

Fixes whitespace and formatting issues:
- Removes trailing whitespace
- Fixes blank lines with whitespace
- Ensures files end with newline
- Fixes indentation issues
"""

import re
import sys
from pathlib import Path


def fix_whitespace(file_path):
    """Fix whitespace issues in a Python file"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        original_content = content

        # Remove trailing whitespace from all lines
        content = re.sub(r"[ \t]+$", "", content, flags=re.MULTILINE)

        # Fix blank lines that contain only whitespace
        content = re.sub(r"^\s*$", "", content, flags=re.MULTILINE)

        # Ensure file ends with exactly one newline
        content = content.rstrip() + "\n"

        # Fix multiple consecutive blank lines (max 2)
        content = re.sub(r"\n{4,}", "\n\n\n", content)

        if content != original_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        return False

    except Exception as e:
        print(f"Error fixing whitespace in {file_path}: {e}")
        return False


def fix_bare_except(file_path):
    """Fix bare except clauses"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        original_content = content

        # Replace bare except: with except Exception:
        content = re.sub(
            r"except\s*:\s*$", "except Exception:", content, flags=re.MULTILINE
        )

        if content != original_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Fixed bare except clauses in {file_path}")
            return True
        return False

    except Exception as e:
        print(f"Error fixing bare except in {file_path}: {e}")
        return False


def fix_python_file(file_path):
    """Fix all whitespace issues in a Python file"""
    print(f"Processing {file_path}...")

    changes_made = False

    # Fix whitespace issues
    if fix_whitespace(file_path):
        changes_made = True

    # Fix bare except clauses
    if fix_bare_except(file_path):
        changes_made = True

    if changes_made:
        print(f"✅ Fixed whitespace issues in {file_path}")
    else:
        print(f"ℹ️  No whitespace issues found in {file_path}")


def fix_directory(directory_path):
    """Fix all Python files in a directory recursively"""
    directory = Path(directory_path)

    if not directory.exists():
        print(f"Directory {directory_path} does not exist")
        return

    # Find all Python files
    python_files = list(directory.rglob("*.py"))

    print(f"Found {len(python_files)} Python files to process")

    fixed_files = 0
    failed_files = []

    for py_file in python_files:
        try:
            fix_python_file(py_file)
            fixed_files += 1
        except Exception as e:
            print(f"❌ Failed to process {py_file}: {e}")
            failed_files.append(py_file)

    print("\n✅ Whitespace fixing complete!")
    print(f"Successfully processed: {fixed_files}/{len(python_files)} files")

    if failed_files:
        print("\n❌ Failed files:")
        for failed_file in failed_files:
            print(f"  - {failed_file}")


def main():
    """Main function"""
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    else:
        target_path = "."

    print("🧹 Starting automated whitespace fixing...")
    print(f"Target: {target_path}")

    target = Path(target_path)

    if target.is_file() and target.suffix == ".py":
        fix_python_file(target)
    elif target.is_dir():
        fix_directory(target)
    else:
        print(f"Invalid target: {target_path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
