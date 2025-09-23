#!/usr/bin/env python3
"""
Automated Import Fixing Script

Fixes common import issues across the codebase:
- Removes unused imports
- Sorts imports according to PEP 8
- Fixes import organization
- Handles missing numpy import
"""

import subprocess
import sys
from pathlib import Path
import re


def run_command(cmd, cwd=None):
    """Run command and return success status"""
    try:
        result = subprocess.run(
            cmd, shell=True, cwd=cwd, capture_output=True, text=True
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        print(f"Error running command {cmd}: {e}")
        return False, "", str(e)


def fix_missing_imports(file_path):
    """Fix missing imports in Python files"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        original_content = content

        # Fix missing numpy import if np is used
        if re.search(r"\bnp\.", content) and "import numpy" not in content:
            # Add numpy import after other imports
            import_section = re.search(
                r"^((?:from .* import .*\n|import .*\n)*)", content, re.MULTILINE
            )
            if import_section:
                imports = import_section.group(1)
                new_imports = imports + "import numpy as np\n"
                content = content.replace(imports, new_imports, 1)
                print(f"Added missing numpy import to {file_path}")

        # Fix missing pandas import if pd is used
        if re.search(r"\bpd\.", content) and "import pandas" not in content:
            import_section = re.search(
                r"^((?:from .* import .*\n|import .*\n)*)", content, re.MULTILINE
            )
            if import_section:
                imports = import_section.group(1)
                new_imports = imports + "import pandas as pd\n"
                content = content.replace(imports, new_imports, 1)
                print(f"Added missing pandas import to {file_path}")

        if content != original_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        return False

    except Exception as e:
        print(f"Error fixing imports in {file_path}: {e}")
        return False


def remove_unused_imports(file_path):
    """Remove unused imports using autoflake"""
    cmd = f"python -m autoflake --remove-all-unused-imports --in-place {file_path}"
    success, stdout, stderr = run_command(cmd)
    if not success:
        print(f"Warning: autoflake failed for {file_path}: {stderr}")
    return success


def sort_imports(file_path):
    """Sort imports using isort"""
    cmd = f"python -m isort {file_path}"
    success, stdout, stderr = run_command(cmd)
    if not success:
        print(f"Warning: isort failed for {file_path}: {stderr}")
    return success


def format_code(file_path):
    """Format code using black"""
    cmd = f"python -m black {file_path}"
    success, stdout, stderr = run_command(cmd)
    if not success:
        print(f"Warning: black failed for {file_path}: {stderr}")
    return success


def fix_python_file(file_path):
    """Fix all import and formatting issues in a Python file"""
    print(f"Processing {file_path}...")

    # Step 1: Fix missing imports
    fix_missing_imports(file_path)

    # Step 2: Remove unused imports (if autoflake is available)
    try:
        remove_unused_imports(file_path)
    except Exception:
        print("autoflake not available, skipping unused import removal")

    # Step 3: Sort imports
    sort_imports(file_path)

    # Step 4: Format code
    format_code(file_path)

    print(f"✅ Completed processing {file_path}")


def fix_directory(directory_path):
    """Fix all Python files in a directory recursively"""
    directory = Path(directory_path)

    if not directory.exists():
        print(f"Directory {directory_path} does not exist")
        return

    # Find all Python files
    python_files = list(directory.rglob("*.py"))

    print(f"Found {len(python_files)} Python files to process")

    failed_files = []

    for py_file in python_files:
        try:
            fix_python_file(py_file)
        except Exception as e:
            print(f"❌ Failed to process {py_file}: {e}")
            failed_files.append(py_file)

    print("\n✅ Processing complete!")
    print(
        f"Successfully processed: {len(python_files) - len(failed_files)}/{len(python_files)} files"
    )

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

    print("🔧 Starting automated import and formatting fixes...")
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
