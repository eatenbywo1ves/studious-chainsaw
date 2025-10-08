#!/usr/bin/env python3
"""
Update import paths after directory reorganization.
This script updates all Python imports to reflect the new directory structure.
"""

import os
import re
from pathlib import Path

# Define import mappings
IMPORT_MAPPINGS = {
    'from libs.constants.constants import': 'from libs.constants.constants import',
    'import libs.constants.constants as constants': 'import libs.constants.constants as constants',
    'from libs.utils.exceptions import': 'from libs.utils.exceptions import',
    'import libs.utils.exceptions as exceptions': 'import libs.utils.exceptions as exceptions',
    'from libs.utils.validation import': 'from libs.utils.validation import',
    'import libs.utils.validation as validation': 'import libs.utils.validation as validation',
}

def update_imports(file_path):
    """Update imports in a single Python file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content
        for old_import, new_import in IMPORT_MAPPINGS.items():
            content = re.sub(old_import, new_import, content)

        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Updated imports in: {file_path}")
            return True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    return False

def find_python_files(root_dir):
    """Find all Python files in the directory tree."""
    python_files = []
    for root, dirs, files in os.walk(root_dir):
        # Skip hidden directories and __pycache__
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
        for file in files:
            if file.endswith('.py'):
                python_files.append(Path(root) / file)
    return python_files

def main():
    """Main function to update all imports."""
    root_dir = Path(__file__).parent

    print("Scanning for Python files...")
    python_files = find_python_files(root_dir)

    print(f"Found {len(python_files)} Python files")

    updated_count = 0
    for file_path in python_files:
        if update_imports(file_path):
            updated_count += 1

    print("\nImport update complete!")
    print(f"Updated {updated_count} files")

if __name__ == "__main__":
    main()
