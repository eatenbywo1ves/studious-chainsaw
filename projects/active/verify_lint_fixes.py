#!/usr/bin/env python3
"""
Verify that all lint errors have been fixed
"""

import subprocess
import sys
from pathlib import Path

def check_file_with_flake8(file_path):
    """Check a single file with flake8 and return any errors"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flake8", str(file_path)],
            capture_output=True,
            text=True,
            cwd=str(Path(file_path).parent)
        )
        return result.stdout.strip() if result.stdout else None
    except Exception as e:
        return f"Error checking {file_path}: {e}"

def main():
    base_path = Path(r"C:\Users\Corbin\development")
    
    # List of Python files to verify
    python_files = [
        "activate.py",
        "analyze_sample.py", 
        "demo_hot_reload.py",
        "demo_new_architecture.py",
        "doctor.py",
        "run_flake8.py",
        "check_lint.py",
        "verify_lint_fixes.py"
    ]
    
    print("=" * 70)
    print("VERIFYING LINT FIXES")
    print("=" * 70)
    
    files_checked = 0
    files_with_errors = 0
    all_errors = []
    
    for file_name in python_files:
        file_path = base_path / file_name
        if not file_path.exists():
            print(f"⚠️  Skipping {file_name} (not found)")
            continue
            
        files_checked += 1
        errors = check_file_with_flake8(file_path)
        
        if errors:
            files_with_errors += 1
            print(f"❌ {file_name}: Found issues")
            for line in errors.split('\n'):
                if line:
                    all_errors.append(f"  {line}")
        else:
            print(f"✅ {file_name}: Clean")
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Files checked: {files_checked}")
    print(f"Files with errors: {files_with_errors}")
    
    if all_errors:
        print("\n❌ REMAINING LINT ERRORS:")
        for error in all_errors:
            print(error)
        return 1
    else:
        print("\n✅ ALL FILES PASS LINT CHECKS!")
        return 0

if __name__ == "__main__":
    sys.exit(main())