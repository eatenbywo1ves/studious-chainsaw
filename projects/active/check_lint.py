#!/usr/bin/env python3
"""
Run flake8 on specific Python files and show results
"""

import subprocess
import sys
from pathlib import Path

# List of Python files to check
files_to_check = [
    "activate.py",
    "analyze_sample.py",
    "demo_hot_reload.py",
    "demo_new_architecture.py",
    "doctor.py",
    "run_flake8.py",
    "check_lint.py"
]

base_path = Path(r"C:\Users\Corbin\development")
total_errors = 0

print("=" * 70)
print("RUNNING FLAKE8 LINT CHECKS")
print("=" * 70)

for file_name in files_to_check:
    file_path = base_path / file_name
    if not file_path.exists():
        continue
        
    print(f"\nChecking {file_name}...")
    
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flake8", str(file_path), "--config", str(base_path / ".flake8")],
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            print(f"  ❌ Issues found:")
            for line in result.stdout.strip().split('\n'):
                if line:
                    print(f"    {line}")
                    total_errors += 1
        else:
            print(f"  ✅ No issues found")
            
    except Exception as e:
        print(f"  ⚠️ Could not check: {e}")

print("\n" + "=" * 70)
print(f"SUMMARY: {total_errors} total lint errors found")
print("=" * 70)

sys.exit(0 if total_errors == 0 else 1)