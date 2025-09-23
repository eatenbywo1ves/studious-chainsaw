#!/usr/bin/env python3
"""
Verify lint fixes by running flake8 on modified files
"""

import subprocess
import sys
from pathlib import Path

def check_file(file_path):
    """Run flake8 on a single file"""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flake8", str(file_path), "--config", ".flake8"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1

def main():
    """Check all modified files"""
    files_to_check = [
        "activate.py",
        "analyze_sample.py",
        "demo_hot_reload.py",
        "doctor.py",
        "check_lint.py"
    ]
    
    print("=" * 60)
    print("LINT VERIFICATION RESULTS")
    print("=" * 60)
    
    total_errors = 0
    base_path = Path(__file__).parent
    
    for filename in files_to_check:
        file_path = base_path / filename
        if not file_path.exists():
            print(f"\n❌ {filename}: File not found")
            continue
            
        print(f"\nChecking {filename}...")
        output, returncode = check_file(file_path)
        
        if output:
            print(f"  Issues found:")
            for line in output.split('\n'):
                if line:
                    print(f"    {line}")
                    total_errors += 1
        else:
            print(f"  ✅ No issues found!")
    
    print("\n" + "=" * 60)
    if total_errors == 0:
        print("✅ SUCCESS: All files pass lint checks!")
    else:
        print(f"❌ FAILED: {total_errors} lint errors found")
    print("=" * 60)
    
    return 0 if total_errors == 0 else 1

if __name__ == "__main__":
    sys.exit(main())