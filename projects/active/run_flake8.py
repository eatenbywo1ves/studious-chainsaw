#!/usr/bin/env python
import subprocess
import sys
import os

os.chdir(r"C:\Users\Corbin\development")
result = subprocess.run([sys.executable, "-m", "flake8", "."], 
                       capture_output=True, text=True)
print(result.stdout)
print(result.stderr, file=sys.stderr)
sys.exit(result.returncode)