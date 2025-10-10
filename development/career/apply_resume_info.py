#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Apply Resume Information from Config File
==========================================

Reads resume_info.txt and updates both resume files automatically.
"""

import os
import sys
import shutil
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "resume_info.txt")
RESUME_MD = os.path.join(SCRIPT_DIR, "GAUNTLET_AI_RESUME.md")
RESUME_TXT = os.path.join(SCRIPT_DIR, "GAUNTLET_AI_RESUME_ATS.txt")

# ============================================================================
# FUNCTIONS
# ============================================================================

def read_config():
    """Read configuration from resume_info.txt"""
    if not os.path.exists(CONFIG_FILE):
        print(f"ERROR: {CONFIG_FILE} not found!")
        print("Please create resume_info.txt with your information.")
        return None

    config = {}
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()

    return config

def create_backup(file_path):
    """Create timestamped backup"""
    if not os.path.exists(file_path):
        print(f"WARNING: {file_path} not found!")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{file_path}.backup_{timestamp}"
    shutil.copy2(file_path, backup_path)
    return backup_path

def update_resume(file_path, config):
    """Update resume file with configuration"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Track changes
    changes = []

    # Update phone
    if 'PHONE' in config:
        old = '[NEED PHONE]'
        if old in content:
            content = content.replace(old, config['PHONE'])
            changes.append(f"Phone: {config['PHONE']}")

    # Update LinkedIn
    if 'LINKEDIN' in config:
        old = '[NEED LINKEDIN URL]'
        if old in content:
            content = content.replace(old, config['LINKEDIN'])
            changes.append(f"LinkedIn: {config['LINKEDIN']}")

    # Update education
    if all(k in config for k in ['DEGREE', 'MAJOR', 'UNIVERSITY', 'GRAD_YEAR']):
        education_line = f"{config['DEGREE']} in {config['MAJOR']} | {config['UNIVERSITY']} | {config['GRAD_YEAR']}"

        # Replace education placeholders
        old_education = "[NEED: Degree] in [NEED: Major] | [NEED: University Name] | [NEED: Graduation Year]"
        if old_education in content:
            content = content.replace(old_education, education_line)
            changes.append(f"Education: {education_line}")

    # Remove example lines
    examples = [
        "Example: B.S. Computer Science | University of Texas | 2022",
        "*Example: B.S. Computer Science | University of Texas | 2022*"
    ]
    for example in examples:
        if example in content:
            content = content.replace(f"\n{example}", "")
            content = content.replace(example, "")
            changes.append("Removed example line")

    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    return changes

# ============================================================================
# MAIN
# ============================================================================

def main():
    print("="*80)
    print("RESUME INFORMATION UPDATER")
    print("="*80)

    # Read configuration
    print("\nReading configuration from resume_info.txt...")
    config = read_config()

    if not config:
        print("\nERROR: Could not read configuration.")
        print("Please edit resume_info.txt with your information.")
        return 1

    # Display configuration
    print("\nConfiguration found:")
    print("-"*80)
    for key, value in config.items():
        print(f"  {key}: {value}")
    print("-"*80)

    # Validate required fields
    required = ['PHONE', 'LINKEDIN', 'DEGREE', 'MAJOR', 'UNIVERSITY', 'GRAD_YEAR']
    missing = [r for r in required if r not in config]

    if missing:
        print(f"\nWARNING: Missing fields: {', '.join(missing)}")
        print("Please update resume_info.txt with all required information.")
        return 1

    # Create backups
    print("\nCreating backups...")
    backup_md = create_backup(RESUME_MD)
    backup_txt = create_backup(RESUME_TXT)

    if backup_md:
        print(f"  Backed up: {os.path.basename(backup_md)}")
    if backup_txt:
        print(f"  Backed up: {os.path.basename(backup_txt)}")

    # Update files
    print("\nUpdating resume files...")

    print(f"\n  Updating {os.path.basename(RESUME_MD)}...")
    changes_md = update_resume(RESUME_MD, config)
    for change in changes_md:
        print(f"    - {change}")

    print(f"\n  Updating {os.path.basename(RESUME_TXT)}...")
    changes_txt = update_resume(RESUME_TXT, config)
    for change in changes_txt:
        print(f"    - {change}")

    # Summary
    print("\n" + "="*80)
    print("RESUME UPDATE COMPLETE!")
    print("="*80)

    print("\nUpdated files:")
    print(f"  - {RESUME_MD}")
    print(f"  - {RESUME_TXT}")

    print("\nBackup files:")
    if backup_md:
        print(f"  - {backup_md}")
    if backup_txt:
        print(f"  - {backup_txt}")

    print("\nFinal Information:")
    print("-"*80)
    print("  Name:       Mark R. Corbin")
    print("  Email:      markrcorbin88@gmail.com")
    print("  GitHub:     github.com/eatenbywo1ves")
    print(f"  Phone:      {config.get('PHONE', 'N/A')}")
    print(f"  LinkedIn:   {config.get('LINKEDIN', 'N/A')}")
    education = f"{config.get('DEGREE')} in {config.get('MAJOR')} | {config.get('UNIVERSITY')} | {config.get('GRAD_YEAR')}"
    print(f"  Education:  {education}")

    print("\n" + "="*80)
    print("NEXT STEPS:")
    print("="*80)
    print("1. Review updated resume files")
    print("2. Convert to PDF (if required)")
    print("3. Submit to Gauntlet AI: https://apply.gauntletai.com/application")
    print("\nYour resume is ready! Good luck with Gauntlet AI!")
    print("="*80)

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
