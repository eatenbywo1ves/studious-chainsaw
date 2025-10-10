#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automated Resume Information Updater
=====================================

Prompts for missing personal information and updates both resume files automatically.
Creates backups before making changes.
"""

import os
import sys
import shutil
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESUME_MD = os.path.join(SCRIPT_DIR, "GAUNTLET_AI_RESUME.md")
RESUME_TXT = os.path.join(SCRIPT_DIR, "GAUNTLET_AI_RESUME_ATS.txt")

# Already confirmed information
CONFIRMED_INFO = {
    "name": "Mark R. Corbin",
    "email": "markrcorbin88@gmail.com",
    "github": "github.com/eatenbywo1ves"
}

# Placeholders to find and replace
PLACEHOLDERS = {
    "phone": "[NEED PHONE]",
    "linkedin": "[NEED LINKEDIN URL]",
    "degree": "[NEED: Degree]",
    "major": "[NEED: Major]",
    "university": "[NEED: University Name]",
    "grad_year": "[NEED: Graduation Year]"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def print_header():
    """Print script header"""
    print("=" * 80)
    print("AUTOMATED RESUME INFORMATION UPDATER")
    print("=" * 80)
    print("\nThis script will update your Gauntlet AI resume with personal information.")
    print("\nCONFIRMED INFORMATION (from codebase):")
    print(f"  Name:   {CONFIRMED_INFO['name']}")
    print(f"  Email:  {CONFIRMED_INFO['email']}")
    print(f"  GitHub: {CONFIRMED_INFO['github']}")
    print("\n" + "-" * 80)
    print("INFORMATION NEEDED FROM YOU:")
    print("-" * 80)

def get_user_input(prompt, example=None, optional=False):
    """Get user input with validation"""
    full_prompt = f"\n{prompt}"
    if example:
        full_prompt += f"\n  Example: {example}"
    if optional:
        full_prompt += "\n  (Press Enter to skip)"
    full_prompt += "\n  > "

    value = input(full_prompt).strip()

    if not value and not optional:
        print("  ⚠️  This field is required. Please provide a value.")
        return get_user_input(prompt, example, optional)

    return value

def create_backup(file_path):
    """Create backup of file"""
    if not os.path.exists(file_path):
        print(f"⚠️  Warning: {file_path} not found!")
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{file_path}.backup_{timestamp}"
    shutil.copy2(file_path, backup_path)
    print(f"✅ Backup created: {os.path.basename(backup_path)}")
    return backup_path

def update_file(file_path, replacements):
    """Update file with replacements"""
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found!")
        return False

    # Read file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Track replacements made
    changes_made = []

    # Apply replacements
    for key, value in replacements.items():
        if value:  # Only replace if value is provided
            old_value = PLACEHOLDERS[key] if key in PLACEHOLDERS else key
            if old_value in content:
                content = content.replace(old_value, value)
                changes_made.append(f"{key}: {old_value} → {value}")

    # Remove example line if education is filled
    if replacements.get('degree'):
        example_line = "Example: B.S. Computer Science | University of Texas | 2022"
        if example_line in content:
            # Remove the line and the preceding newline
            content = content.replace(f"\n{example_line}", "")
            content = content.replace(example_line, "")
            changes_made.append("Removed example line")

    # Write back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    return changes_made

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main function"""
    print_header()

    # Collect information from user
    user_info = {}

    # Phone number
    print("\n1. PHONE NUMBER")
    phone = get_user_input(
        "Enter your phone number:",
        example="(512) 555-1234 or +1-512-555-1234",
        optional=False
    )
    user_info['phone'] = phone

    # LinkedIn
    print("\n2. LINKEDIN PROFILE")
    print("   (If you don't have LinkedIn, you can skip this)")
    linkedin = get_user_input(
        "Enter your LinkedIn URL:",
        example="linkedin.com/in/markrcorbin",
        optional=True
    )
    if linkedin:
        # Ensure it's a proper format
        if not linkedin.startswith("linkedin.com"):
            if not linkedin.startswith("http"):
                linkedin = f"linkedin.com/in/{linkedin}"
        user_info['linkedin'] = linkedin

    # Education
    print("\n3. EDUCATION INFORMATION")

    degree = get_user_input(
        "Enter your degree:",
        example="B.S., M.S., B.A., etc.",
        optional=False
    )

    major = get_user_input(
        "Enter your major/field of study:",
        example="Computer Science, Software Engineering, etc.",
        optional=False
    )

    university = get_user_input(
        "Enter your university name:",
        example="University of Texas at Austin",
        optional=False
    )

    grad_year = get_user_input(
        "Enter your graduation year:",
        example="2022",
        optional=False
    )

    # Combine education into single line
    education_line = f"{degree} in {major} | {university} | {grad_year}"
    user_info['degree'] = degree
    user_info['major'] = major
    user_info['university'] = university
    user_info['grad_year'] = grad_year

    # Confirmation
    print("\n" + "=" * 80)
    print("INFORMATION TO BE UPDATED:")
    print("=" * 80)
    print(f"Phone:      {user_info.get('phone', 'Not provided')}")
    print(f"LinkedIn:   {user_info.get('linkedin', 'Not provided (skipped)')}")
    print(f"Education:  {education_line}")
    print("=" * 80)

    confirm = input("\nProceed with updates? (yes/no): ").strip().lower()
    if confirm not in ['yes', 'y']:
        print("\n❌ Update cancelled by user.")
        return 1

    # Create backups
    print("\n" + "-" * 80)
    print("CREATING BACKUPS")
    print("-" * 80)
    backup_md = create_backup(RESUME_MD)
    backup_txt = create_backup(RESUME_TXT)

    # Prepare replacements dictionary
    replacements = {
        'phone': user_info.get('phone'),
        'linkedin': user_info.get('linkedin'),
        'degree': degree,
        'major': major,
        'university': university,
        'grad_year': grad_year
    }

    # Create full education line replacement
    old_education = f"{PLACEHOLDERS['degree']} in {PLACEHOLDERS['major']} | {PLACEHOLDERS['university']} | {PLACEHOLDERS['grad_year']}"
    new_education = education_line

    # Update files
    print("\n" + "-" * 80)
    print("UPDATING RESUME FILES")
    print("-" * 80)

    # Update Markdown file
    print(f"\n📝 Updating {os.path.basename(RESUME_MD)}...")

    # Read and update MD file
    with open(RESUME_MD, 'r', encoding='utf-8') as f:
        content_md = f.read()

    if user_info.get('phone'):
        content_md = content_md.replace(PLACEHOLDERS['phone'], user_info['phone'])
        print(f"  ✅ Updated phone number")

    if user_info.get('linkedin'):
        content_md = content_md.replace(PLACEHOLDERS['linkedin'], user_info['linkedin'])
        print(f"  ✅ Updated LinkedIn URL")

    content_md = content_md.replace(old_education, new_education)
    print(f"  ✅ Updated education information")

    # Remove example line
    example_line = "*Example: B.S. Computer Science | University of Texas | 2022*"
    if example_line in content_md:
        content_md = content_md.replace(f"\n{example_line}\n", "\n")
        print(f"  ✅ Removed example line")

    with open(RESUME_MD, 'w', encoding='utf-8') as f:
        f.write(content_md)

    print(f"  ✅ {os.path.basename(RESUME_MD)} updated successfully!")

    # Update TXT file
    print(f"\n📝 Updating {os.path.basename(RESUME_TXT)}...")

    with open(RESUME_TXT, 'r', encoding='utf-8') as f:
        content_txt = f.read()

    if user_info.get('phone'):
        content_txt = content_txt.replace(PLACEHOLDERS['phone'], user_info['phone'])
        print(f"  ✅ Updated phone number")

    if user_info.get('linkedin'):
        content_txt = content_txt.replace(PLACEHOLDERS['linkedin'], user_info['linkedin'])
        print(f"  ✅ Updated LinkedIn URL")

    content_txt = content_txt.replace(old_education, new_education)
    print(f"  ✅ Updated education information")

    # Remove example line (different format in TXT)
    example_line_txt = "Example: B.S. Computer Science | University of Texas | 2022"
    if example_line_txt in content_txt:
        content_txt = content_txt.replace(f"\n{example_line_txt}\n", "\n")
        print(f"  ✅ Removed example line")

    with open(RESUME_TXT, 'w', encoding='utf-8') as f:
        f.write(content_txt)

    print(f"  ✅ {os.path.basename(RESUME_TXT)} updated successfully!")

    # Summary
    print("\n" + "=" * 80)
    print("✅ RESUME UPDATE COMPLETE!")
    print("=" * 80)
    print(f"\n📄 Updated Files:")
    print(f"  - {RESUME_MD}")
    print(f"  - {RESUME_TXT}")

    print(f"\n💾 Backup Files:")
    if backup_md:
        print(f"  - {backup_md}")
    if backup_txt:
        print(f"  - {backup_txt}")

    print("\n🎯 NEXT STEPS:")
    print("-" * 80)
    print("1. Review the updated resume files")
    print("2. Convert to PDF (if required by application)")
    print("3. Submit to Gauntlet AI at: https://apply.gauntletai.com/application")

    print("\n💡 PRE-SUBMISSION CHECKLIST:")
    print("  ✅ Name: Mark R. Corbin")
    print("  ✅ Email: markrcorbin88@gmail.com")
    print("  ✅ GitHub: github.com/eatenbywo1ves")
    print(f"  ✅ Phone: {user_info.get('phone')}")
    print(f"  {'✅' if user_info.get('linkedin') else '⚠️ '} LinkedIn: {user_info.get('linkedin', 'Not provided')}")
    print(f"  ✅ Education: {education_line}")
    print("  ✅ Technical achievements: 100x DB, 93% Redis, 20.54x GPU")
    print("  ✅ Resume format: One-page, ATS-optimized")

    print("\n" + "=" * 80)
    print("🚀 YOUR RESUME IS READY FOR GAUNTLET AI!")
    print("=" * 80)
    print("\nGood luck with your application! You're in the elite 2% they're looking for.")

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n❌ Update cancelled by user (Ctrl+C)")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
