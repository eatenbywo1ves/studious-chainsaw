#!/usr/bin/env python3
"""
Apply Quality Fixes - Automated Code Quality Improvements

This script applies the identified quick wins to improve code quality from 8.5/10 to 9.0+/10.

Fixes applied:
1. Add explicit Optional type hints in jwt_auth.py (line 513)
2. Add dict type annotation in jwt_auth.py (line 584)
3. Fix bare except in validate_docs_links.py (line 30)
4. Auto-fix lint issues with ruff

Usage:
    python scripts/utilities/apply_quality_fixes.py [--dry-run]
"""

import re
import sys
from pathlib import Path
from datetime import datetime


class QualityFixer:
    """Applies automated quality improvements to codebase"""

    def __init__(self, repo_root: Path, dry_run: bool = False):
        self.repo_root = repo_root
        self.dry_run = dry_run
        self.changes_made = []
        self.backup_dir = repo_root / f".quality_fixes_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def backup_file(self, file_path: Path):
        """Create backup of file before modification"""
        if not self.dry_run:
            self.backup_dir.mkdir(exist_ok=True)
            backup_path = self.backup_dir / file_path.name
            backup_path.write_text(file_path.read_text(encoding='utf-8'), encoding='utf-8')
            print(f"   📦 Backed up to: {backup_path}")

    def fix_jwt_auth_permissions_type(self):
        """Fix: Add Optional[list[str]] type to permissions parameter"""
        file_path = self.repo_root / "saas" / "auth" / "jwt_auth.py"

        print("\n🔧 Fix 1: Adding Optional[list[str]] type hint to permissions parameter")
        print(f"   File: {file_path}")

        content = file_path.read_text(encoding='utf-8')

        # Pattern to match the function signature on line 513
        old_pattern = r'def generate_api_key\(tenant_id: str, name: str, permissions: list = None\) -> Tuple\[str, str\]:'
        new_pattern = r'def generate_api_key(tenant_id: str, name: str, permissions: Optional[list[str]] = None) -> Tuple[str, str]:'

        if old_pattern in content.replace('\n', ' '):
            if not self.dry_run:
                self.backup_file(file_path)
                content = re.sub(
                    r'def generate_api_key\(tenant_id: str, name: str, permissions: list = None\)',
                    'def generate_api_key(tenant_id: str, name: str, permissions: Optional[list[str]] = None)',
                    content
                )
                file_path.write_text(content, encoding='utf-8')
                self.changes_made.append("jwt_auth.py: Added Optional[list[str]] type hint")
                print("   ✅ Fixed: permissions: Optional[list[str]] = None")
            else:
                print("   [DRY-RUN] Would fix: permissions: Optional[list[str]] = None")
        else:
            print("   ℹ️  Already fixed or pattern not found")

    def fix_jwt_auth_dict_annotation(self):
        """Fix: Add dict[str, Any] type annotation to _original_settings"""
        file_path = self.repo_root / "saas" / "auth" / "jwt_auth.py"

        print("\n🔧 Fix 2: Adding dict[str, Any] type annotation to _original_settings")
        print(f"   File: {file_path}")

        content = file_path.read_text(encoding='utf-8')

        # Pattern to match the assignment on line 584
        old_pattern = r'self\._original_settings = \{\}'
        new_pattern = r'self._original_settings: dict[str, Any] = {}'

        if re.search(r'self\._original_settings = \{\}(?!\s*#.*type:)', content):
            if not self.dry_run:
                if not any('_original_settings' in change for change in self.changes_made):
                    self.backup_file(file_path)
                content = re.sub(
                    r'(self\._original_settings) = \{\}',
                    r'\1: dict[str, Any] = {}',
                    content,
                    count=1
                )
                file_path.write_text(content, encoding='utf-8')
                self.changes_made.append("jwt_auth.py: Added dict[str, Any] annotation")
                print("   ✅ Fixed: _original_settings: dict[str, Any] = {}")
            else:
                print("   [DRY-RUN] Would fix: _original_settings: dict[str, Any] = {}")
        else:
            print("   ℹ️  Already fixed or pattern not found")

    def fix_validate_docs_bare_except(self):
        """Fix: Replace bare except with specific exception types"""
        file_path = self.repo_root / "scripts" / "utilities" / "validate_docs_links.py"

        print("\n🔧 Fix 3: Replacing bare except with specific exceptions")
        print(f"   File: {file_path}")

        content = file_path.read_text(encoding='utf-8')

        # Pattern for bare except around line 30
        old_pattern = r'try:\s+sys\.stdout\.reconfigure\(encoding=\'utf-8\'\)\s+except:\s+pass'
        new_pattern = 'try:\n        sys.stdout.reconfigure(encoding=\'utf-8\')\n    except (AttributeError, OSError):\n        pass'

        if 'except:' in content and 'sys.stdout.reconfigure' in content:
            if not self.dry_run:
                self.backup_file(file_path)
                content = re.sub(
                    r'(\s+)try:\s+sys\.stdout\.reconfigure\(encoding=\'utf-8\'\)\s+except:\s+pass',
                    r'\1try:\n\1    sys.stdout.reconfigure(encoding=\'utf-8\')\n\1except (AttributeError, OSError):\n\1    pass',
                    content
                )
                file_path.write_text(content, encoding='utf-8')
                self.changes_made.append("validate_docs_links.py: Fixed bare except clause")
                print("   ✅ Fixed: except (AttributeError, OSError):")
            else:
                print("   [DRY-RUN] Would fix: except (AttributeError, OSError):")
        else:
            print("   ℹ️  Already fixed or pattern not found")

    def run_ruff_fixes(self):
        """Run ruff auto-fixes"""
        print("\n🔧 Fix 4: Running ruff auto-fixes")

        file_path = self.repo_root / "scripts" / "utilities" / "validate_docs_links.py"
        print(f"   File: {file_path}")

        if not self.dry_run:
            import subprocess
            try:
                result = subprocess.run(
                    ["ruff", "check", str(file_path), "--fix"],
                    capture_output=True,
                    text=True,
                    cwd=self.repo_root
                )
                if result.returncode == 0:
                    print("   ✅ Ruff fixes applied successfully")
                    self.changes_made.append("validate_docs_links.py: Ruff auto-fixes applied")
                else:
                    print(f"   ⚠️  Ruff exited with code {result.returncode}")
                    if result.stdout:
                        print(f"   Output: {result.stdout}")
            except FileNotFoundError:
                print("   ⚠️  Ruff not found - skipping auto-fixes")
        else:
            print("   [DRY-RUN] Would run: ruff check --fix")

    def print_summary(self):
        """Print summary of changes"""
        print("\n" + "="*70)
        print("📊 QUALITY FIXES SUMMARY")
        print("="*70)

        if self.dry_run:
            print("\n🔍 DRY RUN MODE - No changes were made")
            print("\nChanges that would be applied:")
        else:
            print(f"\n✅ Applied {len(self.changes_made)} fixes:")

        if self.changes_made:
            for i, change in enumerate(self.changes_made, 1):
                print(f"   {i}. {change}")
        else:
            print("   No changes needed - files may already be fixed!")

        if not self.dry_run and self.changes_made:
            print(f"\n📦 Backups saved to: {self.backup_dir}")
            print("\n💡 Next steps:")
            print("   1. Run: python -m mypy saas/auth/jwt_auth.py --ignore-missing-imports")
            print("   2. Run: ruff check scripts/utilities/validate_docs_links.py")
            print("   3. Run: python scripts/utilities/validate_docs_links.py")
            print("   4. If all good: git add . && git commit -m 'refactor: apply quality fixes'")

        print("\n" + "="*70)

    def apply_all_fixes(self):
        """Apply all quality fixes"""
        print("\n" + "="*70)
        print("🚀 APPLYING QUALITY FIXES")
        print("="*70)
        print(f"\nMode: {'DRY-RUN' if self.dry_run else 'LIVE'}")
        print(f"Repository: {self.repo_root}")

        # Apply fixes in order
        self.fix_jwt_auth_permissions_type()
        self.fix_jwt_auth_dict_annotation()
        self.fix_validate_docs_bare_except()
        self.run_ruff_fixes()

        # Print summary
        self.print_summary()


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Apply quality fixes to codebase")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed without modifying files")
    args = parser.parse_args()

    # Detect repository root
    script_path = Path(__file__).resolve()
    repo_root = script_path.parent.parent.parent  # scripts/utilities/apply_quality_fixes.py -> development/

    # Apply fixes
    fixer = QualityFixer(repo_root, dry_run=args.dry_run)
    fixer.apply_all_fixes()

    # Exit code
    sys.exit(0 if fixer.changes_made or args.dry_run else 1)


if __name__ == "__main__":
    main()
