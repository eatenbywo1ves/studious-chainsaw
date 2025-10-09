#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Documentation Link Validator

Validates all markdown links in the documentation to ensure they point to existing files.
Can be run manually or as a pre-commit hook.

Usage:
    python validate_docs_links.py [--fix] [--verbose]

Options:
    --fix       Attempt to automatically fix simple issues
    --verbose   Show detailed output
"""

import re
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict

# Fix Windows console encoding for emojis
if sys.platform == 'win32':
    os.system('chcp 65001 >nul 2>&1')
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass


@dataclass
class LinkIssue:
    """Represents a broken link issue"""
    source_file: Path
    line_number: int
    link_text: str
    target_path: str
    issue_type: str  # 'broken', 'outdated', 'ambiguous'


class DocsLinkValidator:
    """Validates markdown links in documentation"""

    def __init__(self, docs_root: Path, verbose: bool = False):
        self.docs_root = docs_root
        self.verbose = verbose
        self.issues: List[LinkIssue] = []
        self.stats = {
            'files_scanned': 0,
            'links_checked': 0,
            'links_valid': 0,
            'links_broken': 0,
            'external_links': 0,
            'anchor_links': 0,
        }

    def validate_all(self) -> bool:
        """Validate all markdown files in docs directory"""
        print(f"🔍 Scanning documentation in: {self.docs_root}")

        md_files = list(self.docs_root.rglob("*.md"))
        self.stats['files_scanned'] = len(md_files)

        for md_file in md_files:
            self._validate_file(md_file)

        self._print_report()
        return len(self.issues) == 0

    def _validate_file(self, file_path: Path):
        """Validate all links in a single markdown file"""
        if self.verbose:
            print(f"  Checking: {file_path.relative_to(self.docs_root)}")

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')

        # Find all markdown links: [text](path)
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'

        for i, line in enumerate(lines, 1):
            for match in re.finditer(link_pattern, line):
                link_text = match.group(1)
                link_target = match.group(2)

                self.stats['links_checked'] += 1

                # Skip external URLs
                if link_target.startswith(('http://', 'https://', 'mailto:')):
                    self.stats['external_links'] += 1
                    continue

                # Skip anchor-only links
                if link_target.startswith('#'):
                    self.stats['anchor_links'] += 1
                    continue

                # Remove anchor from target
                target_path = link_target.split('#')[0]
                if not target_path:  # Was anchor-only after split
                    self.stats['anchor_links'] += 1
                    continue

                # Resolve relative path
                resolved = self._resolve_link(file_path, target_path)

                if not resolved or not resolved.exists():
                    self.stats['links_broken'] += 1
                    self.issues.append(LinkIssue(
                        source_file=file_path,
                        line_number=i,
                        link_text=link_text,
                        target_path=target_path,
                        issue_type='broken'
                    ))
                else:
                    self.stats['links_valid'] += 1

    def _resolve_link(self, source_file: Path, link_path: str) -> Path:
        """Resolve a relative link path to absolute path"""
        # Handle absolute paths from repo root
        if link_path.startswith('/'):
            return self.docs_root.parent / link_path.lstrip('/')

        # Resolve relative to source file's directory
        source_dir = source_file.parent
        target = (source_dir / link_path).resolve()

        return target

    def _print_report(self):
        """Print validation report"""
        print("\n" + "="*70)
        print("📊 DOCUMENTATION LINK VALIDATION REPORT")
        print("="*70)

        # Statistics
        print(f"\n📈 Statistics:")
        print(f"  Files scanned:    {self.stats['files_scanned']}")
        print(f"  Links checked:    {self.stats['links_checked']}")
        print(f"  Valid links:      {self.stats['links_valid']} "
              f"({self._percentage(self.stats['links_valid'], self.stats['links_checked'])})")
        print(f"  Broken links:     {self.stats['links_broken']} "
              f"({self._percentage(self.stats['links_broken'], self.stats['links_checked'])})")
        print(f"  External links:   {self.stats['external_links']} (skipped)")
        print(f"  Anchor links:     {self.stats['anchor_links']} (skipped)")

        # Health status
        total_internal = self.stats['links_valid'] + self.stats['links_broken']
        if total_internal > 0:
            health_pct = (self.stats['links_valid'] / total_internal) * 100

            if health_pct == 100:
                status = "✅ EXCELLENT"
                color = "\033[92m"  # Green
            elif health_pct >= 95:
                status = "✓ GOOD"
                color = "\033[93m"  # Yellow
            else:
                status = "⚠️  NEEDS ATTENTION"
                color = "\033[91m"  # Red

            print(f"\n{color}Health Status: {status} ({health_pct:.1f}%)\033[0m")

        # Broken links details
        if self.issues:
            print(f"\n❌ Broken Links ({len(self.issues)}):")
            print("-"*70)

            # Group by source file
            by_file = defaultdict(list)
            for issue in self.issues:
                by_file[issue.source_file].append(issue)

            for source_file in sorted(by_file.keys()):
                rel_path = source_file.relative_to(self.docs_root)
                issues = by_file[source_file]
                print(f"\n  📄 {rel_path} ({len(issues)} broken links)")

                for issue in issues[:5]:  # Show first 5 per file
                    print(f"     Line {issue.line_number}: [{issue.link_text}]({issue.target_path})")

                if len(issues) > 5:
                    print(f"     ... and {len(issues) - 5} more")

            # Most broken targets
            print(f"\n🔗 Most Frequently Broken Targets:")
            print("-"*70)

            target_counts = defaultdict(int)
            for issue in self.issues:
                target_counts[issue.target_path] += 1

            for target, count in sorted(target_counts.items(), key=lambda x: -x[1])[:10]:
                print(f"  {count}x  {target}")
        else:
            print("\n✅ No broken links found!")

        print("\n" + "="*70)

    def _percentage(self, part: int, total: int) -> str:
        """Calculate percentage as string"""
        if total == 0:
            return "0.0%"
        return f"{(part/total)*100:.1f}%"

    def fix_common_issues(self) -> int:
        """Attempt to automatically fix common link issues"""
        # TODO: Implement auto-fix for common patterns
        # - Update renamed files
        # - Fix case sensitivity issues
        # - Correct path separators
        print("🔧 Auto-fix not yet implemented")
        return 0


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Validate documentation links")
    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--docs-dir", type=Path, default=None,
                       help="Documentation directory (default: auto-detect)")

    args = parser.parse_args()

    # Auto-detect docs directory
    if args.docs_dir:
        docs_dir = args.docs_dir
    else:
        # Assume running from development/scripts/utilities/
        script_dir = Path(__file__).parent
        docs_dir = script_dir.parent.parent / "docs"

    if not docs_dir.exists():
        print(f"❌ Error: Documentation directory not found: {docs_dir}")
        sys.exit(1)

    # Run validation
    validator = DocsLinkValidator(docs_dir, verbose=args.verbose)
    is_valid = validator.validate_all()

    # Auto-fix if requested
    if args.fix and not is_valid:
        fixed = validator.fix_common_issues()
        print(f"\n🔧 Fixed {fixed} issues")

    # Exit with error code if broken links found
    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
