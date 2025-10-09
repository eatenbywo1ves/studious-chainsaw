#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze broken links in active documentation and provide fix recommendations.
Excludes archived and conversation documents.
"""

import re
import sys
import os
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

# Fix Windows console encoding
if sys.platform == 'win32':
    os.system('chcp 65001 >nul 2>&1')
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

@dataclass
class BrokenLink:
    """Represents a single broken link with metadata"""
    source_file: str
    line_number: int
    link_text: str
    target_path: str

    # Analysis fields
    exists_elsewhere: bool = False
    correct_path: str = None
    fix_type: str = None  # 'easy', 'medium', 'hard'
    priority: str = None  # 'high', 'medium', 'low'
    recommendation: str = None
    is_active: bool = True  # Not in archive/conversations

def is_active_doc(file_path: str) -> bool:
    """Check if document is in active directories (not archive/conversations)"""
    path = Path(file_path)
    parts = path.parts

    # Exclude archived and conversation docs
    if 'archive' in parts or 'conversations' in parts:
        return False

    return True

def find_file_in_project(filename: str, project_root: Path) -> List[Path]:
    """Search for a file across the entire project"""
    if not filename:
        return []

    # Extract just the filename without path
    base_name = Path(filename).name

    matches = []
    for path in project_root.rglob(base_name):
        if path.is_file():
            matches.append(path)

    return matches

def analyze_broken_links(dev_root: Path) -> List[BrokenLink]:
    """Run validation and analyze all broken links"""
    docs_root = dev_root / "docs"

    broken_links = []

    # Find all markdown files
    md_files = list(docs_root.rglob("*.md"))

    # Pattern to match markdown links
    link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'

    for md_file in md_files:
        # Check if this is an active document
        is_active = is_active_doc(str(md_file.relative_to(docs_root)))

        with open(md_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        for i, line in enumerate(lines, 1):
            for match in re.finditer(link_pattern, line):
                link_text = match.group(1)
                link_target = match.group(2)

                # Skip external URLs
                if link_target.startswith(('http://', 'https://', 'mailto:')):
                    continue

                # Skip anchor-only links
                if link_target.startswith('#'):
                    continue

                # Remove anchor from target
                target_path = link_target.split('#')[0]
                if not target_path:
                    continue

                # Resolve path
                if target_path.startswith('/'):
                    resolved = dev_root / target_path.lstrip('/')
                else:
                    resolved = (md_file.parent / target_path).resolve()

                # Check if broken
                if not resolved.exists():
                    link = BrokenLink(
                        source_file=str(md_file.relative_to(docs_root)),
                        line_number=i,
                        link_text=link_text,
                        target_path=target_path,
                        is_active=is_active
                    )

                    # Try to find the file elsewhere
                    matches = find_file_in_project(Path(target_path).name, dev_root)
                    if matches:
                        link.exists_elsewhere = True
                        link.correct_path = str(matches[0].relative_to(dev_root))

                    broken_links.append(link)

    return broken_links

def categorize_and_prioritize(links: List[BrokenLink], dev_root: Path) -> List[BrokenLink]:
    """Categorize links by fix difficulty and prioritize"""

    for link in links:
        # Determine fix type and recommendation
        if link.target_path in ['path', './file1.md', './file2.md']:
            # Template/example links - should be removed
            link.fix_type = 'easy'
            link.priority = 'low'
            link.recommendation = "Remove template example link"

        elif link.target_path.startswith('./docs/') or link.target_path.startswith('../docs/'):
            # Wrong path assumption (docs/ is already the root)
            link.fix_type = 'easy'
            link.priority = 'high' if link.is_active else 'low'
            # Try to extract the correct relative path
            correct_target = link.target_path.replace('./docs/', '../').replace('../docs/', '../')
            link.recommendation = f"Update path to: {correct_target}"

        elif link.exists_elsewhere:
            # File exists but path is wrong
            link.fix_type = 'medium'
            link.priority = 'high' if link.is_active else 'low'

            # Calculate relative path from source to target
            source_path = dev_root / "docs" / link.source_file
            target_path = dev_root / link.correct_path

            try:
                rel_path = Path(target_path).relative_to(source_path.parent)
                link.recommendation = f"Update path to: {rel_path}"
            except ValueError:
                # Try going up to common ancestor
                link.recommendation = f"Update path to reference: {link.correct_path}"

        elif 'NVIDIA_BMAD_DEPLOYMENT_PLAN' in link.target_path:
            link.fix_type = 'easy'
            link.priority = 'medium'
            link.recommendation = "Update path to: ../guides/NVIDIA_BMAD_DEPLOYMENT_PLAN.md"

        elif 'fold7_config.json' in link.target_path or 'fold7_ssh_monitor.py' in link.target_path:
            link.fix_type = 'medium'
            link.priority = 'medium'
            if 'fold7_ssh_monitor.py' in link.target_path:
                link.recommendation = "Update path to: ../../scripts/deployment/fold7_ssh_monitor.py"
            else:
                link.recommendation = "Update path to: ../../fold7_config.json (or create config in docs/guides/)"

        elif 'CONTAINER_ESCAPE_RESEARCH_REPORT' in link.target_path:
            link.fix_type = 'medium'
            link.priority = 'medium'
            link.recommendation = "Update path to: ../../security/CONTAINER_ESCAPE_RESEARCH_REPORT.md"

        elif 'GPU_ACCELERATION_STATUS' in link.target_path:
            link.fix_type = 'easy'
            link.priority = 'medium'
            link.recommendation = "Update path to: ../GPU_ACCELERATION_STATUS.md"

        elif 'REDIS_POOL_OPTIMIZATION_GUIDE' in link.target_path:
            link.fix_type = 'easy'
            link.priority = 'high'
            link.recommendation = "Path is correct - file exists at docs/guides/REDIS_POOL_OPTIMIZATION_GUIDE.md"

        elif 'webhooks' in link.target_path:
            link.fix_type = 'medium'
            link.priority = 'low'
            link.recommendation = "Create README.md in services/webhooks/ or remove link"

        elif 'PRODUCTION_SECURITY_AUDIT' in link.target_path:
            link.fix_type = 'hard'
            link.priority = 'low'
            link.recommendation = "Create security audit document or remove link (marked as 'if exists')"

        else:
            # Unknown issue
            link.fix_type = 'hard'
            link.priority = 'medium' if link.is_active else 'low'
            link.recommendation = "Investigate - file may have been deleted or renamed"

    return links

def print_report(links: List[BrokenLink]):
    """Print detailed analysis report"""

    # Filter to only active docs
    active_links = [l for l in links if l.is_active]

    print("\n" + "="*80)
    print("📊 ACTIVE DOCUMENTATION BROKEN LINKS ANALYSIS")
    print("="*80)

    print(f"\n📈 Summary:")
    print(f"  Total broken links: {len(links)}")
    print(f"  Active docs: {len(active_links)}")
    print(f"  Archived docs: {len(links) - len(active_links)}")

    # Group by fix type
    by_fix_type = defaultdict(list)
    for link in active_links:
        by_fix_type[link.fix_type].append(link)

    print(f"\n🔧 By Fix Difficulty:")
    print(f"  Easy:   {len(by_fix_type['easy'])} links")
    print(f"  Medium: {len(by_fix_type['medium'])} links")
    print(f"  Hard:   {len(by_fix_type['hard'])} links")

    # Group by priority
    by_priority = defaultdict(list)
    for link in active_links:
        by_priority[link.priority].append(link)

    print(f"\n⚡ By Priority:")
    print(f"  High:   {len(by_priority['high'])} links")
    print(f"  Medium: {len(by_priority['medium'])} links")
    print(f"  Low:    {len(by_priority['low'])} links")

    # Detailed breakdown
    print("\n" + "="*80)
    print("📋 DETAILED BREAKDOWN")
    print("="*80)

    # Group by source file
    by_file = defaultdict(list)
    for link in active_links:
        by_file[link.source_file].append(link)

    # Sort by priority (high first)
    priority_order = {'high': 0, 'medium': 1, 'low': 2}
    sorted_files = sorted(by_file.keys(),
                         key=lambda f: min(priority_order[l.priority] for l in by_file[f]))

    for source_file in sorted_files:
        file_links = by_file[source_file]
        max_priority = min(file_links, key=lambda l: priority_order[l.priority]).priority

        print(f"\n📄 {source_file}")
        print(f"   Priority: {max_priority.upper()} | Links: {len(file_links)}")
        print("-" * 80)

        for link in sorted(file_links, key=lambda l: l.line_number):
            print(f"\n  Line {link.line_number}: [{link.link_text}]({link.target_path})")
            print(f"  ├─ Fix Type: {link.fix_type.upper()}")
            print(f"  ├─ Priority: {link.priority.upper()}")
            print(f"  └─ Recommendation: {link.recommendation}")

    # Action plan
    print("\n" + "="*80)
    print("🎯 ACTION PLAN")
    print("="*80)

    print("\n### Phase 1: High Priority Easy Fixes (Do First)")
    high_easy = [l for l in active_links if l.priority == 'high' and l.fix_type == 'easy']
    if high_easy:
        for link in high_easy:
            print(f"\n  [ ] {link.source_file}:{link.line_number}")
            print(f"      {link.recommendation}")
    else:
        print("  ✅ None!")

    print("\n### Phase 2: High Priority Medium Fixes")
    high_medium = [l for l in active_links if l.priority == 'high' and l.fix_type == 'medium']
    if high_medium:
        for link in high_medium:
            print(f"\n  [ ] {link.source_file}:{link.line_number}")
            print(f"      {link.recommendation}")
    else:
        print("  ✅ None!")

    print("\n### Phase 3: Medium Priority Fixes")
    medium = [l for l in active_links if l.priority == 'medium']
    if medium:
        print(f"  {len(medium)} fixes needed:")
        for link in medium[:5]:  # Show first 5
            print(f"\n  [ ] {link.source_file}:{link.line_number}")
            print(f"      {link.recommendation}")
        if len(medium) > 5:
            print(f"\n  ... and {len(medium) - 5} more")
    else:
        print("  ✅ None!")

    print("\n### Phase 4: Low Priority / Cleanup")
    low = [l for l in active_links if l.priority == 'low']
    if low:
        print(f"  {len(low)} fixes (templates, examples, optional links)")
    else:
        print("  ✅ None!")

    print("\n" + "="*80)
    print(f"\n✅ Total active broken links to fix: {len(active_links)}")
    print("="*80 + "\n")

def main():
    """Main entry point"""
    # Find development root
    script_dir = Path(__file__).parent
    dev_root = script_dir.parent.parent

    print(f"🔍 Analyzing broken links in: {dev_root / 'docs'}")
    print("   (Excluding archive/ and conversations/)\n")

    # Analyze
    print("⏳ Scanning documentation...")
    links = analyze_broken_links(dev_root)

    print("⏳ Categorizing and prioritizing...")
    links = categorize_and_prioritize(links, dev_root)

    # Print report
    print_report(links)

if __name__ == "__main__":
    main()
