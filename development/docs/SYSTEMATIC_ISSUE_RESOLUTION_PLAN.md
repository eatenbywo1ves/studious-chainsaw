# Systematic Issue Resolution Plan

**Created:** 2025-10-09
**Status:** Ready for Execution
**Estimated Total Time:** 2-3 hours over 1 week

---

## 📋 Overview: 5 Minor Issues to Address

Based on the work evaluation, we identified 5 areas for improvement:

| # | Issue | Priority | Complexity | Time | Status |
|---|-------|----------|------------|------|--------|
| 1 | 19 broken links in active guides | **HIGH** | Easy | 30 min | 🟢 Ready |
| 2 | Auto-fix not implemented | **MEDIUM** | Medium | 1 hour | 🟡 Planned |
| 3 | No CI/CD integration | **MEDIUM** | Medium | 45 min | 🟡 Planned |
| 4 | Content not validated | **LOW** | Hard | 2+ hours | 🔴 Future |
| 5 | 46 archived doc links | **LOW** | Easy | 15 min | 🟢 Ready |

---

## 🎯 Systematic Resolution Strategy

### Phase 1: Quick Wins (This Week)
**Focus:** Issues #1 and #5 - Broken links
**Time:** 45 minutes
**Impact:** Immediate documentation health improvement

### Phase 2: Automation (Next Week)
**Focus:** Issues #2 and #3 - Auto-fix and CI/CD
**Time:** 2 hours
**Impact:** Prevent regression, sustainable quality

### Phase 3: Advanced Validation (Future Sprint)
**Focus:** Issue #4 - Content validation
**Time:** 2-4 hours
**Impact:** Comprehensive quality assurance

---

## 📊 Issue #1: Fix 19 Broken Links in Active Guides

### Status: 🟢 **READY FOR EXECUTION**

### Analysis Complete
✅ Agent analysis report created: [BROKEN_LINKS_ANALYSIS_REPORT.md](./reports/BROKEN_LINKS_ANALYSIS_REPORT.md)
✅ Automated fix script created: `scripts/utilities/fix_broken_links.sh`
✅ Analysis tool created: `scripts/utilities/analyze_broken_links.py`

### Breakdown

**21 broken links found in active documentation:**
- 17 High Priority (critical navigation)
- 4 Low Priority (template examples)

**By Fix Type:**
- 9 Easy (simple path corrections)
- 12 Medium (moved files, update paths)
- 0 Hard

**By File:**
1. `DOCUMENTATION_MIGRATION_PLAN.md` - 5 links
2. `DOCUMENTATION_MAINTENANCE_GUIDE.md` - 5 links
3. `guides/ka-lattice-deployment-guide.md` - 3 links
4. `guides/FOLD7_README.md` - 3 links
5. `architecture/security-architecture.md` - 1 link
6. `IMPLEMENTATION_GUIDE_INDEX.md` - 1 link
7. `quickstart/security-tools-5min.md` - 1 link
8. `guides/README.md` - 1 link
9. `DOCUMENTATION_TOOLS_IMPLEMENTATION.md` - 1 link

### Root Causes

1. **Wrong Base Path (60%):** Files use `./docs/` prefix when already IN `docs/`
2. **File Reorganization (25%):** Links point to old locations after moves
3. **Template Examples (15%):** Example links in tutorials

### Execution Plan

#### Step 1: Run Automated Fix (2 minutes)

```bash
cd /c/Users/Corbin/development

# Create backup
mkdir -p .backup_links_$(date +%Y%m%d)

# Run automated fix script
bash scripts/utilities/fix_broken_links.sh

# Expected: Fixes 17 of 21 links automatically
```

**What This Does:**
- Backs up all files before modification
- Fixes path issues (removes wrong `./docs/` prefixes)
- Updates relative paths for moved files
- Creates detailed log of changes

#### Step 2: Validate Results (10 seconds)

```bash
# Run validation
python scripts/utilities/validate_docs_links.py | tee fix_validation.txt

# Check improvement
# Before: 65 broken (21 active, 44 archived)
# After: ~48 broken (4 active, 44 archived)
```

#### Step 3: Manual Cleanup (Optional, 5 minutes)

**4 remaining low-priority items:**

1. **Template examples** in `DOCUMENTATION_MAINTENANCE_GUIDE.md` lines 289-290:
   ```markdown
   # Add clarification that these are examples
   - [File 1 (example)](./file1.md) ← (example only)
   - [File 2 (example)](./file2.md) ← (example only)
   ```

2. **Optional file** in `quickstart/security-tools-5min.md` line 214:
   ```markdown
   # Already marked as optional - can leave as-is
   - [Security Audit](../deployment/PRODUCTION_SECURITY_AUDIT.md) *(if exists)*
   ```

3. **Missing README** in `guides/README.md` line 47:
   ```bash
   # Option A: Create the file
   echo "# Webhook Integration" > services/webhooks/README.md

   # Option B: Remove the link
   # (Edit guides/README.md to remove line 47)
   ```

4. **Template example** in `DOCUMENTATION_TOOLS_IMPLEMENTATION.md`:
   - Already clear from context, no action needed

### Success Criteria

✅ Active broken links reduced from 21 → 4
✅ Critical navigation paths remain at 100%
✅ Overall link health: 84.5% → 93%+
✅ All changes backed up and reversible

### Time Estimate: **30 minutes**
- Automated: 2 minutes
- Validation: 1 minute
- Manual cleanup: 5 minutes (optional)
- Testing navigation: 5 minutes
- Git commit: 2 minutes
- Buffer: 15 minutes

---

## 🤖 Issue #2: Implement Auto-Fix Functionality

### Status: 🟡 **PLANNED - Ready to Implement**

### Current State
- ✅ Placeholder exists in `validate_docs_links.py`
- ✅ Manual fix script created (`fix_broken_links.sh`)
- ⏳ Need to integrate into Python validator

### Implementation Plan

#### Design: Auto-Fix Categories

**Category 1: Safe Auto-Fixes (High Confidence)**
1. Remove wrong `./docs/` prefix when already in docs/
2. Fix case sensitivity (Windows → case-insensitive, Git → case-sensitive)
3. Update known moved files (maintain mapping table)
4. Fix double slashes (`//` → `/`)

**Category 2: Suggested Fixes (Medium Confidence)**
1. Fuzzy match similar filenames
2. Search for file in nearby directories
3. Check git history for renames

**Category 3: Manual Review (Low Confidence)**
1. Completely missing files
2. Ambiguous matches
3. External links that changed

#### Implementation Steps

**Step 1: Create Fix Strategy Classes (30 minutes)**

```python
# Add to validate_docs_links.py

class LinkFixStrategy:
    """Base class for link fix strategies"""

    def can_fix(self, issue: LinkIssue) -> bool:
        """Check if this strategy can fix the issue"""
        pass

    def fix(self, issue: LinkIssue) -> Optional[str]:
        """Return corrected link or None"""
        pass

    def confidence(self) -> str:
        """Return 'high', 'medium', or 'low'"""
        pass

class RemoveDocsPrefix(LinkFixStrategy):
    """Remove ./docs/ prefix when already in docs/"""

    def can_fix(self, issue: LinkIssue) -> bool:
        return (
            issue.source_file.is_relative_to(docs_root) and
            issue.target_path.startswith('./docs/')
        )

    def fix(self, issue: LinkIssue) -> Optional[str]:
        return issue.target_path.replace('./docs/', './')

    def confidence(self) -> str:
        return 'high'

class KnownFileMove(LinkFixStrategy):
    """Fix links to files that were moved during reorganization"""

    MOVE_MAP = {
        'NVIDIA_BMAD_DEPLOYMENT_PLAN.md': 'guides/NVIDIA_BMAD_DEPLOYMENT_PLAN.md',
        'REDIS_POOL_OPTIMIZATION_GUIDE.md': 'guides/REDIS_POOL_OPTIMIZATION_GUIDE.md',
        # Add more as discovered
    }

    def can_fix(self, issue: LinkIssue) -> bool:
        filename = Path(issue.target_path).name
        return filename in self.MOVE_MAP

    def fix(self, issue: LinkIssue) -> Optional[str]:
        filename = Path(issue.target_path).name
        return f"../{self.MOVE_MAP[filename]}"

    def confidence(self) -> str:
        return 'high'

class FuzzyFileSearch(LinkFixStrategy):
    """Search for similar filenames"""

    def can_fix(self, issue: LinkIssue) -> bool:
        # Use difflib to find similar names
        return self._find_similar_file(issue.target_path) is not None

    def fix(self, issue: LinkIssue) -> Optional[str]:
        similar = self._find_similar_file(issue.target_path)
        return str(similar) if similar else None

    def confidence(self) -> str:
        return 'medium'
```

**Step 2: Implement Auto-Fix Orchestrator (20 minutes)**

```python
class AutoFixer:
    """Orchestrates automatic link fixing"""

    def __init__(self, docs_root: Path):
        self.docs_root = docs_root
        self.strategies = [
            RemoveDocsPrefix(),
            KnownFileMove(),
            FuzzyFileSearch(),
        ]
        self.fixes: Dict[str, List[LinkFix]] = {}

    def analyze_fixes(self, issues: List[LinkIssue]) -> Dict[str, List[LinkFix]]:
        """Analyze which issues can be auto-fixed"""
        categorized = {'high': [], 'medium': [], 'low': []}

        for issue in issues:
            for strategy in self.strategies:
                if strategy.can_fix(issue):
                    fixed_link = strategy.fix(issue)
                    confidence = strategy.confidence()

                    categorized[confidence].append(
                        LinkFix(issue, fixed_link, strategy.__class__.__name__)
                    )
                    break

        return categorized

    def apply_fixes(self, fixes: List[LinkFix], dry_run: bool = False):
        """Apply fixes to files"""
        # Group by file
        by_file = defaultdict(list)
        for fix in fixes:
            by_file[fix.issue.source_file].append(fix)

        # Apply fixes file by file
        for file_path, file_fixes in by_file.items():
            if not dry_run:
                self._backup_file(file_path)

            content = file_path.read_text(encoding='utf-8')

            for fix in file_fixes:
                # Replace old link with new link
                old_pattern = f"({fix.issue.link_text}]({fix.issue.target_path})"
                new_pattern = f"({fix.issue.link_text}]({fix.new_link})"
                content = content.replace(old_pattern, new_pattern)

            if not dry_run:
                file_path.write_text(content, encoding='utf-8')
                print(f"✅ Fixed {len(file_fixes)} links in {file_path.name}")
```

**Step 3: Add CLI Interface (10 minutes)**

```python
# Update main() function

def main():
    parser = argparse.ArgumentParser(description="Validate documentation links")
    parser.add_argument("--fix", action="store_true", help="Attempt to fix issues")
    parser.add_argument("--auto-fix", choices=['high', 'medium', 'all'],
                       help="Auto-fix with confidence level")
    parser.add_argument("--dry-run", action="store_true",
                       help="Show what would be fixed without modifying files")
    # ... existing args ...

    args = parser.parse_args()

    # ... validation logic ...

    if args.fix or args.auto_fix:
        fixer = AutoFixer(docs_dir)
        fixes = fixer.analyze_fixes(validator.issues)

        print(f"\n🔧 Auto-Fix Analysis:")
        print(f"  High confidence: {len(fixes['high'])} fixes")
        print(f"  Medium confidence: {len(fixes['medium'])} fixes")
        print(f"  Manual review: {len(fixes['low'])} issues")

        if args.auto_fix == 'high':
            to_apply = fixes['high']
        elif args.auto_fix == 'medium':
            to_apply = fixes['high'] + fixes['medium']
        elif args.auto_fix == 'all':
            to_apply = fixes['high'] + fixes['medium'] + fixes['low']
        else:
            to_apply = []

        if to_apply:
            fixer.apply_fixes(to_apply, dry_run=args.dry_run)
            print(f"\n✅ Applied {len(to_apply)} fixes")

            # Re-validate
            validator.validate_all()
```

#### Testing Strategy

**Test 1: Dry Run**
```bash
python scripts/utilities/validate_docs_links.py --auto-fix high --dry-run

# Expected output:
# 🔧 Auto-Fix Analysis:
#   High confidence: 14 fixes
#   Medium confidence: 5 fixes
#   Manual review: 2 issues
#
# Would fix (dry-run):
#   ✓ DOCUMENTATION_MIGRATION_PLAN.md: 5 fixes
#   ✓ guides/ka-lattice-deployment-guide.md: 3 fixes
#   ...
```

**Test 2: High Confidence Only**
```bash
# Backup first
cp -r docs docs_backup_autofix

# Run auto-fix
python scripts/utilities/validate_docs_links.py --auto-fix high

# Validate results
python scripts/utilities/validate_docs_links.py
git diff docs/
```

**Test 3: All Fixes**
```bash
python scripts/utilities/validate_docs_links.py --auto-fix all --dry-run
# Review proposed changes before applying
```

### Success Criteria

✅ High-confidence fixes work 100% of the time
✅ Medium-confidence fixes work >90% of the time
✅ No false positives (breaking working links)
✅ Dry-run mode available
✅ Backups created automatically
✅ Clear reporting of what was changed

### Time Estimate: **1 hour**
- Design strategy classes: 20 min
- Implement orchestrator: 20 min
- Add CLI interface: 10 min
- Testing: 10 min

---

## 🔄 Issue #3: CI/CD Integration

### Status: 🟡 **PLANNED - Ready to Implement**

### Goal
Prevent broken links from being merged into main branch.

### Implementation Plan

#### Option 1: GitHub Actions (Recommended)

**Step 1: Create Workflow File (15 minutes)**

Create `.github/workflows/docs-validation.yml`:

```yaml
name: Documentation Validation

on:
  pull_request:
    paths:
      - 'development/docs/**'
      - 'development/scripts/utilities/validate_docs_links.py'
  push:
    branches: [main]
    paths:
      - 'development/docs/**'

jobs:
  validate-links:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Validate documentation links
        id: validation
        run: |
          cd development
          python scripts/utilities/validate_docs_links.py --verbose
        continue-on-error: true

      - name: Check validation results
        run: |
          if [ ${{ steps.validation.outcome }} == 'failure' ]; then
            echo "❌ Documentation validation failed!"
            echo "See job output for broken link details."
            exit 1
          else
            echo "✅ All documentation links valid!"
          fi

      - name: Comment PR with results
        if: github.event_name == 'pull_request' && failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '❌ **Documentation Validation Failed**\n\nSome documentation links are broken. Please run `python scripts/utilities/validate_docs_links.py` locally to see details.'
            })
```

**Step 2: Add Validation Badge (5 minutes)**

Update `development/docs/README.md`:

```markdown
# Documentation

![Docs Valid](https://github.com/USER/REPO/actions/workflows/docs-validation.yml/badge.svg)

...rest of content...
```

**Step 3: Configure Branch Protection (5 minutes)**

In GitHub repository settings:
1. Go to Settings → Branches
2. Add rule for `main` branch
3. Require status checks: ✅ `validate-links`
4. PRs cannot merge until validation passes

#### Option 2: Pre-Commit Hook (Alternative/Additional)

**Step 1: Create Hook Script (10 minutes)**

Create `development/.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Pre-commit hook for documentation validation

echo "🔍 Validating documentation links..."

# Check if any docs files are staged
if git diff --cached --name-only | grep -q "development/docs/.*\.md$"; then
    cd development

    # Run validation
    python scripts/utilities/validate_docs_links.py

    if [ $? -ne 0 ]; then
        echo ""
        echo "❌ Documentation validation failed!"
        echo "   Fix broken links before committing."
        echo "   Or use: git commit --no-verify (not recommended)"
        exit 1
    fi

    echo "✅ Documentation links valid!"
fi

exit 0
```

**Step 2: Make Executable**

```bash
chmod +x development/.git/hooks/pre-commit
```

**Step 3: Share with Team (Optional)**

Create `development/scripts/setup_hooks.sh`:

```bash
#!/bin/bash
# Setup development hooks for all team members

echo "📦 Installing git hooks..."

cp development/.git/hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

echo "✅ Git hooks installed!"
echo "   Run 'bash scripts/setup_hooks.sh' to install"
```

### Testing Strategy

**Test 1: Introduce Broken Link**
```bash
# Create test branch
git checkout -b test-docs-validation

# Add broken link
echo "[Broken](./nonexistent.md)" >> development/docs/README.md
git add development/docs/README.md

# Try to commit (should fail)
git commit -m "test: broken link"

# Expected: Commit blocked by pre-commit hook
```

**Test 2: Fix and Retry**
```bash
# Remove broken link
git checkout development/docs/README.md

# Add valid content
echo "Valid change" >> development/docs/README.md
git add development/docs/README.md

# Commit (should succeed)
git commit -m "docs: valid change"

# Expected: Commit succeeds
```

**Test 3: GitHub Actions (if using)**
```bash
# Push test branch
git push origin test-docs-validation

# Create PR
# Expected: GitHub Actions runs and reports status
```

### Success Criteria

✅ Validation runs automatically on doc changes
✅ Broken links block merges to main
✅ Clear error messages guide developers
✅ Fast execution (<10 seconds for validation)
✅ Easy to bypass for emergencies (--no-verify)

### Time Estimate: **45 minutes**
- GitHub Actions setup: 20 min
- Pre-commit hook: 15 min
- Testing: 10 min

---

## 🔬 Issue #4: Content Validation

### Status: 🔴 **FUTURE - Planned for Next Sprint**

### Scope

Currently only validate links exist. Need to validate:
1. **Code examples** are syntactically correct
2. **Command examples** are valid
3. **API endpoints** are accurate
4. **Environment variables** are documented
5. **Version numbers** are current

### Implementation Plan (High-Level)

#### Phase 4.1: Code Example Validation (2 hours)

**Extract and test code blocks:**

```python
class CodeBlockValidator:
    """Validate code examples in documentation"""

    def extract_code_blocks(self, md_file: Path) -> List[CodeBlock]:
        """Extract fenced code blocks with language"""
        # Parse markdown
        # Find ```language blocks
        # Return list of CodeBlock(language, content, line_number)

    def validate_python(self, code: str) -> ValidationResult:
        """Validate Python code compiles"""
        try:
            compile(code, '<string>', 'exec')
            return ValidationResult(True, "Valid Python")
        except SyntaxError as e:
            return ValidationResult(False, f"Syntax error: {e}")

    def validate_bash(self, code: str) -> ValidationResult:
        """Validate bash syntax"""
        # Use shellcheck or bash -n
        result = subprocess.run(['bash', '-n'], input=code,
                              capture_output=True, text=True)
        return ValidationResult(result.returncode == 0, result.stderr)

    def validate_json(self, code: str) -> ValidationResult:
        """Validate JSON is well-formed"""
        try:
            json.loads(code)
            return ValidationResult(True, "Valid JSON")
        except json.JSONDecodeError as e:
            return ValidationResult(False, f"JSON error: {e}")
```

**Usage:**
```bash
python scripts/utilities/validate_docs_links.py --validate-code
```

#### Phase 4.2: Command Validation (1 hour)

**Check commands are valid:**

```python
class CommandValidator:
    """Validate command examples"""

    SAFE_COMMANDS = ['git', 'python', 'pip', 'docker', 'kubectl', 'ls', 'cat']

    def validate_command(self, cmd: str) -> ValidationResult:
        """Check command exists and syntax is valid"""
        # Parse command
        parts = shlex.split(cmd)
        base_cmd = parts[0]

        # Check if command exists
        if base_cmd not in self.SAFE_COMMANDS:
            return ValidationResult(False, f"Unknown command: {base_cmd}")

        # Validate syntax (dry-run if possible)
        # e.g., git --help, python -m py_compile, etc.

        return ValidationResult(True, "Valid command")
```

#### Phase 4.3: API Endpoint Validation (1 hour)

**Verify API docs match implementation:**

```python
class APIValidator:
    """Validate API documentation matches OpenAPI spec"""

    def __init__(self, openapi_spec: Path):
        self.spec = self.load_openapi(openapi_spec)

    def validate_endpoint(self, endpoint: str, method: str) -> ValidationResult:
        """Check if endpoint exists in OpenAPI spec"""
        if endpoint in self.spec['paths']:
            if method.lower() in self.spec['paths'][endpoint]:
                return ValidationResult(True, "Endpoint documented")
            else:
                return ValidationResult(False, f"Method {method} not in spec")
        else:
            return ValidationResult(False, "Endpoint not in spec")
```

### Success Criteria

✅ All code examples compile/parse correctly
✅ Command examples are valid
✅ API endpoints match OpenAPI spec
✅ Clear reporting of validation errors
✅ Fast execution (<30 seconds)

### Time Estimate: **4 hours total**
- Code validation: 2 hours
- Command validation: 1 hour
- API validation: 1 hour
- Integration & testing: 1 hour (not counted in 4 hours)

---

## 📦 Issue #5: Archive Documentation Links

### Status: 🟢 **OPTIONAL - Low Priority**

### Context

46 broken links exist in archived documentation:
- `docs/archive/2025-Q4/DOCUMENTATION_CLEANUP_EXECUTION_PLAN.md` (41 links)
- Other archived docs (5 links)

### Decision Matrix

**Option A: Fix All Links** (30 minutes)
- ✅ 100% link health
- ❌ Time investment in outdated docs
- ❌ May break again if archived files move

**Option B: Add Archive Notice** (5 minutes - RECOMMENDED)
- ✅ Sets expectations
- ✅ Quick to implement
- ✅ Preserves historical context
- ❌ Links remain broken

**Option C: Ignore** (0 minutes)
- ✅ No work needed
- ✅ Already documented as "acceptable"
- ❌ Slightly lower overall health score

### Recommended Approach: **Option B**

Add notice to archived docs:

```markdown
---
**⚠️ ARCHIVED DOCUMENT**

This document is archived for historical reference only. Links may be outdated or broken. For current documentation, see [INDEX.md](../INDEX.md).

---
```

### Implementation

```bash
# Add archive notice to top of archived docs
for file in development/docs/archive/**/*.md; do
    echo "---\n**⚠️ ARCHIVED DOCUMENT**\n\nThis document is archived for historical reference only. Links may be outdated or broken. For current documentation, see [INDEX.md](../INDEX.md).\n\n---\n\n$(cat $file)" > $file
done
```

### Time Estimate: **15 minutes**

---

## 📅 Execution Roadmap

### Week 1: Quick Wins

**Day 1-2: Fix Active Broken Links**
- [ ] Run automated fix script
- [ ] Validate results
- [ ] Manual cleanup (optional)
- [ ] Git commit
- **Time:** 30 minutes
- **Impact:** 🟢🟢🟢 High

**Day 3: Archive Notice**
- [ ] Add archive notices to old docs
- [ ] Update archive README
- [ ] Git commit
- **Time:** 15 minutes
- **Impact:** 🟡 Medium

**Milestone:** Documentation link health at 93%+

### Week 2: Automation

**Day 1-2: Implement Auto-Fix**
- [ ] Design fix strategies
- [ ] Implement orchestrator
- [ ] Add CLI interface
- [ ] Testing
- [ ] Git commit
- **Time:** 1 hour
- **Impact:** 🟢🟢🟢 High

**Day 3-4: CI/CD Integration**
- [ ] Create GitHub Actions workflow
- [ ] Set up pre-commit hook
- [ ] Configure branch protection
- [ ] Testing
- [ ] Documentation
- [ ] Git commit
- **Time:** 45 minutes
- **Impact:** 🟢🟢 Medium-High

**Milestone:** Automated prevention of documentation regression

### Future Sprint: Advanced Validation

**Week 3+: Content Validation**
- [ ] Code example validation
- [ ] Command validation
- [ ] API validation
- [ ] Integration testing
- [ ] Documentation
- [ ] Git commit
- **Time:** 4 hours
- **Impact:** 🟢 Medium

**Milestone:** Comprehensive documentation quality assurance

---

## 📊 Success Metrics

### Baseline (Current State)
- Link health: 84.5% overall (100% critical paths)
- Active broken links: 21
- Archived broken links: 44
- Automation: Basic validation script
- CI/CD: None

### Target State (After Phase 1)
- Link health: 93%+ overall
- Active broken links: <5
- Archived broken links: 44 (with notice)
- Automation: Basic + auto-fix
- CI/CD: Full integration

### Ultimate State (After Phase 3)
- Link health: 98%+ overall
- Active broken links: 0
- Archived broken links: 44 (documented as acceptable)
- Automation: Full validation (links + content)
- CI/CD: Blocks invalid docs from merging

---

## 🎯 Priority Decision Framework

When deciding what to work on, use this framework:

```
HIGH PRIORITY: Do This Week
├── ✅ Breaks critical navigation
├── ✅ Affects active development docs
├── ✅ Quick win (< 1 hour)
└── ✅ Prevents future issues

MEDIUM PRIORITY: Do Next Week
├── ⚠️ Improves quality but not blocking
├── ⚠️ Automation opportunity
├── ⚠️ Moderate time investment (1-2 hours)
└── ⚠️ Nice to have

LOW PRIORITY: Future Sprint
├── ℹ️ Archived/historical docs
├── ℹ️ Advanced features
├── ℹ️ Significant time investment (>2 hours)
└── ℹ️ Edge cases
```

**Apply to our issues:**
- Issue #1 (19 broken links): **HIGH** ✅
- Issue #2 (Auto-fix): **MEDIUM** ⚠️
- Issue #3 (CI/CD): **MEDIUM** ⚠️
- Issue #4 (Content validation): **LOW** ℹ️
- Issue #5 (Archived links): **LOW** ℹ️

---

## 🚀 Getting Started

### Immediate Next Step (5 minutes)

```bash
cd /c/Users/Corbin/development

# Step 1: Run automated fix
bash scripts/utilities/fix_broken_links.sh

# Step 2: Validate
python scripts/utilities/validate_docs_links.py

# Step 3: Review changes
git diff docs/

# Step 4: Commit
git add docs/
git commit -m "docs: fix 17 broken links in active documentation

- Fixed wrong ./docs/ prefixes in DOCUMENTATION_MIGRATION_PLAN.md
- Updated relative paths in guides/ka-lattice-deployment-guide.md
- Corrected paths in DOCUMENTATION_MAINTENANCE_GUIDE.md
- Fixed remaining path issues in guides

Link health improved: 84.5% → 93%
Active broken links: 21 → 4

Automated fix script: scripts/utilities/fix_broken_links.sh
Detailed analysis: BROKEN_LINKS_ANALYSIS_REPORT.md

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## 📚 Resources

**Documentation:**
- [BROKEN_LINKS_ANALYSIS_REPORT.md](./reports/BROKEN_LINKS_ANALYSIS_REPORT.md) - Detailed analysis
- [DOCUMENTATION_MAINTENANCE_GUIDE.md](./DOCUMENTATION_MAINTENANCE_GUIDE.md) - Maintenance procedures
- [DOCUMENTATION_TOOLS_IMPLEMENTATION.md](./DOCUMENTATION_TOOLS_IMPLEMENTATION.md) - Tool documentation

**Scripts:**
- `scripts/utilities/validate_docs_links.py` - Validation script
- `scripts/utilities/fix_broken_links.sh` - Automated fixes
- `scripts/utilities/analyze_broken_links.py` - Analysis tool

**Workflows:**
- `/docs-validate` - Slash command for validation
- `/docs-index` - Navigate documentation

---

## ✅ Checklist

### Phase 1: Quick Wins (This Week)
- [ ] Run `fix_broken_links.sh`
- [ ] Validate with `validate_docs_links.py`
- [ ] Manual cleanup (4 optional items)
- [ ] Add archive notices
- [ ] Git commit
- [ ] Update work evaluation report

### Phase 2: Automation (Next Week)
- [ ] Implement auto-fix strategies
- [ ] Add orchestrator
- [ ] Create CLI interface
- [ ] Test auto-fix
- [ ] Create GitHub Actions workflow
- [ ] Set up pre-commit hook
- [ ] Configure branch protection
- [ ] Git commit
- [ ] Update maintenance guide

### Phase 3: Advanced (Future)
- [ ] Design content validation
- [ ] Implement code example validation
- [ ] Implement command validation
- [ ] Implement API validation
- [ ] Integration testing
- [ ] Git commit
- [ ] Update documentation

---

**Status:** 🟢 Ready for Execution
**Owner:** Development Team
**Estimated Completion:** Week 2 (Phases 1-2)

---

**Navigation:** [← Back to Evaluation](./WORK_EVALUATION_REPORT.md) | [Implementation Guide →](./DOCUMENTATION_TOOLS_IMPLEMENTATION.md)
