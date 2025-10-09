# Broken Links Quick Reference

**Date:** 2025-10-09
**Status:** 21 broken links in active documentation (17 high priority)

---

## Quick Stats

| Metric | Count |
|--------|-------|
| **Total Broken Links** | 65 |
| **Active Docs** | 21 |
| **Archived Docs** | 44 (ignored) |
| **High Priority** | 17 |
| **Low Priority** | 4 |

---

## One-Command Fix

```bash
# Run from development/ directory
bash scripts/utilities/fix_broken_links.sh
```

This fixes **17 of 21** broken links automatically.

---

## Files Affected (by priority)

### High Priority (17 links)

1. **docs/DOCUMENTATION_MIGRATION_PLAN.md** (5 links)
   - Lines 122, 191, 194, 195, 196
   - Issue: Uses `./docs/` prefix when already in docs/

2. **docs/guides/ka-lattice-deployment-guide.md** (3 links)
   - Lines 300, 301, 302
   - Issue: Wrong relative paths to docs root and tests

3. **docs/DOCUMENTATION_MAINTENANCE_GUIDE.md** (3 links)
   - Lines 298, 305, 310
   - Issue: Template examples with wrong paths

4. **docs/guides/FOLD7_README.md** (3 links)
   - Lines 55, 56, 58
   - Issue: Files moved during reorganization

5. **docs/architecture/security-architecture.md** (1 link)
   - Line 389
   - Issue: Points to archive but file is in security/

6. **docs/IMPLEMENTATION_GUIDE_INDEX.md** (1 link)
   - Line 517
   - Issue: File moved to guides/

7. **docs/quickstart/security-tools-5min.md** (1 link)
   - Line 214
   - Issue: Optional file marked "if exists"

### Low Priority (4 links)

8. **docs/DOCUMENTATION_MAINTENANCE_GUIDE.md** (2 links)
   - Lines 289, 290
   - Issue: Template examples - add "(example)" note

9. **docs/DOCUMENTATION_TOOLS_IMPLEMENTATION.md** (1 link)
   - Line 202
   - Issue: Regex pattern example

10. **docs/guides/README.md** (1 link)
    - Line 47
    - Issue: Missing services/webhooks/README.md

---

## Common Issues & Fixes

### Issue 1: `./docs/` prefix when already in docs/
**Example:** `[link](./docs/INDEX.md)` in a file already in `docs/`
**Fix:** Remove `./docs/` → `[link](INDEX.md)`
**Affected:** 6 links

### Issue 2: Wrong relative path depth
**Example:** `[link](../file.md)` when should be `[link](file.md)`
**Fix:** Adjust `../` based on directory depth
**Affected:** 5 links

### Issue 3: File moved during reorganization
**Example:** Points to old location
**Fix:** Update to new path
**Affected:** 6 links

---

## Manual Actions Needed (4 items)

After running auto-fix script:

1. **DOCUMENTATION_MAINTENANCE_GUIDE.md lines 289-290**
   - Add "(example)" after the links
   - These are template examples in documentation

2. **DOCUMENTATION_MAINTENANCE_GUIDE.md line 310**
   - This is in "Bad Example" section
   - Consider adding comment: `<!-- Intentional bad example -->`

3. **guides/README.md line 47**
   - Create `services/webhooks/README.md` OR
   - Remove the webhook link

4. **quickstart/security-tools-5min.md line 214**
   - Create `docs/deployment/PRODUCTION_SECURITY_AUDIT.md` OR
   - Leave as-is (marked "if exists")

---

## Validation

```bash
# Before fix
python scripts/utilities/validate_docs_links.py
# Result: 65 broken links (21 active, 44 archived)

# After fix
python scripts/utilities/validate_docs_links.py
# Expected: ~4 broken links (low priority items)
```

---

## Categorization

| Fix Type | Count | Description |
|----------|-------|-------------|
| **Easy** | 9 | Simple path corrections |
| **Medium** | 12 | File moved, relative path updates |
| **Hard** | 0 | Complex issues |

| Priority | Count | Description |
|----------|-------|-------------|
| **High** | 17 | Active docs, broken links |
| **Medium** | 0 | - |
| **Low** | 4 | Templates, examples, optional |

---

## Next Steps

1. ✅ Review this document
2. ⏳ Run `bash scripts/utilities/fix_broken_links.sh`
3. ⏳ Verify with `python scripts/utilities/validate_docs_links.py`
4. ⏳ Handle 4 manual actions (optional)
5. ⏳ Commit changes

**Estimated Time:** 5-10 minutes (automated) + 5 minutes (manual items)

---

## Related Documents

- **Full Analysis:** `BROKEN_LINKS_ANALYSIS_REPORT.md` (detailed breakdown with examples)
- **Fix Script:** `scripts/utilities/fix_broken_links.sh` (automated fixes)
- **Validation Tool:** `scripts/utilities/validate_docs_links.py` (detection)
- **Analysis Tool:** `scripts/utilities/analyze_broken_links.py` (categorization)

---

**Last Updated:** 2025-10-09
