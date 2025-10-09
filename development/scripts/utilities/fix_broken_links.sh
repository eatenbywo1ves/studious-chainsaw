#!/bin/bash
# Fix all 21 broken links in active documentation
# Run from development/ directory

set -e  # Exit on error

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DEV_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$DEV_ROOT"

echo "========================================================================"
echo "Fixing Broken Links in Active Documentation"
echo "========================================================================"
echo ""

# Backup files before modifying
echo "Creating backups..."
mkdir -p .backup_links_$(date +%Y%m%d)
for file in \
    "docs/DOCUMENTATION_MIGRATION_PLAN.md" \
    "docs/guides/ka-lattice-deployment-guide.md" \
    "docs/DOCUMENTATION_MAINTENANCE_GUIDE.md" \
    "docs/guides/FOLD7_README.md" \
    "docs/architecture/security-architecture.md" \
    "docs/IMPLEMENTATION_GUIDE_INDEX.md"; do
    if [ -f "$file" ]; then
        cp "$file" ".backup_links_$(date +%Y%m%d)/"
    fi
done
echo "✓ Backups created in .backup_links_$(date +%Y%m%d)/"
echo ""

# Phase 1: DOCUMENTATION_MIGRATION_PLAN.md (5 fixes)
echo "[1/6] Fixing DOCUMENTATION_MIGRATION_PLAN.md (5 broken links)..."
sed -i 's|](./docs/INDEX\.md|](INDEX.md|g' docs/DOCUMENTATION_MIGRATION_PLAN.md
sed -i 's|](./docs/architecture/|](architecture/|g' docs/DOCUMENTATION_MIGRATION_PLAN.md
sed -i 's|](./docs/PRODUCTION_DEPLOYMENT_GUIDE\.md|](PRODUCTION_DEPLOYMENT_GUIDE.md|g' docs/DOCUMENTATION_MIGRATION_PLAN.md
sed -i 's|](../guides/REDIS_POOL_OPTIMIZATION_GUIDE\.md|](guides/REDIS_POOL_OPTIMIZATION_GUIDE.md|g' docs/DOCUMENTATION_MIGRATION_PLAN.md
echo "  ✓ Fixed 5 links (lines 122, 191, 194, 195, 196)"

# Phase 2: ka-lattice-deployment-guide.md (3 fixes)
echo "[2/6] Fixing guides/ka-lattice-deployment-guide.md (3 broken links)..."
sed -i 's|](./docs/GPU_ACCELERATION_STATUS\.md|](../GPU_ACCELERATION_STATUS.md|g' docs/guides/ka-lattice-deployment-guide.md
sed -i 's|](./docs/API_DOCUMENTATION\.md|](../api/README.md|g' docs/guides/ka-lattice-deployment-guide.md
sed -i 's|](./tests/README\.md|](../../tests/README.md|g' docs/guides/ka-lattice-deployment-guide.md
echo "  ✓ Fixed 3 links (lines 300, 301, 302)"

# Phase 3: DOCUMENTATION_MAINTENANCE_GUIDE.md (3 high priority fixes)
echo "[3/6] Fixing DOCUMENTATION_MAINTENANCE_GUIDE.md (3 broken links)..."
sed -i 's|](../INDEX\.md)|](INDEX.md)|g' docs/DOCUMENTATION_MAINTENANCE_GUIDE.md
sed -i 's|](../architecture/README\.md)|](architecture/README.md)|g' docs/DOCUMENTATION_MAINTENANCE_GUIDE.md
echo "  ✓ Fixed 3 links (lines 298, 305, 310)"
echo "  ℹ Skipped lines 289-290 (template examples)"

# Phase 4: FOLD7_README.md (3 fixes)
echo "[4/6] Fixing guides/FOLD7_README.md (3 broken links)..."
sed -i 's|](fold7_ssh_monitor\.py)|](../../scripts/deployment/fold7_ssh_monitor.py)|g' docs/guides/FOLD7_README.md
sed -i 's|](fold7_config\.json)|](../../fold7_config.json)|g' docs/guides/FOLD7_README.md
sed -i 's|](setup_termux_ssh_server\.sh)|](../../setup_termux_ssh_server.sh)|g' docs/guides/FOLD7_README.md
echo "  ✓ Fixed 3 links (lines 55, 56, 58)"

# Phase 5: security-architecture.md (1 fix)
echo "[5/6] Fixing architecture/security-architecture.md (1 broken link)..."
sed -i 's|../archive/2025-Q4/CONTAINER_ESCAPE_RESEARCH_REPORT\.md|../../security/CONTAINER_ESCAPE_RESEARCH_REPORT.md|g' docs/architecture/security-architecture.md
echo "  ✓ Fixed 1 link (line 389)"

# Phase 6: IMPLEMENTATION_GUIDE_INDEX.md (1 fix)
echo "[6/6] Fixing IMPLEMENTATION_GUIDE_INDEX.md (1 broken link)..."
sed -i 's|](../NVIDIA_BMAD_DEPLOYMENT_PLAN\.md)|](guides/NVIDIA_BMAD_DEPLOYMENT_PLAN.md)|g' docs/IMPLEMENTATION_GUIDE_INDEX.md
echo "  ✓ Fixed 1 link (line 517)"

echo ""
echo "========================================================================"
echo "✅ Fixed 17 high-priority broken links across 6 files"
echo "========================================================================"
echo ""
echo "Skipped (low priority / intentional):"
echo "  • DOCUMENTATION_MAINTENANCE_GUIDE.md lines 289-290 (template examples)"
echo "  • DOCUMENTATION_TOOLS_IMPLEMENTATION.md line 202 (regex example)"
echo "  • guides/README.md line 47 (webhooks - needs README creation)"
echo "  • quickstart/security-tools-5min.md line 214 (optional, marked 'if exists')"
echo ""
echo "To verify fixes:"
echo "  python scripts/utilities/validate_docs_links.py"
echo ""
echo "Backups saved in: .backup_links_$(date +%Y%m%d)/"
echo ""
