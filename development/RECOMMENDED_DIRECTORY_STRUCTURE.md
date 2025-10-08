# Recommended Directory Structure

**Project:** Development Directory
**Version:** 2.0 (Post-Cleanup)
**Date:** October 8, 2025

---

## Visual Structure

```
development/
│
├── 📄 Core Configuration (12 files at root)
│   ├── README.md                          # Main project readme
│   ├── QUICK_START_GUIDE.md              # Getting started guide
│   ├── QUICK_DEPLOY.md                   # Quick deployment reference
│   ├── DEPLOYMENT_STATUS_CURRENT.md      # Current deployment status
│   ├── CLEANUP_QUICK_REFERENCE.md        # Cleanup reference
│   ├── .env                              # Environment configuration
│   ├── .env.example                      # Environment template
│   ├── .env.gpu.example                  # GPU environment template
│   ├── .gitignore                        # Git exclusions
│   ├── pyproject.toml                    # Python project config
│   ├── pytest.ini                        # Test configuration
│   └── ruff.toml                         # Linting configuration
│
├── 🐳 Docker Configuration (9 files)
│   ├── docker-compose.yml                # Main compose file
│   ├── docker-compose-core.yml          # Core services
│   ├── docker-compose-saas.yml          # SaaS services
│   ├── docker-compose.local.yml         # Local development
│   ├── docker-compose.ghidra-ml.yml     # Ghidra ML services
│   ├── Dockerfile.catalytic             # Catalytic app
│   ├── Dockerfile.ghidra-ml             # Ghidra ML
│   ├── Dockerfile.saas                   # SaaS platform
│   └── Dockerfile.webhook                # Webhook service
│
├── 📦 Dependencies (7 files)
│   ├── requirements-dev.txt              # Development dependencies
│   ├── requirements-saas.txt             # SaaS dependencies
│   ├── requirements-catalytic.txt        # Catalytic dependencies
│   ├── requirements-gpu.txt              # GPU dependencies
│   ├── requirements-security.txt         # Security dependencies
│   ├── requirements-testing.txt          # Testing dependencies
│   └── requirements.txt                  # Combined requirements
│
├── ⚙️ Configuration Files (5 files)
│   ├── .eslintrc.js                      # JavaScript linting
│   ├── ka-lattice-config.yaml           # KA Lattice configuration
│   ├── fold7_config.json                # Fold7 SSH configuration
│   └── .testcontainers.properties       # Test container settings
│
├── 🎯 Active Planning (2-3 files max)
│   ├── BMAD_NEXT_STEPS_EXECUTION_PLAN.md  # Active roadmap
│   └── RESPONSIBLE_SECURITY_RESEARCH_GUIDE.md
│
│
├── 📁 Core Application Code
│   ├── apps/                             # Core applications
│   │   └── catalytic/                    # Catalytic lattice computing
│   │       ├── gpu/                      # GPU implementations
│   │       │   ├── backend_selector.py   # Backend selection strategies
│   │       │   ├── factory_refactored.py # Refactored factory
│   │       │   ├── factory_builder.py    # Builder pattern
│   │       │   ├── base.py
│   │       │   ├── manager.py
│   │       │   ├── cuda_impl.py
│   │       │   ├── cupy_impl.py
│   │       │   ├── pytorch_impl.py
│   │       │   └── cpu_impl.py
│   │       └── ka_lattice/              # Knowledge architecture
│   │
│   ├── saas/                            # SaaS platform
│   │   ├── api/                         # API layer
│   │   ├── auth/                        # Authentication
│   │   │   ├── auth_dependencies.py     # DI components
│   │   │   ├── middleware_refactored.py # Composable middleware
│   │   │   └── jwt_auth.py              # JWT authentication
│   │   ├── frontend/                    # Next.js frontend
│   │   └── services/                    # Business logic
│   │
│   ├── libs/                            # Shared libraries
│   │   ├── config/                      # Configuration
│   │   ├── gpu/                         # GPU utilities
│   │   ├── constants/                   # Constants
│   │   └── utils/                       # Utilities
│   │
│   └── services/                        # Microservices
│       ├── mcp/                         # Model Context Protocol
│       └── webhooks/                    # Webhook services
│
│
├── 🧪 Tests & Validation
│   └── tests/
│       ├── gpu/                         # GPU tests (13 files)
│       │   ├── test_gpu_refactoring_simple.py
│       │   ├── cupy-with-pytorch-cuda.py
│       │   ├── gpu-libraries-test.py
│       │   └── ... (10 more test files)
│       │
│       ├── benchmarks/                  # Performance benchmarks (2 files)
│       │   ├── gpu-performance-benchmark.py
│       │   └── matrix-optimization-benchmark.py
│       │
│       ├── integration/                 # Integration tests
│       ├── unit/                        # Unit tests
│       ├── e2e/                         # End-to-end tests
│       ├── performance/                 # Performance tests
│       └── conftest.py                  # Pytest configuration
│
│
├── 🔧 Scripts & Automation
│   └── scripts/
│       ├── deployment/                  # Deployment scripts (2 files)
│       │   ├── deploy-ka-lattice-local.py
│       │   └── fold7_ssh_monitor.py
│       │
│       ├── utilities/                   # Utility scripts (7 files)
│       │   ├── convert_ascii_to_pdf.py
│       │   ├── create_mernithian_pdf.py
│       │   ├── glyph_svg_exporter.py
│       │   ├── update-imports.py
│       │   └── ... (3 more utilities)
│       │
│       ├── troubleshooting/            # Diagnostic scripts
│       ├── benchmarks/                 # Benchmarking scripts
│       └── python/                     # Python scripts
│
│
├── 📚 Documentation Hub
│   └── docs/
│       ├── README.md                    # Documentation index
│       │
│       ├── guides/                      # Operational guides (11 files)
│       │   ├── FOLD7_SSH_SETUP.md
│       │   ├── ka-lattice-deployment-guide.md
│       │   ├── saas-deployment-guide.md
│       │   ├── ENV_CONFIGURATION_GUIDE.md
│       │   ├── REDIS_POOL_OPTIMIZATION_GUIDE.md
│       │   └── ... (6 more guides)
│       │
│       ├── specifications/              # Technical specifications (8 files)
│       │   ├── FRAMEWORK_CAPABILITY_ASSESSMENT.md
│       │   ├── GHIDRAGO_SPECIFICATION.md
│       │   ├── JWT_CONSOLIDATION_ANALYSIS.md
│       │   ├── CONFIGURATION_AUDIT_REPORT.md
│       │   └── ... (4 more specs)
│       │
│       ├── reports/                     # Active reports (8 files)
│       │   ├── LINTING_REPORT.md
│       │   ├── REFACTORING_SUMMARY.md
│       │   ├── PRODUCTION_READY_CHECKLIST.md
│       │   ├── D3FEND_NEXT_STEPS.md
│       │   └── ... (4 more reports)
│       │
│       ├── conversations/               # Narrative content (3 files)
│       │   ├── ascii_portraits_collection.md
│       │   ├── cognitive_warfare_conversation.md
│       │   └── mernithian_conversation.md
│       │
│       ├── api/                         # API documentation
│       ├── deployment/                  # Deployment docs
│       ├── monitoring/                  # Monitoring docs
│       │
│       └── archive/                     # Historical documentation
│           ├── README.md                # Archive index
│           │
│           ├── phase-reports/           # Phase completion reports (17 files)
│           │   ├── PHASE1_COMPLETION_SUMMARY.md
│           │   ├── PHASE2_100_PERCENT_COMPLETE.md
│           │   ├── PHASE2_COMPLETE.md
│           │   ├── PHASE3_BATCH_PROCESSING_COMPLETE.md
│           │   ├── PHASE4_GPU_PROFILER_COMPLETE.md
│           │   └── ... (12 more phase reports)
│           │
│           ├── week-reports/            # Weekly reports (11 files)
│           │   ├── WEEK1_COMPLETION_SUMMARY.md
│           │   ├── WEEK2_COMPLETE_SUMMARY.md
│           │   ├── WEEK3_COMPREHENSIVE_LOAD_TESTING_FINAL_REPORT.md
│           │   └── ... (8 more week reports)
│           │
│           ├── deployment-history/      # Deployment history (7 files)
│           │   ├── DEPLOYMENT_COMPLETE_2025-10-05.md
│           │   ├── FINAL_DEPLOYMENT_SUMMARY.md
│           │   └── ... (5 more deployment reports)
│           │
│           └── 2025-Q4/                 # Q4 completion reports (35+ files)
│               ├── BMAD_*.md            # BMAD reports (11 files)
│               ├── REDIS_*.md           # Redis reports (6 files)
│               ├── *SECURITY*.md        # Security reports (9 files)
│               ├── GPU_*.md             # GPU reports (7 files)
│               └── ... (other completions)
│
│
├── 🎨 Visualizations
│   └── visualizations/                  # HTML visualizations (7 files)
│       ├── ascii_portraits_collection.html
│       ├── gpu-optimization-visualization.html
│       ├── mernithian_conversation.html
│       ├── profiler_visualization_v2.html
│       └── ... (3 more visualizations)
│
│
├── 📊 Results & Metrics
│   └── results/
│       ├── gpu/                         # GPU metrics & results (2 files)
│       │   ├── gpu_baseline_metrics.json
│       │   └── memory-optimization-results.json
│       │
│       └── security/                    # Security validation results
│
│
├── 💾 Backups & Data
│   ├── backups/                         # Backup files (2 files)
│   │   ├── ka_knowledge_backup.json (1.7 MB)
│   │   └── proof_library.json
│   │
│   ├── data/                            # Application data
│   ├── cache/                           # Cache files
│   └── models/                          # ML models
│
│
├── 🔒 Security & Infrastructure
│   ├── security/                        # Security implementation
│   │   ├── application/                 # Application security
│   │   │   ├── redis_pool_protocol.py   # Redis pool protocol
│   │   │   ├── redis_pool_implementation.py
│   │   │   ├── redis_connection_manager.py
│   │   │   ├── jwt_security.py
│   │   │   ├── rate_limiting.py
│   │   │   └── security_headers.py
│   │   │
│   │   ├── deployment/                  # Security deployment
│   │   ├── load_tests/                  # Load testing
│   │   ├── d3fend/                      # D3FEND implementation
│   │   └── wiz-challenge/               # Wiz challenge
│   │
│   ├── infra/                           # Infrastructure as code
│   ├── kubernetes/                      # Kubernetes configs
│   ├── monitoring/                      # Observability
│   └── nginx/                           # Nginx configs
│
│
├── 🔧 Tools & External Dependencies
│   ├── tools/                           # External tools
│   │   └── ghidra/                      # Ghidra installation (797 MB)
│   │       └── ghidra_11.4.2_PUBLIC/
│   │
│   └── [Ghidra Projects]                # Ghidra-related directories
│       ├── ghidra_bridge/
│       ├── ghidra_scripts/
│       ├── ghidra-extensions/
│       ├── GhidraGo/
│       ├── GhidraGraph/
│       ├── GhidraLookup/
│       ├── Ghidraaas/
│       └── ... (10 more Ghidra projects)
│
│
├── 🗄️ Archives & Historical
│   ├── archives/                        # Project archives (844 MB)
│   │   ├── phase2-backup/
│   │   └── ghidra-complete-backup/
│   │
│   ├── refactoring/                     # Refactoring artifacts
│   └── temp/                            # Temporary files
│
│
└── 🔄 CI/CD & DevOps
    ├── .github/                         # GitHub Actions
    ├── .config/                         # Tool configurations
    ├── dashboard/                       # Project dashboard
    └── pitch/                           # Project pitch materials
```

---

## File Count Summary

### Root Level (Target: ~40 files)
- **Configuration:** 12 files
- **Docker:** 9 files
- **Dependencies:** 7 files
- **Other Config:** 5 files
- **Active Planning:** 2-3 files
- **Scripts:** 5 batch/shell files

**Total: ~40 files** ✅

---

## Subdirectories (50 organized directories)

### Code (8 directories)
- `apps/`, `saas/`, `libs/`, `services/`
- `tests/`, `scripts/`, `security/`, `infra/`

### Documentation (1 directory with 6 subdirs)
- `docs/` → guides/, specifications/, reports/, conversations/, api/, archive/

### Supporting (6 directories)
- `visualizations/`, `results/`, `backups/`, `data/`, `cache/`, `models/`

### Infrastructure (4 directories)
- `kubernetes/`, `monitoring/`, `nginx/`, `.github/`

### Tools & Archives (5 directories)
- `tools/`, `archives/`, `refactoring/`, `temp/`, `.config/`

### Ghidra Projects (15 directories)
- Various Ghidra-related projects

### Other (5 directories)
- `dashboard/`, `pitch/`, `career/`, `defensive_agents/`, `ssl/`

---

## Documentation Organization

### Active Documentation (Root Level)
```
README.md                     # Main project readme
QUICK_START_GUIDE.md          # Getting started
QUICK_DEPLOY.md               # Quick deployment
DEPLOYMENT_STATUS_CURRENT.md  # Current status
```

### Categorized Documentation (docs/)
```
docs/
├── guides/          # How-to guides for operations
├── specifications/  # Technical architecture specs
├── reports/         # Active status reports
├── conversations/   # Narrative content
└── archive/         # Historical completions
```

### Archive Organization (docs/archive/)
```
docs/archive/
├── phase-reports/       # Organized by phase
├── week-reports/        # Organized by week
├── deployment-history/  # Deployment milestones
└── 2025-Q4/            # Organized by quarter and topic
```

---

## Key Principles

### 1. **Root Directory = Essential Only**
- Configuration files that tools expect at root
- Quick reference documentation (README, QUICK_START)
- Docker/deployment configs
- Dependency files

### 2. **Deep Organization for Everything Else**
- Tests in `tests/` with subcategories
- Scripts in `scripts/` with purpose-based folders
- Documentation in `docs/` with clear categorization
- Supporting files in dedicated directories

### 3. **Historical vs. Active Separation**
- Active docs: Root or `docs/` subdirectories
- Historical docs: `docs/archive/` with clear organization
- Completed projects: `archives/`

### 4. **Logical Grouping**
- Group by **function** (tests, scripts, docs)
- Group by **type** (visualizations, results, backups)
- Group by **status** (active, archived, temporary)

### 5. **Clear Naming**
- Directories: lowercase, plural (tests, scripts, guides)
- Active docs: Present tense (DEPLOYMENT_STATUS_CURRENT)
- Archived docs: Past tense (DEPLOYMENT_COMPLETE)
- Time-based archives: Use dates/quarters (2025-Q4)

---

## Navigation Guide

### "I want to..."

**...get started quickly**
→ `README.md`, `QUICK_START_GUIDE.md`

**...deploy the application**
→ `QUICK_DEPLOY.md`, `docs/guides/`

**...run tests**
→ `tests/gpu/`, `tests/benchmarks/`, `tests/integration/`

**...find a completed report**
→ `docs/archive/README.md` (index), then navigate by phase/week/topic

**...understand the architecture**
→ `docs/specifications/`

**...use a utility script**
→ `scripts/utilities/`

**...view performance metrics**
→ `visualizations/`, `results/gpu/`

**...check current status**
→ `DEPLOYMENT_STATUS_CURRENT.md`, `docs/reports/`

**...configure the environment**
→ `.env.example`, `docs/guides/ENV_CONFIGURATION_GUIDE.md`

**...understand historical context**
→ `docs/archive/` (phase-reports, week-reports, 2025-Q4)

---

## Maintenance Rules

### When Creating New Files

#### Documentation
- **Active guide** → `docs/guides/`
- **Technical spec** → `docs/specifications/`
- **Status report** → `docs/reports/`
- **Quick reference** → Root (only if truly essential)

#### Code
- **Test** → `tests/` (appropriate subdirectory)
- **Script** → `scripts/` (purpose-based subdirectory)
- **Application code** → `apps/`, `saas/`, or `libs/`

#### Supporting Files
- **Visualization** → `visualizations/`
- **Results** → `results/`
- **Backup** → `backups/`

### Quarterly Cleanup

**Every 3 months, archive:**
1. Completed status reports → `docs/archive/YYYY-QX/`
2. Historical planning docs → `docs/archive/YYYY-QX/`
3. Old test results → `results/archive/`
4. Obsolete scripts → `scripts/archive/` or delete

### File Retention Policy

**Keep at Root:**
- Current deployment status
- Quick start/deploy guides
- Configuration files
- Docker compose files

**Archive After Completion:**
- Phase completion reports
- Weekly reports
- Deployment summaries
- BMAD/Redis/Security validations

**Delete Regularly:**
- Cache directories
- Obsolete test files
- Temporary scripts
- Duplicate documents

---

## Before/After Comparison

### Before Cleanup
```
development/
├── 200 files at root ❌
├── 125+ markdown files at root ❌
├── 13 test files at root ❌
├── 30 MB of cache directories ❌
├── Confusing organization ❌
└── Hard to navigate ❌
```

### After Cleanup
```
development/
├── ~40 files at root ✅
├── ~10 markdown files at root ✅
├── 0 test files at root ✅
├── Cache directories deleted ✅
├── Logical organization ✅
└── Easy to navigate ✅
```

---

## Tools & Automation

### Quick Navigation
```bash
# Jump to specific areas
alias docs='cd docs'
alias tests='cd tests'
alias scripts='cd scripts'
alias archive='cd docs/archive'
```

### Find Archived Documents
```bash
# By phase
find docs/archive/phase-reports -name "PHASE2*"

# By topic
find docs/archive/2025-Q4 -name "*REDIS*"

# By week
ls docs/archive/week-reports/
```

### Verify Structure
```bash
# Count root files
ls -1 | wc -l  # Should be ~40

# Count docs at root
ls -1 *.md | wc -l  # Should be ~10

# Show archive organization
tree docs/archive -L 2
```

---

## Benefits of This Structure

### For Developers
✅ **Easy onboarding** - Clear README and quick start
✅ **Fast navigation** - Logical directory organization
✅ **Better IDE performance** - Fewer root files to index
✅ **Clear testing** - All tests in `tests/` with subcategories

### For Operations
✅ **Quick deployment** - Docker configs at root
✅ **Clear guides** - Organized in `docs/guides/`
✅ **Current status** - `DEPLOYMENT_STATUS_CURRENT.md`
✅ **Historical reference** - Complete archive in `docs/archive/`

### For Project Management
✅ **Progress tracking** - Active reports in `docs/reports/`
✅ **Historical context** - Archived completions by phase/week/quarter
✅ **Lessons learned** - Preserved in organized archive
✅ **Future planning** - Active planning docs clearly separated

### For Maintenance
✅ **Easy cleanup** - Clear rules for where files go
✅ **Quarterly archival** - Simple process
✅ **Git performance** - Fewer files at root
✅ **Disk space** - Cache cleanup recovered 30 MB

---

## Implementation Status

**Phase 1:** ✅ Cache cleanup (30 MB recovered)
**Phase 2:** ✅ Historical documentation archived (70+ files)
**Phase 3:** ✅ Code reorganization (26 files moved)
**Phase 4:** ✅ Supporting files organized (20+ files)
**Phase 5:** ✅ Index documents created
**Phase 6:** ✅ Validation complete
**Phase 7:** ✅ Git commit

**Result:** Clean, organized, maintainable directory structure

---

**Status:** ✅ **RECOMMENDED STRUCTURE DOCUMENTED**
**Version:** 2.0
**Last Updated:** October 8, 2025
