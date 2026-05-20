# Architecture Documentation - Usage Guide

**Catalytic Computing Platform**
**Version**: 2.0
**Last Updated**: November 28, 2025
**Status**: Production-Ready ✅

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Documentation Structure](#documentation-structure)
3. [Common Tasks](#common-tasks)
4. [Rendering Diagrams](#rendering-diagrams)
5. [Updating Documentation](#updating-documentation)
6. [Creating New ADRs](#creating-new-adrs)
7. [Maintenance Schedule](#maintenance-schedule)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)
10. [Handoff Information](#handoff-information)

---

## Quick Start

### For First-Time Readers

1. **Start Here**: [`README-COMPREHENSIVE.md`](README-COMPREHENSIVE.md)
   - Complete navigation guide
   - Documentation structure overview
   - Links organized by audience

2. **Executive Overview**: [`00-executive-summary.md`](00-executive-summary.md)
   - High-level platform overview
   - Key metrics and capabilities
   - Technology stack summary

3. **Find Specific Information**: [`INDEX.md`](INDEX.md)
   - Complete file inventory
   - Quick navigation links
   - Content summaries

### For Documentation Maintainers

1. **Review Current Status**: [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md)
   - Completion tracking (currently 100%)
   - File inventory
   - Next steps and priorities

2. **Check This Guide**: [`USAGE_GUIDE.md`](USAGE_GUIDE.md) (this file)
   - Maintenance procedures
   - Update workflows
   - Common tasks

---

## Documentation Structure

The documentation follows a hierarchical structure combining three industry-standard frameworks:

### 1. C4 Model (4 Levels)

```
01-system-context/          # Level 1: System boundary and external actors
├── c4-context.puml         # PlantUML diagram
├── system-context.md       # Documentation
└── stakeholders.md         # Stakeholder analysis

02-container-architecture/  # Level 2: Major services/containers
├── c4-containers.puml      # PlantUML diagram
├── saas-platform.md        # SaaS API documentation
├── catalytic-engine.md     # GPU backend documentation
├── ghidrago-toolkit.md     # Reverse engineering documentation
└── infrastructure.md       # Infrastructure services

03-component-architecture/  # Level 3: Components within containers
├── c4-components-saas.puml     # SaaS components diagram
├── c4-components-catalytic.puml # GPU components diagram
├── c4-components-ghidra.puml    # Ghidra components diagram
├── saas-components.md           # SaaS documentation
├── catalytic-components.md      # GPU documentation
└── ghidrago-components.md       # Ghidra documentation

04-code-architecture/       # Level 4: Class-level details
├── c4-code-auth.puml       # Authentication classes diagram
├── c4-code-rls.puml        # Row-Level Security classes diagram
├── auth-module.md          # Auth implementation docs
├── rls-module.md           # RLS implementation docs
└── gpu-backend-module.md   # GPU backend implementation
```

### 2. Arc42 Template (12 Sections)

```
05-arc42/
├── 01-introduction-goals.md        # Requirements, quality goals
├── 02-constraints.md               # Technical/organizational constraints
├── 03-context-scope.md             # Business and technical context
├── 04-solution-strategy.md         # High-level approach
├── 05-building-block-view.md       # Static decomposition
├── 06-runtime-view.md              # Dynamic behavior
├── 07-deployment-view.md           # Infrastructure
├── 08-concepts.md                  # Cross-cutting patterns
├── 09-design-decisions.md          # Summary of ADRs
├── 10-quality.md                   # Quality requirements
├── 11-risks-technical-debt.md      # Known risks and debt
└── 12-glossary.md                  # Terminology
```

### 3. Architecture Decision Records

```
10-adrs/
├── template.md                     # Standard ADR template
├── 001-fastapi-over-flask.md      # Web framework decision
├── 002-postgresql-rls-multi-tenancy.md
├── 003-jwt-rs256-asymmetric.md
├── 004-pytorch-gpu-acceleration.md
├── 005-docker-compose-profiles.md
├── 006-hashicorp-vault-secrets.md
├── 007-prometheus-grafana-monitoring.md
├── 008-redis-caching-rate-limiting.md
├── 009-stripe-payment-processing.md
├── 010-d3fend-security-framework.md
├── 011-kubernetes-production-orchestration.md
├── 012-cupy-gpu-numpy.md
├── 013-ghidra-framework-integration.md
├── 014-sendgrid-email-delivery.md
└── 015-numba-jit-compilation.md
```

### 4. Cross-Cutting Concerns

```
06-cross-cutting/
├── security.md                     # Security architecture
├── observability.md                # Monitoring and logging
└── error-handling.md               # Error handling patterns

07-deployment/
└── kubernetes.md                   # Production Kubernetes setup

08-data/
└── database-schema.md              # Database design and schema

09-integration/
└── external-services.md            # Third-party integrations
```

---

## Common Tasks

### Task 1: Find Information About a Specific Technology Decision

**Example**: "Why did we choose FastAPI over Django?"

1. Open [`INDEX.md`](INDEX.md)
2. Navigate to "Architecture Decision Records" section
3. Find `ADR-001: FastAPI over Flask/Django`
4. Read the full decision record at `10-adrs/001-fastapi-over-flask.md`

**Or use quick search**:
```bash
# Search all ADRs
grep -r "FastAPI" 10-adrs/

# Search entire documentation
grep -r "FastAPI" .
```

---

### Task 2: Understand System Architecture

**For High-Level Overview**:
1. Start with [`00-executive-summary.md`](00-executive-summary.md)
2. Review System Context: `01-system-context/system-context.md`
3. View Container Architecture: `02-container-architecture/c4-containers.puml` (rendered diagram)

**For Implementation Details**:
1. Review Component Architecture: `03-component-architecture/`
2. Read Code Architecture: `04-code-architecture/`
3. Check specific technology ADRs in `10-adrs/`

---

### Task 3: Review Security Architecture

1. **Security Overview**: `06-cross-cutting/security.md`
2. **Multi-Tenancy**: `10-adrs/002-postgresql-rls-multi-tenancy.md`
3. **Authentication**: `10-adrs/003-jwt-rs256-asymmetric.md`
4. **Secrets Management**: `10-adrs/006-hashicorp-vault-secrets.md`
5. **D3FEND Compliance**: `10-adrs/010-d3fend-security-framework.md`

---

### Task 4: Understand Deployment Architecture

1. **Production Setup**: `07-deployment/kubernetes.md`
2. **Container Overview**: `02-container-architecture/c4-containers.puml`
3. **Infrastructure Services**: `02-container-architecture/infrastructure.md`
4. **Deployment Decision**: `10-adrs/011-kubernetes-production-orchestration.md`

---

### Task 5: Print Documentation

**Option 1: Browser-Based Printing (Easiest)**
1. Open [`print-browser.html`](print-browser.html) in any browser
2. Press `Ctrl+P` (Windows/Linux) or `Cmd+P` (Mac)
3. Choose "Save as PDF" or send to printer

**Option 2: Batch Open in Browser**
1. Run `open-all-for-print.bat` (Windows)
2. Press `Ctrl+P` in each browser tab
3. Print or save as PDF

**Option 3: VS Code Extension**
1. Install "Markdown PDF" extension in VS Code
2. Open any `.md` file
3. Press `Ctrl+Shift+P`, type "Markdown PDF", press Enter
4. PDF will be created in the same directory

---

## Rendering Diagrams

All 7 PlantUML diagrams (`.puml` files) need to be rendered to PNG/SVG before they can be viewed in documentation.

### Automatic Rendering (Recommended)

**Windows (PowerShell)**:
```powershell
cd C:\Users\Corbin\development\docs\architecture
.\render-diagrams.ps1
```

**Linux/Mac (Bash)**:
```bash
cd ~/development/docs/architecture
./render-diagrams.sh
```

**Options**:
- `--png-only` or `-PngOnly`: Render only PNG format
- `--svg-only` or `-SvgOnly`: Render only SVG format (recommended for docs)
- `--check-only` or `-CheckOnly`: Check if PlantUML is installed

### Manual Rendering

If you prefer manual control:

```bash
# Render all diagrams to SVG (best for documentation)
plantuml -tsvg **/*.puml

# Render all diagrams to PNG (best for presentations)
plantuml -tpng **/*.puml

# Render specific diagram
plantuml -tsvg 01-system-context/c4-context.puml
```

### PlantUML Installation

If PlantUML is not installed:

**Windows (Chocolatey)**:
```powershell
choco install plantuml
```

**Mac (Homebrew)**:
```bash
brew install plantuml
```

**Ubuntu/Debian**:
```bash
sudo apt-get install plantuml
```

**Manual (Any OS)**:
1. Download `plantuml.jar` from https://plantuml.com/download
2. Run: `java -jar plantuml.jar -tsvg **/*.puml`

### Embedding Diagrams in Documentation

After rendering, embed diagrams in markdown files:

```markdown
# System Context

The following diagram shows the system boundary and external actors:

![System Context Diagram](01-system-context/c4-context.svg)

## External Systems

As shown in the diagram above, the platform integrates with:
- Stripe for payment processing
- SendGrid for email delivery
- HashiCorp Vault for secrets management
```

---

## Updating Documentation

### When to Update

Architecture documentation should be updated whenever:

1. **Major architecture decisions** are made (create new ADR)
2. **New technologies** are adopted (create ADR, update Arc42 sections)
3. **System boundaries change** (update C4 diagrams and documentation)
4. **Components are added/removed** (update component diagrams)
5. **Deployment architecture changes** (update deployment docs)
6. **Security requirements change** (update security docs and ADRs)
7. **Quality attributes change** (update Arc42 section 10)

### Quarterly Reviews (Scheduled)

- **January 15**: Q1 review
- **April 15**: Q2 review
- **July 15**: Q3 review
- **October 15**: Q4 review

**Review Checklist**:
- [ ] Verify all ADRs are still accurate (mark deprecated if needed)
- [ ] Update technology versions in executive summary
- [ ] Review and update metrics (performance, scale, security)
- [ ] Check for new risks or technical debt
- [ ] Update diagrams if architecture has changed
- [ ] Re-render all PlantUML diagrams
- [ ] Update IMPLEMENTATION_STATUS.md completion status

---

## Creating New ADRs

### When to Create an ADR

Create a new Architecture Decision Record when:

- Making significant technology choices (framework, database, library)
- Changing deployment or infrastructure approaches
- Adopting new architectural patterns
- Making security-critical decisions
- Choosing between multiple viable alternatives

**Do NOT create ADRs for**:
- Minor implementation details
- Tactical coding decisions
- Temporary workarounds
- Obvious/uncontroversial choices

### ADR Creation Process

1. **Copy the template**:
```bash
cd 10-adrs/
cp template.md 016-new-decision-title.md
```

2. **Fill in the ADR**:
   - Update the header (status, date, deciders, technical story)
   - Write the Context section (problem, forces, constraints)
   - Document the Decision (what we chose and why)
   - List Consequences (benefits, trade-offs, side effects)
   - Document Alternatives Considered (and why rejected)
   - Create Implementation Plan (phases, success criteria, risks)

3. **Review and approve**:
   - Technical lead reviews
   - Architecture team approves
   - Update status from "Proposed" to "Accepted"

4. **Link the ADR**:
   - Add to `INDEX.md` (Architecture Decision Records section)
   - Add to `05-arc42/09-design-decisions.md` (summary)
   - Link from related documentation (e.g., component docs)

### ADR Numbering

- Use sequential 3-digit numbers: 001, 002, 003, etc.
- Current highest number: **015** (Numba JIT Compilation)
- Next ADR should be: **016**

### ADR Status Values

- **Proposed**: Under discussion, not yet approved
- **Accepted**: Approved and implemented
- **Deprecated**: No longer valid (replaced by newer decision)
- **Superseded**: Replaced by specific ADR (link to replacement)

### Example ADR Workflow

```bash
# 1. Create new ADR
cd C:\Users\Corbin\development\docs\architecture\10-adrs
cp template.md 016-rust-for-performance-critical-modules.md

# 2. Edit the ADR (fill in all sections)
code 016-rust-for-performance-critical-modules.md

# 3. Render any diagrams you added
cd ..
.\render-diagrams.ps1

# 4. Update index
code INDEX.md
# Add entry: "ADR-016: Rust for Performance-Critical Modules"

# 5. Update Arc42 design decisions
code 05-arc42/09-design-decisions.md
# Add summary of new ADR

# 6. Commit changes
git add 10-adrs/016-*.md INDEX.md 05-arc42/09-design-decisions.md
git commit -m "docs(adr): add ADR-016 for Rust adoption decision"
```

---

## Maintenance Schedule

### Daily Tasks (Development Team)

- [ ] Update code documentation when changing implementation
- [ ] Add code comments referencing relevant ADRs
- [ ] Update API documentation when endpoints change

### Weekly Tasks (Tech Lead)

- [ ] Review new documentation contributions
- [ ] Check for documentation drift (code vs. docs mismatch)
- [ ] Update IMPLEMENTATION_STATUS.md if new docs added

### Monthly Tasks (Architecture Team)

- [ ] Review open ADRs (Proposed status)
- [ ] Check for deprecated technologies (mark ADRs as deprecated)
- [ ] Update technology version numbers
- [ ] Review and update metrics (performance, scale)

### Quarterly Tasks (Full Review)

- [ ] Complete quarterly review checklist (see above)
- [ ] Re-render all diagrams
- [ ] Validate all external links still work
- [ ] Update executive summary with new achievements
- [ ] Review and update quality attributes
- [ ] Check technical debt tracking
- [ ] Update stakeholder analysis if personas change

### Annual Tasks (Major Update)

- [ ] Comprehensive documentation audit
- [ ] Update all Arc42 sections
- [ ] Review entire C4 model hierarchy
- [ ] Update deployment architecture docs
- [ ] Refresh security documentation
- [ ] Generate new PDF/HTML packages for distribution
- [ ] Archive previous version (tag in git)

---

## Troubleshooting

### Problem: PlantUML diagrams won't render

**Solution**:
```bash
# Check if PlantUML is installed
plantuml -version

# If not found, install it (see "Rendering Diagrams" section)
# Windows: choco install plantuml
# Mac: brew install plantuml
# Linux: sudo apt-get install plantuml

# Verify Java is installed (PlantUML requires Java)
java -version

# Try rendering a single diagram manually
plantuml -tsvg 01-system-context/c4-context.puml
```

### Problem: Links between documents are broken

**Cause**: Usually happens when files are renamed or moved

**Solution**:
```bash
# Search for broken links
grep -r "\[.*\](.*\.md)" . | grep -v "http"

# Update links to use relative paths
# Example: [ADR-001](10-adrs/001-fastapi-over-flask.md)
#          NOT: [ADR-001](C:\Full\Path\To\File.md)
```

### Problem: Documentation is out of sync with code

**Prevention**:
1. Link ADRs in code comments:
```python
# See ADR-002 for multi-tenancy strategy
# (C:\Users\Corbin\development\docs\architecture\10-adrs\002-postgresql-rls-multi-tenancy.md)
def set_tenant_context(tenant_id: str):
    ...
```

2. Add pre-commit hooks to remind developers to update docs

3. Include "Documentation" section in pull request template

**Fix**:
1. Review recent code changes
2. Update relevant documentation sections
3. Create new ADR if decision changed
4. Mark old ADR as "Deprecated" or "Superseded"

### Problem: Can't find specific information

**Solution**:
1. Check [`INDEX.md`](INDEX.md) first (complete file inventory)
2. Use global search:
```bash
# Search all documentation
grep -r "search term" C:/Users/Corbin/development/docs/architecture/

# Search only ADRs
grep -r "search term" C:/Users/Corbin/development/docs/architecture/10-adrs/

# Search with context (shows 3 lines before/after match)
grep -r -C 3 "search term" .
```

3. Navigate by audience in [`README-COMPREHENSIVE.md`](README-COMPREHENSIVE.md)

---

## Best Practices

### Writing Documentation

1. **Be Specific**: Use concrete examples, metrics, and data
   - Good: "FastAPI provides <100ms p50 latency at 10K concurrent users"
   - Bad: "FastAPI is fast"

2. **Include Context**: Explain the "why" not just the "what"
   - Every ADR has a "Context" section explaining the problem
   - Link to related decisions and trade-offs

3. **Use Diagrams**: Visual aids improve understanding
   - C4 diagrams show architecture at different levels
   - PlantUML source is version-controlled (trackable changes)

4. **Link Related Information**: Create navigation paths
   - ADRs link to related ADRs
   - Component docs link to relevant ADRs
   - Arc42 design decisions section summarizes all ADRs

5. **Update Regularly**: Documentation rots quickly
   - Quarterly reviews catch drift
   - Pre-commit hooks remind developers

### Maintaining Consistency

1. **Use Templates**: Follow established patterns
   - ADR template for all architecture decisions
   - C4 Model conventions for diagrams
   - Arc42 structure for comprehensive docs

2. **Follow Naming Conventions**:
   - ADRs: `001-kebab-case-title.md`
   - C4 diagrams: `c4-context.puml`, `c4-containers.puml`, etc.
   - Arc42: `01-introduction-goals.md` (numbered)

3. **Consistent Formatting**:
   - Use markdown headers consistently (# for title, ## for sections)
   - Code blocks with language hints: ```python, ```bash
   - Tables for comparisons and matrices

### Version Control

1. **Commit diagram sources (.puml) AND rendered images**:
```bash
git add 01-system-context/c4-context.puml
git add 01-system-context/c4-context.svg
git add 01-system-context/c4-context.png
```

2. **Write descriptive commit messages**:
```bash
git commit -m "docs(adr): add ADR-016 for Rust adoption in GPU backend"
git commit -m "docs(c4): update container diagram with new webhook service"
git commit -m "docs(arc42): update quality requirements for 100K users target"
```

3. **Tag major documentation milestones**:
```bash
git tag -a v2.0-docs -m "Architecture Documentation v2.0 Complete"
git push origin v2.0-docs
```

---

## Handoff Information

### Documentation Ownership

**Primary Maintainer**: Architecture Team
**Contributors**: All engineering teams
**Reviewers**: Tech Lead, Principal Engineer

### Key Stakeholders

1. **Developers**: Primary consumers of component/code architecture docs
2. **DevOps/SRE**: Deployment and infrastructure docs
3. **Security Team**: Security architecture and D3FEND compliance docs
4. **Product Management**: Executive summary and stakeholder analysis
5. **Customers/Partners**: High-level overview and integration docs

### Critical Files to Maintain

**Must Update**:
1. `INDEX.md` - When any file is added/removed
2. `IMPLEMENTATION_STATUS.md` - When documentation work is done
3. `00-executive-summary.md` - When major platform changes occur
4. `10-adrs/*.md` - When architecture decisions are made
5. `05-arc42/09-design-decisions.md` - When new ADRs are created

**Important to Keep Current**:
- All C4 diagrams (render after any architecture change)
- `06-cross-cutting/security.md` (update with security changes)
- `07-deployment/kubernetes.md` (update with infra changes)
- `08-data/database-schema.md` (update with schema changes)

### Tools Required

1. **PlantUML**: Diagram rendering (install via choco/brew/apt)
2. **Git**: Version control (already installed)
3. **Text Editor**: VS Code recommended (with Markdown PDF extension)
4. **Browser**: Any modern browser for HTML viewing

### Support and Resources

**Internal**:
- Architecture team meetings: Bi-weekly Thursdays 2pm
- #architecture Slack channel: Questions and discussions
- Tech Lead office hours: Tuesdays 3-4pm

**External**:
- [C4 Model Documentation](https://c4model.com/)
- [Arc42 Template Guide](https://arc42.org/overview)
- [ADR Best Practices](https://adr.github.io/)
- [PlantUML Reference](https://plantuml.com/)

---

## Next Steps

### Immediate Actions

1. **Render All Diagrams** (if not done):
```powershell
cd C:\Users\Corbin\development\docs\architecture
.\render-diagrams.ps1
```

2. **Review Key Documents**:
   - Read `README-COMPREHENSIVE.md` for navigation
   - Review `00-executive-summary.md` for platform overview
   - Check `INDEX.md` for complete file inventory

3. **Set Up Maintenance Schedule**:
   - Add quarterly review dates to calendar
   - Subscribe to architecture team meetings
   - Join #architecture Slack channel

### Future Enhancements

**Optional Improvements**:
- [ ] PDF generation pipeline (Pandoc automation)
- [ ] Interactive HTML documentation (MkDocs or Docusaurus)
- [ ] Automated link checking (CI/CD integration)
- [ ] Mermaid.js diagrams (alternative to PlantUML)
- [ ] Diagram versioning (track architectural evolution)
- [ ] Documentation metrics dashboard (coverage, staleness)

---

## Conclusion

This documentation suite represents a comprehensive snapshot of the Catalytic Computing Platform architecture as of November 2025. It combines industry-standard frameworks (C4 Model, Arc42, ADRs) to provide multiple perspectives on the system.

**Key Achievements**:
- ✅ 58 documentation files created (100% complete)
- ✅ 7 PlantUML diagrams validated (production-ready)
- ✅ 15 Architecture Decision Records documented
- ✅ 12 Arc42 template sections completed
- ✅ Complete C4 Model hierarchy (4 levels)

**Remember**:
- Documentation is a living artifact - update it regularly
- Use quarterly reviews to keep it current
- Create new ADRs for significant decisions
- Render diagrams after any architecture changes
- Link documentation in code comments

**Questions?**
- Check [`INDEX.md`](INDEX.md) for quick navigation
- Review [`TROUBLESHOOTING`](#troubleshooting) section above
- Contact Architecture Team via #architecture Slack channel

---

**Last Updated**: November 28, 2025
**Next Review**: January 15, 2026
**Version**: 2.0
**Status**: ✅ Production-Ready
