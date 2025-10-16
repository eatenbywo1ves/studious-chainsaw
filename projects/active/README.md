# Active Projects Directory
**Last Organized:** 2025-10-14
**Purpose:** Central repository for active project documentation

---

## Directory Structure

This directory has been organized by documentation type for improved navigation:

```
active/
├── README.md                  (This file)
├── guides/                    Setup and reference guides
├── workflows/                 Workflow and configuration docs
├── security/                  Security assessments and audits
├── architecture/              System architecture and design
├── phases/                    Implementation phase summaries
└── [remaining root files]     Miscellaneous active documents
```

---

## Quick Navigation

### 📚 Guides
**Location:** [guides/](guides/)

Setup guides, quick references, and troubleshooting documentation:
- Alias configuration guides
- Claude Code setup
- Ghidra setup
- Security guides (Hash/AES256)
- Tailscale/Wireshark troubleshooting
- Samsung Fold configuration

### ⚙️ Workflows
**Location:** [workflows/](workflows/)

Workflow examples and configuration hot-reload documentation:
- Workflow examples and patterns
- Config hot reload setup
- Hot reload demo results

### 🔒 Security
**Location:** [security/](security/)

Security assessments, audits, and implementation guides:
- Claude security implementation
- Critical security actions
- Security assessment reports
- SSH security audit reports
- Security improvements summaries

### 🏗️ Architecture
**Location:** [architecture/](architecture/)

System architecture and design documentation:
- Data storage architecture
- MCP agent architecture plans
- Process control flow diagrams
- Workflow architecture

### 📋 Phases
**Location:** [phases/](phases/)

Implementation phase summaries and completion reports:
- Phase 3/4/5 implementation summaries
- Phase production plans
- Implementation complete reports
- TMUX implementation

---

## Organization Principles

**By Type, Not By Project:** Files are organized by their purpose (guide, security doc, phase report) rather than by project. This makes it easier to find similar types of documentation.

**Preserved History:** All documents are retained—organization improves discoverability without discarding historical context.

**Flat Sub-Directories:** Each category uses a flat structure (no deep nesting) for quick access.

---

## Finding Documents

### By Category
Navigate to the relevant subdirectory listed above.

### By Name
Use file search from the active directory:
```bash
find . -name "*keyword*"
```

### By Content
Use grep for content search:
```bash
grep -r "search term" .
```

---

## Maintenance

### Adding New Documents
Place documents in the appropriate category subdirectory:
- **Setup/Reference Guide** → `guides/`
- **Security Document** → `security/`
- **Architecture Design** → `architecture/`
- **Phase Report/Summary** → `phases/`
- **Workflow/Config** → `workflows/`
- **Unclear** → Root (will be categorized during next cleanup)

### Periodic Review
Monthly review recommended to:
- Archive completed phases
- Update documentation links
- Move root files to appropriate categories
- Remove obsolete documents

---

## Related Documentation

- **Project Root:** [../](../)
- **Archived Projects:** [../archived/](../archived/)
- **Platform Code:** [../platform/](../platform/)
- **Documentation:** [../docs/](../docs/)

---

**Organized:** 2025-10-14
**Maintainer:** Development Team
**Status:** ✅ Active Organization
