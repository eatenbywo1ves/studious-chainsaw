# Architecture Documentation - Agent Usage Guide

**Using AI Agents to Maintain, Query, and Enhance Architecture Documentation**

**Version**: 1.0
**Date**: November 28, 2025
**Status**: Production-Ready ✅

---

## Table of Contents

1. [Overview](#overview)
2. [Agent Capabilities Matrix](#agent-capabilities-matrix)
3. [Common Use Cases](#common-use-cases)
4. [Agent Workflows](#agent-workflows)
5. [Best Practices](#best-practices)
6. [Advanced Multi-Agent Patterns](#advanced-multi-agent-patterns)
7. [Automation Examples](#automation-examples)
8. [Troubleshooting](#troubleshooting)

---

## Overview

This guide explains how to use Claude Code's specialized agents to work with the architecture documentation system. Rather than manually searching, updating, or validating documentation, you can leverage agents for automation, analysis, and maintenance.

### Why Use Agents?

**Traditional Approach** (Manual):
- Search through 58+ documentation files manually
- Validate PlantUML diagrams one by one
- Update multiple related documents separately
- Risk missing cross-references and dependencies

**Agent Approach** (Automated):
- Ask agents to find, analyze, and synthesize information
- Automated validation across all diagrams
- Coordinated updates across related documents
- Automatic dependency tracking

---

## Agent Capabilities Matrix

### Quick Reference: Which Agent for Which Task?

| Task | Best Agent | Alternative | Command Example |
|------|------------|-------------|-----------------|
| **Find technology decision** | `Explore` | `technical-researcher` | "Which ADR documents our database choice?" |
| **Validate all diagrams** | `technical-researcher` | N/A | "Validate all PlantUML diagrams for syntax errors" |
| **Update ADR after decision** | `developer` | `architect` | "Create ADR-016 for switching to Rust" |
| **Research best practices** | `technical-researcher` | `search-specialist` | "Research PostgreSQL RLS best practices" |
| **Review code vs. docs alignment** | `code-reviewer` | `architect-reviewer` | "Check if auth module matches ADR-003" |
| **Create new C4 diagram** | `architect` | `developer` | "Create component diagram for new microservice" |
| **Security audit documentation** | `security-auditor` | `compliance-specialist` | "Audit D3FEND coverage in security docs" |
| **Query documentation** | `Explore` (quick) | `general-purpose` | "What's our monitoring strategy?" |
| **Generate deployment guide** | `devops-engineer` | `deployment-engineer` | "Create deployment checklist from docs" |
| **Update Arc42 quality section** | `architect` | `qa` | "Update quality requirements for 100K users" |

---

## Common Use Cases

### Use Case 1: Finding Information in Documentation

**Scenario**: "I need to know why we chose FastAPI over Django"

**Best Agent**: `Explore` (fast, purpose-built for codebase exploration)

**Command**:
```
Use the Explore agent to find the ADR that explains why we chose FastAPI over Django.
Search in: development/docs/architecture/10-adrs/
```

**Why This Agent**:
- ✅ Optimized for quick searches across documentation
- ✅ Understands file structure and naming conventions
- ✅ Can synthesize information from multiple sources
- ✅ Fast results (seconds vs. minutes)

**Alternative**: `technical-researcher` for deeper analysis if you need external context or comparisons

---

### Use Case 2: Validating Documentation Consistency

**Scenario**: "Ensure all PlantUML diagrams are syntactically correct"

**Best Agent**: `technical-researcher`

**Command**:
```
Use the technical-researcher agent to validate all PlantUML diagram files in the architecture documentation.
Check for:
- Syntax correctness
- C4 Model compliance
- Completeness of diagrams
- Cross-diagram consistency

Location: development/docs/architecture/**/*.puml
```

**Why This Agent**:
- ✅ Can analyze multiple technical artifacts simultaneously
- ✅ Understands PlantUML syntax and C4 Model conventions
- ✅ Provides detailed validation reports
- ✅ Catches issues humans might miss

**Example Output**:
```
✅ All 7 diagrams validated as production-ready
⚠️  Minor: c4-containers.puml has duplicate legend macro (cosmetic only)
📋 Recommendation: Standardize to LAYOUT_WITH_LEGEND() across all diagrams
```

---

### Use Case 3: Creating New Architecture Decision Records

**Scenario**: "We decided to adopt Rust for performance-critical modules"

**Best Agent**: `architect` or `developer`

**Command**:
```
Use the architect agent to create ADR-016 for adopting Rust in performance-critical GPU modules.

Context:
- Current: Python with Numba JIT (ADR-015)
- Problem: Need even better performance for lattice calculations
- Proposed: Rewrite critical paths in Rust
- Alternatives: Keep Python, try C++, try Go

Follow the template at: development/docs/architecture/10-adrs/template.md
```

**Why This Agent**:
- ✅ Understands architectural decision-making patterns
- ✅ Can research alternatives and trade-offs
- ✅ Follows ADR template structure precisely
- ✅ Links to related decisions automatically

**Agent Workflow**:
1. Reads existing ADRs to understand context
2. Researches alternatives (Rust vs. C++ vs. Go)
3. Creates ADR following template structure
4. Links to related ADRs (004, 012, 015)
5. Updates INDEX.md and Arc42 design decisions section

---

### Use Case 4: Updating Documentation After Code Changes

**Scenario**: "We added Redis circuit breaker pattern to the caching layer"

**Best Agent**: `developer` (for implementation docs) + `architect` (for high-level updates)

**Multi-Agent Workflow**:
```
1. Use the developer agent to update the cache service component documentation
   - File: development/docs/architecture/03-component-architecture/saas-components.md
   - Add circuit breaker pattern description
   - Include code examples

2. Use the architect agent to update ADR-008 (Redis Caching)
   - Add circuit breaker as implemented pattern
   - Update consequences section
   - Link to monitoring setup
```

**Why Multiple Agents**:
- Developer agent: Handles implementation-level details and code examples
- Architect agent: Maintains architectural perspective and decision rationale

---

### Use Case 5: Security Audit and Compliance Review

**Scenario**: "Verify our documentation covers all D3FEND security requirements"

**Best Agent**: `security-auditor` or `compliance-specialist`

**Command**:
```
Use the security-auditor agent to review our architecture documentation for D3FEND compliance.

Check:
- development/docs/architecture/06-cross-cutting/security.md
- development/docs/architecture/10-adrs/010-d3fend-security-framework.md
- All security-related ADRs (002, 003, 006)

Verify:
1. All 12 D3FEND techniques are documented
2. Implementation evidence for each technique
3. Coverage gaps or missing controls
4. Alignment with current MITRE D3FEND framework
```

**Why This Agent**:
- ✅ Specialized in security frameworks and compliance
- ✅ Can cross-reference multiple documents
- ✅ Identifies coverage gaps
- ✅ Suggests remediation actions

**Example Output**:
```
✅ All 12 D3FEND techniques documented
✅ Implementation evidence complete
⚠️  Recommendation: Add monitoring metrics for D5-IRA (Incident Recovery Analysis)
📋 Suggested: Create ADR-016 for automated threat detection
```

---

### Use Case 6: Deployment Documentation Generation

**Scenario**: "Create a deployment checklist from our Kubernetes documentation"

**Best Agent**: `devops-engineer` or `deployment-engineer`

**Command**:
```
Use the devops-engineer agent to create a production deployment checklist.

Source documents:
- development/docs/architecture/07-deployment/kubernetes.md
- development/docs/architecture/10-adrs/011-kubernetes-production-orchestration.md
- development/docs/architecture/02-container-architecture/*.md

Generate:
1. Pre-deployment checklist (secrets, configs, resources)
2. Deployment steps (in order, with validation)
3. Post-deployment verification
4. Rollback procedures
```

**Why This Agent**:
- ✅ Understands deployment workflows and best practices
- ✅ Can synthesize information from multiple architecture docs
- ✅ Creates actionable, ordered checklists
- ✅ Includes verification and rollback steps

---

### Use Case 7: Researching Technology Alternatives

**Scenario**: "Should we switch from PostgreSQL to CockroachDB for better horizontal scaling?"

**Best Agent**: `technical-researcher`

**Command**:
```
Use the technical-researcher agent to research CockroachDB as an alternative to PostgreSQL.

Current state:
- Read ADR-002: PostgreSQL RLS for Multi-tenancy
- We use PostgreSQL 15 with Row-Level Security

Research:
1. CockroachDB support for Row-Level Security
2. Performance comparison for multi-tenant workloads
3. Migration complexity from PostgreSQL
4. Cost implications
5. Trade-offs and risks

Provide recommendation with evidence.
```

**Why This Agent**:
- ✅ Can research external sources (GitHub, docs, benchmarks)
- ✅ Compares technical solutions objectively
- ✅ Considers existing architecture constraints
- ✅ Provides evidence-based recommendations

---

### Use Case 8: Documentation Quality Review

**Scenario**: "Review all Arc42 sections for completeness and accuracy"

**Best Agent**: `architect-reviewer` or `technical-writer`

**Command**:
```
Use the architect-reviewer agent to review all Arc42 documentation sections.

Review:
- development/docs/architecture/05-arc42/*.md (12 files)

Check for:
1. Completeness (all required sections filled)
2. Accuracy (alignment with current architecture)
3. Clarity (understandable by target audience)
4. Consistency (cross-references and terminology)
5. Stale content (outdated information)

Provide:
- Completeness score (%)
- List of gaps or improvements needed
- Prioritized action items
```

**Why This Agent**:
- ✅ Understands architectural documentation standards
- ✅ Can evaluate quality across multiple dimensions
- ✅ Identifies inconsistencies and gaps
- ✅ Prioritizes improvements

---

## Agent Workflows

### Workflow 1: Creating New Feature Documentation

**Scenario**: Adding new "AI-powered code analysis" feature

**Multi-Agent Orchestration**:

```
Step 1: Planning (architect agent)
"Create architectural design for AI-powered code analysis feature"
- Defines components, data flows, integration points
- Identifies affected systems

Step 2: Decision Documentation (architect agent)
"Create ADR-016 for choosing OpenAI vs. Anthropic vs. local model"
- Documents decision rationale
- Lists alternatives and trade-offs

Step 3: Implementation Details (developer agent)
"Document component-level implementation for AI analysis engine"
- Updates component diagrams
- Adds code examples

Step 4: Deployment Planning (devops-engineer agent)
"Define deployment strategy for AI analysis feature"
- Updates Kubernetes documentation
- Defines resource requirements

Step 5: Security Review (security-auditor agent)
"Review AI feature for security implications"
- Checks data privacy concerns
- Validates D3FEND compliance

Step 6: Quality Validation (qa agent)
"Verify all documentation meets acceptance criteria"
- Checks completeness
- Validates cross-references
```

**Execution**:
```bash
# Run agents sequentially or in parallel (where independent)

# Sequential (each depends on previous)
1. architect: Design the feature
2. architect: Create ADR
3. developer: Document implementation
4. devops-engineer: Plan deployment
5. security-auditor: Security review
6. qa: Final validation

# Time saved: 70-80% vs. manual documentation
```

---

### Workflow 2: Quarterly Documentation Review

**Scenario**: Scheduled quarterly review (January 15, 2026)

**Multi-Agent Review Process**:

```
Step 1: Staleness Detection (Explore agent)
"Find all documentation sections that reference outdated technology versions"
- Scans all 58 files
- Identifies version numbers, dates, metrics

Step 2: Technical Validation (technical-researcher agent)
"Validate all external references and links still work"
- Checks URLs in references sections
- Verifies technology versions are current

Step 3: Diagram Validation (technical-researcher agent)
"Re-validate all PlantUML diagrams"
- Ensures diagrams still render correctly
- Checks for deprecated syntax

Step 4: Security Audit (security-auditor agent)
"Review security documentation for new threats or frameworks"
- Checks for new D3FEND techniques
- Identifies emerging security patterns

Step 5: Architecture Alignment (architect-reviewer agent)
"Verify documentation matches current codebase architecture"
- Compares docs to actual code
- Identifies drift

Step 6: Remediation (developer agent)
"Update all outdated sections identified in review"
- Makes necessary updates
- Links related changes
```

**Automation**:
```powershell
# Quarterly review script (can be automated)
# Location: development/docs/architecture/quarterly-review.ps1

.\quarterly-review.ps1 -Date "2026-01-15"

# Runs all 6 agents in sequence
# Generates review report
# Creates TODO list for remediation
```

---

### Workflow 3: Emergency Update (Critical Security Fix)

**Scenario**: CVE discovered in JWT library, need to update immediately

**Rapid Response Multi-Agent Workflow**:

```
Step 1: Impact Assessment (security-auditor agent) - URGENT
"Assess impact of CVE-XXXX-YYYY in JWT library on our architecture"
- Reads ADR-003 (JWT RS256)
- Checks affected components
- Estimates blast radius

Step 2: Update Documentation (developer agent) - IMMEDIATE
"Update ADR-003 to reflect JWT library upgrade from v1.x to v2.x"
- Documents security patch
- Updates version numbers
- Notes breaking changes

Step 3: Deployment Update (devops-engineer agent) - IMMEDIATE
"Update deployment docs with new JWT library requirements"
- Updates container images
- Notes config changes

Step 4: Communication (technical-writer agent) - URGENT
"Create incident communication from architecture docs"
- Summarizes changes
- Identifies affected stakeholders
- Drafts notification

Total time: Minutes instead of hours
```

---

## Best Practices

### 1. Choose the Right Agent for the Task

**Decision Tree**:

```
Is the task documentation-related?
├─ YES: Is it searching/querying?
│  ├─ YES: Use Explore agent (fast)
│  └─ NO: Is it creating/updating?
│     ├─ Architecture decision → architect agent
│     ├─ Implementation detail → developer agent
│     ├─ Security-related → security-auditor agent
│     └─ Deployment-related → devops-engineer agent
└─ NO: Is it external research?
   ├─ YES: Use technical-researcher agent
   └─ NO: Use general-purpose agent
```

### 2. Be Specific in Agent Prompts

**Bad Prompt**:
```
Update the documentation
```

**Good Prompt**:
```
Use the developer agent to update the cache service documentation at:
development/docs/architecture/03-component-architecture/saas-components.md

Add a new section describing the Redis circuit breaker pattern:
- Pattern description
- Configuration parameters
- Code example (Python)
- Monitoring metrics
- Related ADR link (ADR-008)
```

**Why Good is Better**:
- ✅ Specifies exact agent
- ✅ Provides file path
- ✅ Lists what to add
- ✅ Includes context (related ADRs)

### 3. Leverage Agent Strengths

**Agent Strengths Matrix**:

| Agent | Best For | Avoid For |
|-------|----------|-----------|
| `Explore` | Fast searches, quick queries | Deep technical analysis |
| `technical-researcher` | External research, validation | Simple file searches |
| `architect` | High-level design, ADRs | Implementation details |
| `developer` | Code examples, implementation | Architecture strategy |
| `security-auditor` | Security compliance, D3FEND | General code review |
| `devops-engineer` | Deployment, infrastructure | Application logic |

### 4. Use Multi-Agent Workflows for Complex Tasks

**When to Use Multiple Agents**:

- ✅ Task spans multiple expertise areas (architecture + security + deployment)
- ✅ Need different perspectives (design vs. implementation)
- ✅ Want validation from specialized agents
- ✅ Complex tasks with clear phases

**When to Use Single Agent**:

- ✅ Task is within one domain (just architecture, just deployment)
- ✅ Quick queries or simple updates
- ✅ Time-sensitive tasks

### 5. Document Agent Usage

**Create Agent Logs**:
```markdown
# Agent Usage Log - 2025-11-28

## ADR-016 Creation
- Agent: architect
- Task: Create ADR for Rust adoption
- Duration: 5 minutes
- Result: ADR-016 created, linked to ADR-004, ADR-012, ADR-015

## PlantUML Validation
- Agent: technical-researcher
- Task: Validate all 7 diagrams
- Duration: 3 minutes
- Result: All diagrams production-ready, 1 cosmetic improvement suggested
```

**Benefits**:
- Track what works well
- Identify agent performance patterns
- Improve future agent usage
- Audit trail for documentation changes

---

## Advanced Multi-Agent Patterns

### Pattern 1: Pipeline (Sequential Agents)

**Use Case**: Creating comprehensive feature documentation

**Pattern**:
```
Input → Agent 1 → Output 1 → Agent 2 → Output 2 → Agent 3 → Final Output
```

**Example**:
```
User Request: "Document new payment retry feature"

Pipeline:
1. architect agent → Design decisions (creates ADR)
2. developer agent → Implementation docs (updates components)
3. devops-engineer agent → Deployment guide (updates K8s docs)
4. qa agent → Validation (checks completeness)

Each agent uses previous agent's output as context
```

**Benefits**:
- ✅ Clear dependency chain
- ✅ Each agent specializes
- ✅ Automatic context passing
- ✅ Easy to track progress

### Pattern 2: Parallel (Concurrent Agents)

**Use Case**: Quarterly documentation review

**Pattern**:
```
Input → [Agent 1, Agent 2, Agent 3] → [Output 1, Output 2, Output 3] → Synthesis
```

**Example**:
```
User Request: "Quarterly review of all documentation"

Parallel Execution:
- technical-researcher: Validate all diagrams
- security-auditor: Security compliance check
- architect-reviewer: Arc42 completeness review

All run simultaneously, results synthesized at end
```

**Benefits**:
- ✅ Faster execution (parallel processing)
- ✅ Independent analyses
- ✅ Comprehensive coverage
- ✅ Different perspectives

**Command**:
```
Run the following agents in parallel:
1. technical-researcher: Validate PlantUML diagrams
2. security-auditor: Review D3FEND compliance
3. architect-reviewer: Check Arc42 completeness

Synthesize results into quarterly review report.
```

### Pattern 3: Consensus (Multiple Agents, Same Task)

**Use Case**: Critical architecture decision validation

**Pattern**:
```
Input → [Agent 1, Agent 2, Agent 3] → Compare Outputs → Consensus
```

**Example**:
```
User Request: "Should we adopt GraphQL instead of REST?"

Consensus Approach:
- architect agent: High-level architectural perspective
- developer agent: Implementation complexity perspective
- devops-engineer agent: Deployment and ops perspective

Compare recommendations, identify agreement/disagreement
```

**Benefits**:
- ✅ Multiple perspectives
- ✅ Catches blind spots
- ✅ Reduces bias
- ✅ Higher confidence in decision

### Pattern 4: Hierarchical (Agent Orchestrator)

**Use Case**: Complex documentation project

**Pattern**:
```
Orchestrator Agent
├── Subagent 1 (specialized task)
├── Subagent 2 (specialized task)
└── Subagent 3 (specialized task)
```

**Example**:
```
User Request: "Document new microservice architecture"

Orchestrator (architect agent):
1. Breaks down into tasks
2. Assigns to specialized agents
3. Coordinates execution
4. Synthesizes results

Subagents:
- developer: Component documentation
- security-auditor: Security review
- devops-engineer: Deployment docs
```

**Benefits**:
- ✅ Automatic task decomposition
- ✅ Intelligent agent selection
- ✅ Centralized coordination
- ✅ Scalable to complex projects

---

## Automation Examples

### Example 1: Automated Diagram Validation (Pre-Commit Hook)

**File**: `.git/hooks/pre-commit`

```bash
#!/bin/bash
# Pre-commit hook to validate PlantUML diagrams before commit

echo "🔍 Validating PlantUML diagrams..."

# Use technical-researcher agent via Claude Code CLI
claude-code task technical-researcher \
  "Validate all PlantUML diagrams in development/docs/architecture for syntax errors" \
  --quick

if [ $? -ne 0 ]; then
  echo "❌ PlantUML validation failed. Fix errors before committing."
  exit 1
fi

echo "✅ All diagrams valid"
exit 0
```

**Benefits**:
- Catches diagram errors before they reach main branch
- Automatic validation, no manual checks
- Fast feedback (seconds)

### Example 2: Weekly Staleness Detection

**File**: `development/docs/architecture/check-staleness.ps1`

```powershell
# Weekly automation: Check for stale documentation

Write-Host "📅 Running weekly documentation staleness check..."

# Use Explore agent to find references to dates older than 90 days
claude-code task Explore `
  "Find all documentation sections mentioning dates older than 90 days" `
  --path "development/docs/architecture" `
  --thorough

# Use Explore agent to find outdated version numbers
claude-code task Explore `
  "Find all technology version references and check if newer versions exist" `
  --path "development/docs/architecture" `
  --thorough

Write-Host "✅ Staleness check complete. Review output above."
```

**Schedule**: Run every Monday via Windows Task Scheduler or cron

### Example 3: ADR Creation Template

**File**: `development/docs/architecture/create-adr.ps1`

```powershell
# Automated ADR creation with architect agent

param(
    [Parameter(Mandatory=$true)]
    [string]$Title,

    [Parameter(Mandatory=$true)]
    [string]$Decision,

    [string]$Context,
    [string]$Alternatives
)

Write-Host "📝 Creating ADR: $Title"

# Get next ADR number
$lastADR = Get-ChildItem "10-adrs" -Filter "*.md" |
    Where-Object { $_.Name -match '^\d+' } |
    Sort-Object Name |
    Select-Object -Last 1

$nextNumber = [int]($lastADR.Name.Substring(0,3)) + 1
$fileName = "{0:D3}-{1}.md" -f $nextNumber, ($Title.ToLower() -replace '\s+', '-')

# Use architect agent to create ADR
$prompt = @"
Use the architect agent to create a new Architecture Decision Record.

File: development/docs/architecture/10-adrs/$fileName
Template: development/docs/architecture/10-adrs/template.md

Title: $Title
Decision: $Decision
Context: $Context
Alternatives: $Alternatives

Follow the template structure precisely.
After creation, update INDEX.md and 05-arc42/09-design-decisions.md
"@

claude-code task architect "$prompt"

Write-Host "✅ ADR-$nextNumber created at 10-adrs/$fileName"
```

**Usage**:
```powershell
.\create-adr.ps1 `
  -Title "Rust for GPU Kernels" `
  -Decision "Use Rust for performance-critical GPU kernel code" `
  -Context "Python/Numba not fast enough for real-time lattice calculations" `
  -Alternatives "C++, Go, stay with Python"
```

---

## Troubleshooting

### Problem: Agent Takes Too Long

**Symptoms**: Agent running for >5 minutes on simple task

**Causes & Solutions**:

1. **Wrong Agent for Task**:
   - ❌ Using `technical-researcher` for simple file search
   - ✅ Use `Explore` agent instead (faster)

2. **Prompt Too Broad**:
   - ❌ "Review all documentation"
   - ✅ "Review 05-arc42/10-quality.md for completeness"

3. **Large Scope**:
   - ❌ "Validate everything"
   - ✅ Break into smaller tasks, run in parallel

**Fix**:
```
# Instead of this:
"Use technical-researcher to review all architecture docs"

# Do this:
"Use Explore agent with quick mode to find quality attribute documentation"
```

---

### Problem: Agent Missing Context

**Symptoms**: Agent doesn't understand existing architecture

**Causes & Solutions**:

1. **Insufficient Context in Prompt**:
```
# Bad:
"Create ADR for new database"

# Good:
"Create ADR-016 for migrating from PostgreSQL to CockroachDB.
Current state: ADR-002 documents PostgreSQL with RLS.
Context: Need better horizontal scaling.
Reference: development/docs/architecture/10-adrs/002-postgresql-rls-multi-tenancy.md"
```

2. **Didn't Point to Relevant Docs**:
```
# Bad:
"Update security docs"

# Good:
"Update development/docs/architecture/06-cross-cutting/security.md
Current D3FEND coverage: See ADR-010
New technique to add: D5-IRA (Incident Recovery Analysis)"
```

---

### Problem: Agent Output Doesn't Match Template

**Symptoms**: Created ADR doesn't follow template structure

**Causes & Solutions**:

1. **Template Not Referenced**:
```
# Bad:
"Create ADR about Redis"

# Good:
"Create ADR following template at: development/docs/architecture/10-adrs/template.md
Title: Redis Circuit Breaker Pattern
Decision: Implement circuit breaker for Redis calls"
```

2. **Agent Type Wrong**:
   - ❌ Using `developer` agent for ADR (too implementation-focused)
   - ✅ Use `architect` agent (understands decision structure)

---

### Problem: Multiple Agents Conflict

**Symptoms**: Two agents make contradictory changes

**Causes & Solutions**:

1. **Parallel Agents on Same File**:
```
# Bad:
Run in parallel:
- Agent 1: Update security.md
- Agent 2: Update security.md

# Good:
Run sequentially:
1. Agent 1: Update security.md (D3FEND section)
2. Agent 2: Update security.md (Vault section)
OR use single agent with combined task
```

2. **Unclear Ownership**:
   - Define which agent owns which documentation section
   - Use sequential workflows when editing same files

---

## Summary: Agent Usage Best Practices

### ✅ DO

1. **Choose specialized agents** for their domain expertise
2. **Provide specific prompts** with file paths and context
3. **Use Explore for quick searches** (fast, efficient)
4. **Use technical-researcher for validation** (thorough, external research)
5. **Use architect for ADRs and design docs** (architectural thinking)
6. **Run independent tasks in parallel** (faster execution)
7. **Chain dependent tasks sequentially** (proper context flow)
8. **Document agent usage** (audit trail, lessons learned)
9. **Break complex tasks** into smaller agent-sized chunks
10. **Reference existing docs** in prompts (better context)

### ❌ DON'T

1. **Don't use wrong agent** (e.g., developer for architecture decisions)
2. **Don't give vague prompts** ("update docs" → which docs?)
3. **Don't run multiple agents on same file simultaneously** (conflicts)
4. **Don't skip context** (link to related ADRs, docs)
5. **Don't expect agents to guess** (be explicit about requirements)
6. **Don't use technical-researcher for simple searches** (overkill, slow)
7. **Don't forget to validate** agent output (quick human review)
8. **Don't skip template references** when creating structured docs
9. **Don't run all tasks sequentially** if parallel is possible (slower)
10. **Don't forget to update INDEX.md** after creating new files

---

## Conclusion

Using agents with the architecture documentation system transforms documentation maintenance from a manual, time-consuming process into an automated, efficient workflow.

**Key Benefits**:

- ⏱️ **Time Savings**: 70-80% reduction in documentation tasks
- 🎯 **Accuracy**: Specialized agents catch issues humans miss
- 🔄 **Consistency**: Automated processes ensure uniform quality
- 📊 **Scale**: Handle 58+ files effortlessly
- 🚀 **Speed**: Parallel agent execution for complex tasks

**Getting Started**:

1. Review the [Agent Capabilities Matrix](#agent-capabilities-matrix)
2. Try a simple task: "Use Explore agent to find ADR about FastAPI"
3. Experiment with validation: "Use technical-researcher to validate diagrams"
4. Move to complex workflows: Multi-agent quarterly review

**Next Steps**:

- Set up weekly staleness checks (automated)
- Create pre-commit hooks for diagram validation
- Build ADR creation automation script
- Schedule quarterly reviews with multi-agent workflows

---

**Questions?**
- Review [USAGE_GUIDE.md](USAGE_GUIDE.md) for documentation maintenance
- Check [INDEX.md](INDEX.md) for file navigation
- See [README-COMPREHENSIVE.md](README-COMPREHENSIVE.md) for overall structure

---

**Last Updated**: November 28, 2025
**Version**: 1.0
**Status**: ✅ Production-Ready
