# Documentation Feedback Triage Process

**Created:** 2025-10-09
**Status:** Implementation-Ready
**Owner:** Documentation Team

---

## Executive Summary

This document defines how we categorize, prioritize, and process documentation feedback. The system balances user needs with team capacity, ensuring critical issues are addressed quickly while managing less urgent improvements systematically.

**Key Components:**
1. Feedback taxonomy (5 types)
2. Priority matrix (Impact × Effort)
3. Triage workflow (review → assign → track)
4. Decision criteria (fix now vs. batch vs. defer)
5. Escalation paths

---

## Table of Contents

1. [Feedback Taxonomy](#1-feedback-taxonomy)
2. [Priority Matrix](#2-priority-matrix)
3. [Triage Workflow](#3-triage-workflow)
4. [Decision Criteria](#4-decision-criteria)
5. [Escalation Paths](#5-escalation-paths)
6. [Implementation Guide](#6-implementation-guide)

---

## 1. Feedback Taxonomy

### Type A: Errors/Inaccuracies
**Definition:** Incorrect information that could lead to wrong implementations or misunderstandings.

**Examples:**
- Wrong API endpoint URLs
- Incorrect command syntax
- Outdated configuration values
- False performance claims
- Inaccurate technical specifications

**Priority:** **HIGH** (always)

**Response Time:**
- Critical errors: Same day
- Major errors: Within 48 hours
- Minor errors: Within 1 week

**Example:**
```markdown
Type: Error
Document: guides/REDIS_POOL_OPTIMIZATION_GUIDE.md
Issue: Redis pool size recommendation of 100 causes connection timeouts
Impact: Production deployments failing
Priority: CRITICAL
Fix: Update recommendation to 50, add scaling guidance
```

### Type B: Gaps
**Definition:** Missing information that prevents users from completing tasks.

**Examples:**
- Missing prerequisites
- Incomplete procedures
- No troubleshooting section
- Missing API endpoints
- Undocumented environment variables

**Priority:** **MEDIUM-HIGH** (depends on impact)

**Response Time:**
- Blocking gaps: Within 1 week
- Non-blocking gaps: Within 1 month
- Nice-to-have additions: Backlog

**Example:**
```markdown
Type: Gap
Document: deployment/BMAD_DEPLOYMENT_GUIDE.md
Issue: No section on rollback procedures
Impact: Teams afraid to deploy to production
Priority: HIGH
Fix: Add comprehensive rollback section
```

### Type C: Clarity Issues
**Definition:** Information exists but is confusing, poorly organized, or hard to understand.

**Examples:**
- Unclear explanations
- Poor examples
- Confusing terminology
- Bad organization
- Missing context

**Priority:** **MEDIUM** (depends on document importance)

**Response Time:**
- Critical docs: Within 2 weeks
- Standard docs: Within 1 month
- Archived docs: Backlog

**Example:**
```markdown
Type: Clarity
Document: architecture/saas-architecture.md
Issue: JWT flow diagram is confusing, arrows unclear
Impact: Developers misunderstand authentication flow
Priority: MEDIUM
Fix: Redraw diagram with clearer labels and sequence
```

### Type D: Navigation/Usability
**Definition:** Users can't find information due to poor navigation, broken links, or bad information architecture.

**Examples:**
- Broken links
- Orphaned documents
- Missing cross-references
- Poor INDEX organization
- No search keywords

**Priority:** **HIGH** (affects all docs)

**Response Time:**
- Broken critical links: Same day
- Navigation improvements: Within 1 week
- Optimization: Within 1 month

**Example:**
```markdown
Type: Navigation
Document: INDEX.md
Issue: Can't find monitoring guides, buried in menu
Impact: Users ask in Slack instead of checking docs
Priority: HIGH
Fix: Add "Monitoring" section to INDEX.md top level
```

### Type E: Enhancement Requests
**Definition:** Requests for new features, additional examples, or improvements beyond basic functionality.

**Examples:**
- More code examples
- Additional use cases
- Integration guides
- Advanced tutorials
- Video walkthroughs

**Priority:** **LOW-MEDIUM** (nice to have)

**Response Time:**
- High value enhancements: Within 1 quarter
- Standard enhancements: Backlog
- Low value: Consider/decline

**Example:**
```markdown
Type: Enhancement
Document: quickstart/gpu-5min.md
Issue: Request for advanced GPU optimization guide
Impact: Would help advanced users, but basics covered
Priority: MEDIUM
Fix: Plan for Q2 2025 advanced GPU guide
```

---

## 2. Priority Matrix

### 2.1 Priority Levels

#### CRITICAL (Fix Immediately)
**Criteria:** ANY of these:
- ✅ Causes production failures
- ✅ Security implications
- ✅ Blocks current sprint work
- ✅ Affects >50% of users
- ✅ Data loss risk

**Response:** Same day
**Owner:** Senior team member
**Review:** No review needed, fix and notify

**Examples:**
- Wrong database migration command
- Incorrect security configuration
- Broken deployment guide for current release

#### HIGH (Fix This Week)
**Criteria:** ANY of these:
- ✅ Type A (Error) in active documentation
- ✅ Type D (Navigation) in critical path
- ✅ Type B (Gap) blocking common tasks
- ✅ Affects 10-50% of users
- ✅ Multiple reports of same issue

**Response:** Within 1 week
**Owner:** Team member assigned during triage
**Review:** Quick peer review before publish

**Examples:**
- Broken links in main guides
- Missing prerequisites in quickstart
- Outdated API examples

#### MEDIUM (Fix This Month)
**Criteria:** ANY of these:
- ✅ Type B (Gap) - nice to have
- ✅ Type C (Clarity) in important docs
- ✅ Type E (Enhancement) with high value
- ✅ Affects <10% of users
- ✅ Single user request

**Response:** Within 1 month
**Owner:** Assigned during monthly planning
**Review:** Standard review process

**Examples:**
- Additional examples
- Clarity improvements
- Minor gaps in advanced guides

#### LOW (Backlog)
**Criteria:** ALL of these:
- ✅ Type E (Enhancement) - nice to have
- ✅ Type C (Clarity) in less-used docs
- ✅ Affects <5% of users
- ✅ Workaround exists

**Response:** Next quarter or later
**Owner:** Unassigned
**Review:** Quarterly backlog review

**Examples:**
- Advanced tutorials
- Edge case documentation
- Archived doc improvements

### 2.2 Impact × Effort Matrix

```
                HIGH IMPACT            |  LOW IMPACT
        ─────────────────────────────────────────────────────
        │                              │                     │
LOW     │  DO NEXT                     │  DO IF TIME         │
EFFORT  │  Priority: HIGH              │  Priority: MEDIUM   │
        │  Timeline: This week         │  Timeline: This month│
        │                              │                     │
        ├──────────────────────────────┼─────────────────────┤
        │                              │                     │
HIGH    │  PLAN & SCHEDULE             │  RECONSIDER         │
EFFORT  │  Priority: MEDIUM            │  Priority: LOW      │
        │  Timeline: This month        │  Timeline: Backlog  │
        │                              │                     │
        ─────────────────────────────────────────────────────
```

**How to Use:**

1. **Assess Impact**
   - How many users affected?
   - What's the consequence of not fixing?
   - Is there a workaround?

2. **Estimate Effort**
   - How long to fix? (<1 hour = low, 1-4 hours = medium, >4 hours = high)
   - Does it require code changes or just docs?
   - Do we need subject matter expert input?

3. **Plot on Matrix**
   - High Impact + Low Effort = DO NEXT
   - High Impact + High Effort = PLAN & SCHEDULE
   - Low Impact + Low Effort = DO IF TIME
   - Low Impact + High Effort = RECONSIDER

**Examples:**

| Feedback | Impact | Effort | Quadrant | Priority |
|----------|--------|--------|----------|----------|
| Fix broken link in INDEX.md | High (affects navigation) | Low (2 min) | DO NEXT | HIGH |
| Add missing rollback section | High (blocks deploys) | Medium (2 hours) | PLAN & SCHEDULE | HIGH |
| Fix typo in archived doc | Low (old doc) | Low (1 min) | DO IF TIME | LOW |
| Create video tutorial series | Medium (enhancement) | High (days) | RECONSIDER | LOW |

---

## 3. Triage Workflow

### 3.1 Weekly Triage Meeting

**When:** Every Monday, 10:00 AM
**Duration:** 30 minutes
**Attendees:** Documentation team (2-3 people)
**Location:** Conference room / Video call

**Agenda:**

#### 1. Review New Feedback (15 min)

```bash
# Before meeting, run:
bash scripts/utilities/process_weekly_feedback.sh > triage_prep.txt
```

For each new feedback item:
1. **Categorize:** Type A/B/C/D/E
2. **Assess Impact:** High/Medium/Low
3. **Estimate Effort:** Low/Medium/High
4. **Assign Priority:** Critical/High/Medium/Low
5. **Assign Owner:** Who will fix it?
6. **Set Timeline:** When will it be done?

**Template:**
```markdown
## Feedback: [Brief description]

**Type:** [A/B/C/D/E]
**Impact:** [High/Medium/Low]
**Effort:** [Low/Medium/High]
**Priority:** [Critical/High/Medium/Low]
**Owner:** [Name]
**Timeline:** [Date]
**Status:** [Triaged]

**Decision:** [Fix now / Schedule / Defer / Decline]
**Notes:** [Any context or discussion points]
```

#### 2. Review In-Progress Items (10 min)

- What's blocked?
- What needs help?
- What's done and ready for review?

#### 3. Update Status (5 min)

```bash
# Update feedback files with triage decisions
# Example:
sed -i 's/status: new/status: triaged/' docs/.feedback/2025/Q4/20251009_*.md
```

**Output:**
- Updated feedback files with priorities
- GitHub issues created for high priority items
- Team task list updated

### 3.2 Triage Checklist

**For Each Feedback Item:**

```markdown
- [ ] Read and understand the issue
- [ ] Verify it's a real issue (not user error)
- [ ] Check if already documented elsewhere
- [ ] Categorize by type (A/B/C/D/E)
- [ ] Assess impact (High/Medium/Low)
- [ ] Estimate effort (Low/Medium/High)
- [ ] Determine priority (Critical/High/Medium/Low)
- [ ] Assign owner
- [ ] Set timeline
- [ ] Create GitHub issue (if High+)
- [ ] Update feedback file with decision
- [ ] Notify submitter (if provided)
```

### 3.3 Triage Script

```bash
#!/bin/bash
# scripts/utilities/triage_feedback.sh
#
# Interactive triage helper

FEEDBACK_DIR="development/docs/.feedback/2025/Q4"

echo "📋 Documentation Feedback Triage"
echo "================================="
echo ""

# Find new feedback
new_feedback=$(grep -l "status: new" $FEEDBACK_DIR/*.md)
count=$(echo "$new_feedback" | wc -l)

echo "📬 Found $count new feedback items"
echo ""

for file in $new_feedback; do
    echo "────────────────────────────────────────"
    echo "📄 File: $(basename $file)"
    echo ""
    echo "Content:"
    head -20 "$file"
    echo ""
    echo "────────────────────────────────────────"
    echo ""

    # Interactive prompts
    read -p "Type (A/B/C/D/E): " type
    read -p "Impact (High/Medium/Low): " impact
    read -p "Effort (Low/Medium/High): " effort
    read -p "Priority (Critical/High/Medium/Low): " priority
    read -p "Owner: " owner
    read -p "Timeline (YYYY-MM-DD): " timeline
    read -p "Decision (fix/schedule/defer/decline): " decision

    # Update file
    cat >> "$file" << EOF

---
## Triage Decision

**Type:** $type
**Impact:** $impact
**Effort:** $effort
**Priority:** $priority
**Owner:** $owner
**Timeline:** $timeline
**Decision:** $decision
**Triaged:** $(date +%Y-%m-%d)
EOF

    # Update status in frontmatter
    sed -i "s/status: new/status: triaged/" "$file"

    echo ""
    echo "✅ Triaged: $file"
    echo ""

    # Create GitHub issue for high priority
    if [ "$priority" = "High" ] || [ "$priority" = "Critical" ]; then
        read -p "Create GitHub issue? (y/n): " create_issue
        if [ "$create_issue" = "y" ]; then
            gh issue create \
                --label "documentation,priority-$priority" \
                --title "Docs: $(basename $file .md)" \
                --body-file "$file"
            echo "✅ GitHub issue created"
        fi
    fi

    echo ""
    read -p "Continue to next? (y/n): " continue
    if [ "$continue" != "y" ]; then
        break
    fi
done

echo ""
echo "✅ Triage complete!"
echo ""
echo "📊 Summary:"
echo "  Total triaged: $count"
echo "  See: $FEEDBACK_DIR/"
```

---

## 4. Decision Criteria

### 4.1 Fix Now (Immediate Action)

**Criteria:**
- Critical priority OR
- High priority + Low effort OR
- Multiple users reporting same issue

**Process:**
1. Assign to available team member
2. Fix immediately (same day)
3. Quick peer review
4. Deploy
5. Notify submitter
6. Update metrics

**Example Decision Flow:**
```
Is it Critical? → YES → Fix now (no review needed)
                → NO ↓
Is it High + Low effort? → YES → Fix now (quick review)
                         → NO ↓
Multiple reports? → YES → Escalate → Fix now
                 → NO ↓
             Schedule for later
```

### 4.2 Batch (Schedule for Grouped Fix)

**Criteria:**
- Medium priority OR
- High priority + High effort OR
- Related to other planned work

**Process:**
1. Add to monthly improvement batch
2. Group with similar issues
3. Assign during monthly planning
4. Complete within 30 days
5. Full review process

**Batching Strategy:**
```markdown
## Monthly Documentation Sprint (Last Week of Month)

**Theme:** [e.g., "Redis Documentation Improvements"]

**Included Feedback:**
- #123: Fix Redis pool sizing recommendation
- #145: Add Redis troubleshooting section
- #167: Update Redis architecture diagram
- #189: Add Redis monitoring guide

**Owner:** [Name]
**Timeline:** [Dates]
**Review:** [Review date]
```

### 4.3 Defer (Backlog for Later)

**Criteria:**
- Low priority OR
- Enhancement with uncertain value OR
- Requires significant research/work

**Process:**
1. Add to backlog
2. Tag with quarter (Q1/Q2/Q3/Q4)
3. Review during quarterly planning
4. Re-evaluate priority

**Backlog Management:**
```markdown
# Documentation Backlog

## Q1 2025 Candidates
- [ ] Advanced GPU optimization guide
- [ ] Video tutorial series
- [ ] Interactive examples

## Q2 2025 Candidates
- [ ] Multi-language support
- [ ] Advanced architecture deep-dives
- [ ] Performance tuning guides

## Someday/Maybe
- [ ] Automated doc generation
- [ ] AI-powered search
- [ ] Integrated code examples
```

### 4.4 Decline (Won't Fix)

**Criteria:**
- Out of scope OR
- Better served elsewhere OR
- Duplicate of existing docs OR
- Low value + High effort

**Process:**
1. Thank submitter
2. Explain rationale
3. Suggest alternative (if applicable)
4. Close feedback with status "declined"
5. Document decision for future reference

**Decline Response Template:**
```markdown
Hi [Submitter],

Thank you for the feedback on [document]. We've reviewed your suggestion for [request].

After consideration, we've decided not to implement this because:
- [Reason 1: e.g., "This is better covered in code comments"]
- [Reason 2: e.g., "Out of scope for documentation"]
- [Reason 3: e.g., "Effort doesn't justify value"]

**Alternative:** [If applicable, suggest where to find info or different approach]

We appreciate you taking the time to help improve our documentation!

Best regards,
Documentation Team
```

---

## 5. Escalation Paths

### 5.1 When to Escalate

**Escalate to Team Lead:**
- Multiple critical issues in same area
- Pattern of recurring problems
- Resource constraints preventing timely fixes
- Disagreement on priority
- Requires significant architectural changes

**Escalate to Engineering:**
- Documentation reflects code bugs
- API changes not communicated
- Missing features need documentation
- Code examples don't work

**Escalate to Management:**
- Systemic documentation problems
- Need dedicated documentation resources
- Budget for tools/services
- Strategic documentation direction

### 5.2 Escalation Process

```markdown
## Escalation Template

**To:** [Team Lead / Engineering / Management]
**From:** Documentation Team
**Date:** [Date]
**Subject:** Escalation: [Brief description]

### Issue Summary
[1-2 sentence description]

### Impact
- **Users Affected:** [Number/percentage]
- **Severity:** [Critical/High/Medium]
- **Business Impact:** [Revenue/operations/reputation]

### Why Escalating
- [Reason 1: e.g., "Beyond docs team capacity"]
- [Reason 2: e.g., "Requires code changes"]
- [Reason 3: e.g., "Strategic decision needed"]

### Recommendation
[What you think should be done]

### Timeline
[Urgency and deadline]

### Supporting Data
[Metrics, user feedback, evidence]
```

### 5.3 Escalation Examples

**Example 1: Pattern of API Documentation Errors**
```markdown
**Issue:** 5 separate reports of API docs not matching implementation

**Impact:** Developers wasting 2-3 hours each trying to debug

**Root Cause:** API changes not communicated to docs team

**Escalation:** Engineering Lead
**Request:** Implement process for API change notifications
**Timeline:** Recurring issue, needs systemic fix
```

**Example 2: Documentation Capacity**
```markdown
**Issue:** 40 hours of backlog, team has 10 hours/week

**Impact:** Response time >30 days, users frustrated

**Root Cause:** Documentation part-time activity, no dedicated resource

**Escalation:** Management
**Request:** Hire technical writer or allocate dedicated dev time
**Timeline:** Affecting new feature adoption
```

---

## 6. Implementation Guide

### 6.1 Setup (One Time)

```bash
#!/bin/bash
# Setup triage system

# Create triage directory
mkdir -p development/docs/.triage/{weekly,monthly,backlog}

# Create triage templates
cat > development/docs/.triage/weekly/TEMPLATE.md << 'EOF'
# Weekly Triage - [Date]

**Attendees:** [Names]
**Duration:** [Minutes]

## New Feedback

### Item 1: [Brief description]
- **Type:** [A/B/C/D/E]
- **Impact:** [H/M/L]
- **Effort:** [L/M/H]
- **Priority:** [Critical/High/Medium/Low]
- **Owner:** [Name]
- **Timeline:** [Date]
- **Decision:** [Fix/Schedule/Defer/Decline]
- **Notes:** [Discussion points]

[Repeat for each item]

## In Progress Review

[List and update status of ongoing items]

## Completed This Week

[List completed items]

## Next Week Priorities

1. [Item 1]
2. [Item 2]
3. [Item 3]

---

**Metrics:**
- New feedback: [Count]
- Triaged: [Count]
- Completed: [Count]
- Open high priority: [Count]
EOF

# Create interactive triage script
# (Copy from scripts section above)

echo "✅ Triage system initialized!"
```

### 6.2 Weekly Process (30 minutes)

**Monday Morning Routine:**

```bash
# 1. Prepare for triage (5 min)
bash scripts/utilities/process_weekly_feedback.sh > triage_prep.txt

# 2. Run triage meeting (20 min)
# - Review new feedback
# - Use triage script for interactive session
# - Update feedback files

# 3. Create issues (5 min)
# Create GitHub issues for high priority items

# 4. Update team (5 min)
# Post summary in Slack/Teams
```

**Triage Meeting Script:**
```bash
# Start meeting
cd development/docs/.triage/weekly
cp TEMPLATE.md "$(date +%Y%m%d)_weekly_triage.md"

# Open file for note-taking during meeting
code "$(date +%Y%m%d)_weekly_triage.md"

# Run interactive triage
bash ../../scripts/utilities/triage_feedback.sh

# After meeting: Create summary
cat "$(date +%Y%m%d)_weekly_triage.md" | \
  grep -A 3 "Next Week Priorities" | \
  tail -n +2 > priorities.txt

# Post to Slack
# slack-cli post "#docs" "📋 This week's doc priorities: $(cat priorities.txt)"
```

### 6.3 Monthly Review (1 hour)

**Last Friday of Each Month:**

```bash
# 1. Review backlog (20 min)
# - Look at Medium priority items from last month
# - Re-evaluate priorities
# - Plan monthly sprint

# 2. Metrics review (15 min)
python scripts/utilities/analyze_feedback_trends.py

# 3. Plan monthly batch (15 min)
# - Group related improvements
# - Assign to team members
# - Set sprint goals

# 4. Backlog grooming (10 min)
# - Review Low priority items
# - Archive resolved items
# - Update quarterly roadmap
```

### 6.4 Quarterly Review (2 hours)

**First Week of Each Quarter:**

See [Quarterly Review Process (TODO)](./QUARTERLY_REVIEW_PROCESS.md) for details.

---

## Metrics & Reporting

### Key Metrics to Track

```bash
# scripts/utilities/triage_metrics.py

def calculate_triage_metrics():
    """Calculate triage performance metrics"""

    metrics = {
        # Volume
        'feedback_received': count_feedback(),
        'feedback_triaged': count_triaged(),
        'feedback_completed': count_completed(),

        # Response Time
        'avg_triage_time': avg_time_to_triage(),  # Target: <7 days
        'avg_resolution_time': avg_time_to_resolve(),  # Target: <30 days

        # Quality
        'high_priority_completion_rate': high_pri_completion_rate(),  # Target: >80%
        'user_satisfaction': avg_satisfaction_rating(),  # Target: >4.0

        # Efficiency
        'decline_rate': decline_rate(),  # Target: <10%
        'reopen_rate': reopen_rate(),  # Target: <5%
    }

    return metrics
```

### Weekly Dashboard

```markdown
# Documentation Feedback Dashboard - Week of [Date]

## Volume
- 📬 New feedback: 8 items
- ✅ Triaged: 7 items
- 🎉 Completed: 5 items
- 📊 Open: 15 items

## Priority Breakdown
- 🔴 Critical: 0
- 🟠 High: 3
- 🟡 Medium: 8
- 🟢 Low: 4

## Response Time
- ⏱️ Avg triage time: 3.2 days (Target: <7)
- ⏱️ Avg resolution time: 12.5 days (Target: <30)

## This Week's Completions
1. ✅ Fixed Redis pool sizing docs
2. ✅ Added rollback procedures
3. ✅ Updated API endpoint examples
4. ✅ Fixed 12 broken links
5. ✅ Improved GPU guide clarity

## Next Week Priorities
1. 🎯 Add Kubernetes troubleshooting guide
2. 🎯 Update monitoring dashboards docs
3. 🎯 Fix navigation in INDEX.md
```

---

## Best Practices

### Do's
✅ Review feedback weekly (consistency matters)
✅ Respond to submitters (build trust)
✅ Track metrics (measure improvement)
✅ Batch similar fixes (efficiency)
✅ Document decisions (transparency)
✅ Escalate when needed (don't bottle up)

### Don'ts
❌ Let feedback sit untriaged >2 weeks
❌ Fix without understanding impact
❌ Ignore patterns (systemic issues)
❌ Promise timelines you can't meet
❌ Decline without explanation
❌ Skip follow-up with submitters

---

## Quick Reference

### Triage Decision Tree

```
New Feedback
    ↓
Is it an ERROR (Type A)?
    YES → HIGH priority → Fix this week
    NO ↓
Is it a NAVIGATION issue (Type D)?
    YES → HIGH priority → Fix this week
    NO ↓
Is it a blocking GAP (Type B)?
    YES → Assess impact
        High impact → HIGH priority → Fix this week
        Medium impact → MEDIUM priority → This month
        Low impact → LOW priority → Backlog
    NO ↓
Is it a CLARITY issue (Type C)?
    YES → Assess document importance
        Critical doc → MEDIUM priority → This month
        Standard doc → LOW priority → Backlog
    NO ↓
Is it an ENHANCEMENT (Type E)?
    YES → Assess value vs effort
        High value + Low effort → MEDIUM priority → This month
        Other → LOW priority → Backlog
```

---

## Related Documentation

- [Feedback Collection System](./FEEDBACK_COLLECTION_SYSTEM.md) - How we gather feedback
- [Documentation Metrics](./DOCUMENTATION_METRICS.md) - What we measure
- [Documentation Iteration Workflow (TODO)](./DOCUMENTATION_ITERATION_WORKFLOW.md) - How we make changes
- [Quarterly Review Process (TODO)](./QUARTERLY_REVIEW_PROCESS.md) - Strategic planning

---

**Next:** [Documentation Metrics & KPIs →](./DOCUMENTATION_METRICS.md)
