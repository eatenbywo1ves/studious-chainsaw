# Documentation Metrics & KPIs

**Created:** 2025-10-09
**Status:** Implementation-Ready
**Owner:** Documentation Team

---

## Executive Summary

This document defines the key performance indicators (KPIs) and metrics for measuring documentation health, usage, and impact. The system is designed for markdown-based documentation without backend infrastructure, leveraging git analytics, file-based tracking, and lightweight measurement tools.

**Key Goals:**
1. Measure documentation quality and health
2. Track usage and engagement patterns
3. Assess business impact of documentation
4. Identify improvement opportunities
5. Demonstrate ROI of documentation efforts

---

## Table of Contents

1. [Metric Categories](#1-metric-categories)
2. [Usage Metrics](#2-usage-metrics)
3. [Engagement Metrics](#3-engagement-metrics)
4. [Quality Metrics](#4-quality-metrics)
5. [Impact Metrics](#5-impact-metrics)
6. [Implementation Guide](#6-implementation-guide)

---

## 1. Metric Categories

### Overview of Metric Types

```
📊 DOCUMENTATION METRICS FRAMEWORK

┌─────────────────────────────────────────────────────────┐
│                     USAGE METRICS                       │
│  - Page views (git access)                              │
│  - Search queries                                       │
│  - Most/least accessed documents                       │
│  - Access patterns (time of day, day of week)          │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                  ENGAGEMENT METRICS                     │
│  - Time in documentation (session length)               │
│  - Return visitors                                      │
│  - Cross-reference follow-through                       │
│  - Feedback submission rate                            │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                   QUALITY METRICS                       │
│  - Link health (broken links %)                         │
│  - Content freshness (days since update)                │
│  - Feedback satisfaction scores                         │
│  - Error report rate                                    │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                   IMPACT METRICS                        │
│  - Time to productivity (onboarding)                    │
│  - Support ticket reduction                             │
│  - Deployment success rate                              │
│  - Self-service rate                                    │
└─────────────────────────────────────────────────────────┘
```

### Priority Matrix

| Metric Type | Priority | Measurement Frequency | Owner |
|-------------|----------|----------------------|-------|
| **Usage** | HIGH | Weekly | Doc Team |
| **Engagement** | MEDIUM | Bi-weekly | Doc Team |
| **Quality** | HIGH | Weekly | Doc Team |
| **Impact** | HIGH | Monthly | Doc Team + Engineering |

---

## 2. Usage Metrics

### 2.1 Document Access Tracking

**What to Measure:**
- Total document accesses per week/month
- Unique documents accessed
- Top 10 most accessed documents
- Bottom 10 least accessed documents
- Access by document category

**File-Based Implementation:**

```python
#!/usr/bin/env python3
# scripts/utilities/track_doc_usage.py

import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
import json

def get_doc_access_stats(days=30):
    """
    Track document access via git log
    Assumes each git checkout/view is logged
    """

    since = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

    # Get files modified in commits (proxy for access)
    cmd = [
        'git', 'log',
        f'--since={since}',
        '--name-only',
        '--pretty=format:',
        '--', 'development/docs/**/*.md'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, cwd='/c/Users/Corbin/development')

    files = [f for f in result.stdout.strip().split('\n') if f]
    file_counts = Counter(files)

    # Calculate statistics
    stats = {
        'period_days': days,
        'period_start': since,
        'period_end': datetime.now().strftime('%Y-%m-%d'),
        'total_accesses': len(files),
        'unique_documents': len(file_counts),
        'top_10': file_counts.most_common(10),
        'bottom_10': file_counts.most_common()[-10:] if len(file_counts) >= 10 else [],
        'by_category': categorize_access(file_counts),
        'timestamp': datetime.now().isoformat()
    }

    return stats

def categorize_access(file_counts):
    """Categorize document access by directory"""
    categories = {
        'quickstart': 0,
        'guides': 0,
        'architecture': 0,
        'deployment': 0,
        'monitoring': 0,
        'reference': 0,
        'other': 0
    }

    for file, count in file_counts.items():
        path = Path(file)
        parts = path.parts

        if 'quickstart' in parts:
            categories['quickstart'] += count
        elif 'guides' in parts:
            categories['guides'] += count
        elif 'architecture' in parts:
            categories['architecture'] += count
        elif 'deployment' in parts:
            categories['deployment'] += count
        elif 'monitoring' in parts:
            categories['monitoring'] += count
        elif 'reference' in parts:
            categories['reference'] += count
        else:
            categories['other'] += count

    return categories

def save_usage_stats():
    """Save usage statistics to analytics directory"""

    # Get stats for different periods
    stats_7d = get_doc_access_stats(7)
    stats_30d = get_doc_access_stats(30)
    stats_90d = get_doc_access_stats(90)

    report = {
        'last_7_days': stats_7d,
        'last_30_days': stats_30d,
        'last_90_days': stats_90d,
        'generated_at': datetime.now().isoformat()
    }

    # Save to file
    output_file = Path('development/docs/.analytics/usage_stats.json')
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report, indent=2))

    print(f"✅ Usage stats saved to: {output_file}")

    return report

if __name__ == '__main__':
    report = save_usage_stats()

    # Print summary
    print("\n📊 DOCUMENTATION USAGE REPORT")
    print("=" * 70)

    stats_30d = report['last_30_days']
    print(f"\n📈 Last 30 Days:")
    print(f"  Total accesses: {stats_30d['total_accesses']}")
    print(f"  Unique documents: {stats_30d['unique_documents']}")

    print(f"\n🔝 Top 10 Most Accessed:")
    for file, count in stats_30d['top_10']:
        print(f"  {count:3}x  {Path(file).name}")

    print(f"\n📉 10 Least Accessed:")
    for file, count in stats_30d['bottom_10']:
        print(f"  {count:3}x  {Path(file).name}")

    print(f"\n📂 By Category:")
    for category, count in stats_30d['by_category'].items():
        print(f"  {category:15s}: {count:3} accesses")
```

**KPI Targets:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Unique documents accessed (monthly)** | >50% of total docs | `unique / total * 100` |
| **Top 10 concentration** | <30% of total accesses | `sum(top_10) / total * 100` |
| **Orphaned docs** (0 accesses in 90 days) | <10% | `zero_access / total * 100` |

### 2.2 Search Pattern Analysis

**What to Measure:**
- Common search terms (if using search)
- Commit messages mentioning docs (proxy for issues)
- GitHub Issues with "docs" label
- Slack/Teams questions about docs

**Implementation:**

```python
#!/usr/bin/env python3
# scripts/utilities/analyze_search_patterns.py

def analyze_commit_messages():
    """Analyze git commit messages for documentation patterns"""

    cmd = ['git', 'log', '--all', '--grep=docs:', '--oneline', '--since=30.days']
    result = subprocess.run(cmd, capture_output=True, text=True)

    commits = result.stdout.strip().split('\n')

    patterns = {
        'total': len(commits),
        'fixes': len([c for c in commits if 'fix' in c.lower()]),
        'additions': len([c for c in commits if 'add' in c.lower()]),
        'updates': len([c for c in commits if 'update' in c.lower()]),
        'improvements': len([c for c in commits if 'improve' in c.lower()])
    }

    return patterns

def analyze_github_issues():
    """Analyze GitHub issues labeled with 'documentation'"""

    # Requires gh CLI
    cmd = ['gh', 'issue', 'list', '--label', 'documentation', '--json', 'title,state,createdAt']
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return {'error': 'gh CLI not available or not authenticated'}

    issues = json.loads(result.stdout)

    # Analyze patterns
    thirty_days_ago = datetime.now() - timedelta(days=30)

    recent_issues = [
        i for i in issues
        if datetime.fromisoformat(i['createdAt'].replace('Z', '+00:00')) > thirty_days_ago
    ]

    patterns = {
        'total_issues': len(issues),
        'open_issues': len([i for i in issues if i['state'] == 'OPEN']),
        'closed_issues': len([i for i in issues if i['state'] == 'CLOSED']),
        'recent_issues_30d': len(recent_issues),
        'common_terms': extract_common_terms([i['title'] for i in issues])
    }

    return patterns

def extract_common_terms(titles):
    """Extract common terms from issue titles"""

    # Simple term frequency analysis
    words = []
    for title in titles:
        words.extend(title.lower().split())

    # Filter common words
    stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
    words = [w for w in words if w not in stop_words and len(w) > 3]

    return Counter(words).most_common(10)
```

---

## 3. Engagement Metrics

### 3.1 Return Visitor Tracking

**What to Measure:**
- Weekly active users (unique git authors touching docs)
- Monthly active users
- Repeat visitor rate
- User retention (week-over-week)

**Implementation:**

```python
#!/usr/bin/env python3
# scripts/utilities/track_engagement.py

def get_active_users(days=7):
    """Get unique users accessing docs in time period"""

    since = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

    cmd = [
        'git', 'log',
        f'--since={since}',
        '--pretty=format:%an',
        '--', 'development/docs/**/*.md'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    users = [u for u in result.stdout.strip().split('\n') if u]
    unique_users = set(users)

    return {
        'period_days': days,
        'unique_users': len(unique_users),
        'total_interactions': len(users),
        'avg_interactions_per_user': len(users) / len(unique_users) if unique_users else 0,
        'users': list(unique_users)
    }

def calculate_retention():
    """Calculate week-over-week user retention"""

    # This week
    this_week = get_active_users(7)

    # Last week
    last_week_start = (datetime.now() - timedelta(days=14)).strftime('%Y-%m-%d')
    last_week_end = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')

    cmd = [
        'git', 'log',
        f'--since={last_week_start}',
        f'--until={last_week_end}',
        '--pretty=format:%an',
        '--', 'development/docs/**/*.md'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    last_week_users = set([u for u in result.stdout.strip().split('\n') if u])

    # Calculate retention
    this_week_users = set(this_week['users'])
    retained_users = this_week_users & last_week_users

    retention_rate = len(retained_users) / len(last_week_users) if last_week_users else 0

    return {
        'last_week_users': len(last_week_users),
        'this_week_users': len(this_week_users),
        'retained_users': len(retained_users),
        'retention_rate': retention_rate * 100,
        'new_users': len(this_week_users - last_week_users),
        'churned_users': len(last_week_users - this_week_users)
    }
```

**KPI Targets:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Weekly Active Users** | >20 (adjust for team size) | Unique git authors |
| **Monthly Active Users** | >50 | Unique git authors |
| **Weekly Retention Rate** | >60% | Retained / Last week * 100 |
| **Avg Interactions per User** | >3 | Total interactions / Unique users |

### 3.2 Feedback Submission Rate

**What to Measure:**
- Feedback submissions per month
- Feedback per 100 document accesses
- Feedback response rate (team)
- User satisfaction with feedback process

**Implementation:**

```python
def calculate_feedback_metrics():
    """Calculate feedback-related metrics"""

    # Count feedback files
    feedback_dir = Path('development/docs/.feedback/2025')
    feedback_files = list(feedback_dir.rglob('*.md'))

    # Exclude templates and READMEs
    feedback_files = [f for f in feedback_files if 'TEMPLATE' not in f.name and 'README' not in f.name]

    # Get feedback from last 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_feedback = [
        f for f in feedback_files
        if datetime.fromtimestamp(f.stat().st_mtime) > thirty_days_ago
    ]

    # Analyze feedback types
    feedback_types = {'error': 0, 'gap': 0, 'clarity': 0, 'navigation': 0, 'enhancement': 0}

    for file in feedback_files:
        content = file.read_text()
        for ftype in feedback_types.keys():
            if f'type: {ftype}' in content.lower():
                feedback_types[ftype] += 1

    # Analyze feedback status
    feedback_status = {'new': 0, 'triaged': 0, 'in_progress': 0, 'completed': 0, 'declined': 0}

    for file in feedback_files:
        content = file.read_text()
        for status in feedback_status.keys():
            if f'status: {status}' in content.lower():
                feedback_status[status] += 1
                break

    # Calculate satisfaction (if ratings in feedback)
    satisfaction_scores = []
    for file in feedback_files:
        content = file.read_text()
        # Look for rating patterns like "Rating: 4/5" or similar
        import re
        matches = re.findall(r'rating:?\s*(\d)/5', content.lower())
        satisfaction_scores.extend([int(m) for m in matches])

    avg_satisfaction = sum(satisfaction_scores) / len(satisfaction_scores) if satisfaction_scores else 0

    return {
        'total_feedback': len(feedback_files),
        'feedback_last_30d': len(recent_feedback),
        'feedback_by_type': feedback_types,
        'feedback_by_status': feedback_status,
        'avg_satisfaction': avg_satisfaction,
        'response_rate': feedback_status['triaged'] / len(feedback_files) if feedback_files else 0
    }
```

**KPI Targets:**

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Feedback Submission Rate** | 1-2% of doc accesses | Feedback / Accesses * 100 |
| **Feedback Response Rate** | >90% triaged within 7 days | Triaged / Total * 100 |
| **Avg Satisfaction Score** | >4.0/5 | Sum(ratings) / Count |

### 3.3 Cross-Reference Follow-Through

**What to Measure:**
- Links clicked from navigation
- Cross-reference usage
- Index utilization
- README file access rate

**Proxy Measurement:**

```python
def analyze_navigation_patterns():
    """
    Analyze navigation patterns by looking at commit sequences
    Assumption: Sequential commits in same session indicate navigation
    """

    # Get commit log with timestamps
    cmd = [
        'git', 'log',
        '--since=30.days',
        '--pretty=format:%at|%an|%s',
        '--', 'development/docs/**/*.md'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    commits = []
    for line in result.stdout.strip().split('\n'):
        if '|' in line:
            timestamp, author, subject = line.split('|', 2)
            commits.append({
                'timestamp': int(timestamp),
                'author': author,
                'subject': subject
            })

    # Identify sessions (commits within 5 minutes by same author)
    sessions = []
    current_session = []

    for commit in sorted(commits, key=lambda x: x['timestamp']):
        if not current_session:
            current_session.append(commit)
        elif (commit['timestamp'] - current_session[-1]['timestamp'] < 300 and
              commit['author'] == current_session[-1]['author']):
            current_session.append(commit)
        else:
            if len(current_session) > 1:
                sessions.append(current_session)
            current_session = [commit]

    if len(current_session) > 1:
        sessions.append(current_session)

    # Analyze session patterns
    avg_session_length = sum(len(s) for s in sessions) / len(sessions) if sessions else 0

    return {
        'total_sessions': len(sessions),
        'avg_documents_per_session': avg_session_length,
        'multi_doc_sessions': len([s for s in sessions if len(s) > 1]),
        'navigation_rate': len([s for s in sessions if len(s) > 1]) / len(sessions) if sessions else 0
    }
```

---

## 4. Quality Metrics

### 4.1 Link Health Tracking

**What to Measure:**
- Total links in documentation
- Broken links count and percentage
- Broken links trend over time
- Time to fix broken links

**Implementation:**

```python
#!/usr/bin/env python3
# scripts/utilities/track_quality_metrics.py

def get_link_health():
    """Get current link health status"""

    # Run existing validator
    result = subprocess.run(
        ['python', 'scripts/utilities/validate_docs_links.py'],
        capture_output=True,
        text=True
    )

    # Parse output
    stats = {}
    for line in result.stdout.split('\n'):
        if 'Files scanned:' in line:
            stats['files_scanned'] = int(re.search(r'\d+', line).group())
        elif 'Links checked:' in line:
            stats['links_checked'] = int(re.search(r'\d+', line).group())
        elif 'Valid links:' in line:
            stats['links_valid'] = int(re.search(r'\d+', line).group())
        elif 'Broken links:' in line:
            stats['links_broken'] = int(re.search(r'\d+', line).group())

    if stats.get('links_checked', 0) > 0:
        stats['health_percentage'] = (stats['links_valid'] / stats['links_checked']) * 100
    else:
        stats['health_percentage'] = 100

    stats['timestamp'] = datetime.now().isoformat()

    return stats

def track_link_health_over_time():
    """Track link health trend"""

    current = get_link_health()

    # Save to trends
    trends_file = Path('development/docs/.analytics/trends/link_health.json')
    trends_file.parent.mkdir(parents=True, exist_ok=True)

    if trends_file.exists():
        trends = json.loads(trends_file.read_text())
    else:
        trends = []

    trends.append(current)

    # Keep last 90 days
    ninety_days_ago = (datetime.now() - timedelta(days=90)).isoformat()
    trends = [t for t in trends if t['timestamp'] > ninety_days_ago]

    trends_file.write_text(json.dumps(trends, indent=2))

    # Calculate trend
    if len(trends) >= 2:
        improvement = trends[-1]['health_percentage'] - trends[0]['health_percentage']
        print(f"📈 Health trend: {improvement:+.1f}% over {len(trends)} measurements")

    return current
```

**KPI Targets:**

| Metric | Target | Status |
|--------|--------|--------|
| **Overall Link Health** | >95% | ✅ GOOD / ⚠️ ATTENTION / ❌ CRITICAL |
| **Critical Path Links** | 100% | Must be perfect |
| **Time to Fix Broken Link** | <7 days | High priority |
| **Regression Rate** | <1% per month | New broken links |

### 4.2 Content Freshness

**What to Measure:**
- Average days since last update
- Percentage of docs >90 days old
- Percentage of docs >180 days old
- Documentation velocity (updates per week)

**Implementation:**

```python
def calculate_content_freshness():
    """Calculate content freshness metrics"""

    docs_dir = Path('development/docs')
    doc_files = [f for f in docs_dir.rglob('*.md') if '/.' not in str(f)]  # Exclude hidden dirs

    now = datetime.now()
    freshness_data = []

    for doc in doc_files:
        # Get last modified time from git
        cmd = ['git', 'log', '-1', '--format=%at', '--', str(doc)]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stdout.strip():
            last_modified = datetime.fromtimestamp(int(result.stdout.strip()))
            days_old = (now - last_modified).days

            freshness_data.append({
                'file': str(doc.relative_to(docs_dir)),
                'days_old': days_old,
                'last_modified': last_modified.isoformat()
            })

    # Calculate statistics
    if freshness_data:
        ages = [d['days_old'] for d in freshness_data]

        stats = {
            'total_documents': len(freshness_data),
            'avg_age_days': sum(ages) / len(ages),
            'median_age_days': sorted(ages)[len(ages) // 2],
            'docs_90d_old': len([a for a in ages if a > 90]),
            'docs_180d_old': len([a for a in ages if a > 180]),
            'docs_365d_old': len([a for a in ages if a > 365]),
            'pct_90d_old': len([a for a in ages if a > 90]) / len(ages) * 100,
            'pct_180d_old': len([a for a in ages if a > 180]) / len(ages) * 100,
            'oldest_docs': sorted(freshness_data, key=lambda x: x['days_old'], reverse=True)[:10]
        }
    else:
        stats = {}

    return stats
```

**KPI Targets:**

| Metric | Target | Threshold |
|--------|--------|-----------|
| **Avg Document Age** | <90 days | ⚠️ if >120 days |
| **Docs >90 Days Old** | <30% | ⚠️ if >50% |
| **Docs >180 Days Old** | <10% | ⚠️ if >20% |
| **Update Velocity** | >5 docs/week | Continuous improvement |

### 4.3 Error Report Rate

**What to Measure:**
- Errors reported per 100 document accesses
- Error resolution time
- Recurring error rate
- Error-free documentation percentage

**Implementation:**

```python
def calculate_error_metrics():
    """Calculate error-related metrics"""

    # Count error feedback
    feedback_dir = Path('development/docs/.feedback')
    error_feedback = []

    for file in feedback_dir.rglob('*.md'):
        content = file.read_text()
        if 'type: error' in content.lower() or 'type: a' in content.lower():
            error_feedback.append({
                'file': file,
                'date': datetime.fromtimestamp(file.stat().st_mtime)
            })

    # Last 30 days
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_errors = [e for e in error_feedback if e['date'] > thirty_days_ago]

    # Get total doc accesses (from usage stats)
    usage_file = Path('development/docs/.analytics/usage_stats.json')
    if usage_file.exists():
        usage_data = json.loads(usage_file.read_text())
        total_accesses = usage_data['last_30_days']['total_accesses']
    else:
        total_accesses = 0

    error_rate = (len(recent_errors) / total_accesses * 100) if total_accesses > 0 else 0

    # Calculate resolution time
    resolution_times = []
    for error in error_feedback:
        content = error['file'].read_text()
        if 'status: completed' in content.lower():
            # Try to extract completion date (simplified)
            # In real implementation, parse YAML frontmatter
            resolution_times.append(7)  # Placeholder

    avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else 0

    return {
        'total_errors_reported': len(error_feedback),
        'errors_last_30d': len(recent_errors),
        'error_rate_per_100_accesses': error_rate,
        'avg_resolution_time_days': avg_resolution_time,
        'unresolved_errors': len([e for e in error_feedback if 'status: new' in e['file'].read_text().lower()])
    }
```

**KPI Targets:**

| Metric | Target | Threshold |
|--------|--------|-----------|
| **Error Rate** | <1 error per 100 accesses | ⚠️ if >2% |
| **Avg Resolution Time** | <7 days | ⚠️ if >14 days |
| **Recurring Errors** | 0 | Each error should be fixed permanently |
| **Unresolved Errors** | <5 at any time | Clear backlog regularly |

---

## 5. Impact Metrics

### 5.1 Time to Productivity (Onboarding)

**What to Measure:**
- Days to first successful deployment (new hires)
- Days to first feature completion
- Self-service success rate
- Questions asked before documentation consulted

**Implementation:**

```python
def track_onboarding_metrics():
    """
    Track onboarding impact
    Requires manual data collection or integration with HR/onboarding systems
    """

    # This is typically collected via surveys or interviews
    # Store in .analytics/onboarding/

    onboarding_file = Path('development/docs/.analytics/onboarding/2025_Q4.json')

    if onboarding_file.exists():
        data = json.loads(onboarding_file.read_text())
    else:
        data = []

    # Example data structure
    example = {
        'employee_id': 'EMP123',
        'start_date': '2025-01-15',
        'first_deployment': '2025-01-18',  # 3 days
        'first_feature': '2025-01-22',      # 7 days
        'documentation_rating': 4.5,
        'questions_to_team': 3,             # Low is better
        'self_service_success': True,
        'feedback': 'Docs were very helpful, especially quickstart guides'
    }

    # Calculate metrics
    if data:
        avg_time_to_deployment = sum(
            (datetime.fromisoformat(d['first_deployment']) -
             datetime.fromisoformat(d['start_date'])).days
            for d in data
        ) / len(data)

        avg_time_to_feature = sum(
            (datetime.fromisoformat(d['first_feature']) -
             datetime.fromisoformat(d['start_date'])).days
            for d in data
        ) / len(data)

        self_service_rate = len([d for d in data if d['self_service_success']]) / len(data) * 100

        return {
            'total_onboarded': len(data),
            'avg_days_to_first_deployment': avg_time_to_deployment,
            'avg_days_to_first_feature': avg_time_to_feature,
            'self_service_success_rate': self_service_rate,
            'avg_documentation_rating': sum(d['documentation_rating'] for d in data) / len(data),
            'avg_questions_asked': sum(d['questions_to_team'] for d in data) / len(data)
        }

    return {}
```

**KPI Targets:**

| Metric | Target | Impact |
|--------|--------|--------|
| **Time to First Deployment** | <3 days | ⭐ Faster onboarding |
| **Time to First Feature** | <7 days | ⭐ Increased productivity |
| **Self-Service Success Rate** | >80% | ⭐ Reduced team load |
| **Questions Asked** | <5 before docs | ⭐ Better documentation |

### 5.2 Support Ticket Reduction

**What to Measure:**
- Documentation-related tickets before/after improvements
- Slack questions about topics covered in docs
- Email support requests
- Office hours attendance (may go down if docs improve)

**Implementation:**

```python
def track_support_impact():
    """
    Track support ticket reduction
    Requires integration with support systems or manual tracking
    """

    # Track Slack questions (requires Slack API or manual logging)
    # Track GitHub Issues with 'question' label

    # Example: Analyze GitHub Issues
    cmd = ['gh', 'issue', 'list', '--label', 'question', '--json', 'createdAt,title', '--limit', 1000]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        issues = json.loads(result.stdout)

        # Group by month
        by_month = {}
        for issue in issues:
            created = datetime.fromisoformat(issue['createdAt'].replace('Z', '+00:00'))
            month_key = created.strftime('%Y-%m')

            if month_key not in by_month:
                by_month[month_key] = 0
            by_month[month_key] += 1

        # Calculate trend
        months = sorted(by_month.keys())
        if len(months) >= 2:
            first_month = by_month[months[0]]
            last_month = by_month[months[-1]]
            reduction_pct = (first_month - last_month) / first_month * 100 if first_month > 0 else 0

            return {
                'by_month': by_month,
                'trend': 'decreasing' if reduction_pct > 0 else 'increasing',
                'reduction_percentage': reduction_pct,
                'current_month_questions': last_month
            }

    return {}
```

**KPI Targets:**

| Metric | Target | Impact |
|--------|--------|--------|
| **Support Ticket Reduction** | -20% quarter-over-quarter | ⭐ Less team interruption |
| **Slack Questions** | -30% for documented topics | ⭐ Self-service increase |
| **Documentation Referrals** | >50% of questions | ⭐ Docs effectiveness |

### 5.3 Deployment Success Rate

**What to Measure:**
- Successful deployments following guide
- Rollback rate (may decrease with better docs)
- Time to deploy (may decrease)
- Configuration errors (should decrease)

**Implementation:**

```python
def track_deployment_impact():
    """
    Track deployment success metrics
    Requires deployment logging or CI/CD integration
    """

    # Example: Parse deployment logs or CI/CD data
    # This is typically collected from production systems

    # Placeholder structure
    deployment_metrics = {
        'total_deployments': 45,
        'successful_deployments': 43,
        'success_rate': 95.6,
        'avg_deployment_time_minutes': 23,
        'rollback_rate': 4.4,
        'configuration_errors': 2,
        'documentation_consulted_pct': 78
    }

    return deployment_metrics
```

**KPI Targets:**

| Metric | Target | Impact |
|--------|--------|--------|
| **Deployment Success Rate** | >95% | ⭐ Fewer production issues |
| **Avg Deployment Time** | <30 minutes | ⭐ Faster releases |
| **Rollback Rate** | <5% | ⭐ Higher confidence |
| **Config Errors** | 0 | ⭐ Better documentation |

### 5.4 Documentation ROI

**What to Measure:**
- Time saved (hours) = Questions avoided × Time per question
- Cost saved = Time saved × Hourly rate
- Documentation maintenance cost
- ROI = (Time saved - Maintenance cost) / Maintenance cost

**Implementation:**

```python
def calculate_documentation_roi():
    """Calculate ROI of documentation efforts"""

    # Assumptions (adjust for your organization)
    avg_question_time_minutes = 15  # Time to answer a question
    avg_hourly_rate = 75  # Average engineer hourly rate
    doc_maintenance_hours_per_week = 5
    weeks_per_year = 52

    # Get metrics
    support_metrics = track_support_impact()

    # Calculate questions avoided (compare to baseline or industry average)
    # Assumption: Without docs, 50% more questions
    current_questions_per_month = support_metrics.get('current_month_questions', 20)
    questions_avoided_per_month = current_questions_per_month * 0.5

    # Time saved
    time_saved_minutes_per_month = questions_avoided_per_month * avg_question_time_minutes
    time_saved_hours_per_year = (time_saved_minutes_per_month * 12) / 60

    # Cost saved
    cost_saved_per_year = time_saved_hours_per_year * avg_hourly_rate

    # Maintenance cost
    maintenance_cost_per_year = doc_maintenance_hours_per_week * weeks_per_year * avg_hourly_rate

    # ROI
    net_benefit = cost_saved_per_year - maintenance_cost_per_year
    roi_percentage = (net_benefit / maintenance_cost_per_year) * 100 if maintenance_cost_per_year > 0 else 0

    return {
        'questions_avoided_per_month': questions_avoided_per_month,
        'time_saved_hours_per_year': time_saved_hours_per_year,
        'cost_saved_per_year': cost_saved_per_year,
        'maintenance_cost_per_year': maintenance_cost_per_year,
        'net_benefit': net_benefit,
        'roi_percentage': roi_percentage
    }
```

**Example Output:**

```
📊 DOCUMENTATION ROI ANALYSIS

Questions avoided per month: 10
Time saved per year: 30 hours
Cost saved per year: $2,250
Maintenance cost per year: $19,500
Net benefit: -$17,250
ROI: -88.5%

Note: ROI may appear negative in early stages but improves as
documentation matures and usage scales. Focus on leading indicators
like user satisfaction and self-service rate.
```

---

## 6. Implementation Guide

### 6.1 Initial Setup

```bash
#!/bin/bash
# scripts/setup_metrics_tracking.sh

echo "📊 Setting up Documentation Metrics Tracking"
echo "============================================="

# Create analytics directory structure
mkdir -p development/docs/.analytics/{trends,dashboards,onboarding,surveys}

# Create initial metrics collection scripts
# (Copy Python scripts from above sections)

# Create cron job / Task Scheduler entry for automated collection
echo "⏰ Setting up automated collection..."

# Linux/Mac: Add to crontab
# 0 9 * * 1 cd /path/to/development && python scripts/utilities/collect_all_metrics.py

# Windows: Use Task Scheduler
# schtasks /create /tn "DocMetrics" /tr "python C:\...\collect_all_metrics.py" /sc weekly /d MON /st 09:00

echo "✅ Metrics tracking setup complete!"
```

### 6.2 Master Metrics Collection Script

```python
#!/usr/bin/env python3
# scripts/utilities/collect_all_metrics.py

"""
Master script to collect all documentation metrics
Run weekly via cron or Task Scheduler
"""

import json
from pathlib import Path
from datetime import datetime

def collect_all_metrics():
    """Collect all metrics and generate reports"""

    print("📊 Collecting Documentation Metrics")
    print("=" * 70)

    # Collect each metric category
    print("\n📈 Collecting usage metrics...")
    usage = save_usage_stats()

    print("\n👥 Collecting engagement metrics...")
    engagement = {
        'active_users': get_active_users(7),
        'retention': calculate_retention(),
        'feedback': calculate_feedback_metrics()
    }

    print("\n✅ Collecting quality metrics...")
    quality = {
        'link_health': track_link_health_over_time(),
        'freshness': calculate_content_freshness(),
        'errors': calculate_error_metrics()
    }

    print("\n🎯 Collecting impact metrics...")
    impact = {
        'onboarding': track_onboarding_metrics(),
        'support': track_support_impact(),
        'deployment': track_deployment_impact(),
        'roi': calculate_documentation_roi()
    }

    # Compile master report
    master_report = {
        'date': datetime.now().isoformat(),
        'usage': usage,
        'engagement': engagement,
        'quality': quality,
        'impact': impact
    }

    # Save master report
    report_file = Path(f'development/docs/.analytics/weekly_report_{datetime.now().strftime("%Y%m%d")}.json')
    report_file.write_text(json.dumps(master_report, indent=2))

    print(f"\n💾 Master report saved: {report_file}")

    # Generate summary
    generate_summary_report(master_report)

def generate_summary_report(data):
    """Generate human-readable summary"""

    print("\n" + "=" * 70)
    print("📊 DOCUMENTATION METRICS SUMMARY")
    print("=" * 70)

    # Usage
    usage_30d = data['usage']['last_30_days']
    print(f"\n📈 USAGE (Last 30 Days)")
    print(f"  Total accesses: {usage_30d['total_accesses']}")
    print(f"  Unique documents: {usage_30d['unique_documents']}")
    print(f"  Top accessed: {Path(usage_30d['top_10'][0][0]).name} ({usage_30d['top_10'][0][1]}x)")

    # Engagement
    print(f"\n👥 ENGAGEMENT")
    print(f"  Weekly active users: {data['engagement']['active_users']['unique_users']}")
    print(f"  Retention rate: {data['engagement']['retention']['retention_rate']:.1f}%")
    print(f"  Feedback submissions: {data['engagement']['feedback']['feedback_last_30d']}")

    # Quality
    print(f"\n✅ QUALITY")
    print(f"  Link health: {data['quality']['link_health']['health_percentage']:.1f}%")
    print(f"  Avg document age: {data['quality']['freshness']['avg_age_days']:.0f} days")
    print(f"  Errors reported: {data['quality']['errors']['errors_last_30d']}")

    # Impact
    if data['impact']['roi']:
        print(f"\n🎯 IMPACT")
        print(f"  Time saved: {data['impact']['roi']['time_saved_hours_per_year']:.0f} hours/year")
        print(f"  Cost saved: ${data['impact']['roi']['cost_saved_per_year']:,.0f}")
        print(f"  ROI: {data['impact']['roi']['roi_percentage']:.0f}%")

    print("\n" + "=" * 70)

if __name__ == '__main__':
    collect_all_metrics()
```

### 6.3 Visualization Dashboard

**Simple CSV Export for Spreadsheet Visualization:**

```python
def export_to_csv():
    """Export metrics to CSV for visualization in Excel/Google Sheets"""

    # Load recent reports
    reports_dir = Path('development/docs/.analytics')
    report_files = sorted(reports_dir.glob('weekly_report_*.json'))[-12:]  # Last 12 weeks

    # Extract key metrics
    rows = []
    for report_file in report_files:
        data = json.loads(report_file.read_text())

        row = {
            'Date': data['date'][:10],
            'Total Accesses': data['usage']['last_7_days']['total_accesses'],
            'Unique Docs': data['usage']['last_7_days']['unique_documents'],
            'Active Users': data['engagement']['active_users']['unique_users'],
            'Link Health %': data['quality']['link_health']['health_percentage'],
            'Avg Age Days': data['quality']['freshness']['avg_age_days'],
            'Errors': data['quality']['errors']['errors_last_30d'],
            'Feedback': data['engagement']['feedback']['feedback_last_30d']
        }

        rows.append(row)

    # Write to CSV
    import csv

    csv_file = Path('development/docs/.analytics/dashboards/metrics_trend.csv')
    csv_file.parent.mkdir(parents=True, exist_ok=True)

    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"✅ Metrics exported to: {csv_file}")
    print("   Open in Excel/Google Sheets to create charts")
```

### 6.4 Automated Reporting

**Weekly Email Report:**

```python
def generate_email_report(report_data):
    """Generate HTML email report"""

    html = f"""
    <html>
    <body>
        <h1>📊 Documentation Metrics - Week of {report_data['date'][:10]}</h1>

        <h2>📈 Usage Highlights</h2>
        <ul>
            <li>Total accesses: {report_data['usage']['last_7_days']['total_accesses']}</li>
            <li>Unique documents: {report_data['usage']['last_7_days']['unique_documents']}</li>
            <li>Most accessed: {Path(report_data['usage']['last_7_days']['top_10'][0][0]).name}</li>
        </ul>

        <h2>✅ Quality Status</h2>
        <ul>
            <li>Link health: {report_data['quality']['link_health']['health_percentage']:.1f}%</li>
            <li>Errors reported: {report_data['quality']['errors']['errors_last_30d']}</li>
        </ul>

        <h2>🎯 Actions Needed</h2>
        <ul>
            <!-- Dynamically generate action items based on thresholds -->
        </ul>

        <p><a href="file:///path/to/development/docs/.analytics/">View Full Report</a></p>
    </body>
    </html>
    """

    # Save HTML report
    html_file = Path(f'development/docs/.analytics/dashboards/weekly_report_{datetime.now().strftime("%Y%m%d")}.html')
    html_file.write_text(html)

    print(f"✅ Email report generated: {html_file}")

    # TODO: Send via email (requires SMTP setup)
    # send_email(to='team@company.com', subject='Weekly Doc Metrics', body_html=html)
```

---

## Quick Reference

### Metric Thresholds

```
🟢 GREEN (Good):     Link Health >95%, Avg Age <90 days, Error Rate <1%
🟡 YELLOW (Watch):   Link Health 90-95%, Avg Age 90-120 days, Error Rate 1-2%
🔴 RED (Action):     Link Health <90%, Avg Age >120 days, Error Rate >2%
```

### Weekly Checklist

```bash
# Every Monday:
1. python scripts/utilities/collect_all_metrics.py
2. Review summary report
3. Identify action items (RED metrics)
4. Update team in standup
5. Export to CSV for leadership dashboard
```

### Monthly Dashboard Template

```markdown
# Documentation Metrics Dashboard - [Month Year]

## Executive Summary
- 📊 Overall Health: [Green/Yellow/Red]
- 📈 Usage Trend: [Up/Down/Stable]
- ✅ Quality Score: [X/100]
- 🎯 Impact: [High/Medium/Low]

## Key Metrics
| Metric | This Month | Last Month | Target | Status |
|--------|------------|------------|--------|--------|
| Link Health | 95.2% | 94.1% | >95% | 🟢 |
| Avg Age | 87 days | 92 days | <90 days | 🟢 |
| Active Users | 23 | 19 | >20 | 🟢 |
| Error Rate | 1.2% | 1.8% | <1% | 🟡 |

## Top 5 Most Accessed
1. [Document 1] - 145 views
2. [Document 2] - 132 views
3. [Document 3] - 98 views
4. [Document 4] - 87 views
5. [Document 5] - 76 views

## Actions This Month
- ✅ Fixed 17 broken links
- ✅ Updated 12 outdated guides
- ✅ Added 3 new quickstart guides
- 🟡 In Progress: Advanced GPU guide

## Goals Next Month
- 🎯 Achieve 100% link health
- 🎯 Update all docs >180 days old
- 🎯 Increase feedback submissions by 20%
```

---

## Related Documentation

- [Feedback Collection System](./FEEDBACK_COLLECTION_SYSTEM.md) - How we gather data
- [Feedback Triage Process](./FEEDBACK_TRIAGE_PROCESS.md) - How we act on feedback
- [Iteration Workflow](./DOCUMENTATION_ITERATION_WORKFLOW.md) - How we make changes
- [Quarterly Review Process](./QUARTERLY_REVIEW_PROCESS.md) - Strategic planning

---

**Next:** [Documentation Iteration Workflow →](./DOCUMENTATION_ITERATION_WORKFLOW.md)
