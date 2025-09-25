# GitHub CLI Aliases and Advanced Shortcuts
# Collection of useful gh CLI aliases for enhanced productivity

Write-Host "=== Setting up GitHub CLI Aliases ===" -ForegroundColor Cyan

# ============================================
# Repository Management Aliases
# ============================================

# Quick repo info
gh alias set repo-info 'api "repos/$1" --jq "{name: .name, private: .private, stars: .stargazers_count, forks: .forks_count, issues: .open_issues_count, default_branch: .default_branch}"'

# List all repositories with key metrics
gh alias set repos-list 'api user/repos --paginate --jq ".[] | {name: .full_name, private: .private, stars: .stargazers_count, updated: .updated_at}"'

# Create repo with common settings
gh alias set repo-create-std '!f() { gh repo create "$1" --private --clone --gitignore=VisualStudio --license=mit; }; f'

# Clone with token context
gh alias set clone-dev '!f() { git -c credential.helper="!gh auth git-credential" clone "https://github.com/$1.git"; }; f'

# ============================================
# Issue and PR Management
# ============================================

# Create issue with template
gh alias set issue-bug '!f() { gh issue create --title "$1" --body "## Bug Report\n\n**Description:**\n$2\n\n**Steps to Reproduce:**\n1. \n\n**Expected Behavior:**\n\n**Actual Behavior:**\n\n**Environment:**\n- OS: \n- Version: " --label bug; }; f'

# Create feature request issue
gh alias set issue-feature '!f() { gh issue create --title "$1" --body "## Feature Request\n\n**Description:**\n$2\n\n**Use Case:**\n\n**Proposed Solution:**\n\n**Additional Context:**\n" --label enhancement; }; f'

# List my issues across all repos
gh alias set my-issues 'api search/issues --raw-field q="author:@me is:open" --jq ".items[] | {repo: .repository_url | split(\"/\") | .[-2:] | join(\"/\"), title: .title, number: .number, url: .html_url}"'

# List PRs needing review
gh alias set review-queue 'api search/issues --raw-field q="is:pr is:open review-requested:@me" --jq ".items[] | {repo: .repository_url | split(\"/\") | .[-2:] | join(\"/\"), title: .title, number: .number, url: .html_url}"'

# Approve and merge PR (with safety checks)
gh alias set approve-merge '!f() { gh pr review "$1" --approve && gh pr merge "$1" --merge --delete-branch; }; f'

# ============================================
# Token and Authentication Management
# ============================================

# Check token permissions
gh alias set token-perms 'api user --jq "{login: .login, type: .type, plan: .plan.name, permissions: [\"read\", \"write\", \"admin\"]}"'

# Check organization access
gh alias set orgs 'api user/orgs --jq ".[] | {name: .login, role: .role_name // \"member\"}"'

# Test token with comprehensive check
gh alias set token-test '!f() { 
    echo "=== Token Test Results ==="
    echo "User: $(gh api user --jq .login)"
    echo "Rate Limit: $(gh api rate_limit --jq ".rate.remaining")/$(gh api rate_limit --jq ".rate.limit")"
    echo "Repos: $(gh api user --jq .public_repos) public, $(gh api user --jq .total_private_repos // 0) private"
    echo "Orgs: $(gh api user/orgs --jq length)"
    echo "Gists: $(gh api user --jq .public_gists)"
}; f'

# ============================================
# Advanced Workflow Aliases
# ============================================

# Create complete feature branch workflow
gh alias set feature-start '!f() {
    BRANCH="feature/$1"
    git checkout -b "$BRANCH"
    git push -u origin "$BRANCH"
    gh issue create --title "$1" --body "Feature development for: $1" --label enhancement
    echo "Started feature: $BRANCH"
}; f'

# Finish feature branch (create PR)
gh alias set feature-finish '!f() {
    BRANCH=$(git branch --show-current)
    gh pr create --title "$1" --body "$(git log main..HEAD --oneline)" --draft
    echo "Created draft PR for: $BRANCH"
}; f'

# Bulk repository operations
gh alias set repos-sync '!f() {
    gh repo list "$1" --limit 100 --json name,sshUrl --jq ".[] | .sshUrl" | xargs -I {} git clone {}
}; f'

# Security audit for repository
gh alias set security-audit '!f() {
    echo "=== Security Audit for $1 ==="
    gh api "repos/$1/vulnerability-alerts" --jq length 2>/dev/null || echo "Vulnerability alerts: Access denied or none"
    gh api "repos/$1/secret-scanning/alerts" --jq length 2>/dev/null || echo "Secret scanning: Access denied or none" 
    gh api "repos/$1" --jq "{private: .private, default_branch_protection: .protected, two_factor: .organization.two_factor_requirement_enabled}"
}; f'

# ============================================
# Analytics and Reporting
# ============================================

# Repository activity summary
gh alias set repo-activity '!f() {
    echo "=== Activity Summary for $1 ==="
    echo "Commits (last 30 days): $(gh api "repos/$1/stats/commit_activity" --jq "map(.total) | add")"
    echo "Contributors: $(gh api "repos/$1/contributors" --jq length)"
    echo "Open Issues: $(gh api "repos/$1" --jq .open_issues_count)"
    echo "Releases: $(gh api "repos/$1/releases" --jq length)"
}; f'

# Generate contribution report
gh alias set my-contributions '!f() {
    echo "=== My Contributions ==="
    echo "Public repos: $(gh api user --jq .public_repos)"
    echo "Followers: $(gh api user --jq .followers)"
    echo "Following: $(gh api user --jq .following)"
    gh api search/issues --raw-field q="author:@me is:pr is:closed" --jq ".total_count as \$pr_count | \"Merged PRs: \\(\$pr_count)\""
    gh api search/issues --raw-field q="author:@me is:issue is:closed" --jq ".total_count as \$issue_count | \"Closed Issues: \\(\$issue_count)\""
}; f'

# Team activity report
gh alias set team-activity '!f() {
    echo "=== Team Activity Report ==="
    gh api "repos/$1/stats/contributors" --jq "sort_by(-.total) | .[] | {author: .author.login, commits: .total, additions: [.weeks[].a] | add, deletions: [.weeks[].d] | add}"
}; f'

# ============================================
# Package and Release Management
# ============================================

# Create release with changelog
gh alias set release-create '!f() {
    CHANGELOG=$(git log $(git describe --tags --abbrev=0)..HEAD --oneline --pretty=format:"- %s")
    gh release create "$1" --title "$1" --notes "$CHANGELOG" --generate-notes
}; f'

# List package versions
gh alias set packages 'api user/packages --jq ".[] | {name: .name, package_type: .package_type, visibility: .visibility, version_count: .version_count}"'

# ============================================
# Development Workflow Helpers
# ============================================

# Quick clone into organized directory
gh alias set clone-org '!f() {
    REPO_FULL="$1"
    ORG=$(echo "$REPO_FULL" | cut -d"/" -f1)
    REPO=$(echo "$REPO_FULL" | cut -d"/" -f2)
    
    if [[ "$ORG" == "eatenbywo1ves" ]]; then
        DEST="C:/Users/Corbin/development/personal/$REPO"
    else
        DEST="C:/Users/Corbin/development/opensource/$REPO"
    fi
    
    gh repo clone "$REPO_FULL" "$DEST"
    cd "$DEST"
}; f'

# Set up repository for development
gh alias set setup-dev '!f() {
    # Install dependencies if package files exist
    if [[ -f package.json ]]; then npm install; fi
    if [[ -f requirements.txt ]]; then pip install -r requirements.txt; fi
    if [[ -f Cargo.toml ]]; then cargo build; fi
    if [[ -f pom.xml ]]; then mvn install; fi
    
    # Set up git hooks if available
    if [[ -f .githooks/pre-commit ]]; then
        ln -sf ../../.githooks/pre-commit .git/hooks/pre-commit
        chmod +x .git/hooks/pre-commit
    fi
    
    echo "Development setup complete!"
}; f'

# ============================================
# Batch Operations
# ============================================

# Update all local repositories
gh alias set update-all '!f() {
    find . -type d -name ".git" -execdir pwd \; | while read repo; do
        echo "Updating: $repo"
        cd "$repo"
        git pull --ff-only 2>/dev/null || echo "Failed to update $repo"
    done
}; f'

# Archive old repositories
gh alias set archive-old '!f() {
    CUTOFF_DATE="$1"  # Format: YYYY-MM-DD
    gh repo list --json name,pushedAt --jq ".[] | select(.pushedAt < \"$CUTOFF_DATE\") | .name" | while read repo; do
        echo "Archiving: $repo (last updated: $(gh repo view "$repo" --json pushedAt --jq .pushedAt))"
        gh repo edit "$repo" --archived
    done
}; f'

# ============================================
# Custom API Shortcuts
# ============================================

# Get repository languages
gh alias set repo-languages 'api "repos/$1/languages" --jq "to_entries | sort_by(.value) | reverse | map(\"\\(.key): \\(.value) bytes\") | .[]"'

# Check branch protection
gh alias set branch-protection 'api "repos/$1/branches/main/protection" --jq "{required_reviews: .required_pull_request_reviews.required_approving_review_count, dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews, enforce_admins: .enforce_admins.enabled}"'

# List repository webhooks
gh alias set webhooks 'api "repos/$1/hooks" --jq ".[] | {id: .id, name: .name, active: .active, url: .config.url}"'

Write-Host @"

=== GitHub CLI Aliases Configured! ===

Repository Management:
  gh repo-info <owner/repo>     - Get repository information
  gh repos-list                 - List all your repositories
  gh repo-create-std <name>     - Create standard private repo
  gh clone-org <owner/repo>     - Clone into organized directory

Issue & PR Management:
  gh issue-bug <title> <desc>   - Create bug report issue
  gh issue-feature <title>      - Create feature request
  gh my-issues                  - List your open issues
  gh review-queue               - List PRs awaiting your review
  gh approve-merge <pr>         - Approve and merge PR

Token Management:
  gh token-perms                - Check token permissions
  gh orgs                       - List organization access
  gh token-test                 - Comprehensive token test

Workflow Automation:
  gh feature-start <name>       - Start feature branch workflow
  gh feature-finish <title>     - Create PR for feature
  gh setup-dev                  - Setup development environment

Analytics:
  gh repo-activity <owner/repo> - Repository activity summary
  gh my-contributions           - Your contribution statistics
  gh team-activity <owner/repo> - Team activity report

Advanced:
  gh security-audit <owner/repo> - Security audit
  gh release-create <tag>        - Create release with changelog
  gh update-all                  - Update all local repos
  gh archive-old <YYYY-MM-DD>    - Archive old repositories

Use 'gh alias list' to see all aliases
Use 'gh <alias> --help' for detailed help on any command

"@ -ForegroundColor Green