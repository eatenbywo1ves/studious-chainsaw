# Install GitHub CLI Aliases
# Run this script to install all GitHub CLI aliases

Write-Host "=== Installing GitHub CLI Aliases ===" -ForegroundColor Cyan

# Check if gh CLI is available
try {
    gh --version | Out-Null
} catch {
    Write-Host "GitHub CLI (gh) is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install GitHub CLI from: https://cli.github.com/" -ForegroundColor Yellow
    exit 1
}

# List of aliases to install
$aliases = @{
    # Repository Management
    "repo-info" = 'api "repos/$1" --jq "{name: .name, private: .private, stars: .stargazers_count, forks: .forks_count, issues: .open_issues_count, default_branch: .default_branch}"'
    "repos-list" = 'api user/repos --paginate --jq ".[] | {name: .full_name, private: .private, stars: .stargazers_count, updated: .updated_at}"'
    "repo-create-std" = '!f() { gh repo create "$1" --private --clone --gitignore=VisualStudio --license=mit; }; f'
    
    # Issue Management
    "issue-bug" = '!f() { gh issue create --title "$1" --body "## Bug Report\n\n**Description:**\n$2\n\n**Steps to Reproduce:**\n1. \n\n**Expected Behavior:**\n\n**Actual Behavior:**\n\n**Environment:**\n- OS: \n- Version: " --label bug; }; f'
    "issue-feature" = '!f() { gh issue create --title "$1" --body "## Feature Request\n\n**Description:**\n$2\n\n**Use Case:**\n\n**Proposed Solution:**\n\n**Additional Context:**\n" --label enhancement; }; f'
    "my-issues" = 'api search/issues --raw-field q="author:@me is:open" --jq ".items[] | {repo: .repository_url | split(\"/\") | .[-2:] | join(\"/\"), title: .title, number: .number, url: .html_url}"'
    "review-queue" = 'api search/issues --raw-field q="is:pr is:open review-requested:@me" --jq ".items[] | {repo: .repository_url | split(\"/\") | .[-2:] | join(\"/\"), title: .title, number: .number, url: .html_url}"'
    
    # Token Management
    "token-perms" = 'api user --jq "{login: .login, type: .type, plan: .plan.name}"'
    "orgs" = 'api user/orgs --jq ".[] | {name: .login, role: .role_name // \"member\"}"'
    "token-test" = '!f() { echo "=== Token Test ==="; echo "User: $(gh api user --jq .login)"; echo "Rate: $(gh api rate_limit --jq ".rate.remaining")/$(gh api rate_limit --jq ".rate.limit")"; echo "Repos: $(gh api user --jq .public_repos) public"; }; f'
    
    # Analytics
    "repo-activity" = '!f() { echo "=== Activity for $1 ==="; echo "Contributors: $(gh api "repos/$1/contributors" --jq length)"; echo "Issues: $(gh api "repos/$1" --jq .open_issues_count)"; }; f'
    "my-contributions" = '!f() { echo "=== My Stats ==="; echo "Repos: $(gh api user --jq .public_repos)"; echo "Followers: $(gh api user --jq .followers)"; }; f'
    
    # Utilities
    "repo-languages" = 'api "repos/$1/languages" --jq "to_entries | sort_by(.value) | reverse | map(\"\(.key): \(.value) bytes\") | .[]"'
    "security-check" = '!f() { echo "=== Security Check for $1 ==="; gh api "repos/$1" --jq "{private: .private, default_branch: .default_branch}"; }; f'
}

Write-Host "Installing aliases..." -ForegroundColor Yellow

$installed = 0
$failed = 0

foreach ($alias in $aliases.GetEnumerator()) {
    try {
        # Remove existing alias if it exists (suppress errors)
        gh alias delete $alias.Key 2>$null | Out-Null
        
        # Set new alias
        $result = gh alias set $alias.Key $alias.Value 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ $($alias.Key)" -ForegroundColor Green
            $installed++
        } else {
            Write-Host "  ✗ $($alias.Key) - $result" -ForegroundColor Red
            $failed++
        }
    } catch {
        Write-Host "  ✗ $($alias.Key) - $_" -ForegroundColor Red
        $failed++
    }
}

Write-Host "`n=== Installation Complete ===" -ForegroundColor Cyan
Write-Host "Installed: $installed aliases" -ForegroundColor Green
if ($failed -gt 0) {
    Write-Host "Failed: $failed aliases" -ForegroundColor Red
}

Write-Host "`nTesting installation..." -ForegroundColor Yellow
try {
    $aliasCount = (gh alias list 2>&1 | Measure-Object -Line).Lines
    Write-Host "Total aliases available: $aliasCount" -ForegroundColor Green
} catch {
    Write-Host "Could not verify alias installation" -ForegroundColor Yellow
}

Write-Host @"

=== Usage Examples ===

Repository Info:
  gh repo-info eatenbywo1ves/hello-world

List Your Repos:
  gh repos-list

Create Bug Report:
  gh issue-bug "App crashes on startup" "Detailed description here"

Check Token:
  gh token-test

View All Aliases:
  gh alias list

"@ -ForegroundColor Cyan