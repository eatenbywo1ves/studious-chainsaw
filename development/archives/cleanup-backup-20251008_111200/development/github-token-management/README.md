# GitHub Personal Access Token Management System

A comprehensive toolkit for managing GitHub Personal Access Tokens (PATs) efficiently and securely.

## 📋 Overview

This system provides:
- **Token Management**: Secure storage and rotation of multiple GitHub tokens
- **Context Switching**: Different tokens for different project types (personal, work, open source)
- **Automation**: Automated monitoring, expiration alerts, and security auditing
- **CLI Enhancement**: Custom GitHub CLI aliases for improved productivity
- **Git Integration**: Repository-specific configurations for seamless authentication

## 🚀 Quick Start

### 1. Initial Setup
```powershell
# Install the GitHub Token Manager
.\Install-GitHubTokenManager.ps1

# Set up Git configurations
.\Setup-GitConfigs.ps1

# Install GitHub CLI aliases
.\Install-GitHubAliases.ps1
```

### 2. Configure Your First Token
```powershell
# Set your development token
sght development "ghp_your_token_here" -SetAsCurrent

# Test the configuration
ghts
testgh
```

### 3. Organize Your Projects
```
C:\Users\Corbin\development\
├── personal\     # Personal projects (uses GITHUB_TOKEN_DEVELOPMENT)
├── work\         # Work projects (uses GITHUB_TOKEN_WORK)
└── opensource\   # Open source contributions (uses GITHUB_TOKEN_READONLY)
```

## 🛠 Components

### PowerShell Modules

#### GitHub Token Manager (`github-token-manager.ps1`)
Core functionality for token management:

```powershell
# Quick status check
ghts

# Set tokens for different contexts
sght development "ghp_xxxx"
sght work "ghp_yyyy" 
sght readonly "ghp_zzzz"

# Switch between contexts
swgh development
swgh work

# Rotate tokens
rotgh development

# Test permissions
testgh

# Check expiration
expgh
```

#### Token Automation (`token-automation.ps1`)
Advanced monitoring and security features:

```powershell
# Start continuous monitoring
mongh

# Generate usage report
repgh -DaysBack 30

# Run security audit
auditgh

# Enable automated rotation alerts
autogh

# Backup configuration
backupgh
```

### Git Configuration Templates

The system creates conditional Git configurations:

- **Personal repos** → `~/.gitconfig-personal`
- **Work repos** → `~/.gitconfig-work`
- **Open source** → `~/.gitconfig-opensource`
- **GitHub integration** → `~/.gitconfig-github`

### GitHub CLI Aliases

Enhanced productivity with custom aliases:

```bash
# Repository management
gh repo-info owner/repo
gh repos-list
gh repo-create-std my-new-repo

# Issue management
gh issue-bug "Title" "Description"
gh issue-feature "Feature request title"
gh my-issues
gh review-queue

# Analytics
gh repo-activity owner/repo
gh my-contributions
```

## 📚 Detailed Usage

### Token Context Management

Different tokens for different purposes:

| Context | Use Case | Recommended Scopes |
|---------|----------|-------------------|
| `development` | Daily development work | `repo`, `workflow`, `write:packages`, `gist` |
| `work` | Company/work projects | `repo:status`, `public_repo`, `read:org` |
| `ci` | CI/CD automation | `repo:status`, `public_repo` |
| `packages` | Package management | `write:packages`, `read:packages` |
| `admin` | Organization management | `admin:org`, `admin:repo_hook` |
| `readonly` | Tools and utilities | `public_repo`, `read:user` |

### Directory-Based Token Selection

Tokens are automatically selected based on project location:

```bash
# Clone into organized directories
gh clone-org eatenbywo1ves/my-project  # → development/personal/
git clone work-org/project              # → development/work/

# Different tokens used automatically
cd development/personal/my-project      # Uses GITHUB_TOKEN_DEVELOPMENT
cd development/work/company-project     # Uses GITHUB_TOKEN_WORK
```

### Security Best Practices

#### Token Rotation
```powershell
# Manual rotation
rotgh development -ExpirationDays 90

# Automated rotation alerts
autogh -CheckDays 7
```

#### Security Monitoring
```powershell
# Run security audit
auditgh

# Monitor token usage
mongh -CheckInterval 60

# Generate usage reports
repgh -DaysBack 7
```

#### Safe Token Storage
- Never store tokens in plain text files
- Use Windows Credential Manager for secure storage
- Set appropriate environment variables per context
- Enable token expiration (30-90 days recommended)

### Advanced Workflows

#### Feature Development Workflow
```bash
# Start new feature
gh feature-start "user-authentication"

# Work on feature...
git add -A
git commit -m "Add login form"
git push

# Create PR when ready
gh feature-finish "Add user authentication system"
```

#### Repository Maintenance
```bash
# Update all local repositories
gh update-all

# Archive old repositories
gh archive-old 2024-01-01

# Security audit across repos
gh security-audit owner/repo
```

#### Bulk Operations
```bash
# Clone all repositories from organization
gh repos-sync organization-name

# Set up development environment
gh setup-dev

# Generate team activity report
gh team-activity owner/repo
```

## 🔧 Configuration Examples

### Environment Variables Setup
```powershell
# Set for current session
$env:GITHUB_TOKEN_DEVELOPMENT = "ghp_development_token_here"
$env:GITHUB_TOKEN_WORK = "ghp_work_token_here"
$env:GITHUB_TOKEN_READONLY = "ghp_readonly_token_here"

# Set permanently
[Environment]::SetEnvironmentVariable("GITHUB_TOKEN_DEVELOPMENT", "ghp_token", "User")
```

### Git URL Rewrites
```gitconfig
# Automatically inject tokens
[url "https://oauth2:${GITHUB_TOKEN_DEVELOPMENT}@github.com/eatenbywo1ves/"]
    insteadOf = https://github.com/eatenbywo1ves/

[url "https://oauth2:${GITHUB_TOKEN_WORK}@github.com/company-org/"]
    insteadOf = https://github.com/company-org/
```

### Repository-Specific Configuration
```bash
# Set token for specific repository
cd my-repo
git config credential.https://github.com.password "ghp_specific_token"

# Use different email for work repos
git config user.email "work@company.com"
```

## 🚨 Troubleshooting

### Common Issues

#### Token Not Working
```bash
# Clear credential cache
git config --global --unset credential.helper

# Re-authenticate
gh auth logout
gh auth login

# Test authentication
gh token-test
```

#### Wrong Token Being Used
```bash
# Check current configuration
git config --list --show-origin | grep credential

# Verify token in environment
echo $GITHUB_TOKEN_DEVELOPMENT

# Switch context
swgh development
```

#### Rate Limit Issues
```bash
# Check rate limit status
gh api rate_limit

# Monitor usage
mongh

# Use different token
swgh readonly  # For read-only operations
```

### Debug Commands

```bash
# Git debugging
set GIT_CURL_VERBOSE=1
set GIT_TRACE=1
git fetch

# Test API access
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Check token permissions
gh token-perms
testgh
```

## 📊 Monitoring and Analytics

### Token Usage Monitoring
```powershell
# Start monitoring (runs continuously)
Start-GitHubTokenMonitor -CheckInterval 60

# View historical usage
Get-GitHubTokenUsageReport -DaysBack 30
```

### Security Auditing
```powershell
# Comprehensive security check
Invoke-GitHubTokenSecurityAudit

# Check token expiration
Get-GitHubTokenExpiration

# Monitor for security alerts
# (Scheduled task created by Enable-AutoTokenRotation)
```

### Performance Analytics
```bash
# Repository activity
gh repo-activity owner/repo

# Personal contribution summary
gh my-contributions

# Team performance metrics
gh team-activity owner/repo
```

## 🔐 Security Recommendations

### Token Scopes
- **Principle of Least Privilege**: Only grant necessary scopes
- **Separate Tokens**: Use different tokens for different purposes
- **Regular Reviews**: Audit token permissions quarterly

### Storage Security
- **Never commit tokens** to repositories
- **Use secure storage** (Windows Credential Manager)
- **Environment variables** for automation only
- **Encrypted backups** for token configurations

### Rotation Policy
- **Regular rotation**: Every 30-90 days
- **Automated alerts**: 7 days before expiration
- **Emergency rotation**: Immediately if compromised
- **Documentation**: Track rotation in logs

### Monitoring
- **Daily usage checks**: Monitor API rate limits
- **Security audits**: Weekly automated scans
- **Access reviews**: Monthly permission audits
- **Incident response**: Plan for token compromise

## 🆘 Emergency Procedures

### Token Compromise
1. **Immediately revoke** the compromised token on GitHub
2. **Generate new token** with minimal required scopes
3. **Update local configuration** with new token
4. **Audit recent activity** in GitHub audit log
5. **Notify team** if organization token affected

### System Recovery
```powershell
# Backup current configuration
backupgh

# Restore from backup if needed
# (Manual process - copy from backup directory)

# Re-authenticate from scratch
gh auth logout
gh auth login

# Verify system health
auditgh
testgh
```

## 📝 Change Log

Track your token management activities:

- **Token rotations**: Logged in `rotation-log.json`
- **Security audits**: Timestamped reports in `security-audit-*.json`
- **Usage monitoring**: Daily logs in `monitoring-logs/`
- **System changes**: Backup snapshots in `backups/`

---

## 🔗 Quick Reference

### Essential Commands
```powershell
ghts          # Check token status
sght          # Set GitHub token
swgh          # Switch context
testgh        # Test permissions
auditgh       # Security audit
```

### Key Files
- `github-token-manager.ps1` - Core token management
- `token-automation.ps1` - Monitoring and security
- `Setup-GitConfigs.ps1` - Git configuration setup
- `Install-GitHubAliases.ps1` - CLI aliases installation
- `current-token-config.md` - Current configuration documentation

### Support
- Check `git-config-templates.md` for configuration examples
- Review `github-cli-aliases.ps1` for available aliases
- Run `Get-Help <function-name> -Full` for detailed help

---

*Generated by GitHub Token Management System v1.0*