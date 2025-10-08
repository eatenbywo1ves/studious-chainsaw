# Git Configuration Templates for Token Management

## Repository-Specific Token Configuration

### 1. Global Git Config Setup
Add to `~/.gitconfig` or `C:\Users\Corbin\.gitconfig`:

```gitconfig
# Default user configuration
[user]
    name = eatenbywo1ves
    email = markrcorbin88@gmail.com

# Include GitHub-specific config
[include]
    path = ~/.gitconfig-github

# Conditional includes for different project directories
[includeIf "gitdir:~/development/work/"]
    path = ~/.gitconfig-work

[includeIf "gitdir:~/development/personal/"]
    path = ~/.gitconfig-personal

[includeIf "gitdir:~/development/opensource/"]
    path = ~/.gitconfig-opensource

# Default credential helper
[credential]
    helper = manager
```

### 2. GitHub-Specific Configuration
Create `~/.gitconfig-github`:

```gitconfig
# GitHub-specific settings
[github]
    user = eatenbywo1ves

# URL rewrites for HTTPS with token
[url "https://oauth2:${GITHUB_TOKEN}@github.com/"]
    insteadOf = https://github.com/

[url "https://oauth2:${GITHUB_TOKEN}@github.com/"]
    insteadOf = git@github.com:

# GitHub CLI integration
[credential "https://github.com"]
    helper = !gh auth git-credential
```

### 3. Work Projects Configuration
Create `~/.gitconfig-work`:

```gitconfig
# Work-specific configuration
[user]
    email = work-email@company.com

# Use work token for company repos
[url "https://oauth2:${GITHUB_TOKEN_WORK}@github.com/company-org/"]
    insteadOf = https://github.com/company-org/

[core]
    sshCommand = ssh -i ~/.ssh/id_rsa_work
```

### 4. Personal Projects Configuration
Create `~/.gitconfig-personal`:

```gitconfig
# Personal projects configuration
[user]
    email = markrcorbin88@gmail.com

# Use personal development token
[url "https://oauth2:${GITHUB_TOKEN_DEVELOPMENT}@github.com/eatenbywo1ves/"]
    insteadOf = https://github.com/eatenbywo1ves/

[core]
    sshCommand = ssh -i ~/.ssh/id_rsa_personal
```

### 5. Open Source Contribution Configuration
Create `~/.gitconfig-opensource`:

```gitconfig
# Open source contribution settings
[user]
    email = markrcorbin88@gmail.com

# Use minimal scope token for open source
[url "https://oauth2:${GITHUB_TOKEN_READONLY}@github.com/"]
    insteadOf = https://github.com/

# Sign commits for open source
[commit]
    gpgsign = true

[gpg]
    program = gpg
```

## Per-Repository Configuration

### Setting Token for Specific Repository
Run these commands in a repository directory:

```bash
# Set repository-specific token
git config credential.helper store
git config credential.https://github.com.username oauth2
git config credential.https://github.com.password YOUR_TOKEN_HERE

# Or use environment variable
git config url."https://oauth2:${GITHUB_TOKEN_SPECIFIC}@github.com/".insteadOf "https://github.com/"
```

### Using Different Emails per Repo
```bash
# In work repository
git config user.email "work@company.com"

# In personal repository  
git config user.email "personal@email.com"
```

## Token URL Patterns

### Basic Authentication URL
```
https://USERNAME:TOKEN@github.com/owner/repo.git
```

### OAuth2 Format (Recommended)
```
https://oauth2:TOKEN@github.com/owner/repo.git
```

### Using x-access-token
```
https://x-access-token:TOKEN@github.com/owner/repo.git
```

## Environment Variable Setup

### Windows (PowerShell)
```powershell
# Set for current session
$env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxx"
$env:GITHUB_TOKEN_WORK = "ghp_yyyyyyyyyyyy"
$env:GITHUB_TOKEN_READONLY = "ghp_zzzzzzzzzzzz"

# Set permanently (user level)
[Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "ghp_xxxxxxxxxxxx", "User")
```

### Windows (Command Prompt)
```cmd
# Set for current session
set GITHUB_TOKEN=ghp_xxxxxxxxxxxx

# Set permanently
setx GITHUB_TOKEN "ghp_xxxxxxxxxxxx"
```

## Testing Configuration

### Verify Remote URL with Token
```bash
git remote -v
git config --get remote.origin.url
```

### Test Authentication
```bash
# Test with curl
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Test with Git
git ls-remote https://github.com/eatenbywo1ves/private-repo.git
```

### Debug Git Authentication
```bash
# Enable Git debugging
set GIT_CURL_VERBOSE=1
set GIT_TRACE=1
git fetch

# Check credential helper
git config --list | grep credential
```

## Security Best Practices

1. **Never commit tokens to repositories**
   - Add `.env` and `*.token` to `.gitignore`
   - Use git-secrets to prevent accidental commits

2. **Use minimal scopes**
   - Read-only tokens for public repos
   - Write access only where needed

3. **Rotate tokens regularly**
   - Set calendar reminders
   - Use token expiration dates

4. **Separate tokens by purpose**
   - Development token for daily work
   - CI/CD token for automation
   - Read-only token for tools

5. **Monitor token usage**
   - Check GitHub audit log
   - Review API rate limit usage
   - Monitor for unauthorized access

## Troubleshooting

### Token Not Working
```bash
# Clear credential cache
git config --global --unset credential.helper
git config --system --unset credential.helper

# Re-authenticate with gh
gh auth logout
gh auth login
```

### Multiple Accounts Issue
```bash
# Use SSH config for multiple accounts
Host github-personal
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_rsa_personal

Host github-work
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_rsa_work

# Clone with specific host
git clone git@github-personal:username/repo.git
```