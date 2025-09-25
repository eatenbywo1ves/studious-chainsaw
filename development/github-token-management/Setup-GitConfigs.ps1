# Setup Git Configurations for GitHub Token Management
# This script creates Git configuration files for different contexts

Write-Host "=== Git Configuration Setup for GitHub Tokens ===" -ForegroundColor Cyan

# Define paths
$gitConfigPath = "$env:USERPROFILE\.gitconfig"
$gitConfigGitHubPath = "$env:USERPROFILE\.gitconfig-github"
$gitConfigWorkPath = "$env:USERPROFILE\.gitconfig-work"
$gitConfigPersonalPath = "$env:USERPROFILE\.gitconfig-personal"
$gitConfigOpenSourcePath = "$env:USERPROFILE\.gitconfig-opensource"

# Function to backup existing config
function Backup-GitConfig {
    param([string]$Path)
    
    if (Test-Path $Path) {
        $backupPath = "$Path.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item $Path $backupPath
        Write-Host "Backed up existing config to: $backupPath" -ForegroundColor Yellow
    }
}

# Create GitHub-specific configuration
Write-Host "`nCreating GitHub-specific configuration..." -ForegroundColor Yellow

$githubConfig = @'
# GitHub-specific settings
[github]
    user = eatenbywo1ves

# GitHub CLI integration
[credential "https://github.com"]
    helper = !gh auth git-credential

# URL rewrites for token authentication
# These will use environment variables when set
[url "https://github.com/"]
    insteadOf = git://github.com/
'@

if (!(Test-Path $gitConfigGitHubPath)) {
    $githubConfig | Out-File -FilePath $gitConfigGitHubPath -Encoding UTF8
    Write-Host "Created: $gitConfigGitHubPath" -ForegroundColor Green
} else {
    Write-Host "File already exists: $gitConfigGitHubPath" -ForegroundColor Yellow
}

# Create Work configuration template
Write-Host "Creating work projects configuration template..." -ForegroundColor Yellow

$workConfig = @'
# Work-specific configuration
# Update the email and organization name as needed
[user]
    email = work-email@company.com

# Use work token for company repos
# Replace 'company-org' with your organization name
[url "https://oauth2:${GITHUB_TOKEN_WORK}@github.com/company-org/"]
    insteadOf = https://github.com/company-org/

# Optional: Use specific SSH key for work
# [core]
#     sshCommand = ssh -i ~/.ssh/id_rsa_work
'@

if (!(Test-Path $gitConfigWorkPath)) {
    $workConfig | Out-File -FilePath $gitConfigWorkPath -Encoding UTF8
    Write-Host "Created template: $gitConfigWorkPath" -ForegroundColor Green
    Write-Host "  Note: Update email and organization in this file" -ForegroundColor Yellow
}

# Create Personal configuration
Write-Host "Creating personal projects configuration..." -ForegroundColor Yellow

$personalConfig = @'
# Personal projects configuration
[user]
    email = markrcorbin88@gmail.com

# Use personal development token for your repos
[url "https://oauth2:${GITHUB_TOKEN_DEVELOPMENT}@github.com/eatenbywo1ves/"]
    insteadOf = https://github.com/eatenbywo1ves/
    
# Also handle SSH URLs
[url "https://oauth2:${GITHUB_TOKEN_DEVELOPMENT}@github.com/eatenbywo1ves/"]
    insteadOf = git@github.com:eatenbywo1ves/

# Optional: Use specific SSH key for personal projects
# [core]
#     sshCommand = ssh -i ~/.ssh/id_rsa_personal
'@

if (!(Test-Path $gitConfigPersonalPath)) {
    $personalConfig | Out-File -FilePath $gitConfigPersonalPath -Encoding UTF8
    Write-Host "Created: $gitConfigPersonalPath" -ForegroundColor Green
}

# Create Open Source configuration
Write-Host "Creating open source contribution configuration..." -ForegroundColor Yellow

$opensourceConfig = @'
# Open source contribution settings
[user]
    email = markrcorbin88@gmail.com

# Use minimal scope token for open source (read-only when possible)
[url "https://oauth2:${GITHUB_TOKEN_READONLY}@github.com/"]
    insteadOf = https://github.com/

# Sign commits for open source contributions
[commit]
    gpgsign = false  # Set to true if you have GPG configured

# Optional: GPG configuration
# [gpg]
#     program = gpg
#     format = openpgp
'@

if (!(Test-Path $gitConfigOpenSourcePath)) {
    $opensourceConfig | Out-File -FilePath $gitConfigOpenSourcePath -Encoding UTF8
    Write-Host "Created: $gitConfigOpenSourcePath" -ForegroundColor Green
}

# Update main Git config to include conditional includes
Write-Host "`nUpdating main Git configuration..." -ForegroundColor Yellow

# Check if we need to add includes
$mainConfigUpdates = @()
$existingConfig = if (Test-Path $gitConfigPath) { Get-Content $gitConfigPath -Raw } else { "" }

# Check for existing includes
$includeGitHub = $existingConfig -match '\.gitconfig-github'
$includeWork = $existingConfig -match 'gitdir:.*development/work/'
$includePersonal = $existingConfig -match 'gitdir:.*development/personal/'
$includeOpenSource = $existingConfig -match 'gitdir:.*development/opensource/'

if (!$includeGitHub) {
    $mainConfigUpdates += @'

# Include GitHub-specific configuration
[include]
    path = ~/.gitconfig-github
'@
}

if (!$includeWork) {
    $mainConfigUpdates += @'

# Include work configuration for work projects
[includeIf "gitdir:~/development/work/"]
    path = ~/.gitconfig-work
[includeIf "gitdir:C:/Users/Corbin/development/work/"]
    path = ~/.gitconfig-work
'@
}

if (!$includePersonal) {
    $mainConfigUpdates += @'

# Include personal configuration for personal projects
[includeIf "gitdir:~/development/personal/"]
    path = ~/.gitconfig-personal
[includeIf "gitdir:C:/Users/Corbin/development/personal/"]
    path = ~/.gitconfig-personal
'@
}

if (!$includeOpenSource) {
    $mainConfigUpdates += @'

# Include open source configuration
[includeIf "gitdir:~/development/opensource/"]
    path = ~/.gitconfig-opensource
[includeIf "gitdir:C:/Users/Corbin/development/opensource/"]
    path = ~/.gitconfig-opensource
'@
}

if ($mainConfigUpdates.Count -gt 0) {
    Backup-GitConfig -Path $gitConfigPath
    $mainConfigUpdates | ForEach-Object { Add-Content -Path $gitConfigPath -Value $_ }
    Write-Host "Updated main Git config with conditional includes" -ForegroundColor Green
} else {
    Write-Host "Main Git config already has all includes" -ForegroundColor Green
}

# Create directory structure for organized projects
Write-Host "`nCreating project directory structure..." -ForegroundColor Yellow

$directories = @(
    "C:\Users\Corbin\development\personal",
    "C:\Users\Corbin\development\work",
    "C:\Users\Corbin\development\opensource"
)

foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created directory: $dir" -ForegroundColor Green
        
        # Create README in each directory
        $readmePath = Join-Path $dir "README.md"
        $readmeContent = "# $(Split-Path $dir -Leaf | ForEach-Object { $_.Substring(0,1).ToUpper() + $_.Substring(1) }) Projects`n`nThis directory uses specific Git configuration for $(Split-Path $dir -Leaf) projects."
        $readmeContent | Out-File -FilePath $readmePath -Encoding UTF8
    } else {
        Write-Host "Directory exists: $dir" -ForegroundColor Yellow
    }
}

# Display current Git configuration
Write-Host "`n=== Current Git Configuration Summary ===" -ForegroundColor Cyan
Write-Host "User Name: $(git config --global user.name)" -ForegroundColor Yellow
Write-Host "User Email: $(git config --global user.email)" -ForegroundColor Yellow
Write-Host "Credential Helper: $(git config --global credential.helper)" -ForegroundColor Yellow

# Test configuration
Write-Host "`n=== Testing Configuration ===" -ForegroundColor Cyan
$testResults = @()

# Test if configs are readable
$configs = @($gitConfigGitHubPath, $gitConfigWorkPath, $gitConfigPersonalPath, $gitConfigOpenSourcePath)
foreach ($config in $configs) {
    if (Test-Path $config) {
        $testResults += "✓ $(Split-Path $config -Leaf) exists"
    } else {
        $testResults += "✗ $(Split-Path $config -Leaf) missing"
    }
}

$testResults | ForEach-Object { Write-Host $_ -ForegroundColor Green }

Write-Host @"

=== Setup Complete! ===

Your Git is now configured for multi-context GitHub token usage.

Project Structure:
- C:\Users\Corbin\development\personal\    → Personal projects (uses GITHUB_TOKEN_DEVELOPMENT)
- C:\Users\Corbin\development\work\        → Work projects (uses GITHUB_TOKEN_WORK)  
- C:\Users\Corbin\development\opensource\  → Open source (uses GITHUB_TOKEN_READONLY)

Next Steps:
1. Set environment variables for each token type:
   `$env:GITHUB_TOKEN_DEVELOPMENT = "ghp_xxxx"
   `$env:GITHUB_TOKEN_WORK = "ghp_yyyy"
   `$env:GITHUB_TOKEN_READONLY = "ghp_zzzz"

2. Clone repositories into the appropriate directories

3. Test with: git config --list --show-origin

"@ -ForegroundColor Green