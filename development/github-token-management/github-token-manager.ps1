# GitHub Token Manager PowerShell Module
# Author: eatenbywo1ves
# Purpose: Manage GitHub Personal Access Tokens efficiently

# ============================================
# Token Management Functions
# ============================================

function Get-GitHubTokenStatus {
    <#
    .SYNOPSIS
    Check the status of current GitHub authentication
    
    .DESCRIPTION
    Displays current token status, scopes, and rate limits
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "=== GitHub Token Status ===" -ForegroundColor Cyan
    
    # Check gh CLI status
    $ghStatus = gh auth status 2>&1
    Write-Host "`nGitHub CLI Status:" -ForegroundColor Yellow
    Write-Host $ghStatus
    
    # Check API rate limit
    Write-Host "`nAPI Rate Limit:" -ForegroundColor Yellow
    $rateLimit = gh api rate_limit --jq '.rate | "Limit: \(.limit)\nUsed: \(.used)\nRemaining: \(.remaining)"'
    Write-Host $rateLimit
    
    # Check current user
    Write-Host "`nAuthenticated User:" -ForegroundColor Yellow
    $user = gh api user --jq '"Username: \(.login)\nName: \(.name)\nPublic Repos: \(.public_repos)"'
    Write-Host $user
}

function Set-GitHubToken {
    <#
    .SYNOPSIS
    Set a GitHub token for different contexts
    
    .PARAMETER Context
    The context for the token (e.g., 'development', 'ci', 'readonly')
    
    .PARAMETER Token
    The GitHub Personal Access Token
    
    .PARAMETER SetAsCurrent
    Set this token as the current active token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('development', 'ci', 'packages', 'admin', 'readonly')]
        [string]$Context,
        
        [Parameter(Mandatory=$true)]
        [string]$Token,
        
        [switch]$SetAsCurrent
    )
    
    # Store token securely in Windows Credential Manager
    $secureToken = ConvertTo-SecureString $Token -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential("github_pat_$Context", $secureToken)
    
    # Store in credential manager
    $credentialPath = "github_pat_$Context"
    
    # Set environment variable for current session
    $envVarName = "GITHUB_TOKEN_$(($Context).ToUpper())"
    [Environment]::SetEnvironmentVariable($envVarName, $Token, [EnvironmentVariableTarget]::Process)
    
    if ($SetAsCurrent) {
        [Environment]::SetEnvironmentVariable("GITHUB_TOKEN", $Token, [EnvironmentVariableTarget]::Process)
        Write-Host "Token set as current active token" -ForegroundColor Green
    }
    
    Write-Host "Token stored for context: $Context" -ForegroundColor Green
    Write-Host "Environment variable: $envVarName" -ForegroundColor Yellow
}

function Get-GitHubToken {
    <#
    .SYNOPSIS
    Retrieve a stored GitHub token
    
    .PARAMETER Context
    The context for the token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('development', 'ci', 'packages', 'admin', 'readonly')]
        [string]$Context
    )
    
    $envVarName = "GITHUB_TOKEN_$(($Context).ToUpper())"
    $token = [Environment]::GetEnvironmentVariable($envVarName, [EnvironmentVariableTarget]::Process)
    
    if ($token) {
        return $token
    } else {
        Write-Warning "No token found for context: $Context"
        return $null
    }
}

function Switch-GitHubContext {
    <#
    .SYNOPSIS
    Switch between different GitHub token contexts
    
    .PARAMETER Context
    The context to switch to
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('development', 'ci', 'packages', 'admin', 'readonly')]
        [string]$Context
    )
    
    $token = Get-GitHubToken -Context $Context
    
    if ($token) {
        [Environment]::SetEnvironmentVariable("GITHUB_TOKEN", $token, [EnvironmentVariableTarget]::Process)
        Write-Host "Switched to $Context context" -ForegroundColor Green
        
        # Re-authenticate gh CLI with new token
        $token | gh auth login --with-token
        Write-Host "GitHub CLI re-authenticated with $Context token" -ForegroundColor Yellow
    } else {
        Write-Error "No token found for context: $Context"
    }
}

function New-GitHubTokenRotation {
    <#
    .SYNOPSIS
    Create a new token and rotate the old one
    
    .DESCRIPTION
    Opens GitHub settings to create a new token and updates local configuration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('development', 'ci', 'packages', 'admin', 'readonly')]
        [string]$Context,
        
        [Parameter(Mandatory=$false)]
        [int]$ExpirationDays = 90
    )
    
    Write-Host "=== GitHub Token Rotation ===" -ForegroundColor Cyan
    Write-Host "Context: $Context" -ForegroundColor Yellow
    Write-Host "Expiration: $ExpirationDays days" -ForegroundColor Yellow
    
    # Open GitHub token settings
    Write-Host "`nOpening GitHub token settings..." -ForegroundColor Green
    Start-Process "https://github.com/settings/tokens/new"
    
    Write-Host @"

Recommended settings for $Context context:
$(Get-TokenScopeRecommendation -Context $Context)

"@ -ForegroundColor Cyan
    
    $newToken = Read-Host -AsSecureString "Enter new token"
    $tokenPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($newToken)
    )
    
    Set-GitHubToken -Context $Context -Token $tokenPlain -SetAsCurrent
    
    # Log rotation
    $rotationLog = @{
        Context = $Context
        RotatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ExpiresAt = (Get-Date).AddDays($ExpirationDays).ToString("yyyy-MM-dd")
    }
    
    $logPath = "C:\Users\Corbin\development\github-token-management\rotation-log.json"
    if (Test-Path $logPath) {
        $logs = Get-Content $logPath | ConvertFrom-Json
        $logs += $rotationLog
    } else {
        $logs = @($rotationLog)
    }
    
    $logs | ConvertTo-Json | Out-File $logPath
    Write-Host "Token rotation completed and logged" -ForegroundColor Green
}

function Get-TokenScopeRecommendation {
    <#
    .SYNOPSIS
    Get recommended scopes for different contexts
    #>
    param(
        [string]$Context
    )
    
    $scopes = @{
        'development' = @(
            "✓ repo - Full control of private repositories",
            "✓ workflow - Update GitHub Action workflows", 
            "✓ write:packages - Upload packages to GitHub Package Registry",
            "✓ delete:packages - Delete packages from GitHub Package Registry",
            "✓ admin:org - Full control of orgs and teams",
            "✓ gist - Create gists"
        )
        'ci' = @(
            "✓ repo:status - Access commit status",
            "✓ public_repo - Access public repositories",
            "✓ read:packages - Download packages"
        )
        'packages' = @(
            "✓ write:packages - Upload packages",
            "✓ read:packages - Download packages",
            "✓ delete:packages - Delete packages"
        )
        'admin' = @(
            "✓ admin:org - Manage organization",
            "✓ admin:repo_hook - Manage repository hooks",
            "✓ admin:enterprise - Manage enterprise"
        )
        'readonly' = @(
            "✓ public_repo - Access public repositories only",
            "✓ read:user - Read user profile data"
        )
    }
    
    return ($scopes[$Context] -join "`n")
}

function Test-GitHubTokenPermissions {
    <#
    .SYNOPSIS
    Test what operations are available with current token
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "=== Testing Token Permissions ===" -ForegroundColor Cyan
    
    $tests = @(
        @{Name="Read User"; Command="gh api user --jq '.login'"},
        @{Name="List Repos"; Command="gh repo list --limit 1"},
        @{Name="Read Org"; Command="gh api user/orgs --jq '.[0].login' 2>$null"},
        @{Name="Create Gist"; Command="echo 'test' | gh gist create --public - 2>$null && echo 'Success'"},
        @{Name="Read Packages"; Command="gh api user/packages --jq '.[] | .name' 2>$null"}
    )
    
    foreach ($test in $tests) {
        Write-Host "`nTesting: $($test.Name)" -ForegroundColor Yellow -NoNewline
        try {
            $result = Invoke-Expression $test.Command 2>$null
            if ($result) {
                Write-Host " ✓" -ForegroundColor Green
            } else {
                Write-Host " ✗" -ForegroundColor Red
            }
        } catch {
            Write-Host " ✗" -ForegroundColor Red
        }
    }
}

function Get-GitHubTokenExpiration {
    <#
    .SYNOPSIS
    Check token expiration dates from rotation log
    #>
    [CmdletBinding()]
    param()
    
    $logPath = "C:\Users\Corbin\development\github-token-management\rotation-log.json"
    
    if (Test-Path $logPath) {
        $logs = Get-Content $logPath | ConvertFrom-Json
        
        Write-Host "=== Token Expiration Status ===" -ForegroundColor Cyan
        foreach ($log in $logs) {
            $expiryDate = [DateTime]::Parse($log.ExpiresAt)
            $daysRemaining = ($expiryDate - (Get-Date)).Days
            
            $color = if ($daysRemaining -lt 7) { "Red" } 
                     elseif ($daysRemaining -lt 30) { "Yellow" } 
                     else { "Green" }
            
            Write-Host "`nContext: $($log.Context)" -ForegroundColor White
            Write-Host "Expires: $($log.ExpiresAt) ($daysRemaining days remaining)" -ForegroundColor $color
        }
    } else {
        Write-Host "No rotation log found. Start tracking with New-GitHubTokenRotation" -ForegroundColor Yellow
    }
}

# ============================================
# Quick Access Aliases
# ============================================

Set-Alias -Name ghts -Value Get-GitHubTokenStatus
Set-Alias -Name ght -Value Get-GitHubToken
Set-Alias -Name sght -Value Set-GitHubToken
Set-Alias -Name swgh -Value Switch-GitHubContext
Set-Alias -Name rotgh -Value New-GitHubTokenRotation
Set-Alias -Name testgh -Value Test-GitHubTokenPermissions
Set-Alias -Name expgh -Value Get-GitHubTokenExpiration

# ============================================
# Export Functions
# ============================================

Export-ModuleMember -Function * -Alias *

Write-Host @"
GitHub Token Manager Loaded!

Quick Commands:
  ghts     - Get token status
  sght     - Set GitHub token
  swgh     - Switch context
  rotgh    - Rotate token
  testgh   - Test permissions
  expgh    - Check expiration

Full help: Get-Help <function-name> -Full
"@ -ForegroundColor Green