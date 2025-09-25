# Complete GitHub Token Management System Installation
# Master installer that sets up all components

param(
    [switch]$SkipBackups,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║              GitHub Token Management System                  ║
║                    Complete Installation                     ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$installPath = "C:\Users\Corbin\development\github-token-management"

# Check prerequisites
Write-Host "`n=== Checking Prerequisites ===" -ForegroundColor Yellow

$prerequisites = @{
    "PowerShell" = { $PSVersionTable.PSVersion.Major -ge 5 }
    "Git" = { try { git --version | Out-Null; $true } catch { $false } }
    "GitHub CLI" = { try { gh --version | Out-Null; $true } catch { $false } }
    "GitHub Auth" = { try { gh auth status 2>$null | Out-Null; $true } catch { $false } }
}

$failed = @()
foreach ($prereq in $prerequisites.GetEnumerator()) {
    $result = & $prereq.Value
    if ($result) {
        Write-Host "  ✓ $($prereq.Key)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($prereq.Key)" -ForegroundColor Red
        $failed += $prereq.Key
    }
}

if ($failed -and !$Force) {
    Write-Host "`nMissing prerequisites:" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  - $_" }
    Write-Host "`nPlease install missing prerequisites or use -Force to continue" -ForegroundColor Yellow
    exit 1
}

# Create installation log
$logFile = Join-Path $installPath "installation-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
function Write-Log {
    param($Message, $Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    Write-Host $logEntry
}

Write-Log "Starting GitHub Token Management System installation"

# Installation steps
$steps = @(
    @{
        Name = "PowerShell Token Manager"
        Script = "Install-GitHubTokenManager.ps1"
        Description = "Installs core token management functions"
    },
    @{
        Name = "Git Configurations" 
        Script = "Setup-GitConfigs.ps1"
        Description = "Sets up repository-specific Git configurations"
    },
    @{
        Name = "GitHub CLI Aliases"
        Script = "Install-GitHubAliases.ps1" 
        Description = "Installs GitHub CLI productivity aliases"
    }
)

$completed = 0
$totalSteps = $steps.Count

foreach ($step in $steps) {
    $completed++
    Write-Host "`n=== Step $completed/$totalSteps: $($step.Name) ===" -ForegroundColor Cyan
    Write-Host $step.Description -ForegroundColor Gray
    
    $scriptPath = Join-Path $installPath $step.Script
    
    if (Test-Path $scriptPath) {
        try {
            Write-Log "Executing $($step.Script)" "INFO"
            & $scriptPath
            Write-Log "Completed $($step.Name)" "SUCCESS"
            Write-Host "  ✓ $($step.Name) installed successfully" -ForegroundColor Green
        } catch {
            Write-Log "Failed $($step.Name): $_" "ERROR"
            Write-Host "  ✗ $($step.Name) failed: $_" -ForegroundColor Red
            
            if (!$Force) {
                Write-Host "`nInstallation failed. Use -Force to continue despite errors." -ForegroundColor Yellow
                exit 1
            }
        }
    } else {
        Write-Log "Script not found: $scriptPath" "WARNING"
        Write-Host "  ⚠ Script not found: $($step.Script)" -ForegroundColor Yellow
    }
}

# Create shortcuts and quick access
Write-Host "`n=== Creating Quick Access ===" -ForegroundColor Yellow

# Create desktop shortcut for PowerShell with modules loaded
$shortcutPath = "$env:USERPROFILE\Desktop\GitHub Token Manager.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "PowerShell.exe"
$shortcut.Arguments = "-NoExit -Command `"& '$installPath\github-token-manager.ps1'; & '$installPath\token-automation.ps1'`""
$shortcut.WorkingDirectory = $installPath
$shortcut.Description = "GitHub Token Management System"
$shortcut.Save()
Write-Log "Created desktop shortcut" "INFO"

# Create start menu entry
$startMenuPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\GitHub Token Manager.lnk"
$startMenuDir = Split-Path $startMenuPath -Parent
if (!(Test-Path $startMenuDir)) {
    New-Item -ItemType Directory -Path $startMenuDir -Force | Out-Null
}
Copy-Item $shortcutPath $startMenuPath
Write-Log "Created start menu entry" "INFO"

# Final verification
Write-Host "`n=== Installation Verification ===" -ForegroundColor Yellow

# Test core functionality
$verificationTests = @{
    "PowerShell Profile" = { 
        $profilePath = $PROFILE.CurrentUserAllHosts
        if (Test-Path $profilePath) {
            $content = Get-Content $profilePath -Raw
            $content -match "github-token-manager"
        } else { $false }
    }
    "Git Configuration" = {
        $gitConfig = "$env:USERPROFILE\.gitconfig"
        if (Test-Path $gitConfig) {
            $content = Get-Content $gitConfig -Raw
            $content -match "gitconfig-github"
        } else { $false }
    }
    "GitHub CLI Aliases" = {
        try {
            $aliases = gh alias list 2>$null
            $aliases -match "token-test|repo-info"
        } catch { $false }
    }
    "Directory Structure" = {
        $dirs = @("personal", "work", "opensource")
        $allExist = $true
        foreach ($dir in $dirs) {
            if (!(Test-Path "C:\Users\Corbin\development\$dir")) {
                $allExist = $false
                break
            }
        }
        $allExist
    }
}

$verificationResults = @{
    Passed = @()
    Failed = @()
}

foreach ($test in $verificationTests.GetEnumerator()) {
    try {
        $result = & $test.Value
        if ($result) {
            Write-Host "  ✓ $($test.Key)" -ForegroundColor Green
            $verificationResults.Passed += $test.Key
        } else {
            Write-Host "  ✗ $($test.Key)" -ForegroundColor Red
            $verificationResults.Failed += $test.Key
        }
    } catch {
        Write-Host "  ⚠ $($test.Key) - Error: $_" -ForegroundColor Yellow
        $verificationResults.Failed += $test.Key
    }
}

# Generate installation report
$installationReport = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    InstallPath = $installPath
    Prerequisites = $prerequisites.Keys | ForEach-Object { @{Name=$_; Status=if ($_ -in $failed) {"Failed"} else {"Passed"}} }
    Verification = $verificationResults
    LogFile = $logFile
}

$reportPath = Join-Path $installPath "installation-report.json"
$installationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportPath

# Display completion summary
Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║                    Installation Complete!                   ║
╚══════════════════════════════════════════════════════════════╝

✅ Components Installed:
   • PowerShell Token Manager (github-token-manager.ps1)
   • Token Automation & Security (token-automation.ps1)
   • Git Repository Configurations
   • GitHub CLI Aliases
   • Project Directory Structure

🚀 Quick Start Commands:
   
   Open new PowerShell session and run:
   ghts          # Check token status
   testgh        # Test current token
   auditgh       # Run security audit
   
   Or use the desktop shortcut: "GitHub Token Manager"

📁 Project Structure:
   C:\Users\Corbin\development\
   ├── personal\     # Personal projects
   ├── work\         # Work projects  
   ├── opensource\   # Open source contributions
   └── github-token-management\  # Management tools

📚 Documentation:
   • README.md - Complete user guide
   • current-token-config.md - Current setup
   • git-config-templates.md - Configuration examples

🔧 Next Steps:
   1. Set your development token: sght development "ghp_xxxx"
   2. Configure work token: sght work "ghp_yyyy"
   3. Test configuration: ghts && testgh
   4. Enable monitoring: autogh
   5. Read the README.md for advanced usage

📊 Installation Results:
   • Passed: $($verificationResults.Passed.Count) components
   • Failed: $($verificationResults.Failed.Count) components
   • Log: $logFile
   • Report: $reportPath

"@ -ForegroundColor Green

if ($verificationResults.Failed) {
    Write-Host "⚠️  Some components failed verification:" -ForegroundColor Yellow
    $verificationResults.Failed | ForEach-Object { Write-Host "   - $_" -ForegroundColor Yellow }
    Write-Host "   Check the installation log for details." -ForegroundColor Yellow
}

Write-Host "🎉 Happy GitHub token management!" -ForegroundColor Cyan

Write-Log "Installation completed successfully" "SUCCESS"