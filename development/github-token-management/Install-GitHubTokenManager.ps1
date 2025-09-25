# GitHub Token Manager Installation Script
# This script adds the GitHub Token Manager to your PowerShell profile

$modulePath = "C:\Users\Corbin\development\github-token-management\github-token-manager.ps1"

Write-Host "=== GitHub Token Manager Installation ===" -ForegroundColor Cyan

# Check if PowerShell profile exists
$profilePath = $PROFILE.CurrentUserAllHosts
$profileDir = Split-Path $profilePath -Parent

if (!(Test-Path $profileDir)) {
    Write-Host "Creating PowerShell profile directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
}

if (!(Test-Path $profilePath)) {
    Write-Host "Creating PowerShell profile..." -ForegroundColor Yellow
    New-Item -ItemType File -Path $profilePath -Force | Out-Null
}

# Check if module is already loaded in profile
$profileContent = Get-Content $profilePath -ErrorAction SilentlyContinue
$moduleLoadCommand = ". `"$modulePath`""

if ($profileContent -contains $moduleLoadCommand) {
    Write-Host "GitHub Token Manager already installed in profile" -ForegroundColor Green
} else {
    Write-Host "Adding GitHub Token Manager to PowerShell profile..." -ForegroundColor Yellow
    
    # Add module loading to profile
    Add-Content -Path $profilePath -Value @"

# GitHub Token Manager
if (Test-Path "$modulePath") {
    . "$modulePath"
}
"@
    
    Write-Host "GitHub Token Manager installed successfully!" -ForegroundColor Green
}

# Load module for current session
Write-Host "`nLoading GitHub Token Manager for current session..." -ForegroundColor Yellow
. $modulePath

Write-Host @"

Installation Complete!

The GitHub Token Manager will now load automatically in new PowerShell sessions.

To start using it now, run:
  ghts     - Check current token status
  testgh   - Test token permissions
  
For full documentation, see:
  C:\Users\Corbin\development\github-token-management\

"@ -ForegroundColor Green