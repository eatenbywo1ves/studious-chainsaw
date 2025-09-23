# Ghidra Installation Script for Windows
# Downloads and sets up Ghidra reverse engineering framework

Write-Host "=== Ghidra Installation Script ===" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Java installation
Write-Host "Checking for Java installation..." -ForegroundColor Yellow
try {
    $javaVersion = java -version 2>&1 | Select-String "version"
    if ($javaVersion) {
        Write-Host "✓ Java is installed: $javaVersion" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ Java not found. Installing OpenJDK 17..." -ForegroundColor Red
    
    # Install Java using winget
    $installResult = winget install Microsoft.OpenJDK.17
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Java installed successfully!" -ForegroundColor Green
        Write-Host "Please restart PowerShell for Java to be available in PATH" -ForegroundColor Yellow
    } else {
        Write-Host "✗ Failed to install Java. Please install Java 17+ manually from:" -ForegroundColor Red
        Write-Host "https://adoptium.net/temurin/releases/" -ForegroundColor Cyan
        exit 1
    }
}

Write-Host ""
Write-Host "Downloading Ghidra 11.2..." -ForegroundColor Yellow
Write-Host "This may take several minutes (file size ~350MB)..." -ForegroundColor Gray

# Step 2: Download Ghidra
$ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20241105.zip"
$outputPath = "C:\Users\Corbin\development\ghidra_latest.zip"

try {
    # Download with progress
    $ProgressPreference = 'Continue'
    Invoke-WebRequest -Uri $ghidraUrl -OutFile $outputPath -UseBasicParsing
    Write-Host "✓ Download complete!" -ForegroundColor Green
} catch {
    Write-Host "✗ Download failed: $_" -ForegroundColor Red
    Write-Host "Please download Ghidra manually from:" -ForegroundColor Yellow
    Write-Host "https://github.com/NationalSecurityAgency/ghidra/releases" -ForegroundColor Cyan
    exit 1
}

Write-Host ""
Write-Host "Extracting Ghidra..." -ForegroundColor Yellow

# Step 3: Extract Ghidra
try {
    Expand-Archive -Path $outputPath -DestinationPath "C:\Users\Corbin\development\" -Force
    Write-Host "✓ Extraction complete!" -ForegroundColor Green
} catch {
    Write-Host "✗ Extraction failed: $_" -ForegroundColor Red
    exit 1
}

# Step 4: Create launcher scripts
Write-Host ""
Write-Host "Creating launcher scripts..." -ForegroundColor Yellow

# Create batch launcher
$batchLauncher = @"
@echo off
echo Starting Ghidra...
cd /d "C:\Users\Corbin\development\ghidra_11.2_PUBLIC"
call ghidraRun.bat
pause
"@
Set-Content -Path "C:\Users\Corbin\development\launch_ghidra.bat" -Value $batchLauncher

# Create PowerShell launcher
$psLauncher = @'
Write-Host "Starting Ghidra..." -ForegroundColor Green
Set-Location "C:\Users\Corbin\development\ghidra_11.2_PUBLIC"
& .\ghidraRun.bat
'@
Set-Content -Path "C:\Users\Corbin\development\launch_ghidra.ps1" -Value $psLauncher

Write-Host "✓ Launcher scripts created!" -ForegroundColor Green

# Step 5: Create desktop shortcut (optional)
$createShortcut = Read-Host "Would you like to create a desktop shortcut? (Y/N)"
if ($createShortcut -eq 'Y' -or $createShortcut -eq 'y') {
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Ghidra.lnk")
    $Shortcut.TargetPath = "C:\Users\Corbin\development\ghidra_11.2_PUBLIC\ghidraRun.bat"
    $Shortcut.WorkingDirectory = "C:\Users\Corbin\development\ghidra_11.2_PUBLIC"
    $Shortcut.IconLocation = "C:\Users\Corbin\development\ghidra_11.2_PUBLIC\support\ghidra.ico"
    $Shortcut.Save()
    Write-Host "✓ Desktop shortcut created!" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Installation Complete! ===" -ForegroundColor Green
Write-Host ""
Write-Host "Ghidra is installed at:" -ForegroundColor Cyan
Write-Host "  C:\Users\Corbin\development\ghidra_11.2_PUBLIC" -ForegroundColor White
Write-Host ""
Write-Host "To launch Ghidra:" -ForegroundColor Cyan
Write-Host "  Option 1: Run launch_ghidra.bat" -ForegroundColor White
Write-Host "  Option 2: Run launch_ghidra.ps1 in PowerShell" -ForegroundColor White
Write-Host "  Option 3: Navigate to ghidra_11.2_PUBLIC and run ghidraRun.bat" -ForegroundColor White
Write-Host ""
Write-Host "First time setup:" -ForegroundColor Yellow
Write-Host "  - Ghidra will ask you to create a project directory" -ForegroundColor Gray
Write-Host "  - Accept the user agreement" -ForegroundColor Gray
Write-Host "  - Configure memory settings if needed (default is usually fine)" -ForegroundColor Gray
Write-Host ""