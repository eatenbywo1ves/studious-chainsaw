# Automated Ghidra Plugin Build Script (PowerShell)
# Run with: powershell -ExecutionPolicy Bypass -File Build-GhidraPlugins.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Ghidra Plugin Automated Build System" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$GhidraInstallDir = "C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV"
$PluginBaseDir = "$env:USERPROFILE\ghidra-plugins"
$ExtensionsDir = "$env:USERPROFILE\.ghidra\.ghidra_12.0_DEV\Extensions"
$ScriptsDir = "$GhidraInstallDir\Ghidra\Features\Base\ghidra_scripts"

Write-Host "Ghidra Directory: $GhidraInstallDir" -ForegroundColor Yellow
Write-Host ""

# Create directories if needed
if (!(Test-Path $ExtensionsDir)) {
    Write-Host "Creating Extensions directory..." -ForegroundColor Green
    New-Item -ItemType Directory -Path $ExtensionsDir -Force | Out-Null
}

# Function to build a plugin
function Build-GhidraPlugin {
    param(
        [string]$PluginName,
        [string]$PluginPath,
        [string]$Description
    )

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Building $Description" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    if (Test-Path $PluginPath) {
        Set-Location $PluginPath

        # Check for gradlew.bat
        $gradlewPath = Join-Path $PluginPath "gradlew.bat"
        if (Test-Path $gradlewPath) {
            Write-Host "Building $PluginName..." -ForegroundColor Yellow

            # Run gradle build
            & cmd.exe /c "$gradlewPath -PGHIDRA_INSTALL_DIR=`"$GhidraInstallDir`" buildExtension 2>&1"

            # Check for built extension
            $distPath = Join-Path $PluginPath "dist"
            if (Test-Path $distPath) {
                $zipFiles = Get-ChildItem -Path $distPath -Filter "*.zip" 2>$null
                if ($zipFiles) {
                    Write-Host "Copying $PluginName to Extensions..." -ForegroundColor Green
                    Copy-Item -Path "$distPath\*.zip" -Destination $ExtensionsDir -Force
                    Write-Host "SUCCESS: $PluginName built and installed" -ForegroundColor Green
                } else {
                    Write-Host "WARNING: No zip file found for $PluginName" -ForegroundColor Yellow
                }
            } else {
                Write-Host "WARNING: Build may have failed for $PluginName" -ForegroundColor Yellow
            }
        } else {
            Write-Host "ERROR: gradlew.bat not found for $PluginName" -ForegroundColor Red
        }
    } else {
        Write-Host "SKIP: $PluginName not found at $PluginPath" -ForegroundColor Gray
    }
    Write-Host ""
}

# Build plugins
Build-GhidraPlugin -PluginName "Ghidrathon" `
                   -PluginPath "$PluginBaseDir\Ghidrathon" `
                   -Description "Ghidrathon (Python 3 Support)"

Build-GhidraPlugin -PluginName "Kaiju" `
                   -PluginPath "$PluginBaseDir\kaiju" `
                   -Description "Kaiju (Binary Analysis Framework)"

Build-GhidraPlugin -PluginName "CppClassAnalyzer" `
                   -PluginPath "$PluginBaseDir\Ghidra-Cpp-Class-Analyzer" `
                   -Description "C++ Class Analyzer"

Build-GhidraPlugin -PluginName "ret-sync" `
                   -PluginPath "$PluginBaseDir\ret-sync\ext_ghidra" `
                   -Description "ret-sync (Debugger Synchronization)"

# Install script-based plugins
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installing Script-Based Plugins" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# GhidraEmu
$ghidraEmuPath = "$PluginBaseDir\GhidraEmu"
if (Test-Path $ghidraEmuPath) {
    Write-Host "Installing GhidraEmu scripts..." -ForegroundColor Yellow
    $pyFiles = Get-ChildItem -Path $ghidraEmuPath -Filter "*.py" 2>$null
    if ($pyFiles) {
        Copy-Item -Path "$ghidraEmuPath\*.py" -Destination $ScriptsDir -Force
        Write-Host "SUCCESS: GhidraEmu scripts installed" -ForegroundColor Green
    }
} else {
    Write-Host "SKIP: GhidraEmu not found" -ForegroundColor Gray
}

# LazyGhidra
$lazyGhidraPath = "$PluginBaseDir\LazyGhidra\ghidra_scripts"
if (Test-Path $lazyGhidraPath) {
    Write-Host "Installing LazyGhidra scripts..." -ForegroundColor Yellow
    Copy-Item -Path "$lazyGhidraPath\*" -Destination $ScriptsDir -Recurse -Force
    Write-Host "SUCCESS: LazyGhidra scripts installed" -ForegroundColor Green
} else {
    Write-Host "SKIP: LazyGhidra not found" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Build Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Extensions installed to:" -ForegroundColor Yellow
Write-Host "  $ExtensionsDir" -ForegroundColor White
Write-Host ""
Write-Host "Scripts installed to:" -ForegroundColor Yellow
Write-Host "  $ScriptsDir" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "1. Launch Ghidra"
Write-Host "2. Go to File -> Install Extensions"
Write-Host "3. Select the plugins you want to enable"
Write-Host "4. Restart Ghidra"
Write-Host "5. For scripts: Window -> Script Manager -> Refresh"
Write-Host ""
Write-Host "Build process complete!" -ForegroundColor Green
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")