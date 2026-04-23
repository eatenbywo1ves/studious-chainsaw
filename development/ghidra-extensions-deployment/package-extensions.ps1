# Catalytic Computing - Ghidra Extensions Build & Deployment
#
# Builds all locally-developed Ghidra extensions against one or both
# Ghidra installs (stable 11.4.2 + dev 12.0) and optionally deploys the
# resulting ZIPs to the corresponding user-settings Extensions directories.
#
# Usage:
#   .\package-extensions.ps1                       # build for stable only
#   .\package-extensions.ps1 -Target both          # build for both versions
#   .\package-extensions.ps1 -Target both -Install # build + deploy to user settings
param(
    [ValidateSet('stable', 'dev', 'both')]
    [string]$Target = 'stable',
    [switch]$Install,
    [switch]$SkipBuildFailures
)

$ErrorActionPreference = 'Stop'

# Ghidra install + user-settings Extensions dir per target.
# User-settings dirs are where Ghidra auto-loads extensions on startup.
$GhidraTargets = @{
    stable = @{
        InstallDir  = 'C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC'
        ExtUserDir  = 'C:\Users\Corbin\Downloads\software\.ghidra\.ghidra_11.4.2_PUBLIC\Extensions'
        Label       = '11.4.2_PUBLIC'
    }
    dev = @{
        InstallDir  = 'C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV'
        ExtUserDir  = 'C:\Users\Corbin\Downloads\software\.ghidra\.ghidra_12.0_DEV\Extensions'
        Label       = '12.0_DEV'
    }
}

# Extension registry. 'source' = path to extension project root.
# 'build' = gradle (runs gradlew buildExtension) or pack (manual zip from source tree).
$Extensions = @(
    @{ Name = 'GhidraGo';      Source = 'C:\Users\Corbin\development\GhidraGo';      Build = 'gradle' }
    @{ Name = 'GhidraGraph';   Source = 'C:\Users\Corbin\development\GhidraGraph';   Build = 'gradle' }
    @{ Name = 'GhidraCtrlP';   Source = 'C:\Users\Corbin\development\GhidraCtrlP';   Build = 'gradle' }
    @{ Name = 'GhidrAssist';   Source = 'C:\Users\Corbin\development\GhidrAssist';   Build = 'gradle' }
    @{ Name = 'crypto_detect'; Source = 'C:\Users\Corbin\development\ghidra-extensions-deployment\extensions\crypto_detect\source'; Build = 'gradle' }
    @{ Name = 'retsync';       Source = 'C:\tmp\ret-sync\ext_ghidra';                Build = 'gradle' }
)

function Require-JavaHome {
    if (-not $env:JAVA_HOME -or -not (Test-Path "$env:JAVA_HOME\bin\java.exe")) {
        throw "JAVA_HOME is not set or invalid. Run: setx JAVA_HOME 'C:\Program Files\Eclipse Adoptium\jdk-21.0.10.7-hotspot'"
    }
}

function Build-Extension {
    param($Extension, $GhidraInstall, $Label)
    $name = $Extension.Name
    $src  = $Extension.Source

    if (-not (Test-Path $src)) {
        Write-Host "  [SKIP] $name source not found: $src" -ForegroundColor Yellow
        return $null
    }

    if ($Extension.Build -eq 'gradle') {
        $gradlew = Join-Path $GhidraInstall 'support\gradle\gradlew.bat'
        if (-not (Test-Path $gradlew)) {
            throw "gradlew not found at $gradlew"
        }
        Push-Location $src
        try {
            $env:GHIDRA_INSTALL_DIR = $GhidraInstall
            & $gradlew buildExtension -x buildHelp 2>&1 | Out-String | Write-Host
            if ($LASTEXITCODE -ne 0) {
                throw "gradlew buildExtension failed for $name ($Label), exit=$LASTEXITCODE"
            }
        } finally {
            Pop-Location
        }
        # Find the most recent ZIP in dist/
        $distDir = Join-Path $src 'dist'
        $zip = Get-ChildItem -Path $distDir -Filter '*.zip' -ErrorAction SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $zip) {
            throw "No ZIP found in $distDir after build"
        }
        return $zip.FullName
    }

    throw "Unknown build type '$($Extension.Build)' for $name"
}

function Deploy-Extension {
    param($ZipPath, $ExtUserDir, $ExtensionName)
    if (-not (Test-Path $ExtUserDir)) {
        New-Item -ItemType Directory -Force -Path $ExtUserDir | Out-Null
    }
    $targetDir = Join-Path $ExtUserDir $ExtensionName
    if (Test-Path $targetDir) {
        Remove-Item -Recurse -Force $targetDir
    }
    Expand-Archive -Path $ZipPath -DestinationPath $ExtUserDir -Force
    Write-Host "    -> deployed to $targetDir" -ForegroundColor Green
}

# ----- main -----
Require-JavaHome

$targetKeys = if ($Target -eq 'both') { @('stable', 'dev') } else { @($Target) }

Write-Host "Catalytic Computing Ghidra Extensions Builder" -ForegroundColor Cyan
Write-Host ("Targets: {0}  |  Install deploy: {1}" -f ($targetKeys -join ','), $Install.IsPresent) -ForegroundColor Cyan
Write-Host ""

$results = @()

foreach ($tkey in $targetKeys) {
    $t = $GhidraTargets[$tkey]
    Write-Host "==== Target: $($t.Label) ====" -ForegroundColor Magenta
    if (-not (Test-Path $t.InstallDir)) {
        Write-Host "  [SKIP] Ghidra install not found: $($t.InstallDir)" -ForegroundColor Yellow
        continue
    }

    foreach ($ext in $Extensions) {
        Write-Host "-- $($ext.Name) --" -ForegroundColor Cyan
        try {
            $zip = Build-Extension -Extension $ext -GhidraInstall $t.InstallDir -Label $t.Label
            if ($null -eq $zip) { continue }
            Write-Host "    built: $zip" -ForegroundColor Green
            $results += [PSCustomObject]@{ Target=$t.Label; Extension=$ext.Name; Zip=$zip; Status='built' }

            if ($Install) {
                Deploy-Extension -ZipPath $zip -ExtUserDir $t.ExtUserDir -ExtensionName $ext.Name
                $results[-1].Status = 'deployed'
            }
        } catch {
            Write-Host "    FAILED: $_" -ForegroundColor Red
            $results += [PSCustomObject]@{ Target=$t.Label; Extension=$ext.Name; Zip=$null; Status="failed: $_" }
            if (-not $SkipBuildFailures) { throw }
        }
    }
    Write-Host ""
}

Write-Host "==== Summary ====" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$failed = @($results | Where-Object { $_.Status -like 'failed*' })
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) failure(s). Use -SkipBuildFailures to continue past errors." -ForegroundColor Yellow
    exit 1
}
Write-Host "All operations completed successfully." -ForegroundColor Green
