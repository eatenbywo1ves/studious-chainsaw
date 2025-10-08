# Documentation Cleanup Validation Script
# Validates that the cleanup was successful

param(
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$script:validationErrors = @()
$script:validationWarnings = @()
$script:validationSuccess = @()

function Write-ValidationResult {
    param(
        [string]$Test,
        [bool]$Passed,
        [string]$Message,
        [string]$Level = "Error"
    )

    if ($Passed) {
        $script:validationSuccess += "✓ $Test"
        Write-Host "✓ $Test" -ForegroundColor Green
    } else {
        if ($Level -eq "Warning") {
            $script:validationWarnings += "⚠ $Test - $Message"
            Write-Host "⚠ $Test - $Message" -ForegroundColor Yellow
        } else {
            $script:validationErrors += "✗ $Test - $Message"
            Write-Host "✗ $Test - $Message" -ForegroundColor Red
        }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DOCUMENTATION CLEANUP VALIDATION" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Test 1: Count .md files
Write-Host "Test 1: File count validation" -ForegroundColor Yellow
$mdFiles = Get-ChildItem -Path "C:\Users\Corbin\development" -Filter "*.md" -Recurse -File |
    Where-Object { $_.FullName -notmatch "node_modules|ghidra_11.4.2_PUBLIC" }

$mdCount = $mdFiles.Count
$homeCount = (Get-ChildItem -Path "C:\Users\Corbin" -Filter "*.md" -File).Count

Write-Host "  Development .md files: $mdCount"
Write-Host "  Home .md files: $homeCount"

Write-ValidationResult -Test "Total file count reduced" `
    -Passed ($mdCount -lt 150) `
    -Message "Expected <150 files, found $mdCount"

# Test 2: Archive directories exist
Write-Host "`nTest 2: Archive structure validation" -ForegroundColor Yellow
$archiveDirs = @(
    "C:\Users\Corbin\development\archives\weekly-reports",
    "C:\Users\Corbin\development\archives\session-summaries",
    "C:\Users\Corbin\development\archives\phase-completions",
    "C:\Users\Corbin\development\archives\historical-plans"
)

foreach ($dir in $archiveDirs) {
    $dirName = Split-Path $dir -Leaf
    Write-ValidationResult -Test "Archive directory exists: $dirName" `
        -Passed (Test-Path $dir) `
        -Message "Directory not found: $dir"
}

# Test 3: Master guides exist
Write-Host "`nTest 3: Master guide validation" -ForegroundColor Yellow
$masterGuides = @(
    "C:\Users\Corbin\development\docs\guides\BMAD_MASTER_GUIDE.md",
    "C:\Users\Corbin\development\docs\guides\REDIS_PRODUCTION_GUIDE.md",
    "C:\Users\Corbin\development\docs\guides\GPU_ACCELERATION_GUIDE.md",
    "C:\Users\Corbin\development\docs\guides\SECURITY_MASTER_GUIDE.md",
    "C:\Users\Corbin\development\docs\guides\TESTING_GUIDE.md",
    "C:\Users\Corbin\development\docs\guides\MCP_PRODUCTION_GUIDE.md",
    "C:\Users\Corbin\development\docs\guides\MONITORING_OPERATIONS_GUIDE.md"
)

foreach ($guide in $masterGuides) {
    $guideName = Split-Path $guide -Leaf
    if (Test-Path $guide) {
        Write-ValidationResult -Test "Master guide exists: $guideName" -Passed $true
    } else {
        Write-ValidationResult -Test "Master guide exists: $guideName" `
            -Passed $false `
            -Message "Guide not found - Phase 3 may be incomplete" `
            -Level "Warning"
    }
}

# Test 4: Documentation index exists
Write-Host "`nTest 4: Documentation index validation" -ForegroundColor Yellow
Write-ValidationResult -Test "Documentation index exists" `
    -Passed (Test-Path "C:\Users\Corbin\development\docs\README.md") `
    -Message "docs/README.md not found"

# Test 5: Check for duplicate patterns
Write-Host "`nTest 5: Duplicate pattern detection" -ForegroundColor Yellow
$duplicatePatterns = @(
    "*COMPLETION_SUMMARY*.md",
    "*DEPLOYMENT_COMPLETE*.md",
    "*_STATUS_*.md"
)

foreach ($pattern in $duplicatePatterns) {
    $matches = Get-ChildItem -Path "C:\Users\Corbin\development" -Filter $pattern -Recurse -File |
        Where-Object { $_.FullName -notmatch "archives|node_modules|ghidra" }

    if ($matches.Count -gt 2) {
        Write-ValidationResult -Test "No excessive duplicates for $pattern" `
            -Passed $false `
            -Message "Found $($matches.Count) files matching pattern" `
            -Level "Warning"

        if ($Verbose) {
            $matches | ForEach-Object { Write-Host "    - $($_.FullName)" -ForegroundColor DarkGray }
        }
    } else {
        Write-ValidationResult -Test "No excessive duplicates for $pattern" -Passed $true
    }
}

# Test 6: Backup exists
Write-Host "`nTest 6: Backup validation" -ForegroundColor Yellow
$backupDirs = Get-ChildItem -Path "C:\Users\Corbin\development\archives" -Directory |
    Where-Object { $_.Name -match "cleanup-backup-" } |
    Sort-Object CreationTime -Descending

if ($backupDirs.Count -gt 0) {
    $latestBackup = $backupDirs[0]
    Write-ValidationResult -Test "Backup exists" -Passed $true
    Write-Host "  Latest backup: $($latestBackup.Name)" -ForegroundColor DarkGray
} else {
    Write-ValidationResult -Test "Backup exists" `
        -Passed $false `
        -Message "No backup found in archives/"
}

# Test 7: Git commits
Write-Host "`nTest 7: Git commit validation" -ForegroundColor Yellow
$recentCommits = git log --oneline -10 --grep="docs:"

if ($recentCommits) {
    Write-ValidationResult -Test "Documentation commits exist" -Passed $true
    if ($Verbose) {
        Write-Host "  Recent commits:" -ForegroundColor DarkGray
        $recentCommits | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
} else {
    Write-ValidationResult -Test "Documentation commits exist" `
        -Passed $false `
        -Message "No recent 'docs:' commits found" `
        -Level "Warning"
}

# Test 8: Key files not deleted
Write-Host "`nTest 8: Essential file preservation" -ForegroundColor Yellow
$essentialFiles = @(
    "C:\Users\Corbin\development\README.md",
    "C:\Users\Corbin\development\QUICK_START_GUIDE.md",
    "C:\Users\Corbin\development\PHASE_5_ROADMAP.md",
    "C:\Users\Corbin\development\PLUGIN_ROADMAP_2025.md",
    "C:\Users\Corbin\CATALYTIC_COMPUTING_DOCUMENTATION.md",
    "C:\Users\Corbin\README.md"
)

foreach ($file in $essentialFiles) {
    $fileName = Split-Path $file -Leaf
    Write-ValidationResult -Test "Essential file preserved: $fileName" `
        -Passed (Test-Path $file) `
        -Message "File missing: $file"
}

# Test 9: Directory structure
Write-Host "`nTest 9: Directory structure validation" -ForegroundColor Yellow
$expectedDirs = @(
    "C:\Users\Corbin\development\docs",
    "C:\Users\Corbin\development\docs\guides",
    "C:\Users\Corbin\development\docs\api",
    "C:\Users\Corbin\development\docs\deployment",
    "C:\Users\Corbin\development\docs\monitoring",
    "C:\Users\Corbin\development\archives"
)

foreach ($dir in $expectedDirs) {
    $dirName = $dir -replace ".*\\development\\", ""
    Write-ValidationResult -Test "Directory exists: $dirName" `
        -Passed (Test-Path $dir) `
        -Message "Directory not found: $dir" `
        -Level "Warning"
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n✓ Passed: $($script:validationSuccess.Count)" -ForegroundColor Green
if ($script:validationWarnings.Count -gt 0) {
    Write-Host "⚠ Warnings: $($script:validationWarnings.Count)" -ForegroundColor Yellow
}
if ($script:validationErrors.Count -gt 0) {
    Write-Host "✗ Errors: $($script:validationErrors.Count)" -ForegroundColor Red
}

if ($script:validationErrors.Count -eq 0 -and $script:validationWarnings.Count -eq 0) {
    Write-Host "`n🎉 All validation tests passed! Documentation cleanup successful." -ForegroundColor Green
} elseif ($script:validationErrors.Count -eq 0) {
    Write-Host "`n⚠ Validation passed with warnings. Review warnings above." -ForegroundColor Yellow
} else {
    Write-Host "`n✗ Validation failed. Please review errors above." -ForegroundColor Red
    exit 1
}

# Final stats
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "CLEANUP STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Development .md files: $mdCount" -ForegroundColor White
Write-Host "Home directory .md files: $homeCount" -ForegroundColor White
Write-Host "Total: $($mdCount + $homeCount)" -ForegroundColor White

$archiveCount = (Get-ChildItem -Path "C:\Users\Corbin\development\archives" -Filter "*.md" -Recurse -File).Count
Write-Host "Archived files: $archiveCount" -ForegroundColor White

Write-Host "`nCleanup completed on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
