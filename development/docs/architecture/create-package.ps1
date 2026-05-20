# Architecture Documentation - Package Builder
# Creates a complete deliverable package of all architecture documentation

param(
    [string]$OutputDir = ".\package",
    [switch]$IncludeRenderedDiagrams,
    [switch]$RenderDiagramsFirst
)

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Architecture Documentation Packager" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Get current directory
$ArchDir = Get-Location

Write-Host "📦 Building documentation package..." -ForegroundColor Yellow
Write-Host "   Source: $ArchDir" -ForegroundColor Gray
Write-Host "   Output: $OutputDir`n" -ForegroundColor Gray

# Create output directory
if (Test-Path $OutputDir) {
    Write-Host "⚠️  Output directory exists. Cleaning..." -ForegroundColor Yellow
    Remove-Item -Path $OutputDir -Recurse -Force
}

New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
Write-Host "✅ Created output directory: $OutputDir`n" -ForegroundColor Green

# Render diagrams if requested
if ($RenderDiagramsFirst) {
    Write-Host "🎨 Rendering diagrams first..." -ForegroundColor Yellow

    if (Test-Path ".\render-diagrams.ps1") {
        & .\render-diagrams.ps1
        Write-Host ""
    } else {
        Write-Host "⚠️  render-diagrams.ps1 not found. Skipping diagram rendering." -ForegroundColor Yellow
        Write-Host ""
    }
}

# Define files to include
$foundationFiles = @(
    "00-executive-summary.md",
    "README-COMPREHENSIVE.md",
    "IMPLEMENTATION_STATUS.md",
    "INDEX.md",
    "USAGE_GUIDE.md"
)

$utilityFiles = @(
    "print-browser.html",
    "open-all-for-print.bat",
    "render-diagrams.ps1",
    "render-diagrams.sh"
)

# Directories to copy recursively
$directories = @(
    "01-system-context",
    "02-container-architecture",
    "03-component-architecture",
    "04-code-architecture",
    "05-arc42",
    "06-cross-cutting",
    "07-deployment",
    "08-data",
    "09-integration",
    "10-adrs"
)

# Copy foundation files
Write-Host "📄 Copying foundation files..." -ForegroundColor Cyan
$copiedCount = 0

foreach ($file in $foundationFiles) {
    if (Test-Path $file) {
        Copy-Item -Path $file -Destination $OutputDir -Force
        Write-Host "   ✅ $file" -ForegroundColor Green
        $copiedCount++
    } else {
        Write-Host "   ⚠️  $file not found" -ForegroundColor Yellow
    }
}

Write-Host "   Copied $copiedCount/$($foundationFiles.Count) foundation files`n" -ForegroundColor Gray

# Copy utility files
Write-Host "🛠️  Copying utility files..." -ForegroundColor Cyan
$copiedCount = 0

foreach ($file in $utilityFiles) {
    if (Test-Path $file) {
        Copy-Item -Path $file -Destination $OutputDir -Force
        Write-Host "   ✅ $file" -ForegroundColor Green
        $copiedCount++
    } else {
        Write-Host "   ⚠️  $file not found" -ForegroundColor Yellow
    }
}

Write-Host "   Copied $copiedCount/$($utilityFiles.Count) utility files`n" -ForegroundColor Gray

# Copy directories
Write-Host "📁 Copying documentation directories..." -ForegroundColor Cyan
$totalFiles = 0

foreach ($dir in $directories) {
    if (Test-Path $dir) {
        $destPath = Join-Path $OutputDir $dir

        # Copy directory structure
        Copy-Item -Path $dir -Destination $OutputDir -Recurse -Force

        # Count files
        $fileCount = (Get-ChildItem -Path $destPath -Recurse -File).Count
        $totalFiles += $fileCount

        Write-Host "   ✅ $dir ($fileCount files)" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  $dir not found" -ForegroundColor Yellow
    }
}

Write-Host "   Copied $totalFiles files from $($directories.Count) directories`n" -ForegroundColor Gray

# Remove rendered diagrams if not requested
if (-not $IncludeRenderedDiagrams) {
    Write-Host "🗑️  Removing rendered diagrams (keeping .puml sources)..." -ForegroundColor Yellow

    $removed = 0
    Get-ChildItem -Path $OutputDir -Recurse -File | Where-Object {
        $_.Extension -eq ".png" -or $_.Extension -eq ".svg"
    } | ForEach-Object {
        Remove-Item $_.FullName -Force
        $removed++
    }

    if ($removed -gt 0) {
        Write-Host "   Removed $removed rendered diagram(s)" -ForegroundColor Gray
        Write-Host "   (Run with -IncludeRenderedDiagrams to include them)`n" -ForegroundColor Gray
    } else {
        Write-Host "   No rendered diagrams found`n" -ForegroundColor Gray
    }
}

# Create README for the package
$packageReadme = @"
# Catalytic Computing Platform - Architecture Documentation Package

**Version**: 2.0
**Package Date**: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Status**: Production-Ready ✅

---

## Package Contents

This package contains the complete architecture documentation for the Catalytic Computing Platform.

### Files Included

- **Foundation Documents** (5 files):
  - ``00-executive-summary.md`` - Comprehensive platform overview
  - ``README-COMPREHENSIVE.md`` - Navigation guide
  - ``IMPLEMENTATION_STATUS.md`` - Completion tracking
  - ``INDEX.md`` - Complete file inventory
  - ``USAGE_GUIDE.md`` - Maintenance and usage instructions

- **C4 Model Diagrams**:
  - Level 1: System Context (3 files)
  - Level 2: Container Architecture (5 files)
  - Level 3: Component Architecture (6 files)
  - Level 4: Code Architecture (5 files)

- **Arc42 Template** (12 sections):
  - Complete architectural template covering all aspects

- **Architecture Decision Records**:
  - 15 ADRs + template (16 files total)
  - Documents all major technology and architecture decisions

- **Cross-Cutting Concerns** (3 files):
  - Security, Observability, Error Handling

- **Specialized Documentation**:
  - Deployment, Data, Integration architecture

- **Utilities**:
  - Diagram rendering scripts (PowerShell and Bash)
  - Print-friendly HTML summary
  - Batch printing launcher

---

## Getting Started

1. **First-Time Readers**: Start with ``README-COMPREHENSIVE.md``
2. **Executive Overview**: Read ``00-executive-summary.md``
3. **Find Specific Info**: Use ``INDEX.md`` for navigation
4. **Maintenance**: Review ``USAGE_GUIDE.md``

---

## Rendering Diagrams

PlantUML diagrams (.puml files) need to be rendered before viewing:

**Windows**:
``````powershell
.\render-diagrams.ps1
``````

**Linux/Mac**:
``````bash
./render-diagrams.sh
``````

See ``USAGE_GUIDE.md`` for detailed instructions.

---

## Documentation Frameworks Used

- **C4 Model**: 4-level architecture visualization
- **Arc42**: 12-section comprehensive template
- **ADRs**: Architecture decision records with rationale

---

## Key Metrics Documented

- 649x GPU speedup (CuPy over CPU)
- 99.29% success at 10,000 concurrent users
- <100ms p50 API latency
- 12 D3FEND security techniques implemented
- 7.24 TFLOPS sustained GPU performance

---

## Technology Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy
- **Database**: PostgreSQL 15 (RLS), Redis 7
- **GPU**: PyTorch 2.0+, CuPy 12.1, Numba, CUDA 12.1
- **Security**: HashiCorp Vault, JWT RS256, D3FEND
- **Infrastructure**: Kubernetes, Docker Compose, Prometheus, Grafana
- **Integrations**: Stripe, SendGrid, Ghidra

---

## Support

For questions or updates:
- Review ``USAGE_GUIDE.md`` for maintenance procedures
- Check ``INDEX.md`` for quick navigation
- Contact Architecture Team via internal channels

---

**Package Created**: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Total Files**: $(Get-ChildItem -Path $OutputDir -Recurse -File | Measure-Object).Count
**Package Size**: $([math]::Round((Get-ChildItem -Path $OutputDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB, 2)) MB
"@

$packageReadme | Out-File -FilePath "$OutputDir\README.md" -Encoding UTF8
Write-Host "📝 Created package README.md`n" -ForegroundColor Green

# Create manifest file
$manifestPath = "$OutputDir\MANIFEST.txt"
$manifest = @"
CATALYTIC COMPUTING PLATFORM - ARCHITECTURE DOCUMENTATION PACKAGE
================================================================

Package Version: 2.0
Creation Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Source Location: $ArchDir

FILE MANIFEST
=============

"@

$manifest | Out-File -FilePath $manifestPath -Encoding UTF8

Get-ChildItem -Path $OutputDir -Recurse -File | ForEach-Object {
    $relativePath = $_.FullName.Replace($OutputDir, "").TrimStart('\')
    $size = [math]::Round($_.Length / 1KB, 2)
    "$relativePath ($size KB)" | Out-File -FilePath $manifestPath -Append -Encoding UTF8
}

Write-Host "📋 Created manifest file: MANIFEST.txt`n" -ForegroundColor Green

# Generate package statistics
$stats = @{
    TotalFiles = (Get-ChildItem -Path $OutputDir -Recurse -File).Count
    TotalSize = [math]::Round((Get-ChildItem -Path $OutputDir -Recurse -File | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
    MarkdownFiles = (Get-ChildItem -Path $OutputDir -Recurse -Filter "*.md").Count
    PlantUMLFiles = (Get-ChildItem -Path $OutputDir -Recurse -Filter "*.puml").Count
    RenderedDiagrams = (Get-ChildItem -Path $OutputDir -Recurse -File | Where-Object { $_.Extension -eq ".png" -or $_.Extension -eq ".svg" }).Count
    Directories = (Get-ChildItem -Path $OutputDir -Recurse -Directory).Count
}

# Final summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Package Build Complete!" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "📊 Package Statistics:" -ForegroundColor Yellow
Write-Host "   Total Files: $($stats.TotalFiles)" -ForegroundColor Gray
Write-Host "   Markdown Files: $($stats.MarkdownFiles)" -ForegroundColor Gray
Write-Host "   PlantUML Diagrams: $($stats.PlantUMLFiles)" -ForegroundColor Gray
Write-Host "   Rendered Diagrams: $($stats.RenderedDiagrams)" -ForegroundColor Gray
Write-Host "   Directories: $($stats.Directories)" -ForegroundColor Gray
Write-Host "   Total Size: $($stats.TotalSize) MB`n" -ForegroundColor Gray

Write-Host "📁 Package Location: $OutputDir" -ForegroundColor Green
Write-Host "   - README.md (start here)" -ForegroundColor Gray
Write-Host "   - MANIFEST.txt (complete file listing)`n" -ForegroundColor Gray

# Suggest next steps
Write-Host "Next Steps:" -ForegroundColor Yellow

if ($stats.RenderedDiagrams -eq 0) {
    Write-Host "   1. Render diagrams: cd $OutputDir && .\render-diagrams.ps1" -ForegroundColor Gray
} else {
    Write-Host "   1. ✅ Diagrams already rendered ($($stats.RenderedDiagrams) files)" -ForegroundColor Green
}

Write-Host "   2. Review package: cd $OutputDir && code README.md" -ForegroundColor Gray
Write-Host "   3. Archive package: Compress-Archive -Path $OutputDir -DestinationPath architecture-docs-v2.0.zip" -ForegroundColor Gray
Write-Host "   4. Share or distribute the package as needed`n" -ForegroundColor Gray

Write-Host "✅ Package build complete!`n" -ForegroundColor Green
