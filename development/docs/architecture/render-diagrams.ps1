# Architecture Documentation - PlantUML Diagram Renderer
# Automatically renders all .puml diagrams to PNG and SVG formats

param(
    [switch]$PngOnly,
    [switch]$SvgOnly,
    [switch]$CheckOnly
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "PlantUML Diagram Rendering Automation" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if PlantUML is installed
$plantumlInstalled = $false
$plantumlPath = $null

# Check common locations
$commonPaths = @(
    "plantuml",
    "C:\Program Files\PlantUML\plantuml.jar",
    "C:\Tools\plantuml.jar",
    "$env:USERPROFILE\bin\plantuml.jar"
)

foreach ($path in $commonPaths) {
    if ($path -eq "plantuml") {
        $result = Get-Command plantuml -ErrorAction SilentlyContinue
        if ($result) {
            $plantumlInstalled = $true
            $plantumlPath = "plantuml"
            break
        }
    } elseif (Test-Path $path) {
        $plantumlInstalled = $true
        $plantumlPath = $path
        break
    }
}

if (-not $plantumlInstalled) {
    Write-Host "❌ PlantUML not found!`n" -ForegroundColor Red
    Write-Host "PlantUML Installation Options:`n" -ForegroundColor Yellow

    Write-Host "Option 1: Install via Chocolatey (Recommended)" -ForegroundColor Green
    Write-Host "  choco install plantuml`n" -ForegroundColor Gray

    Write-Host "Option 2: Install via Scoop" -ForegroundColor Green
    Write-Host "  scoop install plantuml`n" -ForegroundColor Gray

    Write-Host "Option 3: Download JAR manually" -ForegroundColor Green
    Write-Host "  1. Download from: https://plantuml.com/download" -ForegroundColor Gray
    Write-Host "  2. Save plantuml.jar to: C:\Tools\plantuml.jar" -ForegroundColor Gray
    Write-Host "  3. Run: java -jar C:\Tools\plantuml.jar`n" -ForegroundColor Gray

    Write-Host "After installation, run this script again.`n" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ PlantUML found: $plantumlPath`n" -ForegroundColor Green

# Find all .puml files
$pumlFiles = Get-ChildItem -Path . -Recurse -Filter "*.puml"
$fileCount = $pumlFiles.Count

Write-Host "Found $fileCount PlantUML diagram(s):`n" -ForegroundColor Cyan

$index = 1
foreach ($file in $pumlFiles) {
    $relativePath = $file.FullName.Replace((Get-Location).Path, "").TrimStart('\')
    Write-Host "  $index. $relativePath" -ForegroundColor Gray
    $index++
}
Write-Host ""

if ($CheckOnly) {
    Write-Host "✅ Check complete. PlantUML is installed and ready to render $fileCount diagrams.`n" -ForegroundColor Green
    exit 0
}

# Rendering function
function Render-Diagrams {
    param(
        [string]$Format,
        [array]$Files
    )

    Write-Host "Rendering to $Format format..." -ForegroundColor Yellow

    $successCount = 0
    $failCount = 0

    foreach ($file in $Files) {
        $relativePath = $file.FullName.Replace((Get-Location).Path, "").TrimStart('\')
        Write-Host "  Processing: $relativePath" -ForegroundColor Gray

        try {
            if ($plantumlPath -eq "plantuml") {
                # PlantUML is in PATH
                $output = & plantuml -t$Format $file.FullName 2>&1
            } else {
                # PlantUML is a JAR file
                $output = & java -jar $plantumlPath -t$Format $file.FullName 2>&1
            }

            if ($LASTEXITCODE -eq 0) {
                Write-Host "    ✅ Rendered to $($file.DirectoryName)\$($file.BaseName).$Format" -ForegroundColor Green
                $successCount++
            } else {
                Write-Host "    ❌ Failed: $output" -ForegroundColor Red
                $failCount++
            }
        } catch {
            Write-Host "    ❌ Error: $_" -ForegroundColor Red
            $failCount++
        }
    }

    Write-Host "`n  Summary: $successCount/$fileCount diagrams rendered successfully" -ForegroundColor Cyan
    if ($failCount -gt 0) {
        Write-Host "  Failures: $failCount" -ForegroundColor Red
    }
    Write-Host ""

    return $successCount
}

# Render diagrams based on parameters
$totalSuccess = 0

if (-not $SvgOnly) {
    Write-Host "`n--- Rendering PNG (for presentations) ---`n" -ForegroundColor Cyan
    $totalSuccess += Render-Diagrams -Format "png" -Files $pumlFiles
}

if (-not $PngOnly) {
    Write-Host "`n--- Rendering SVG (for documentation) ---`n" -ForegroundColor Cyan
    $totalSuccess += Render-Diagrams -Format "svg" -Files $pumlFiles
}

# Final summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Rendering Complete!" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Diagrams rendered: $totalSuccess" -ForegroundColor Green
Write-Host "Output locations:" -ForegroundColor Yellow

foreach ($file in $pumlFiles) {
    $dir = $file.DirectoryName
    $base = $file.BaseName

    if (-not $SvgOnly -and (Test-Path "$dir\$base.png")) {
        Write-Host "  📄 $dir\$base.png" -ForegroundColor Gray
    }
    if (-not $PngOnly -and (Test-Path "$dir\$base.svg")) {
        Write-Host "  📄 $dir\$base.svg" -ForegroundColor Gray
    }
}

Write-Host "`nNext steps:" -ForegroundColor Yellow
Write-Host "  1. Review rendered diagrams in their respective directories" -ForegroundColor Gray
Write-Host "  2. Embed diagrams in documentation using markdown:" -ForegroundColor Gray
Write-Host "     ![Diagram Title](./path/to/diagram.svg)" -ForegroundColor DarkGray
Write-Host "  3. Commit both .puml source and rendered images to version control`n" -ForegroundColor Gray

Write-Host "✅ All done!`n" -ForegroundColor Green
