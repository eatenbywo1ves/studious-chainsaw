# Print Architecture Documentation
# Converts markdown to PDF and sends to printer

param(
    [switch]$ConvertOnly,  # Just convert to PDF, don't print
    [switch]$PrintAll,     # Print all documents
    [switch]$PrintSummary, # Print executive summary only
    [string]$PrinterName   # Specific printer name
)

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Architecture Documentation Printer" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

$baseDir = $PSScriptRoot
$outputDir = "$baseDir\pdf-output"

# Create output directory
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    Write-Host "Created output directory: $outputDir" -ForegroundColor Green
}

# Check for available converters
$pandocInstalled = Get-Command pandoc -ErrorAction SilentlyContinue
$markdownPdfInstalled = Get-Command markdown-pdf -ErrorAction SilentlyContinue

if (-not $pandocInstalled -and -not $markdownPdfInstalled) {
    Write-Host "No markdown-to-PDF converter found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install one of the following:" -ForegroundColor Yellow
    Write-Host "1. Pandoc (recommended):" -ForegroundColor White
    Write-Host "   choco install pandoc" -ForegroundColor Gray
    Write-Host "   - or -" -ForegroundColor Gray
    Write-Host "   Download from: https://pandoc.org/installing.html" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. markdown-pdf (Node.js):" -ForegroundColor White
    Write-Host "   npm install -g markdown-pdf" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Alternative: Use browser method (see below)" -ForegroundColor Yellow
    Write-Host ""

    # Offer browser-based alternative
    Write-Host "=== BROWSER-BASED PRINTING (NO INSTALL NEEDED) ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Install VS Code extension 'Markdown PDF' by yzane" -ForegroundColor White
    Write-Host "2. Open each .md file in VS Code" -ForegroundColor White
    Write-Host "3. Press Ctrl+Shift+P" -ForegroundColor White
    Write-Host "4. Type 'Markdown PDF: Export (pdf)' and press Enter" -ForegroundColor White
    Write-Host "5. PDF will be created in the same folder" -ForegroundColor White
    Write-Host ""
    Write-Host "OR use Chrome/Edge:" -ForegroundColor Yellow
    Write-Host "1. Install 'Markdown Viewer' browser extension" -ForegroundColor White
    Write-Host "2. Open .md files in browser (file:///path/to/file.md)" -ForegroundColor White
    Write-Host "3. Press Ctrl+P to print/save as PDF" -ForegroundColor White
    Write-Host ""

    exit 1
}

# Function to convert markdown to PDF using pandoc
function Convert-MarkdownToPDF {
    param(
        [string]$MarkdownFile,
        [string]$OutputPdf
    )

    Write-Host "Converting: $(Split-Path $MarkdownFile -Leaf)" -ForegroundColor White

    if ($pandocInstalled) {
        # Pandoc with nice formatting
        pandoc $MarkdownFile -o $OutputPdf `
            --pdf-engine=xelatex `
            -V geometry:margin=1in `
            -V fontsize=11pt `
            -V colorlinks=true `
            --toc `
            --toc-depth=3 `
            2>$null

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Created: $(Split-Path $OutputPdf -Leaf)" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ⚠ Warning: PDF conversion had issues, trying simpler method..." -ForegroundColor Yellow
            # Try without XeLaTeX
            pandoc $MarkdownFile -o $OutputPdf `
                -V geometry:margin=1in `
                --toc `
                2>$null

            if ($LASTEXITCODE -eq 0) {
                Write-Host "  ✓ Created: $(Split-Path $OutputPdf -Leaf)" -ForegroundColor Green
                return $true
            }
        }
    } elseif ($markdownPdfInstalled) {
        markdown-pdf $MarkdownFile -o $OutputPdf

        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Created: $(Split-Path $OutputPdf -Leaf)" -ForegroundColor Green
            return $true
        }
    }

    Write-Host "  ✗ Failed to convert" -ForegroundColor Red
    return $false
}

# Documents to convert/print
$documents = @()

if ($PrintSummary) {
    Write-Host "Converting Executive Summary only..." -ForegroundColor Yellow
    $documents = @(
        @{
            Name = "Executive Summary"
            Source = "$baseDir\00-executive-summary.md"
            Output = "$outputDir\00-executive-summary.pdf"
        }
    )
} elseif ($PrintAll) {
    Write-Host "Converting ALL documentation files..." -ForegroundColor Yellow
    $documents = @(
        @{Name = "Executive Summary"; Source = "$baseDir\00-executive-summary.md"; Output = "$outputDir\00-executive-summary.pdf"},
        @{Name = "Master README"; Source = "$baseDir\README-COMPREHENSIVE.md"; Output = "$outputDir\README-COMPREHENSIVE.pdf"},
        @{Name = "Implementation Status"; Source = "$baseDir\IMPLEMENTATION_STATUS.md"; Output = "$outputDir\IMPLEMENTATION_STATUS.pdf"},
        @{Name = "System Context"; Source = "$baseDir\01-system-context\system-context.md"; Output = "$outputDir\01-system-context.pdf"},
        @{Name = "Stakeholders"; Source = "$baseDir\01-system-context\stakeholders.md"; Output = "$outputDir\02-stakeholders.pdf"},
        @{Name = "ADR Template"; Source = "$baseDir\10-adrs\template.md"; Output = "$outputDir\ADR-template.pdf"},
        @{Name = "ADR-001 FastAPI"; Source = "$baseDir\10-adrs\001-fastapi-over-flask.md"; Output = "$outputDir\ADR-001-fastapi.pdf"}
    )
} else {
    # Default: Print key documents
    Write-Host "Converting key documents (Executive Summary + System Context)..." -ForegroundColor Yellow
    $documents = @(
        @{Name = "Executive Summary"; Source = "$baseDir\00-executive-summary.md"; Output = "$outputDir\00-executive-summary.pdf"},
        @{Name = "System Context"; Source = "$baseDir\01-system-context\system-context.md"; Output = "$outputDir\01-system-context.pdf"},
        @{Name = "Implementation Status"; Source = "$baseDir\IMPLEMENTATION_STATUS.md"; Output = "$outputDir\IMPLEMENTATION_STATUS.pdf"}
    )
}

Write-Host ""

# Convert all documents
$convertedPdfs = @()
foreach ($doc in $documents) {
    if (Test-Path $doc.Source) {
        $success = Convert-MarkdownToPDF -MarkdownFile $doc.Source -OutputPdf $doc.Output
        if ($success) {
            $convertedPdfs += $doc.Output
        }
    } else {
        Write-Host "  ⚠ Skipped: $($doc.Name) (file not found)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Conversion Summary" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "PDFs created: $($convertedPdfs.Count)" -ForegroundColor Green
Write-Host "Output directory: $outputDir" -ForegroundColor White
Write-Host ""

if ($convertedPdfs.Count -eq 0) {
    Write-Host "No PDFs were created. Exiting." -ForegroundColor Red
    exit 1
}

# List created PDFs
Write-Host "Created PDFs:" -ForegroundColor Yellow
foreach ($pdf in $convertedPdfs) {
    $fileInfo = Get-Item $pdf
    Write-Host "  - $(Split-Path $pdf -Leaf) ($([math]::Round($fileInfo.Length / 1KB, 1)) KB)" -ForegroundColor White
}
Write-Host ""

if ($ConvertOnly) {
    Write-Host "Conversion complete! (Print skipped - use -PrintAll to print)" -ForegroundColor Green
    Write-Host "PDFs are ready in: $outputDir" -ForegroundColor White
    explorer $outputDir
    exit 0
}

# Print the PDFs
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Printing PDFs" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Get default printer or use specified one
if ($PrinterName) {
    $printer = Get-Printer | Where-Object {$_.Name -eq $PrinterName} | Select-Object -First 1
} else {
    $printer = Get-Printer | Where-Object {$_.Default -eq $true} | Select-Object -First 1
}

if (-not $printer) {
    Write-Host "No printer found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Available printers:" -ForegroundColor Yellow
    Get-Printer | ForEach-Object {
        $defaultMark = if ($_.Default) { " (DEFAULT)" } else { "" }
        Write-Host "  - $($_.Name)$defaultMark" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "To specify a printer, use:" -ForegroundColor Yellow
    Write-Host "  .\print-docs.ps1 -PrinterName 'Printer Name Here'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "PDFs are ready in: $outputDir" -ForegroundColor White
    Write-Host "You can print them manually." -ForegroundColor White
    explorer $outputDir
    exit 1
}

Write-Host "Using printer: $($printer.Name)" -ForegroundColor Green
Write-Host ""

foreach ($pdf in $convertedPdfs) {
    Write-Host "Printing: $(Split-Path $pdf -Leaf)" -ForegroundColor White

    try {
        # Print the PDF
        Start-Process -FilePath $pdf -Verb Print -PassThru | Out-Null
        Start-Sleep -Seconds 2  # Wait for print dialog
        Write-Host "  ✓ Sent to printer" -ForegroundColor Green
    } catch {
        Write-Host "  ✗ Failed to print: $_" -ForegroundColor Red
        Write-Host "  → You can manually print from: $pdf" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Printing Complete!" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: PDF files are saved in: $outputDir" -ForegroundColor White
Write-Host "You can print them again manually if needed." -ForegroundColor White
Write-Host ""

# Open the folder for manual inspection
explorer $outputDir
