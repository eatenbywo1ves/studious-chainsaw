# PowerShell script to validate Ghidra extensions
param(
    [string]$BuildDir = "build\catalytic-ghidra-extensions"
)

Write-Host "Catalytic Computing - Extension Validation Suite" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

$ValidationResults = @{}
$TotalTests = 0
$PassedTests = 0

function Test-ExtensionPackage {
    param(
        [string]$ExtensionName,
        [string]$ZipPath
    )
    
    Write-Host "Validating $ExtensionName..." -ForegroundColor Yellow
    $TestResults = @{}
    
    # Test 1: ZIP file exists and is not empty
    $TestResults['ZIP_EXISTS'] = Test-Path $ZipPath
    if ($TestResults['ZIP_EXISTS']) {
        $ZipSize = (Get-Item $ZipPath).Length
        $TestResults['ZIP_NOT_EMPTY'] = $ZipSize -gt 1024  # At least 1KB
        $TestResults['ZIP_SIZE_MB'] = [math]::Round($ZipSize / 1MB, 2)
    } else {
        $TestResults['ZIP_NOT_EMPTY'] = $false
        $TestResults['ZIP_SIZE_MB'] = 0
    }
    
    # Test 2: ZIP can be opened and contains expected structure
    if ($TestResults['ZIP_EXISTS']) {
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $Zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
            
            $TestResults['STRUCTURE_VALID'] = $true
            $TestResults['ENTRY_COUNT'] = $Zip.Entries.Count
            $Zip.Dispose()
        } catch {
            $TestResults['STRUCTURE_VALID'] = $false
            $TestResults['ENTRY_COUNT'] = 0
            Write-Host "  Error reading ZIP: $_" -ForegroundColor Red
        }
    } else {
        $TestResults['STRUCTURE_VALID'] = $false
        $TestResults['ENTRY_COUNT'] = 0
    }
    
    return $TestResults
}

function Show-TestResult {
    param(
        [string]$TestName,
        [bool]$Result,
        [string]$Details = ""
    )
    
    $script:TotalTests++
    if ($Result) {
        $script:PassedTests++
        Write-Host "  PASS: $TestName" -ForegroundColor Green
        if ($Details) { Write-Host "    $Details" -ForegroundColor Gray }
    } else {
        Write-Host "  FAIL: $TestName" -ForegroundColor Red
        if ($Details) { Write-Host "    $Details" -ForegroundColor Gray }
    }
}

# Check if build directory exists
if (-not (Test-Path $BuildDir)) {
    Write-Host "ERROR: Build directory not found: $BuildDir" -ForegroundColor Red
    Write-Host "Please run the build script first." -ForegroundColor Yellow
    exit 1
}

$DistDir = Join-Path $BuildDir "dist"
$DocsDir = Join-Path $BuildDir "docs"

Write-Host "Build directory: $BuildDir" -ForegroundColor Green
Write-Host "Distribution directory: $DistDir" -ForegroundColor Green
Write-Host "Documentation directory: $DocsDir" -ForegroundColor Green
Write-Host ""

# Test each extension
$Extensions = @('GhidraCtrlP', 'GhidraLookup', 'GhidrAssist', 'Ghidrathon')

foreach ($Extension in $Extensions) {
    $ExtensionDir = Join-Path $DistDir $Extension
    $ZipFiles = Get-ChildItem -Path $ExtensionDir -Filter "*.zip" -ErrorAction SilentlyContinue
    
    if ($ZipFiles) {
        $ZipPath = $ZipFiles[0].FullName
        $Results = Test-ExtensionPackage -ExtensionName $Extension -ZipPath $ZipPath
        
        Show-TestResult "ZIP file exists" $Results['ZIP_EXISTS']
        Show-TestResult "ZIP file not empty" $Results['ZIP_NOT_EMPTY'] "Size: $($Results['ZIP_SIZE_MB']) MB"
        Show-TestResult "ZIP structure valid" $Results['STRUCTURE_VALID'] "Entries: $($Results['ENTRY_COUNT'])"
        
        $ValidationResults[$Extension] = $Results
    } else {
        Write-Host "$Extension - NO ZIP FILE FOUND" -ForegroundColor Red
        Show-TestResult "ZIP file exists" $false
        Show-TestResult "ZIP file not empty" $false
        Show-TestResult "ZIP structure valid" $false
    }
    
    Write-Host ""
}

# Test documentation
Write-Host "Validating Documentation..." -ForegroundColor Yellow
$RequiredDocs = @('README.md', 'INSTALLATION_GUIDE.md')

foreach ($Doc in $RequiredDocs) {
    $DocPath = Join-Path $DocsDir $Doc
    $Exists = Test-Path $DocPath
    Show-TestResult "Documentation $Doc exists" $Exists
    
    if ($Exists) {
        $Content = Get-Content $DocPath -Raw
        $NotEmpty = $Content.Length -gt 100
        Show-TestResult "Documentation $Doc not empty" $NotEmpty "Size: $($Content.Length) chars"
    }
}

Write-Host ""

# Test master package
$MasterZip = "build\CatalyticComputing-GhidraExtensions-1.0.0.zip"
if (Test-Path $MasterZip) {
    $MasterSize = [math]::Round((Get-Item $MasterZip).Length / 1MB, 2)
    Show-TestResult "Master package exists" $true "Size: $MasterSize MB"
    Show-TestResult "Master package reasonable size" ($MasterSize -gt 10 -and $MasterSize -lt 100) "Expected: 10-100 MB"
} else {
    Show-TestResult "Master package exists" $false
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "VALIDATION SUMMARY" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

$PassPercentage = [math]::Round(($PassedTests / $TotalTests) * 100, 1)
$PercentageString = $PassPercentage.ToString() + "%"
Write-Host "Tests Passed: $PassedTests / $TotalTests ($PercentageString)"

if ($PassPercentage -eq 100) {
    Write-Host "ALL TESTS PASSED! Extensions are ready for deployment." -ForegroundColor Green
} elseif ($PassPercentage -ge 90) {
    Write-Host "Most tests passed. Minor issues detected." -ForegroundColor Yellow
} elseif ($PassPercentage -ge 70) {
    Write-Host "Some tests failed. Review issues before deployment." -ForegroundColor Yellow
} else {
    Write-Host "Multiple test failures. Extensions need attention." -ForegroundColor Red
}

Write-Host ""

# Generate validation report
$ReportPath = "build\validation-report.json"
$ValidationReport = @{
    'timestamp' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    'total_tests' = $TotalTests
    'passed_tests' = $PassedTests
    'pass_percentage' = $PassPercentage
    'extensions' = $ValidationResults
}

$ValidationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Validation report saved: $ReportPath" -ForegroundColor Green

# Exit with appropriate code
if ($PassPercentage -lt 70) {
    exit 1
} else {
    exit 0
}