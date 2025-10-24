# SaaS Platform Load Testing Runner
# PowerShell script to execute comprehensive load tests

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("1k", "10k", "both", "baseline")]
    [string]$TestType = "both",

    [Parameter(Mandatory=$false)]
    [string]$Host = "http://localhost:8000",

    [Parameter(Mandatory=$false)]
    [int]$Duration = 5
)

$ErrorActionPreference = "Stop"

# Colors for output
function Write-Header {
    param([string]$Message)
    Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Yellow
    Write-Host "$('=' * 80)`n" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Blue
}

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

Write-Header "SaaS Platform Load Testing - Pre-Flight Checks"

# Check if Locust is installed
Write-Info "Checking Locust installation..."
try {
    $locustVersion = python -m locust --version 2>&1
    if ($locustVersion -match "locust") {
        Write-Success "Locust is installed: $($locustVersion -replace '\n','')"
    } else {
        throw "Locust check failed"
    }
} catch {
    Write-Error "Locust is not installed!"
    Write-Info "Install with: pip install locust"
    exit 1
}

# Check if API server is running
Write-Info "Checking if SaaS API server is running on $Host..."
try {
    $response = Invoke-WebRequest -Uri "$Host/health" -Method GET -TimeoutSec 5 -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Success "API server is running and healthy"
    } else {
        throw "Health check returned $($response.StatusCode)"
    }
} catch {
    Write-Error "API server is not accessible at $Host"
    Write-Info "Start the server first:"
    Write-Info "  cd saas"
    Write-Info "  python -m uvicorn api.saas_server:app --host 0.0.0.0 --port 8000"
    Write-Warning "Continuing anyway - tests will fail if server isn't running..."
}

# Change to tests/performance directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$testDir = Join-Path $scriptPath "tests\performance"

if (Test-Path $testDir) {
    Set-Location $testDir
    Write-Success "Changed to test directory: $testDir"
} else {
    Write-Error "Test directory not found: $testDir"
    exit 1
}

# Check if locustfile exists
if (-not (Test-Path "locustfile.py")) {
    Write-Error "locustfile.py not found in current directory!"
    exit 1
}

# ============================================================================
# RUN TESTS
# ============================================================================

function Run-LoadTest {
    param(
        [string]$TestName,
        [int]$Users,
        [int]$SpawnRate,
        [int]$RunTime,
        [string]$Host
    )

    Write-Header "Running $TestName"
    Write-Info "Users: $Users | Spawn Rate: $SpawnRate/sec | Duration: $RunTime min | Host: $Host"

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportName = "loadtest_${TestName}_${timestamp}"

    # Run Locust in headless mode
    Write-Info "Starting Locust..."
    Write-Info "Command: locust -f locustfile.py --users $Users --spawn-rate $SpawnRate --run-time ${RunTime}m --host $Host --html ${reportName}.html --csv ${reportName}"

    python -m locust `
        -f locustfile.py `
        --users $Users `
        --spawn-rate $SpawnRate `
        --run-time "${RunTime}m" `
        --host $Host `
        --headless `
        --html "${reportName}.html" `
        --csv "${reportName}" `
        --loglevel INFO

    if ($LASTEXITCODE -eq 0) {
        Write-Success "$TestName completed successfully!"
        Write-Info "HTML Report: ${testDir}\${reportName}.html"
        Write-Info "CSV Data: ${testDir}\${reportName}_stats.csv"
    } else {
        Write-Error "$TestName failed with exit code $LASTEXITCODE"
    }

    # Brief pause between tests
    if ($TestType -eq "both") {
        Write-Info "Waiting 30 seconds before next test..."
        Start-Sleep -Seconds 30
    }
}

# ============================================================================
# EXECUTE TESTS BASED ON TYPE
# ============================================================================

switch ($TestType) {
    "baseline" {
        Write-Header "Running Baseline Test (100 users)"
        Run-LoadTest -TestName "baseline_100users" -Users 100 -SpawnRate 20 -RunTime 2 -Host $Host
    }

    "1k" {
        Write-Header "Running 1K Users Test"
        Run-LoadTest -TestName "1k_users" -Users 1000 -SpawnRate 100 -RunTime $Duration -Host $Host
    }

    "10k" {
        Write-Header "Running 10K Users Test"
        Run-LoadTest -TestName "10k_users" -Users 10000 -SpawnRate 200 -RunTime $Duration -Host $Host
    }

    "both" {
        Write-Header "Running Complete Load Test Suite"

        # Baseline test
        Run-LoadTest -TestName "baseline_100users" -Users 100 -SpawnRate 20 -RunTime 2 -Host $Host

        # 1K users test
        Run-LoadTest -TestName "1k_users" -Users 1000 -SpawnRate 100 -RunTime $Duration -Host $Host

        # 10K users test
        Run-LoadTest -TestName "10k_users" -Users 10000 -SpawnRate 200 -RunTime $Duration -Host $Host
    }
}

# ============================================================================
# SUMMARY
# ============================================================================

Write-Header "Load Testing Complete!"

Write-Info "Test reports saved in: $testDir"
Write-Info ""
Write-Info "Next steps:"
Write-Info "  1. Review HTML reports for detailed metrics"
Write-Info "  2. Check that P95 response time < 200ms"
Write-Info "  3. Verify success rate > 99%"
Write-Info "  4. Look for connection pool exhaustion errors"
Write-Info "  5. If all pass → proceed to staging deployment!"
Write-Info ""

# Open the latest HTML report in browser
$latestReport = Get-ChildItem -Path $testDir -Filter "loadtest_*.html" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latestReport) {
    Write-Info "Opening latest report in browser..."
    Start-Process $latestReport.FullName
}

Write-Success "Load testing session complete!"
