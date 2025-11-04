# DEPLOYMENT TEST VALIDATION RUNNER
# PowerShell script to execute comprehensive test suite

Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      DEPLOYMENT TEST VALIDATION - COMPREHENSIVE SUITE         ║" -ForegroundColor Cyan
Write-Host "║      Security Fixes (SEC-009 to SEC-012) Validation           ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Change to script directory
Set-Location $PSScriptRoot

Write-Host "Working Directory: $(Get-Location)" -ForegroundColor Yellow
Write-Host "Python Version:" -ForegroundColor Yellow
python --version
Write-Host ""

# Check if pytest is available
Write-Host "Checking dependencies..." -ForegroundColor Yellow
try {
    python -m pytest --version | Out-Null
    Write-Host "✓ pytest found`n" -ForegroundColor Green
} catch {
    Write-Host "Installing test dependencies..." -ForegroundColor Yellow
    pip install -r requirements-test.txt
}

$results = @{}

# Function to run pytest
function Run-PytestPhase {
    param (
        [string]$PhaseName,
        [string[]]$Args
    )

    Write-Host "`n$('='*80)" -ForegroundColor Cyan
    Write-Host "  $PhaseName" -ForegroundColor Cyan
    Write-Host "$('='*80)`n" -ForegroundColor Cyan

    Write-Host "Command: python -m pytest $($Args -join ' ')`n" -ForegroundColor Gray

    python -m pytest @Args

    $success = $LASTEXITCODE -eq 0
    $results[$PhaseName] = $success

    if ($success) {
        Write-Host "`n✅ $PhaseName - PASSED`n" -ForegroundColor Green
    } else {
        Write-Host "`n❌ $PhaseName - FAILED`n" -ForegroundColor Red
    }

    return $success
}

# PHASE 1: Unit Tests
Run-PytestPhase -PhaseName "PHASE 1: Unit Tests (Mocked Dependencies)" `
    -Args @("tests/unit/", "-v", "--tb=short")

# PHASE 2: Integration Tests
Run-PytestPhase -PhaseName "PHASE 2: Integration Tests (Real Redis Required)" `
    -Args @("tests/integration/", "-v", "--tb=short")

# PHASE 3: Security Tests
Run-PytestPhase -PhaseName "PHASE 3: Security Tests (SEC-009 to SEC-012)" `
    -Args @("-m", "security", "-v", "--tb=short")

# PHASE 4: Race Condition Tests
Run-PytestPhase -PhaseName "PHASE 4: Race Condition Tests (CRITICAL)" `
    -Args @("-m", "race_condition", "-v", "-s")

# PHASE 5: Coverage Analysis
Run-PytestPhase -PhaseName "PHASE 5: Coverage Analysis (Target: >80%)" `
    -Args @(
        "tests/",
        "--cov=auth",
        "--cov=api",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "--cov-fail-under=80"
    )

# Generate Summary
Write-Host "`n$('='*80)" -ForegroundColor Cyan
Write-Host "  TEST EXECUTION SUMMARY" -ForegroundColor Cyan
Write-Host "$('='*80)`n" -ForegroundColor Cyan

Write-Host "Results by Phase:" -ForegroundColor Yellow
foreach ($phase in $results.Keys | Sort-Object) {
    $status = if ($results[$phase]) { "PASS" } else { "FAIL" }
    $symbol = if ($results[$phase]) { "✅" } else { "❌" }
    $color = if ($results[$phase]) { "Green" } else { "Red" }
    Write-Host "  $symbol $($phase.PadRight(50)): $status" -ForegroundColor $color
}

$total = $results.Count
$passed = ($results.Values | Where-Object { $_ -eq $true }).Count
$failed = $total - $passed

Write-Host "`n$('='*80)" -ForegroundColor Cyan
Write-Host "Total Phases: $total" -ForegroundColor Yellow
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "$('='*80)`n" -ForegroundColor Cyan

if ($failed -eq 0) {
    Write-Host "✅ ALL TESTS PASSED - READY FOR DEPLOYMENT`n" -ForegroundColor Green
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Review coverage report: open htmlcov/index.html"
    Write-Host "  2. Create deployment commit"
    Write-Host "  3. Deploy to staging environment`n"
    exit 0
} else {
    Write-Host "❌ $failed PHASE(S) FAILED - DEPLOYMENT BLOCKED`n" -ForegroundColor Red
    Write-Host "Required Actions:" -ForegroundColor Yellow
    Write-Host "  1. Review test failures above"
    Write-Host "  2. Fix failing tests"
    Write-Host "  3. Re-run validation: .\run_tests.ps1`n"
    exit 1
}
