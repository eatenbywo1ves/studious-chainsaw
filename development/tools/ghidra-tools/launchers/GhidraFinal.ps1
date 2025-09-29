# Final Ghidra Launcher - Let LaunchSupport do its job
# This approach trusts LaunchSupport.jar to handle classpath and class loading

param(
    [string]$GhidraPath = "C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC",
    [string]$MaxMemory = "4G"
)

Write-Host "Final Ghidra Launcher - Console Safe Edition" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green

# Verify installation
if (-not (Test-Path $GhidraPath)) {
    Write-Host "ERROR: Ghidra not found at: $GhidraPath" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$supportJar = Join-Path $GhidraPath "support\LaunchSupport.jar"
if (-not (Test-Path $supportJar)) {
    Write-Host "ERROR: LaunchSupport.jar not found" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Ghidra: $GhidraPath" -ForegroundColor Cyan
Write-Host "Memory: $MaxMemory" -ForegroundColor Cyan

# Verify Java
try {
    $javaVersion = & java -version 2>&1 | Select-String "version"
    Write-Host "Java: $($javaVersion -replace '.*"([^"]+)".*', '$1')" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Java not found" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Starting Ghidra using LaunchSupport..." -ForegroundColor Yellow

# Simple approach - let LaunchSupport handle everything
$javaArgs = @(
    "-cp", $supportJar,
    "-Xmx$MaxMemory",
    "LaunchSupport",
    "`"$GhidraPath`"",
    "ghidra.GhidraRun"
)

try {
    # Use Start-Process with proper console handling
    $process = Start-Process -FilePath "java" -ArgumentList $javaArgs -WorkingDirectory $GhidraPath -PassThru -WindowStyle Normal

    if ($process) {
        Write-Host "Process started: PID $($process.Id)" -ForegroundColor Green

        # Monitor startup
        Write-Host "Monitoring startup (20 seconds)..." -ForegroundColor Yellow

        for ($i = 1; $i -le 10; $i++) {
            Start-Sleep -Seconds 2

            if ($process.HasExited) {
                Write-Host "Process exited with code: $($process.ExitCode)" -ForegroundColor Red
                break
            }

            Write-Host "Check $i/10 - Still running..." -ForegroundColor Green
        }

        if (-not $process.HasExited) {
            Write-Host ""
            Write-Host "SUCCESS! Ghidra is running!" -ForegroundColor Green
            Write-Host "Look for the Ghidra window - it may take additional time to appear" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Next steps:" -ForegroundColor Cyan
            Write-Host "1. Wait for Ghidra GUI to appear (30-60 seconds)" -ForegroundColor White
            Write-Host "2. Go to File -> Configure -> Extensions" -ForegroundColor White
            Write-Host "3. Enable CryptoDetect and RetSync extensions" -ForegroundColor White
            Write-Host "4. Restart Ghidra to activate extensions" -ForegroundColor White
        } else {
            Write-Host "Launch attempt failed." -ForegroundColor Red
            Write-Host ""
            Write-Host "Alternative: Try manual Windows launch:" -ForegroundColor Yellow
            Write-Host "1. Open Windows Explorer" -ForegroundColor White
            Write-Host "2. Navigate to: $GhidraPath" -ForegroundColor White
            Write-Host "3. Double-click ghidraRun.bat directly" -ForegroundColor White
        }
    }

} catch {
    Write-Host "Launch error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Launcher complete." -ForegroundColor Green
Read-Host "Press Enter to exit"