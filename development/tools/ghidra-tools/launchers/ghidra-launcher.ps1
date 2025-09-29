# Ghidra PowerShell Launcher
# Robust launcher that bypasses console redirection issues

param(
    [string]$GhidraPath = "C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC"
)

Write-Host "Ghidra PowerShell Launcher" -ForegroundColor Green
Write-Host "=========================" -ForegroundColor Green

# Verify Ghidra installation
if (-not (Test-Path $GhidraPath)) {
    Write-Host "ERROR: Ghidra not found at: $GhidraPath" -ForegroundColor Red
    exit 1
}

$ghidraRunPath = Join-Path $GhidraPath "ghidraRun.bat"
if (-not (Test-Path $ghidraRunPath)) {
    Write-Host "ERROR: ghidraRun.bat not found at: $ghidraRunPath" -ForegroundColor Red
    exit 1
}

Write-Host "Found Ghidra at: $GhidraPath" -ForegroundColor Green

# Check Java
try {
    $javaVersion = & java -version 2>&1 | Select-String "version"
    Write-Host "Java found: $($javaVersion -replace '.*"([^"]+)".*', '$1')" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Java not found in PATH" -ForegroundColor Red
    exit 1
}

# Launch Ghidra in background process with proper console handling
Write-Host "Launching Ghidra in background process..." -ForegroundColor Yellow

try {
    # Method 1: Start-Process with WindowStyle Hidden then Normal
    $process = Start-Process -FilePath $ghidraRunPath -WorkingDirectory $GhidraPath -PassThru -WindowStyle Normal

    if ($process) {
        Write-Host "Ghidra launched successfully!" -ForegroundColor Green
        Write-Host "Process ID: $($process.Id)" -ForegroundColor Cyan

        # Wait a moment to see if process starts properly
        Start-Sleep -Seconds 3

        if (-not $process.HasExited) {
            Write-Host "Ghidra is starting up..." -ForegroundColor Green
            Write-Host "You can now configure extensions via File -> Configure -> Extensions" -ForegroundColor Yellow
        } else {
            Write-Host "WARNING: Ghidra process exited quickly. Exit code: $($process.ExitCode)" -ForegroundColor Yellow
        }
    } else {
        throw "Failed to start process"
    }
} catch {
    Write-Host "ERROR launching Ghidra: $($_.Exception.Message)" -ForegroundColor Red

    # Fallback method: Use cmd /c with detached process
    Write-Host "Trying alternative launch method..." -ForegroundColor Yellow

    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = "cmd.exe"
        $startInfo.Arguments = "/c `"cd /d `"$GhidraPath`" && ghidraRun.bat`""
        $startInfo.UseShellExecute = $true
        $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal

        $process = [System.Diagnostics.Process]::Start($startInfo)

        if ($process) {
            Write-Host "Ghidra launched using fallback method!" -ForegroundColor Green
            Write-Host "Process ID: $($process.Id)" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "ERROR: All launch methods failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Manual Launch Instructions:" -ForegroundColor Yellow
        Write-Host "1. Open Windows Explorer" -ForegroundColor White
        Write-Host "2. Navigate to: $GhidraPath" -ForegroundColor White
        Write-Host "3. Double-click on ghidraRun.bat" -ForegroundColor White
        exit 1
    }
}

Write-Host ""
Write-Host "Launcher complete. Ghidra should be starting..." -ForegroundColor Green