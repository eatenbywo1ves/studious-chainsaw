# Direct JVM Ghidra Launcher
# Bypasses batch files to launch Ghidra directly via Java

param(
    [string]$GhidraPath = "C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC",
    [string]$MaxMemory = "4G"
)

Write-Host "Direct JVM Ghidra Launcher" -ForegroundColor Green
Write-Host "==========================" -ForegroundColor Green

# Verify installation
if (-not (Test-Path $GhidraPath)) {
    Write-Host "ERROR: Ghidra not found at: $GhidraPath" -ForegroundColor Red
    exit 1
}

$launchSupportJar = Join-Path $GhidraPath "support\LaunchSupport.jar"
if (-not (Test-Path $launchSupportJar)) {
    Write-Host "ERROR: LaunchSupport.jar not found" -ForegroundColor Red
    exit 1
}

Write-Host "Ghidra Installation: $GhidraPath" -ForegroundColor Green
Write-Host "Max Memory: $MaxMemory" -ForegroundColor Green

# Build classpath for LaunchSupport
$classpath = $launchSupportJar

# Check Java
try {
    $javaVersion = & java -version 2>&1 | Select-String "version"
    Write-Host "Java: $($javaVersion -replace '.*"([^"]+)".*', '$1')" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Java not found in PATH" -ForegroundColor Red
    exit 1
}

# Prepare Java arguments
$javaArgs = @(
    "-cp", $classpath,
    "-Xmx$MaxMemory",
    "-Dghidra.install.dir=`"$GhidraPath`"",
    "-Duser.dir=`"$GhidraPath`"",
    "LaunchSupport",
    "$GhidraPath",
    "ghidra.GhidraRun"
)

Write-Host "Launching Ghidra directly via JVM..." -ForegroundColor Yellow
Write-Host "Command: java $($javaArgs -join ' ')" -ForegroundColor Cyan

try {
    # Create process with proper working directory
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = "java"
    $startInfo.Arguments = $javaArgs -join " "
    $startInfo.WorkingDirectory = $GhidraPath
    $startInfo.UseShellExecute = $true
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal

    $process = [System.Diagnostics.Process]::Start($startInfo)

    if ($process) {
        Write-Host "Ghidra launched successfully!" -ForegroundColor Green
        Write-Host "Process ID: $($process.Id)" -ForegroundColor Cyan

        # Monitor process for a few seconds
        Start-Sleep -Seconds 5

        if (-not $process.HasExited) {
            Write-Host "Ghidra is running normally" -ForegroundColor Green
            Write-Host "Extensions can be configured via File -> Configure -> Extensions" -ForegroundColor Yellow
        } else {
            Write-Host "Process exited with code: $($process.ExitCode)" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "ERROR: Failed to launch Ghidra: $($_.Exception.Message)" -ForegroundColor Red

    Write-Host ""
    Write-Host "Alternative: Manual Launch" -ForegroundColor Yellow
    Write-Host "1. Open Command Prompt as Administrator" -ForegroundColor White
    Write-Host "2. Navigate to: $GhidraPath" -ForegroundColor White
    Write-Host "3. Run: ghidraRun.bat" -ForegroundColor White
}

Write-Host ""
Write-Host "Direct launcher complete" -ForegroundColor Green