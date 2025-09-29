# Advanced Ghidra PowerShell Launcher
# Uses direct Java execution to bypass batch file issues

param(
    [string]$GhidraPath = "C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC",
    [string]$MaxMemory = "4G"
)

Write-Host "Advanced Ghidra Launcher" -ForegroundColor Green
Write-Host "========================" -ForegroundColor Green

# Verify installation
if (-not (Test-Path $GhidraPath)) {
    Write-Host "ERROR: Ghidra not found at: $GhidraPath" -ForegroundColor Red
    exit 1
}

Write-Host "Ghidra Directory: $GhidraPath" -ForegroundColor Cyan
Write-Host "Memory Limit: $MaxMemory" -ForegroundColor Cyan

# Build classpath manually
$supportJar = Join-Path $GhidraPath "support\LaunchSupport.jar"
if (-not (Test-Path $supportJar)) {
    Write-Host "ERROR: LaunchSupport.jar not found" -ForegroundColor Red
    exit 1
}

Write-Host "LaunchSupport: $supportJar" -ForegroundColor Green

# Check Java
try {
    $javaVersion = & java -version 2>&1 | Select-String "version"
    Write-Host "Java: $($javaVersion -replace '.*"([^"]+)".*', '$1')" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Java not found" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Starting Ghidra with direct Java execution..." -ForegroundColor Yellow

# Method 1: Direct Java launch with LaunchSupport
$javaArgs = @(
    "-cp", $supportJar,
    "-Xmx$MaxMemory",
    "-Dfile.encoding=UTF-8",
    "-Duser.country=US",
    "-Duser.language=en",
    "-Djava.awt.headless=false",
    "-Dghidra.install.dir=`"$GhidraPath`"",
    "-Duser.dir=`"$GhidraPath`"",
    "LaunchSupport",
    "`"$GhidraPath`"",
    "ghidra.GhidraRun"
)

try {
    Write-Host "Java arguments: $($javaArgs -join ' ')" -ForegroundColor Cyan

    # Start Java process with proper environment
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = "java"
    $startInfo.Arguments = $javaArgs -join " "
    $startInfo.WorkingDirectory = $GhidraPath
    $startInfo.UseShellExecute = $true
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden  # Start hidden to avoid console issues

    $process = [System.Diagnostics.Process]::Start($startInfo)

    if ($process) {
        Write-Host "Ghidra process started: PID $($process.Id)" -ForegroundColor Green

        # Wait a moment then check if still running
        Start-Sleep -Seconds 3

        if (-not $process.HasExited) {
            Write-Host "Ghidra is initializing... (This may take 30-60 seconds)" -ForegroundColor Green
            Write-Host "Check your taskbar for the Ghidra window" -ForegroundColor Yellow
        } else {
            Write-Host "Process exited with code: $($process.ExitCode)" -ForegroundColor Yellow
            Write-Host "Trying alternative method..." -ForegroundColor Yellow

            # Method 2: System.Diagnostics approach with different settings
            $altProcess = Start-Process -FilePath "java" -ArgumentList $javaArgs -WorkingDirectory $GhidraPath -PassThru -WindowStyle Hidden

            if ($altProcess) {
                Write-Host "Alternative launch successful: PID $($altProcess.Id)" -ForegroundColor Green
            }
        }
    }

} catch {
    Write-Host "Error launching Ghidra: $($_.Exception.Message)" -ForegroundColor Red

    # Fallback: Show manual instructions
    Write-Host ""
    Write-Host "Manual Alternative:" -ForegroundColor Yellow
    Write-Host "1. Open Command Prompt as Administrator" -ForegroundColor White
    Write-Host "2. Run: cd /d `"$GhidraPath`"" -ForegroundColor White
    Write-Host "3. Run: java -cp support\LaunchSupport.jar -Xmx4G LaunchSupport `"$GhidraPath`" ghidra.GhidraRun" -ForegroundColor White
}

Write-Host ""
Write-Host "Launcher complete. Monitor taskbar for Ghidra window." -ForegroundColor Green