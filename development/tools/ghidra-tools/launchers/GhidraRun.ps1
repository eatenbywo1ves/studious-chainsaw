# Complete Ghidra PowerShell Launcher
# Uses proper Java arguments from launch.properties to ensure successful startup

param(
    [string]$GhidraPath = "C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC",
    [string]$MaxMemory = "4G"
)

Write-Host "Complete Ghidra PowerShell Launcher" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green

# Verify Ghidra installation
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

Write-Host "Ghidra Directory: $GhidraPath" -ForegroundColor Cyan
Write-Host "Max Memory: $MaxMemory" -ForegroundColor Cyan

# Check Java availability
try {
    $javaPath = (Get-Command java -ErrorAction Stop).Source
    $javaVersion = & java -version 2>&1 | Select-String "version"
    Write-Host "Java: $javaPath" -ForegroundColor Green
    Write-Host "Version: $($javaVersion -replace '.*"([^"]+)".*', '$1')" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Java not found in PATH" -ForegroundColor Red
    Write-Host "Please ensure Java 17+ is installed and in your PATH" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "Building Java arguments from launch.properties..." -ForegroundColor Yellow

# Build comprehensive Java arguments based on launch.properties
$javaArgs = @(
    # Classpath
    "-cp", $supportJar,

    # Memory
    "-Xmx$MaxMemory",

    # Critical: Ghidra custom class loader (from launch.properties line 8)
    "-Djava.system.class.loader=ghidra.GhidraClassLoader",

    # Encoding and locale (from launch.properties)
    "-Dfile.encoding=UTF8",
    "-Duser.country=US",
    "-Duser.language=en",
    "-Duser.variant=",

    # Graphics settings (Windows-specific from launch.properties)
    "-Dsun.java2d.opengl=false",
    "-Dsun.java2d.d3d=false",

    # Network settings
    "-Djdk.tls.client.protocols=TLSv1.2,TLSv1.3",

    # Class sharing (from launch.properties)
    "-Xshare:off",

    # Python console encoding
    "-Dpython.console.encoding=UTF-8",

    # Log4j Windows setting
    "-Dlog4j.skipJansi=true",

    # GUI settings
    "-Djava.awt.headless=false",

    # Ghidra installation directory
    "-Dghidra.install.dir=`"$GhidraPath`"",

    # Working directory
    "-Duser.dir=`"$GhidraPath`"",

    # Main class and arguments
    "LaunchSupport",
    "`"$GhidraPath`"",
    "ghidra.GhidraRun"
)

Write-Host "Starting Ghidra..." -ForegroundColor Green
Write-Host "This may take 30-60 seconds for initial startup" -ForegroundColor Yellow
Write-Host ""

try {
    # Create process start info
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = "java"
    $startInfo.Arguments = $javaArgs -join " "
    $startInfo.WorkingDirectory = $GhidraPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $false
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal

    Write-Host "Command: java $($javaArgs -join ' ')" -ForegroundColor Gray
    Write-Host ""

    # Start the process
    $process = [System.Diagnostics.Process]::Start($startInfo)

    if ($process) {
        Write-Host "Ghidra started successfully!" -ForegroundColor Green
        Write-Host "Process ID: $($process.Id)" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Monitoring startup..." -ForegroundColor Yellow

        # Monitor for a reasonable time
        for ($i = 1; $i -le 10; $i++) {
            Start-Sleep -Seconds 2

            if ($process.HasExited) {
                Write-Host "Process exited with code: $($process.ExitCode)" -ForegroundColor Red
                if ($process.ExitCode -ne 0) {
                    Write-Host "Launch failed. This may be due to:" -ForegroundColor Yellow
                    Write-Host "- Java version incompatibility (requires Java 17+)" -ForegroundColor White
                    Write-Host "- Missing or corrupted Ghidra installation" -ForegroundColor White
                    Write-Host "- Insufficient memory" -ForegroundColor White
                }
                break
            }

            Write-Host "Startup check $i/10 - Process running..." -ForegroundColor Green
        }

        if (-not $process.HasExited) {
            Write-Host ""
            Write-Host "Ghidra is starting up successfully!" -ForegroundColor Green
            Write-Host "The GUI should appear shortly. Be patient during first launch." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Once Ghidra opens:" -ForegroundColor Cyan
            Write-Host "1. Go to File -> Configure -> Extensions" -ForegroundColor White
            Write-Host "2. Enable CryptoDetect and RetSync extensions" -ForegroundColor White
            Write-Host "3. Restart Ghidra to activate extensions" -ForegroundColor White
        }
    } else {
        throw "Failed to start Java process"
    }

} catch {
    Write-Host "ERROR: Failed to start Ghidra" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting suggestions:" -ForegroundColor Yellow
    Write-Host "1. Verify Java 17+ is installed: java -version" -ForegroundColor White
    Write-Host "2. Try running as Administrator" -ForegroundColor White
    Write-Host "3. Check Windows Defender/Antivirus exclusions" -ForegroundColor White
    Write-Host "4. Ensure sufficient disk space and memory" -ForegroundColor White
}

Write-Host ""
Write-Host "Launcher script complete." -ForegroundColor Green
Read-Host "Press Enter to exit"