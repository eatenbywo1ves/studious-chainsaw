@echo off
echo === Ghidra Installation Script ===
echo.

:: Check if Java is installed
echo Checking for Java installation...
java -version 2>nul
if %errorlevel% neq 0 (
    echo Java is not installed. Installing OpenJDK 17...
    winget install Microsoft.OpenJDK.17
    if %errorlevel% neq 0 (
        echo Failed to install Java. Please install Java 17+ manually.
        echo Download from: https://adoptium.net/temurin/releases/
        pause
        exit /b 1
    )
    echo Java installed successfully!
) else (
    echo Java is already installed.
)

echo.
echo Downloading Ghidra 11.2...
echo This may take several minutes (file size ~350MB)...

:: Download Ghidra using PowerShell
powershell -Command "& {Try {Invoke-WebRequest -Uri 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20241105.zip' -OutFile 'ghidra_latest.zip' -UseBasicParsing} Catch {Write-Host 'Download failed: ' $_.Exception.Message; exit 1}}"

if %errorlevel% neq 0 (
    echo Download failed. Please download Ghidra manually from:
    echo https://github.com/NationalSecurityAgency/ghidra/releases
    pause
    exit /b 1
)

echo.
echo Extracting Ghidra...

:: Extract using PowerShell
powershell -Command "& {Expand-Archive -Path 'ghidra_latest.zip' -DestinationPath '.' -Force}"

if %errorlevel% neq 0 (
    echo Extraction failed.
    pause
    exit /b 1
)

echo.
echo Creating desktop shortcut...

:: Create a launcher batch file
echo @echo off > launch_ghidra.bat
echo echo Starting Ghidra... >> launch_ghidra.bat
echo cd /d "%~dp0ghidra_11.2_PUBLIC" >> launch_ghidra.bat
echo call ghidraRun.bat >> launch_ghidra.bat
echo pause >> launch_ghidra.bat

echo.
echo === Installation Complete! ===
echo.
echo Ghidra has been installed to: %CD%\ghidra_11.2_PUBLIC
echo.
echo To launch Ghidra, run: launch_ghidra.bat
echo Or navigate to ghidra_11.2_PUBLIC and run ghidraRun.bat
echo.
pause