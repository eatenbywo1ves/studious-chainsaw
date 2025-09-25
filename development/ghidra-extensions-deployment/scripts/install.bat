@echo off
REM Ghidra Extensions Installer for Windows
REM Automatically installs CryptoDetect and RetSync extensions

setlocal EnableDelayedExpansion

echo ============================================
echo    Ghidra Extensions Installer - Windows
echo ============================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Warning: Not running as administrator. Some features may not work.
    echo.
)

REM Step 1: Check Ghidra installation
if "%GHIDRA_INSTALL_DIR%"=="" (
    echo ERROR: GHIDRA_INSTALL_DIR environment variable not set
    echo.
    echo Searching for Ghidra installation...
    
    REM Search common locations
    set SEARCH_PATHS=C:\ghidra* C:\Tools\ghidra* C:\Program Files\ghidra* D:\ghidra* D:\Tools\ghidra*
    
    for %%p in (%SEARCH_PATHS%) do (
        if exist "%%p\ghidraRun.bat" (
            set GHIDRA_INSTALL_DIR=%%p
            echo Found Ghidra at: %%p
            goto :found_ghidra
        )
    )
    
    echo.
    echo Could not find Ghidra installation automatically.
    echo Please set GHIDRA_INSTALL_DIR manually:
    echo.
    echo Example: set GHIDRA_INSTALL_DIR=C:\ghidra_12.0_DEV
    echo.
    pause
    exit /b 1
)

:found_ghidra
echo Using Ghidra installation: %GHIDRA_INSTALL_DIR%
echo.

REM Step 2: Detect Ghidra version
if exist "%GHIDRA_INSTALL_DIR%\Ghidra\application.properties" (
    for /f "tokens=2 delims==" %%v in ('findstr "application.version" "%GHIDRA_INSTALL_DIR%\Ghidra\application.properties"') do (
        set GHIDRA_VERSION=%%v
    )
) else (
    echo Warning: Could not detect Ghidra version
    set GHIDRA_VERSION=unknown
)

echo Detected Ghidra version: %GHIDRA_VERSION%
echo.

REM Step 3: Create Extensions directory if it doesn't exist
set EXTENSIONS_DIR=%USERPROFILE%\.ghidra\.ghidra_%GHIDRA_VERSION%_DEV\Extensions
if not exist "%EXTENSIONS_DIR%" (
    echo Creating Extensions directory...
    mkdir "%EXTENSIONS_DIR%"
)

REM Step 4: Install CryptoDetect
echo Installing CryptoDetect Extension...
echo ----------------------------------------

set CRYPTO_SOURCE=%~dp0..\extensions\crypto_detect\source
set CRYPTO_DEST=%EXTENSIONS_DIR%\crypto_detect

if exist "%CRYPTO_DEST%" (
    echo Removing existing CryptoDetect installation...
    rmdir /s /q "%CRYPTO_DEST%"
)

echo Copying CryptoDetect files...
xcopy /E /I /Y "%CRYPTO_SOURCE%" "%CRYPTO_DEST%" >nul 2>&1

if %errorLevel% equ 0 (
    echo [SUCCESS] CryptoDetect installed successfully
) else (
    echo [ERROR] Failed to install CryptoDetect
)
echo.

REM Step 5: Install RetSync
echo Installing RetSync Extension...
echo ----------------------------------------

set RETSYNC_SOURCE=%~dp0..\extensions\retsync\ghidra_10.2
set RETSYNC_DEST=%EXTENSIONS_DIR%\retsync

if exist "%RETSYNC_DEST%" (
    echo Removing existing RetSync installation...
    rmdir /s /q "%RETSYNC_DEST%"
)

echo Copying RetSync files...
xcopy /E /I /Y "%RETSYNC_SOURCE%" "%RETSYNC_DEST%" >nul 2>&1

if %errorLevel% equ 0 (
    echo [SUCCESS] RetSync installed successfully
) else (
    echo [ERROR] Failed to install RetSync
)
echo.

REM Step 6: Verify installation
echo Verifying Installation...
echo ----------------------------------------

set INSTALL_SUCCESS=1

if exist "%CRYPTO_DEST%\extension.properties" (
    echo [OK] CryptoDetect extension files found
) else (
    echo [FAIL] CryptoDetect extension files missing
    set INSTALL_SUCCESS=0
)

if exist "%RETSYNC_DEST%\extension.properties" (
    echo [OK] RetSync extension files found
) else (
    echo [FAIL] RetSync extension files missing
    set INSTALL_SUCCESS=0
)

echo.
echo ============================================
if %INSTALL_SUCCESS% equ 1 (
    echo    INSTALLATION COMPLETED SUCCESSFULLY
    echo.
    echo Extensions have been installed to:
    echo %EXTENSIONS_DIR%
    echo.
    echo Next steps:
    echo 1. Start Ghidra
    echo 2. Navigate to File -^> Configure -^> Extensions
    echo 3. Enable the installed extensions
    echo 4. Restart Ghidra to activate
) else (
    echo    INSTALLATION COMPLETED WITH ERRORS
    echo.
    echo Please check the error messages above and try again.
)
echo ============================================
echo.

REM Step 7: Optional - Create desktop shortcuts
echo Would you like to create desktop shortcuts? (Y/N)
set /p CREATE_SHORTCUTS=

if /i "%CREATE_SHORTCUTS%"=="Y" (
    echo Creating desktop shortcuts...
    
    REM Create Ghidra shortcut
    powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\Ghidra.lnk'); $Shortcut.TargetPath = '%GHIDRA_INSTALL_DIR%\ghidraRun.bat'; $Shortcut.WorkingDirectory = '%GHIDRA_INSTALL_DIR%'; $Shortcut.IconLocation = '%GHIDRA_INSTALL_DIR%\support\ghidra.ico'; $Shortcut.Save()"
    
    echo Desktop shortcut created
)

echo.
echo Press any key to exit...
pause >nul

endlocal