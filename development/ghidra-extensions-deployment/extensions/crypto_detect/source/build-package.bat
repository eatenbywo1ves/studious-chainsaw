@echo off
REM Build script for CryptoDetect extension on Windows

echo Building CryptoDetect Extension...
echo.

REM Check if GHIDRA_INSTALL_DIR is set
if "%GHIDRA_INSTALL_DIR%"=="" (
    echo ERROR: GHIDRA_INSTALL_DIR environment variable not set
    echo Please set it to your Ghidra installation directory
    echo Example: set GHIDRA_INSTALL_DIR=C:\ghidra_12.0_DEV
    pause
    exit /b 1
)

echo Using Ghidra installation: %GHIDRA_INSTALL_DIR%
echo.

REM Clean previous build
echo Cleaning previous build...
if exist build rmdir /s /q build
if exist lib rmdir /s /q lib

REM Build the extension
echo Building extension...
call gradle clean build
if %ERRORLEVEL% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

REM Create distribution package
echo Creating distribution package...
if not exist dist mkdir dist
if exist dist\crypto_detect.zip del dist\crypto_detect.zip

REM Copy files for packaging
if not exist temp mkdir temp
xcopy /E /I /Y src temp\crypto_detect\src
copy extension.properties temp\crypto_detect\
copy Module.manifest temp\crypto_detect\
copy LICENSE temp\crypto_detect\
copy README.md temp\crypto_detect\
copy INSTALL.md temp\crypto_detect\
copy CHANGELOG.md temp\crypto_detect\
if exist build\libs\*.jar copy build\libs\*.jar temp\crypto_detect\lib\

REM Create zip package
cd temp
powershell Compress-Archive -Path crypto_detect -DestinationPath ..\dist\crypto_detect.zip -Force
cd ..

REM Clean up temp directory
rmdir /s /q temp

echo.
echo Build completed successfully!
echo Extension package created: dist\crypto_detect.zip
echo.
pause