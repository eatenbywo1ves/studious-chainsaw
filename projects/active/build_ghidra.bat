@echo off
echo === Building Ghidra from Source ===
echo.

cd /d C:\Users\Corbin\development\ghidra

echo Checking for Gradle...
where gradle >nul 2>&1
if %errorlevel% neq 0 (
    echo Gradle not found in PATH. Using Gradle wrapper...
    set GRADLE_CMD=gradlew.bat
) else (
    echo Found Gradle in PATH
    set GRADLE_CMD=gradle
)

echo.
echo Step 1: Fetching dependencies...
echo This may take several minutes on first run...
call %GRADLE_CMD% -I gradle/support/fetchDependencies.gradle

if %errorlevel% neq 0 (
    echo Failed to fetch dependencies
    pause
    exit /b 1
)

echo.
echo Step 2: Building Ghidra...
echo This will take 5-10 minutes...
call %GRADLE_CMD% buildGhidra

if %errorlevel% neq 0 (
    echo Build failed
    pause
    exit /b 1
)

echo.
echo === Build Complete! ===
echo.
echo Ghidra distribution created in: build\dist\
echo.

:: Find the built zip file
for %%f in (build\dist\ghidra*.zip) do (
    echo Found: %%f
    set GHIDRA_ZIP=%%f
)

echo.
echo To install the built version:
echo 1. Extract the zip file from build\dist\
echo 2. Run ghidraRun.bat from the extracted folder
echo.
pause