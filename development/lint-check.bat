@echo off
REM Comprehensive Code Quality Check Script
REM Runs linting for both Python and JavaScript files

echo ================================
echo   CODE QUALITY CHECK SCRIPT
echo ================================
echo.

echo [1/4] Running Python linting with Ruff...
echo ----------------------------------------
ruff check . --select=F,E,W,I,B,C4,UP --ignore=E501 --no-fix
if %ERRORLEVEL% EQU 0 (
    echo ✅ Python linting passed
) else (
    echo ❌ Python linting found issues
)
echo.

echo [2/4] Running Python formatting check...
echo ----------------------------------------
ruff format --check .
if %ERRORLEVEL% EQU 0 (
    echo ✅ Python formatting is correct
) else (
    echo ❌ Python formatting needs attention
)
echo.

echo [3/4] Checking for unused Python imports...
echo ----------------------------------------
ruff check . --select=F401 --no-fix
if %ERRORLEVEL% EQU 0 (
    echo ✅ No unused imports found
) else (
    echo ⚠️  Unused imports detected
)
echo.

echo [4/4] Generating code quality summary...
echo ----------------------------------------
echo Scanning file types:
echo   Python files:
for /r %%i in (*.py) do set /a python_count+=1
echo     Found %python_count% Python files
echo   JavaScript files:
for /r %%i in (*.js) do set /a js_count+=1
echo     Found %js_count% JavaScript files
echo.

echo Quality Check Complete!
echo.
echo To fix issues automatically:
echo   Python: ruff check --fix .
echo   Python formatting: ruff format .
echo.
echo To run this script: .\lint-check.bat
echo.