@echo off
REM Integration Test Runner for Windows
REM Automates starting test environment, running tests, and cleanup

echo ========================================
echo   Integration Test Runner
echo ========================================
echo.

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo Error: Docker is not running
    exit /b 1
)

REM Step 1: Start test environment
echo [1/5] Starting test environment...
docker compose -f docker-compose.test.yml up -d

REM Step 2: Wait for services to be healthy
echo [2/5] Waiting for services to be healthy...
echo Waiting 30 seconds for services to initialize...
timeout /t 30 /nobreak >nul

echo Checking service health...
docker compose -f docker-compose.test.yml ps

REM Step 3: Run tests
echo.
echo [3/5] Running integration tests...

REM Parse arguments
set "COVERAGE="
set "TEST_FILTER="
set "VERBOSE=-v"

:parse_args
if "%~1"=="" goto end_parse
if "%~1"=="--coverage" (
    set "COVERAGE=--cov=saas --cov=apps/catalytic --cov-report=html --cov-report=term"
    shift
    goto parse_args
)
if "%~1"=="--filter" (
    set "TEST_FILTER=-k %~2"
    shift
    shift
    goto parse_args
)
if "%~1"=="--quiet" (
    set "VERBOSE="
    shift
    goto parse_args
)
shift
goto parse_args
:end_parse

REM Run pytest
if defined TEST_FILTER (
    echo Running filtered tests: %TEST_FILTER%
    pytest %VERBOSE% %COVERAGE% %TEST_FILTER%
) else (
    echo Running all integration tests...
    pytest %VERBOSE% %COVERAGE%
)

set TEST_EXIT_CODE=%ERRORLEVEL%

REM Step 4: Show results
echo.
echo [4/5] Test Results

if %TEST_EXIT_CODE% equ 0 (
    echo [92m✓ All tests passed![0m
) else (
    echo [91m✗ Some tests failed (exit code: %TEST_EXIT_CODE%)[0m
)

REM Step 5: Cleanup
echo.
echo [5/5] Cleanup
set /p CLEANUP="Stop test environment? (y/n): "

if /i "%CLEANUP%"=="y" (
    echo Stopping test environment...
    docker compose -f docker-compose.test.yml down
    echo [92m✓ Test environment stopped[0m
) else (
    echo Test environment still running. Stop manually with:
    echo   docker compose -f docker-compose.test.yml down
)

REM Show coverage report if generated
if defined COVERAGE (
    if exist htmlcov\index.html (
        echo.
        echo Coverage report generated: htmlcov\index.html
    )
)

echo.
echo ========================================
echo   Integration Test Run Complete
echo ========================================

exit /b %TEST_EXIT_CODE%
