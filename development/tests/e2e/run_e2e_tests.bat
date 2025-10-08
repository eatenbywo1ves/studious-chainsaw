@echo off
REM E2E Test Runner for Windows
REM Manages E2E test environment and execution

echo ========================================
echo   E2E Test Runner
echo ========================================
echo.

REM Check Docker
docker info >nul 2>&1
if errorlevel 1 (
    echo Error: Docker is not running
    exit /b 1
)

REM Step 1: Start E2E environment
echo [1/6] Starting E2E test environment...
docker compose -f docker-compose.e2e.yml up -d

REM Step 2: Wait for services
echo [2/6] Waiting for services to be ready...
echo Waiting 40 seconds for all services to initialize...
timeout /t 40 /nobreak >nul

echo Checking service health...
docker compose -f docker-compose.e2e.yml ps

REM Step 3: Run E2E tests
echo.
echo [3/6] Running E2E tests...

REM Set environment variables
set E2E_API_URL=http://localhost:8002
set E2E_TIMEOUT=60

REM Parse arguments
set "REPORT_HTML="
set "VERBOSE=-v"
set "TEST_FILTER="

:parse_args
if "%~1"=="" goto end_parse
if "%~1"=="--html" (
    set "REPORT_HTML=--html=e2e_report.html --self-contained-html"
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

REM Run tests
if defined TEST_FILTER (
    echo Running filtered E2E tests: %TEST_FILTER%
    pytest %VERBOSE% %REPORT_HTML% %TEST_FILTER%
) else (
    echo Running all E2E tests...
    pytest %VERBOSE% %REPORT_HTML%
)

set E2E_EXIT_CODE=%ERRORLEVEL%

REM Step 4: Show results
echo.
echo [4/6] Test Results

if %E2E_EXIT_CODE% equ 0 (
    echo [92m✓ All E2E tests passed![0m
) else (
    echo [91m✗ Some E2E tests failed (exit code: %E2E_EXIT_CODE%)[0m
)

REM Step 5: Show logs if failed
if %E2E_EXIT_CODE% neq 0 (
    echo.
    echo [5/6] Showing service logs...
    docker compose -f docker-compose.e2e.yml logs --tail=50 saas-api-e2e
)

REM Step 6: Cleanup
echo.
echo [6/6] Cleanup
set /p CLEANUP="Stop E2E environment? (y/n): "

if /i "%CLEANUP%"=="y" (
    echo Stopping E2E environment...
    docker compose -f docker-compose.e2e.yml down
    echo [92m✓ E2E environment stopped[0m
) else (
    echo E2E environment still running. Stop manually with:
    echo   docker compose -f docker-compose.e2e.yml down
)

REM Show HTML report
if defined REPORT_HTML (
    if exist e2e_report.html (
        echo.
        echo HTML report generated: e2e_report.html
    )
)

echo.
echo ========================================
echo   E2E Test Run Complete
echo ========================================

exit /b %E2E_EXIT_CODE%
