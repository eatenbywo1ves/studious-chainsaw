@echo off
REM ============================================================================
REM Run Complete Load Testing Suite
REM Tests: Baseline (1K) -> Stress (5K) -> Ultimate (10K)
REM ============================================================================

echo ================================================================================
echo OPTIMIZED REDIS POOL - LOAD TESTING SUITE
echo ================================================================================
echo.

REM Verify server is running
echo [1/5] Verifying server is running...
curl -s http://localhost:8000/health >nul 2>&1
if errorlevel 1 (
    echo     [ERROR] Server not responding on http://localhost:8000
    echo     Start the server first with: start-optimized-server.bat
    pause
    exit /b 1
)
echo     [OK] Server is running
echo.

REM Check Redis pool status
echo [2/5] Checking Redis pool status...
curl -s http://localhost:8000/health/redis
echo.
echo.

REM Verify locust is installed
echo [3/5] Verifying Locust is installed...
locust --version >nul 2>&1
if errorlevel 1 (
    echo     [ERROR] Locust not installed!
    echo     Install with: pip install locust
    pause
    exit /b 1
)
echo     [OK] Locust is installed
echo.

REM Create results directory
echo [4/5] Creating results directory...
if not exist "results" mkdir results
echo     [OK] results\ directory ready
echo.

echo [5/5] Starting load test sequence...
echo.

REM ============================================================================
REM TEST 1: BASELINE (1,000 users)
REM ============================================================================
echo ================================================================================
echo TEST 1/3: BASELINE (1,000 users)
echo ================================================================================
echo Target: 1,000 concurrent users
echo Spawn Rate: 50 users/second
echo Duration: 3 minutes
echo Expected: p95 ^< 200ms, failure rate ^< 0.5%%
echo ================================================================================
echo.

locust -f locustfile.py AuthenticationLoadTest ^
    --host http://localhost:8000 ^
    --users 1000 ^
    --spawn-rate 50 ^
    --run-time 3m ^
    --headless ^
    --csv=results/optimized_baseline_1000users ^
    --html=results/optimized_baseline_1000users.html

echo.
echo [BASELINE COMPLETE] Results saved to results/optimized_baseline_1000users.*
echo.
timeout /t 10 /nobreak
echo.

REM ============================================================================
REM TEST 2: STRESS (5,000 users)
REM ============================================================================
echo ================================================================================
echo TEST 2/3: STRESS (5,000 users)
echo ================================================================================
echo Target: 5,000 concurrent users
echo Spawn Rate: 100 users/second
echo Duration: 5 minutes
echo Expected: p95 ^< 300ms, failure rate ^< 0.5%%
echo ================================================================================
echo.

locust -f locustfile.py AuthenticationLoadTest ^
    --host http://localhost:8000 ^
    --users 5000 ^
    --spawn-rate 100 ^
    --run-time 5m ^
    --headless ^
    --csv=results/optimized_stress_5000users ^
    --html=results/optimized_stress_5000users.html

echo.
echo [STRESS COMPLETE] Results saved to results/optimized_stress_5000users.*
echo.
timeout /t 10 /nobreak
echo.

REM ============================================================================
REM TEST 3: ULTIMATE (10,000 users)
REM ============================================================================
echo ================================================================================
echo TEST 3/3: ULTIMATE (10,000 users)
echo ================================================================================
echo Target: 10,000 concurrent users
echo Spawn Rate: 100 users/second
echo Duration: 5 minutes
echo Expected: p95 ^< 500ms, failure rate ^< 1%%
echo ================================================================================
echo.

locust -f locustfile.py AuthenticationLoadTest ^
    --host http://localhost:8000 ^
    --users 10000 ^
    --spawn-rate 100 ^
    --run-time 5m ^
    --headless ^
    --csv=results/optimized_ultimate_10000users ^
    --html=results/optimized_ultimate_10000users.html

echo.
echo [ULTIMATE COMPLETE] Results saved to results/optimized_ultimate_10000users.*
echo.

REM ============================================================================
REM SUMMARY
REM ============================================================================
echo.
echo ================================================================================
echo LOAD TESTING SUITE COMPLETE
echo ================================================================================
echo.
echo Results saved to: results\
echo.
echo Files created:
echo   - optimized_baseline_1000users_stats.csv
echo   - optimized_baseline_1000users.html
echo   - optimized_stress_5000users_stats.csv
echo   - optimized_stress_5000users.html
echo   - optimized_ultimate_10000users_stats.csv
echo   - optimized_ultimate_10000users.html
echo.
echo ================================================================================
echo NEXT STEPS
echo ================================================================================
echo 1. Review HTML reports in results\ directory
echo 2. Check pool metrics: curl http://localhost:8000/health/redis
echo 3. Compare to Week 3 Day 1 baseline results
echo 4. Generate performance comparison report
echo ================================================================================
echo.

pause
