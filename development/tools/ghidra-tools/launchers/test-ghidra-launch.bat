@echo off
REM Test script to capture Ghidra launch output and errors

echo Testing Ghidra Launch with Output Capture
echo ==========================================
echo.

set GHIDRA_DIR=C:\Users\Corbin\development\ghidra_11.4.2_PUBLIC
set LOG_FILE=C:\Users\Corbin\development\ghidra-launch.log

echo Ghidra Directory: %GHIDRA_DIR%
echo Log File: %LOG_FILE%
echo.

REM Clear previous log
if exist "%LOG_FILE%" del "%LOG_FILE%"

echo Starting Ghidra with output capture...
echo.

cd /d "%GHIDRA_DIR%"

REM Capture both stdout and stderr
echo [%DATE% %TIME%] Starting Ghidra launch test >> "%LOG_FILE%"
echo Current Directory: %CD% >> "%LOG_FILE%"
echo Java Version: >> "%LOG_FILE%"
java -version >> "%LOG_FILE%" 2>&1
echo. >> "%LOG_FILE%"

echo Attempting to run ghidraRun.bat... >> "%LOG_FILE%"
echo ---------------------------------------- >> "%LOG_FILE%"

REM Try to run with timeout and capture output
timeout 30 "%GHIDRA_DIR%\ghidraRun.bat" >> "%LOG_FILE%" 2>&1

echo. >> "%LOG_FILE%"
echo [%DATE% %TIME%] Launch attempt completed >> "%LOG_FILE%"

echo.
echo Launch test completed. Check log file:
echo %LOG_FILE%
echo.

REM Show last few lines of log
echo Last 20 lines of log:
echo =====================
type "%LOG_FILE%" | tail -20

pause