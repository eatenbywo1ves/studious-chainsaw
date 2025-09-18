@echo off
REM ========================================
REM    DEVELOPMENT WORKSPACE LAUNCHER
REM ========================================
REM Quick launcher for complete dev environment
REM

setlocal enabledelayedexpansion

cd /d C:\Users\Corbin

cls
echo.
echo    ===================================================
echo            DEVELOPMENT WORKSPACE LAUNCHER
echo    ===================================================
echo.
echo    Select workspace profile:
echo.
echo    [1] Full Development - All services and tools
echo    [2] MCP Services - MCP orchestrator and dashboard
echo    [3] Financial - Financial apps and MCP services
echo    [4] Reverse Engineering - Ghidra integration
echo    [5] Minimal - Just code editor
echo    [6] Custom - Choose services manually
echo    [0] Exit
echo.
echo    ===================================================
echo.

choice /c 1234560 /n /m "   Select profile: "

set profile_choice=%errorlevel%

if %profile_choice%==7 goto :exit

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo    [ERROR] Python is not installed or not in PATH
    echo.
    pause
    exit /b 1
)

if %profile_choice%==1 (
    echo.
    echo    Starting FULL DEVELOPMENT workspace...
    echo    =====================================
    python Tools\workspace-launcher\workspace_manager.py launch --profile full
)

if %profile_choice%==2 (
    echo.
    echo    Starting MCP SERVICES workspace...
    echo    ==================================
    python Tools\workspace-launcher\workspace_manager.py launch --profile mcp
)

if %profile_choice%==3 (
    echo.
    echo    Starting FINANCIAL workspace...
    echo    ===============================
    python Tools\workspace-launcher\workspace_manager.py launch --profile financial
)

if %profile_choice%==4 (
    echo.
    echo    Starting REVERSE ENGINEERING workspace...
    echo    =========================================
    python Tools\workspace-launcher\workspace_manager.py launch --profile reverse-engineering
)

if %profile_choice%==5 (
    echo.
    echo    Starting MINIMAL workspace...
    echo    =============================
    python Tools\workspace-launcher\workspace_manager.py launch --profile minimal
)

if %profile_choice%==6 (
    echo.
    echo    Starting CUSTOM workspace configuration...
    echo    ==========================================
    python Tools\workspace-launcher\workspace_manager.py launch --interactive
)

echo.
echo    ===================================================
echo.
echo    Workspace is ready! Press any key to view status...
pause >nul

python Tools\workspace-launcher\workspace_manager.py status

echo.
pause
goto :exit

:exit
exit /b 0