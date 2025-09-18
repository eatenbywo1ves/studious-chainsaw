@echo off
REM Quick launcher shortcuts for common tasks

if "%1"=="" goto :menu

if /i "%1"=="mcp" goto :mcp
if /i "%1"=="ghidra" goto :ghidra
if /i "%1"=="financial" goto :financial
if /i "%1"=="dashboard" goto :dashboard
if /i "%1"=="stop" goto :stop
if /i "%1"=="status" goto :status

echo Unknown command: %1
goto :menu

:menu
echo.
echo Quick Launchers:
echo ================
echo   quick-launchers mcp       - Start MCP services only
echo   quick-launchers ghidra    - Start Ghidra-Claude bridge
echo   quick-launchers financial - Start financial apps
echo   quick-launchers dashboard - Open MCP dashboard
echo   quick-launchers stop      - Stop all services
echo   quick-launchers status    - Show workspace status
echo.
exit /b 0

:mcp
echo Starting MCP services...
cd /d C:\Users\Corbin
start "MCP Orchestrator" cmd /k python Tools\mcp-orchestrator\mcp_orchestrator.py monitor
timeout /t 3 >nul
start "MCP Dashboard" cmd /k python Tools\mcp-orchestrator\dashboard.py
timeout /t 3 >nul
start http://localhost:5000
exit /b 0

:ghidra
echo Starting Ghidra-Claude bridge...
cd /d C:\Users\Corbin
start "Ghidra Bridge" cmd /k python ghidra-claude\ghidra_claude_bridge.py
exit /b 0

:financial
echo Starting financial simulator...
cd /d C:\Users\Corbin\projects\financial-apps\financial-simulator
start "Financial Simulator" cmd /k npm run dev
timeout /t 5 >nul
start http://localhost:5173
exit /b 0

:dashboard
echo Opening MCP dashboard...
start http://localhost:5000
exit /b 0

:stop
echo Stopping all services...
taskkill /F /IM python.exe 2>nul
taskkill /F /IM node.exe 2>nul
echo Services stopped.
exit /b 0

:status
cd /d C:\Users\Corbin
python Tools\workspace-launcher\workspace_manager.py status
pause
exit /b 0