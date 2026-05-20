@echo off
REM Workspace Launcher - Quick start for development environment

echo ========================================
echo       DEVELOPMENT WORKSPACE LAUNCHER
echo ========================================
echo.

cd /d "%USERPROFILE%"

echo Select workspace profile:
echo.
echo [1] Full Development - All services and tools
echo [2] MCP Services - MCP orchestrator and dashboard
echo [3] Financial - Financial apps and MCP services
echo [4] Reverse Engineering - Ghidra integration
echo [5] Minimal - Just code editor
echo [6] Custom - Choose services manually
echo.

choice /c 123456 /n /m "Select profile (1-6): "

if %errorlevel%==1 python Tools\workspace-launcher\workspace_manager.py launch --profile full
if %errorlevel%==2 python Tools\workspace-launcher\workspace_manager.py launch --profile mcp
if %errorlevel%==3 python Tools\workspace-launcher\workspace_manager.py launch --profile financial
if %errorlevel%==4 python Tools\workspace-launcher\workspace_manager.py launch --profile reverse-engineering
if %errorlevel%==5 python Tools\workspace-launcher\workspace_manager.py launch --profile minimal
if %errorlevel%==6 python Tools\workspace-launcher\workspace_manager.py launch --interactive

pause
