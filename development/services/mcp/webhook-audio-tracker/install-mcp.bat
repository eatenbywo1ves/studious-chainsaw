@echo off
echo ========================================
echo   Installing Webhook Audio Tracker MCP
echo ========================================
echo.

:: Install required MCP SDK packages
echo Installing MCP SDK dependencies...
npm install @modelcontextprotocol/sdk axios

if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: Failed to install dependencies
    echo.
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Adding to Claude Code Configuration
echo ========================================
echo.

:: Check if Claude Code config exists
set CLAUDE_CONFIG=%USERPROFILE%\.claude\config.json

if not exist "%USERPROFILE%\.claude" (
    echo Creating Claude Code config directory...
    mkdir "%USERPROFILE%\.claude"
)

:: Create or update config
echo Adding MCP server configuration...

:: For now, display the configuration that needs to be added
echo.
echo Add the following to your Claude Code config at:
echo %CLAUDE_CONFIG%
echo.
type claude-code-config.json
echo.
echo.
echo Or run this PowerShell command to merge it automatically:
echo.
echo powershell -ExecutionPolicy Bypass -File merge-config.ps1
echo.

echo ========================================
echo   Installation Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Add the MCP configuration to your Claude Code config
echo 2. Start the webhook server: start.bat
echo 3. Restart Claude Code to load the MCP server
echo 4. Test with: "Play a test audio cue"
echo.

pause
