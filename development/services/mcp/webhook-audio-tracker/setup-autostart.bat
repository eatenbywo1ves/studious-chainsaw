@echo off
echo ========================================
echo   Webhook Audio Tracker - Autostart Setup
echo ========================================
echo.
echo This will configure the Webhook Audio Tracker to start automatically
echo when you log into Windows.
echo.
echo Setup method: Windows Task Scheduler
echo Task Name: WebhookAudioTracker
echo.
pause

:: Create a scheduled task to run at user login
schtasks /create /tn "WebhookAudioTracker" /tr "wscript.exe \"%~dp0start-background.vbs\"" /sc onlogon /ru "%USERNAME%" /f

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================
    echo   SUCCESS!
    echo ========================================
    echo.
    echo The Webhook Audio Tracker will now start automatically when you log in.
    echo.
    echo To manually start it now, run: start-background.vbs
    echo To disable autostart, run: remove-autostart.bat
    echo.
) else (
    echo.
    echo ========================================
    echo   ERROR!
    echo ========================================
    echo.
    echo Failed to create scheduled task.
    echo You may need to run this script as Administrator.
    echo.
)

pause
