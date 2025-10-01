@echo off
echo ========================================
echo   Webhook Audio Tracker - Remove Autostart
echo ========================================
echo.
echo This will remove the automatic startup configuration.
echo.
pause

:: Delete the scheduled task
schtasks /delete /tn "WebhookAudioTracker" /f

if %ERRORLEVEL% equ 0 (
    echo.
    echo ========================================
    echo   SUCCESS!
    echo ========================================
    echo.
    echo The Webhook Audio Tracker autostart has been removed.
    echo.
) else (
    echo.
    echo ========================================
    echo   ERROR!
    echo ========================================
    echo.
    echo Failed to remove scheduled task.
    echo It may not exist or you may need Administrator privileges.
    echo.
)

pause
