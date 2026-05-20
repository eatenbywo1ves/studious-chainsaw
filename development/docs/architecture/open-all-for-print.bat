@echo off
echo Opening all architecture documents in browser...
echo Press Ctrl+P in each window to print!
echo.

start chrome 00-executive-summary.md
timeout /t 2 >nul

start chrome 01-system-context\system-context.md
timeout /t 2 >nul

start chrome 01-system-context\stakeholders.md
timeout /t 2 >nul

start chrome IMPLEMENTATION_STATUS.md
timeout /t 2 >nul

start chrome README-COMPREHENSIVE.md
timeout /t 2 >nul

start chrome 10-adrs\001-fastapi-over-flask.md

echo.
echo All documents opened!
echo Press Ctrl+P in each browser tab to print.
pause
