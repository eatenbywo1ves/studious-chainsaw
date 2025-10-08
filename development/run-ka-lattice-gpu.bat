@echo off
REM KA Lattice GPU-Accelerated Launcher
REM Uses Python 3.12 with PyTorch CUDA support

echo ============================================================
echo KA Lattice GPU-Accelerated Launcher
echo ============================================================
echo Python: 3.12 with PyTorch 2.5.1+cu121
echo GPU: CUDA 12.1 via PyTorch bundled libraries
echo ============================================================
echo.

REM Check if Python 3.12 is available
py -3.12 --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.12 not found!
    echo Please install Python 3.12 to use GPU acceleration.
    echo.
    echo Alternatives:
    echo   - Install Python 3.12 from python.org
    echo   - Or use CPU-only mode with: python %*
    pause
    exit /b 1
)

REM Run with Python 3.12
echo [OK] Python 3.12 found
echo.
echo Launching KA Lattice with GPU acceleration...
echo.

py -3.12 %*