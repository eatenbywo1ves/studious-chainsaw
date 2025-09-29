@echo off
REM Setup Numba CUDA to use PyTorch's CUDA 12.1 libraries
REM Comprehensive Numba GPU computing configuration

echo [SETUP] Configuring Numba CUDA with PyTorch's CUDA Runtime
echo ============================================================

REM Set PyTorch library paths
set "TORCH_LIB=C:\Users\Corbin\AppData\Local\Programs\Python\Python312\Lib\site-packages\torch\lib"

REM Add to PATH for current session
set "PATH=%TORCH_LIB%;%PATH%"

REM Set CUDA environment variables for current session
set "CUDA_HOME=%TORCH_LIB%"
set "CUDA_PATH=%TORCH_LIB%"
set "LD_LIBRARY_PATH=%TORCH_LIB%"

echo.
echo Environment configured:
echo   PyTorch Lib: %TORCH_LIB%
echo   CUDA_HOME: %CUDA_HOME%
echo.

REM Test Numba CUDA with proper environment
echo Testing Numba CUDA installation...
py -3.12 numba-setup-test.py

echo.
echo Setup Notes:
echo   - Traditional numba.cuda is working with PyTorch CUDA 12.1
echo   - Modern numba-cuda package installed but needs configuration
echo   - Use Python 3.12 for best compatibility
echo   - GPU: NVIDIA GeForce GTX 1080 (Compute Capability 6.1)
echo.
echo For permanent setup, add these to your system environment variables:
echo   CUDA_HOME=%TORCH_LIB%
echo   Add to PATH: %TORCH_LIB%
echo.
echo To test performance: python test-numba-cuda.py
echo.