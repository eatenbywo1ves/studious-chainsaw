@echo off
REM Setup CuPy to use PyTorch's CUDA 12.x runtime libraries
REM Updated to properly configure CuPy with PyTorch's CUDA

echo [SETUP] Configuring CuPy with PyTorch's CUDA Runtime
echo ============================================================

REM Set PyTorch library paths
set "TORCH_LIB=C:\Users\Corbin\AppData\Local\Programs\Python\Python312\Lib\site-packages\torch\lib"

REM Create bin directory symlink for CuPy compatibility
if not exist "%TORCH_LIB%\bin" (
    echo Creating bin directory link for CuPy...
    mklink /D "%TORCH_LIB%\bin" "%TORCH_LIB%" >nul 2>&1
)

REM Add to PATH for current session
set "PATH=%TORCH_LIB%;%PATH%"

REM Set CUDA environment variables for current session
set "CUDA_PATH=%TORCH_LIB%"
set "CUDNN_PATH=%TORCH_LIB%"
set "LD_LIBRARY_PATH=%TORCH_LIB%"

echo.
echo Environment configured:
echo   PyTorch Lib: %TORCH_LIB%
echo   CUDA_PATH: %CUDA_PATH%
echo.

REM Test CuPy with proper environment
echo Testing CuPy installation...
py -3.12 -c "import os; os.environ['CUDA_PATH']=r'%TORCH_LIB%'; import cupy as cp; print(f'CuPy {cp.__version__}'); a = cp.array([1,2,3]); print(f'GPU array test: {a}'); print('[SUCCESS] CuPy configured with PyTorch CUDA!')" 2>&1

echo.
echo For permanent setup, add these to your system environment variables:
echo   CUDA_PATH=%TORCH_LIB%
echo   Add to PATH: %TORCH_LIB%
echo.