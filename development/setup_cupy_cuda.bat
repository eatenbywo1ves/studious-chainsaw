@echo off
REM Setup CuPy to use PyTorch's CUDA 12.x runtime libraries
REM Pirate mode: Setting sail with proper cargo!

echo [PIRATE] Setting up CuPy with PyTorch's CUDA Runtime!
echo ============================================================

REM Add PyTorch's lib directory to PATH
set "TORCH_LIB=C:\Users\Corbin\AppData\Local\Programs\Python\Python312\Lib\site-packages\torch\lib"
set "PATH=%TORCH_LIB%;%PATH%"

REM Set CUDA environment variables
set "CUDA_PATH=%TORCH_LIB%"
set "CUDNN_PATH=%TORCH_LIB%"

echo Environment configured:
echo   PATH includes: %TORCH_LIB%
echo   CUDA_PATH: %CUDA_PATH%
echo.

REM Run Python with CuPy test
py -3.12 -c "import cupy as cp; print(f'CuPy {cp.__version__}'); print(f'CUDA available: {cp.cuda.is_available()}'); x = cp.array([1,2,3]); print(f'GPU array: {x}'); print('CuPy WORKING with PyTorch CUDA!')"

echo.
echo To use CuPy in this session, run Python commands now.
echo Type 'py -3.12' to start Python with CuPy enabled.
echo.