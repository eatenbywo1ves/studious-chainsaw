@echo off
REM Compile test binaries for GhidrAssist benchmarking
REM Requires MinGW or similar GCC for Windows

echo Compiling GhidrAssist test binaries...
echo.

REM Simple tests
echo [1/3] Compiling hello_world...
gcc -g -o hello_world.exe hello_world.c
if %errorlevel% equ 0 (
    echo   ✓ hello_world.exe created
) else (
    echo   ✗ Compilation failed
)

echo [2/3] Compiling simple_math...
gcc -g -o simple_math.exe simple_math.c
if %errorlevel% equ 0 (
    echo   ✓ simple_math.exe created
) else (
    echo   ✗ Compilation failed
)

echo [3/3] Compiling vulnerable_client...
gcc -g -Wno-deprecated-declarations -o vulnerable_client.exe vulnerable_client.c
if %errorlevel% equ 0 (
    echo   ✓ vulnerable_client.exe created
) else (
    echo   ✗ Compilation failed
)

echo.
echo Compilation complete!
echo.
echo Test binaries:
dir /B *.exe 2>nul
echo.
echo Next steps:
echo 1. Open binaries in Ghidra
echo 2. Load GhidrAssist plugin
echo 3. Run benchmark tests
pause
