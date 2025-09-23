@echo off
echo Building tmux-clone for Windows...

REM Check if we have a C compiler
where gcc >nul 2>&1
if %errorlevel% == 0 (
    echo Using GCC compiler...
    gcc -Wall -Wextra -std=c99 -D_GNU_SOURCE -Iinclude -o bin/tmux-clone.exe src/*.c
) else (
    where cl >nul 2>&1
    if %errorlevel% == 0 (
        echo Using Microsoft Visual C++ compiler...
        if not exist bin mkdir bin
        cl /I include src\*.c /Fe:bin\tmux-clone.exe
    ) else (
        echo No suitable C compiler found. Please install:
        echo - GCC (via MinGW or similar)
        echo - Microsoft Visual Studio Build Tools
        exit /b 1
    )
)

echo Build complete!
echo Run: bin\tmux-clone.exe --help