@echo off
echo =====================================
echo   CUDA 12.7 QUICK DOWNLOAD
echo =====================================
echo.
echo This will download CUDA Toolkit 12.7 (3.3 GB)
echo Download location: %USERPROFILE%\Downloads\
echo.
pause

echo.
echo Starting download...
echo This may take 5-15 minutes depending on your connection
echo.

curl -L -o "%USERPROFILE%\Downloads\cuda_12.7.0_installer.exe" https://developer.download.nvidia.com/compute/cuda/12.7.0/local_installers/cuda_12.7.0_566.49_windows.exe

if %ERRORLEVEL% == 0 (
    echo.
    echo =====================================
    echo   DOWNLOAD COMPLETE!
    echo =====================================
    echo.
    echo Installer saved to: %USERPROFILE%\Downloads\cuda_12.7.0_installer.exe
    echo.
    echo To install:
    echo 1. Run the installer
    echo 2. Choose "Custom" installation
    echo 3. Select CUDA Development and Runtime components
    echo.
    echo Run installer now? (Close this window to cancel)
    pause
    start "" "%USERPROFILE%\Downloads\cuda_12.7.0_installer.exe"
) else (
    echo.
    echo ERROR: Download failed!
    echo Please download manually from:
    echo https://developer.nvidia.com/cuda-downloads
    pause
)