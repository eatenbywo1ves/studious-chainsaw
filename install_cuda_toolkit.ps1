# CUDA Toolkit 12.7 Installation Helper
# For NVIDIA GeForce GTX 1080

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  CUDA TOOLKIT 12.7 INSTALLER HELPER " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Check current GPU status
Write-Host "[1] Checking GPU Status..." -ForegroundColor Yellow
$gpu = nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader,nounits 2>$null
if ($gpu) {
    Write-Host "    GPU Found: $gpu" -ForegroundColor Green
} else {
    Write-Host "    ERROR: NVIDIA GPU not detected!" -ForegroundColor Red
    exit 1
}

# CUDA download URL for Windows 11 x64
$cudaUrl = "https://developer.download.nvidia.com/compute/cuda/12.7.0/local_installers/cuda_12.7.0_566.49_windows.exe"
$installerPath = "$env:USERPROFILE\Downloads\cuda_12.7.0_installer.exe"

Write-Host ""
Write-Host "[2] Download Options:" -ForegroundColor Yellow
Write-Host "    A. Download CUDA Toolkit automatically (3.3 GB)" -ForegroundColor White
Write-Host "    B. Open NVIDIA website to download manually" -ForegroundColor White
Write-Host "    C. Skip download (already have installer)" -ForegroundColor White
Write-Host ""

$choice = Read-Host "Select option (A/B/C)"

switch ($choice.ToUpper()) {
    "A" {
        Write-Host ""
        Write-Host "[3] Downloading CUDA Toolkit 12.7..." -ForegroundColor Yellow
        Write-Host "    This will take several minutes (3.3 GB file)" -ForegroundColor Gray

        try {
            $ProgressPreference = 'Continue'
            Invoke-WebRequest -Uri $cudaUrl -OutFile $installerPath -UseBasicParsing
            Write-Host "    Download complete!" -ForegroundColor Green
            $runInstaller = $true
        } catch {
            Write-Host "    Download failed: $_" -ForegroundColor Red
            Write-Host "    Please download manually from:" -ForegroundColor Yellow
            Write-Host "    https://developer.nvidia.com/cuda-downloads" -ForegroundColor Cyan
            $runInstaller = $false
        }
    }
    "B" {
        Write-Host ""
        Write-Host "[3] Opening NVIDIA download page..." -ForegroundColor Yellow
        Start-Process "https://developer.nvidia.com/cuda-downloads"
        Write-Host "    Please download: CUDA Toolkit 12.7 for Windows 11 x64" -ForegroundColor Cyan
        Write-Host "    Save to: $installerPath" -ForegroundColor Gray
        $runInstaller = $false
    }
    "C" {
        Write-Host ""
        Write-Host "[3] Checking for existing installer..." -ForegroundColor Yellow
        if (Test-Path $installerPath) {
            Write-Host "    Installer found!" -ForegroundColor Green
            $runInstaller = $true
        } else {
            Write-Host "    Installer not found at: $installerPath" -ForegroundColor Red
            $runInstaller = $false
        }
    }
    default {
        Write-Host "Invalid option selected" -ForegroundColor Red
        exit 1
    }
}

# Installation instructions
Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "       INSTALLATION INSTRUCTIONS     " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "When running the CUDA installer:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Choose 'Custom' installation" -ForegroundColor White
Write-Host "2. Select these components:" -ForegroundColor White
Write-Host "   [X] CUDA Development" -ForegroundColor Green
Write-Host "   [X] CUDA Runtime" -ForegroundColor Green
Write-Host "   [X] CUDA Documentation (optional)" -ForegroundColor Gray
Write-Host "   [X] Driver components (if newer)" -ForegroundColor Green
Write-Host ""
Write-Host "3. Installation will take 5-10 minutes" -ForegroundColor White
Write-Host ""

if ($runInstaller -and (Test-Path $installerPath)) {
    $runNow = Read-Host "Run installer now? (Y/N)"
    if ($runNow -eq "Y" -or $runNow -eq "y") {
        Write-Host ""
        Write-Host "Starting CUDA installer..." -ForegroundColor Green
        Write-Host "Please follow the instructions above!" -ForegroundColor Yellow
        Start-Process -FilePath $installerPath -Wait

        Write-Host ""
        Write-Host "[4] Post-Installation Verification" -ForegroundColor Yellow

        # Check if nvcc is available
        $nvccPath = where.exe nvcc 2>$null
        if ($nvccPath) {
            Write-Host "    CUDA compiler found: $nvccPath" -ForegroundColor Green
            nvcc --version
        } else {
            Write-Host "    CUDA compiler not found in PATH" -ForegroundColor Yellow
            Write-Host "    You may need to restart your terminal" -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "        NEXT STEPS AFTER INSTALL     " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Restart your terminal/PowerShell" -ForegroundColor White
Write-Host ""
Write-Host "2. Verify installation:" -ForegroundColor White
Write-Host "   nvcc --version" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Test GPU libraries:" -ForegroundColor White
Write-Host "   python -c `"import cupy; print('CuPy OK')`"" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Run GPU benchmark:" -ForegroundColor White
Write-Host "   python test_cupy_acceleration.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "5. For PyTorch GPU support:" -ForegroundColor White
Write-Host "   pip uninstall torch" -ForegroundColor Cyan
Write-Host "   pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124" -ForegroundColor Cyan
Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "          HELPER COMPLETE            " -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan