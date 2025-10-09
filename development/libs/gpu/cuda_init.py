"""
CUDA Environment Initialization
Configures CUDA paths using PyTorch's bundled CUDA libraries (Phase 2 Solution)

This module solves the CURAND_STATUS_INITIALIZATION_FAILED issue by directing
CuPy and other GPU libraries to use PyTorch's bundled CUDA 12.1 runtime.

Usage:
    # Import at the start of your application before any GPU operations
    from libs.gpu.cuda_init import initialize_cuda_environment

    initialize_cuda_environment()
    # Now CuPy, Numba, and other GPU libraries can use CUDA

Requirements:
    - Python 3.12 with PyTorch 2.5.1+cu121 (has bundled CUDA libraries)
    - CuPy 13.6.0 (cupy-cuda12x)
    - Windows with NVIDIA GPU
"""

import os
import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Global flag to track initialization
_cuda_initialized = False
_cuda_available = False
_torch_cuda_lib_path: Optional[Path] = None


def initialize_cuda_environment(force: bool = False, verbose: bool = True) -> bool:
    """
    Initialize CUDA environment using PyTorch's bundled CUDA libraries

    This function must be called before importing CuPy or using GPU operations.
    It configures environment variables to point to PyTorch's CUDA runtime.

    Args:
        force: Re-initialize even if already initialized
        verbose: Print status messages

    Returns:
        True if CUDA is available and initialized, False otherwise
    """
    global _cuda_initialized, _cuda_available, _torch_cuda_lib_path

    if _cuda_initialized and not force:
        if verbose:
            logger.info(f"CUDA already initialized: {_torch_cuda_lib_path}")
        return _cuda_available

    try:
        # Import PyTorch to get its bundled CUDA libraries
        import torch

        if not torch.cuda.is_available():
            if verbose:
                logger.warning("PyTorch reports CUDA not available")
            _cuda_initialized = True
            _cuda_available = False
            return False

        # Get PyTorch's lib directory (contains CUDA DLLs)
        torch_path = Path(torch.__file__).parent
        torch_lib = torch_path / "lib"

        if not torch_lib.exists():
            if verbose:
                logger.error(f"PyTorch lib directory not found: {torch_lib}")
            _cuda_initialized = True
            _cuda_available = False
            return False

        # Check for CUDA DLLs
        cuda_dlls = list(torch_lib.glob("*cuda*.dll"))
        if not cuda_dlls:
            if verbose:
                logger.warning(f"No CUDA DLLs found in {torch_lib}")
            _cuda_initialized = True
            _cuda_available = False
            return False

        # Configure environment variables
        torch_lib_str = str(torch_lib.absolute())
        os.environ["CUDA_PATH"] = torch_lib_str
        os.environ["CUDA_HOME"] = torch_lib_str

        # Add to PATH (prepend to prioritize PyTorch's CUDA)
        current_path = os.environ.get("PATH", "")
        if torch_lib_str not in current_path:
            os.environ["PATH"] = torch_lib_str + ";" + current_path

        # Add DLL directory for Windows
        if hasattr(os, "add_dll_directory"):
            try:
                os.add_dll_directory(torch_lib_str)
            except Exception as e:
                logger.warning(f"Could not add DLL directory: {e}")

        _torch_cuda_lib_path = torch_lib
        _cuda_initialized = True
        _cuda_available = True

        if verbose:
            logger.info("[OK] CUDA environment initialized")
            logger.info(f"  PyTorch version: {torch.__version__}")
            logger.info(f"  CUDA version: {torch.version.cuda}")
            logger.info(f"  CUDA lib path: {torch_lib}")
            logger.info(f"  GPU: {torch.cuda.get_device_name(0)}")

        return True

    except ImportError as e:
        if verbose:
            logger.error(f"PyTorch not available: {e}")
        _cuda_initialized = True
        _cuda_available = False
        return False

    except Exception as e:
        if verbose:
            logger.error(f"CUDA initialization failed: {e}")
        _cuda_initialized = True
        _cuda_available = False
        return False


def is_cuda_available() -> bool:
    """
    Check if CUDA is available

    Returns:
        True if CUDA was successfully initialized, False otherwise
    """
    if not _cuda_initialized:
        initialize_cuda_environment(verbose=False)

    return _cuda_available


def get_cuda_lib_path() -> Optional[Path]:
    """
    Get the path to CUDA libraries

    Returns:
        Path to PyTorch's CUDA lib directory if available, None otherwise
    """
    if not _cuda_initialized:
        initialize_cuda_environment(verbose=False)

    return _torch_cuda_lib_path


def get_cuda_info() -> Tuple[bool, dict]:
    """
    Get detailed CUDA information

    Returns:
        Tuple of (cuda_available, info_dict)
        info_dict contains: version, device_name, lib_path, dll_count
    """
    if not _cuda_initialized:
        initialize_cuda_environment(verbose=False)

    info = {
        "available": _cuda_available,
        "initialized": _cuda_initialized,
        "lib_path": str(_torch_cuda_lib_path) if _torch_cuda_lib_path else None,
        "dll_count": 0,
        "version": None,
        "device_name": None,
    }

    if _cuda_available:
        try:
            import torch

            info["version"] = torch.version.cuda
            info["device_name"] = torch.cuda.get_device_name(0)

            if _torch_cuda_lib_path:
                info["dll_count"] = len(list(_torch_cuda_lib_path.glob("*.dll")))
        except Exception as e:
            logger.error(f"Error getting CUDA info: {e}")

    return _cuda_available, info


def validate_cupy_curand() -> bool:
    """
    Validate that CuPy's CURAND functionality works

    Returns:
        True if CURAND test passes, False otherwise
    """
    if not is_cuda_available():
        return False

    try:
        import cupy as cp

        # Test CURAND - this was the problematic operation
        x = cp.random.randn(10)
        logger.info(f"[OK] CuPy CURAND test passed: shape={x.shape}")
        return True
    except Exception as e:
        logger.error(f"CuPy CURAND test failed: {e}")
        return False


# Auto-initialize on import if requested
if os.environ.get("AUTO_INIT_CUDA", "").lower() in ("1", "true", "yes"):
    initialize_cuda_environment(verbose=True)


if __name__ == "__main__":
    # Test the initialization
    print("=" * 60)
    print("CUDA Environment Initialization Test")
    print("=" * 60)

    success = initialize_cuda_environment(verbose=True)

    if success:
        print("\n[OK] CUDA initialization successful!")

        # Test CuPy CURAND
        print("\nTesting CuPy CURAND...")
        if validate_cupy_curand():
            print("[OK] CuPy CURAND working!")
        else:
            print("[FAIL] CuPy CURAND test failed")
    else:
        print("\n[FAIL] CUDA initialization failed")
        print("  Possible reasons:")
        print("  - PyTorch not installed or CPU-only version")
        print("  - Python version not 3.12 (needs PyTorch with CUDA)")
        print("  - No NVIDIA GPU available")

    # Print detailed info
    available, info = get_cuda_info()
    print("\nCUDA Information:")
    for key, value in info.items():
        print(f"  {key}: {value}")
