#!/usr/bin/env python3
"""
Test and fix Numba CUDA support for GTX 1080
Pirate mode: Making Numba walk the plank until it works!
"""

import os
import numpy as np

# Set CUDA environment variables to use PyTorch's CUDA 12.1 libraries
TORCH_CUDA_PATH = (
    r"C:\Users\Corbin\AppData\Local\Programs\Python\Python312\Lib\site-packages\torch\lib"
)
os.environ["CUDA_HOME"] = TORCH_CUDA_PATH
os.environ["CUDA_PATH"] = TORCH_CUDA_PATH
os.environ["PATH"] = TORCH_CUDA_PATH + ";" + os.environ.get("PATH", "")

print("[PIRATE] Testing Numba CUDA Support")
print("=" * 60)

try:
    from numba import cuda, config
    import numba

    print(f"[INFO] Numba version: {numba.__version__}")
    print(f"[INFO] CUDA available: {cuda.is_available()}")

    # Try to detect GPUs
    cuda.detect()

    # Check configuration
    print("\n[CONFIG] Numba CUDA config:")
    print(f"  CUDA_HOME: {os.environ.get('CUDA_HOME', 'Not set')}")
    print(f"  Disable CUDA: {config.DISABLE_CUDA}")

    if cuda.is_available():
        print("\n[SUCCESS] CUDA is available!")

        # Test a simple kernel
        @cuda.jit
        def add_kernel(x, y, out):
            idx = cuda.grid(1)
            if idx < x.size:
                out[idx] = x[idx] + y[idx]

        # Create test arrays
        n = 1000000
        x = np.arange(n, dtype=np.float32)
        y = np.ones(n, dtype=np.float32)
        out = np.zeros(n, dtype=np.float32)

        # Transfer to GPU and run kernel
        d_x = cuda.to_device(x)
        d_y = cuda.to_device(y)
        d_out = cuda.device_array_like(out)

        # Configure kernel
        threads_per_block = 256
        blocks_per_grid = (n + threads_per_block - 1) // threads_per_block

        # Run kernel
        add_kernel[blocks_per_grid, threads_per_block](d_x, d_y, d_out)

        # Get result
        result = d_out.copy_to_host()

        # Verify
        expected = x + y
        if np.allclose(result, expected):
            print("\n[TEST] Kernel execution: PASSED!")
            print(f"  Processed {n} elements")
            print(f"  Result sample: {result[:5]}")
        else:
            print("\n[TEST] Kernel execution: FAILED!")

    else:
        print("\n[WARNING] CUDA not available. Checking why...")

        # Try to manually initialize CUDA
        try:
            # Check for PyTorch CUDA libraries
            cuda_dll_path = os.path.join(TORCH_CUDA_PATH, "cudart64_12.dll")
            if os.path.exists(cuda_dll_path):
                print(f"[CHECK] PyTorch CUDA runtime found at: {cuda_dll_path}")
            else:
                print("[CHECK] PyTorch CUDA runtime not found")

            # Check for CUDA libraries
            if os.path.exists(TORCH_CUDA_PATH):
                print(f"[CHECK] PyTorch CUDA libraries found at: {TORCH_CUDA_PATH}")
            else:
                print("[CHECK] PyTorch CUDA libraries not found")

            # Try lower-level CUDA detection
            from numba.cuda.cudadrv import driver

            driver.init()
            print("[CHECK] Driver initialized")

        except Exception as e:
            print(f"[ERROR] Manual CUDA init failed: {e}")

        # Alternative: Check if it's a version mismatch
        print("\n[INFO] Using PyTorch's CUDA 12.1 libraries (compatible with Numba 0.62.0)")
        print("[INFO] If still failing, try: pip install numba-cuda")
        print("[SOLUTION] Consider using modern numba-cuda package for better CUDA 12+ support")

except ImportError as e:
    print(f"[ERROR] Failed to import Numba: {e}")
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    import traceback

    traceback.print_exc()

print("\n" + "=" * 60)
print("[COMPLETE] Numba CUDA test finished!")
