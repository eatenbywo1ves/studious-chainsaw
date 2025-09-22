#!/usr/bin/env python3
"""
Test and fix Numba CUDA support for GTX 1080
Pirate mode: Making Numba walk the plank until it works!
"""

import os
import sys
import numpy as np

# Set CUDA environment variables
os.environ['CUDA_HOME'] = r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.0'
os.environ['CUDA_PATH'] = r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.0'
os.environ['PATH'] = os.environ.get('PATH', '') + r';C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.0\bin'

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
    print(f"\n[CONFIG] Numba CUDA config:")
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
            # Check for CUDA toolkit
            nvcc_path = r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.0\bin\nvcc.exe'
            if os.path.exists(nvcc_path):
                print(f"[CHECK] NVCC found at: {nvcc_path}")
            else:
                print("[CHECK] NVCC not found")
            
            # Check for CUDA libraries
            cuda_lib = r'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.0\lib\x64'
            if os.path.exists(cuda_lib):
                print(f"[CHECK] CUDA libraries found at: {cuda_lib}")
            else:
                print("[CHECK] CUDA libraries not found")
            
            # Try lower-level CUDA detection
            from numba.cuda.cudadrv import driver
            driver.init()
            print(f"[CHECK] Driver initialized")
            
        except Exception as e:
            print(f"[ERROR] Manual CUDA init failed: {e}")
        
        # Alternative: Check if it's a version mismatch
        print("\n[INFO] Numba might not support CUDA 13.0 yet")
        print("[INFO] Numba 0.62.0 typically supports CUDA 11.x-12.x")
        print("[SOLUTION] May need to downgrade CUDA toolkit or wait for Numba update")

except ImportError as e:
    print(f"[ERROR] Failed to import Numba: {e}")
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("[COMPLETE] Numba CUDA test finished!")