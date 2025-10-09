#!/usr/bin/env python3
"""
Quick Numba CUDA setup verification test
"""

import os

# Set environment using PyTorch's CUDA libraries
TORCH_LIB = r"C:\Users\Corbin\AppData\Local\Programs\Python\Python312\Lib\site-packages\torch\lib"
os.environ["CUDA_HOME"] = TORCH_LIB
os.environ["CUDA_PATH"] = TORCH_LIB

try:
    from numba import cuda
    import numba
    import numpy as np

    print(f"Numba {numba.__version__}")
    print(f"CUDA available: {cuda.is_available()}")

    if cuda.is_available():
        # Simple kernel test
        @cuda.jit
        def test_kernel(arr):
            idx = cuda.grid(1)
            if idx < arr.size:
                arr[idx] = arr[idx] * 2

        # Test data
        data = np.ones(1000, dtype=np.float32)
        d_data = cuda.to_device(data)

        # Run kernel
        test_kernel[10, 100](d_data)
        result = d_data.copy_to_host()

        if result[0] == 2.0:
            print("[SUCCESS] Numba CUDA kernel execution working!")
            print(f"GPU: {cuda.get_current_device().name.decode()}")
            print(f"Compute Capability: {cuda.get_current_device().compute_capability}")
        else:
            print("[WARNING] Kernel execution failed")
    else:
        print("[ERROR] CUDA not available")

except Exception as e:
    print(f"[ERROR] {e}")
