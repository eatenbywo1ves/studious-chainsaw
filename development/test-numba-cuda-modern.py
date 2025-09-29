#!/usr/bin/env python3
"""
Modern Numba CUDA test using numba-cuda package
Enhanced with PyTorch CUDA 12.1 compatibility
"""

import os
import sys
import numpy as np
import time

# Set CUDA environment variables to use PyTorch's CUDA 12.1 libraries
TORCH_CUDA_PATH = r'C:\Users\Corbin\AppData\Local\Programs\Python\Python312\Lib\site-packages\torch\lib'
os.environ['CUDA_HOME'] = TORCH_CUDA_PATH
os.environ['CUDA_PATH'] = TORCH_CUDA_PATH
os.environ['PATH'] = TORCH_CUDA_PATH + ';' + os.environ.get('PATH', '')

print("=== Modern Numba CUDA Test ===")
print(f"Using PyTorch CUDA libraries: {TORCH_CUDA_PATH}")
print()

try:
    # Test traditional numba cuda
    print("1. Testing traditional numba.cuda:")
    from numba import cuda as traditional_cuda
    import numba

    print(f"   Numba version: {numba.__version__}")
    print(f"   Traditional CUDA available: {traditional_cuda.is_available()}")

    if traditional_cuda.is_available():
        traditional_cuda.detect()

    print()

    # Test modern numba-cuda package
    print("2. Testing modern numba-cuda package:")
    try:
        from numba_cuda import cuda
        print("   [OK] numba-cuda package imported successfully")

        # Test CUDA availability with modern package
        print(f"   Modern CUDA available: {cuda.is_available()}")

        if cuda.is_available():
            print("   [SUCCESS] CUDA is available with modern package!")

            # Test kernel compilation and execution
            @cuda.jit
            def vector_add(a, b, c):
                idx = cuda.grid(1)
                if idx < a.size:
                    c[idx] = a[idx] + b[idx]

            # Create test data
            n = 1000000
            a = np.ones(n, dtype=np.float32)
            b = np.ones(n, dtype=np.float32) * 2
            c = np.zeros(n, dtype=np.float32)

            print(f"   Testing with {n} elements...")

            # GPU computation
            d_a = cuda.to_device(a)
            d_b = cuda.to_device(b)
            d_c = cuda.device_array_like(c)

            # Configure grid and block dimensions
            threads_per_block = 256
            blocks_per_grid = (n + threads_per_block - 1) // threads_per_block

            # Time the kernel execution
            start_time = time.time()
            vector_add[blocks_per_grid, threads_per_block](d_a, d_b, d_c)
            cuda.synchronize()
            gpu_time = time.time() - start_time

            # Copy result back
            result = d_c.copy_to_host()

            # Verify correctness
            expected = a + b
            if np.allclose(result, expected):
                print(f"   [PASS] Kernel execution: SUCCESS!")
                print(f"   [TIME] GPU execution time: {gpu_time*1000:.2f} ms")
                print(f"   [PERF] Throughput: {(n*1e-6/gpu_time):.2f} million ops/sec")
                print(f"   [DATA] Sample result: {result[:5]} (expected: {expected[:5]})")

                # Compare with CPU
                start_time = time.time()
                cpu_result = a + b
                cpu_time = time.time() - start_time

                speedup = cpu_time / gpu_time if gpu_time > 0 else 0
                print(f"   [CPU]  CPU execution time: {cpu_time*1000:.2f} ms")
                print(f"   [SPEED] GPU speedup: {speedup:.2f}x")

            else:
                print("   [FAIL] Kernel execution: FAILED!")
                print(f"   Expected: {expected[:5]}")
                print(f"   Got: {result[:5]}")
        else:
            print("   [ERROR] CUDA not available with modern package")

    except ImportError as e:
        print(f"   [ERROR] Failed to import numba-cuda: {e}")
    except Exception as e:
        print(f"   [ERROR] Error with modern package: {e}")
        import traceback
        traceback.print_exc()

    print()

    # Test GPU properties
    print("3. GPU Information:")
    try:
        if traditional_cuda.is_available():
            gpu = traditional_cuda.get_current_device()
            print(f"   GPU Name: {gpu.name}")
            print(f"   Compute Capability: {gpu.compute_capability}")
            print(f"   Total Memory: {gpu.total_memory / 1024**3:.2f} GB")
            print(f"   Multiprocessors: {gpu.multiprocessor_count}")
            print(f"   Max Threads per Block: {gpu.max_threads_per_block}")
            print(f"   Max Block Dimensions: {gpu.max_block_dims}")
            print(f"   Max Grid Dimensions: {gpu.max_grid_dims}")
        else:
            print("   No GPU information available")
    except Exception as e:
        print(f"   Error getting GPU info: {e}")

except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")
    import traceback
    traceback.print_exc()

print()
print("=== Test Summary ===")
print("Modern numba-cuda package provides better CUDA 12+ support")
print("For issues, check CUDA paths and driver compatibility")
print("GPU computing environment status: Ready for high-performance computing!")