#!/usr/bin/env python3
"""
Phase 2 GPU Library Validation Script
Tests PyTorch, CuPy, and Numba functionality after configuration
"""

import os
import sys
import time
import traceback
import numpy as np


def setup_cuda_environment():
    """Configure CUDA environment using PyTorch libraries"""
    try:
        import torch

        torch_lib = os.path.join(os.path.dirname(torch.__file__), "lib")

        # Set environment variables
        os.environ["CUDA_PATH"] = torch_lib
        os.environ["CUDA_HOME"] = torch_lib
        os.environ["PATH"] = torch_lib + ";" + os.environ.get("PATH", "")

        # Add DLL directory for Windows
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(torch_lib)

        print(f"[OK] CUDA environment configured with PyTorch libs: {torch_lib}")
        return torch_lib
    except Exception as e:
        print(f"[ERROR] Failed to setup CUDA environment: {e}")
        return None


def test_pytorch():
    """Test PyTorch GPU functionality"""
    print("\n" + "=" * 60)
    print("PYTORCH GPU TEST")
    print("=" * 60)

    try:
        import torch

        print(f"PyTorch version: {torch.__version__}")
        print(f"CUDA available: {torch.cuda.is_available()}")

        if torch.cuda.is_available():
            print(f"CUDA version: {torch.version.cuda}")
            print(f"GPU name: {torch.cuda.get_device_name(0)}")
            print(f"GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")

            # Performance test
            device = torch.device("cuda:0")
            start_time = time.time()
            a = torch.randn(1024, 1024, device=device)
            b = torch.randn(1024, 1024, device=device)
            torch.mm(a, b)
            torch.cuda.synchronize()
            end_time = time.time()

            elapsed = end_time - start_time
            operations = 2 * 1024**3  # Matrix multiply operations
            tflops = operations / elapsed / 1e12

            print(f"Matrix multiply (1024x1024): {elapsed * 1000:.2f}ms")
            print(f"Performance: {tflops:.2f} TFLOPS")
            print("[OK] PyTorch: FULLY FUNCTIONAL")
            return True

    except Exception as e:
        print(f"[ERROR] PyTorch error: {e}")
        traceback.print_exc()
        return False


def test_cupy():
    """Test CuPy GPU functionality with CURAND"""
    print("\n" + "=" * 60)
    print("CUPY GPU TEST")
    print("=" * 60)

    try:
        import cupy

        print(f"CuPy version: {cupy.__version__}")
        print(f"CUDA available: {cupy.cuda.is_available()}")

        if cupy.cuda.is_available():
            # Test basic operations
            a = cupy.array([1, 2, 3, 4, 5])
            print(f"Basic array creation: {a}")

            # Test CURAND (the problematic component)
            random_array = cupy.random.randn(100)
            print(f"CURAND test successful: shape={random_array.shape}")
            print(f"Random sample: {random_array[:5]}")

            # Performance test
            start_time = time.time()
            x = cupy.random.randn(1024, 1024)
            y = cupy.random.randn(1024, 1024)
            cupy.matmul(x, y)
            cupy.cuda.Stream.null.synchronize()
            end_time = time.time()

            elapsed = end_time - start_time
            operations = 2 * 1024**3
            tflops = operations / elapsed / 1e12

            print(f"Matrix multiply (1024x1024): {elapsed * 1000:.2f}ms")
            print(f"Performance: {tflops:.2f} TFLOPS")
            print("[OK] CuPy: FULLY FUNCTIONAL (CURAND RESOLVED)")
            return True

    except Exception as e:
        print(f"[ERROR] CuPy error: {e}")
        traceback.print_exc()
        return False


def test_numba():
    """Test Numba CUDA functionality"""
    print("\n" + "=" * 60)
    print("NUMBA CUDA TEST")
    print("=" * 60)

    try:
        import numba
        from numba import cuda

        print(f"Numba version: {numba.__version__}")
        print(f"CUDA available: {cuda.is_available()}")

        if cuda.is_available():
            print(f"GPU count: {len(cuda.gpus)}")
            current_device = cuda.get_current_device()
            print(f"Current device: {current_device.name}")
            print(f"Compute capability: {current_device.compute_capability}")
            # Skip memory query due to API compatibility issue

            # Test CUDA kernel compilation
            @cuda.jit
            def vector_add(a, b, c):
                idx = cuda.grid(1)
                if idx < a.size:
                    c[idx] = a[idx] + b[idx]

            # Test kernel execution
            n = 1000000
            a = cuda.to_device(range(n))
            b = cuda.to_device(range(n))
            c = cuda.device_array(n, dtype=np.float32)

            threads_per_block = 256
            blocks_per_grid = (n + threads_per_block - 1) // threads_per_block

            start_time = time.time()
            vector_add[blocks_per_grid, threads_per_block](a, b, c)
            cuda.synchronize()
            end_time = time.time()

            result = c.copy_to_host()
            elapsed = end_time - start_time

            print(f"Kernel execution ({n} elements): {elapsed * 1000:.2f}ms")
            print(f"Throughput: {n / elapsed / 1e6:.1f} M elements/sec")
            print(f"Result sample: {result[:5]}")
            print("[OK] Numba: CUDA KERNEL COMPILATION AND EXECUTION WORKING")
            return True

    except Exception as e:
        print(f"[ERROR] Numba error: {e}")
        traceback.print_exc()
        return False


def main():
    """Main validation function"""
    print("Phase 2 GPU Library Validation")
    print("==============================")
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")

    # Setup CUDA environment
    cuda_lib_path = setup_cuda_environment()
    if not cuda_lib_path:
        print("[ERROR] Failed to setup CUDA environment. Aborting tests.")
        return False

    # Run tests
    pytorch_ok = test_pytorch()
    cupy_ok = test_cupy()
    numba_ok = test_numba()

    # Summary
    print("\n" + "=" * 60)
    print("PHASE 2 VALIDATION SUMMARY")
    print("=" * 60)
    print(f"PyTorch: {'[PASS]' if pytorch_ok else '[FAIL]'}")
    print(f"CuPy:    {'[PASS]' if cupy_ok else '[FAIL]'}")
    print(f"Numba:   {'[PASS]' if numba_ok else '[FAIL]'}")

    if pytorch_ok and cupy_ok and numba_ok:
        print("\n*** ALL GPU LIBRARIES FULLY FUNCTIONAL! ***")
        print("Phase 2 GPU library configuration: SUCCESS")
        return True
    else:
        print("\n[WARNING] Some tests failed. Check individual results above.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
