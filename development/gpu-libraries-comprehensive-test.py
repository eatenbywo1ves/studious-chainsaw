#!/usr/bin/env python3
"""
Comprehensive GPU Libraries Test Suite
Tests PyTorch, CuPy, and Numba GPU functionality
"""

import time
import numpy as np

def test_pytorch():
    """Test PyTorch GPU functionality"""
    print("=" * 60)
    print("[TEST 1] PyTorch GPU Support")
    print("=" * 60)

    try:
        import torch
        print(f"[OK] PyTorch version: {torch.__version__}")
        print(f"[OK] CUDA available: {torch.cuda.is_available()}")

        if torch.cuda.is_available():
            print(f"[OK] CUDA device: {torch.cuda.get_device_name(0)}")
            print(f"[OK] CUDA capability: {torch.cuda.get_device_capability(0)}")
            print(f"[OK] GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")

            # Performance test
            print("\nPerformance Test:")
            device = torch.device('cuda')
            a = torch.randn(2048, 2048, device=device)
            b = torch.randn(2048, 2048, device=device)

            start_time = time.time()
            torch.mm(a, b)
            torch.cuda.synchronize()
            elapsed = time.time() - start_time

            # Calculate FLOPS (2048^3 * 2 operations for matrix multiply)
            flops = (2048 ** 3) * 2
            tflops = flops / elapsed / 1e12

            print(f"[OK] Matrix multiply (2048x2048): {elapsed*1000:.1f}ms")
            print(f"[OK] Performance: {tflops:.2f} TFLOPS")

            return True
        else:
            print("[FAIL] CUDA not available")
            return False

    except ImportError:
        print("[FAIL] PyTorch not installed")
        return False
    except Exception as e:
        print(f"[FAIL] PyTorch error: {e}")
        return False

def test_cupy():
    """Test CuPy GPU functionality"""
    print("\n" + "=" * 60)
    print("[TEST 2] CuPy GPU Support")
    print("=" * 60)

    try:
        import cupy as cp
        print(f"[OK] CuPy version: {cp.__version__}")
        print(f"[OK] CUDA available: {cp.cuda.is_available()}")

        if cp.cuda.is_available():
            print(f"[OK] Device count: {cp.cuda.runtime.getDeviceCount()}")

            with cp.cuda.Device(0):
                props = cp.cuda.runtime.getDeviceProperties(0)
                print(f"[OK] Device name: {props['name'].decode('utf-8')}")
                print(f"[OK] Compute capability: {props['major']}.{props['minor']}")
                print(f"[OK] Memory: {props['totalGlobalMem'] / 1e9:.1f} GB")

            # Performance test
            print("\nPerformance Test:")
            a = cp.random.randn(2048, 2048, dtype=cp.float32)
            b = cp.random.randn(2048, 2048, dtype=cp.float32)

            start_time = time.time()
            cp.matmul(a, b)
            cp.cuda.Stream.null.synchronize()
            elapsed = time.time() - start_time

            # Calculate FLOPS
            flops = (2048 ** 3) * 2
            tflops = flops / elapsed / 1e12

            print(f"[OK] Matrix multiply (2048x2048): {elapsed*1000:.1f}ms")
            print(f"[OK] Performance: {tflops:.2f} TFLOPS")

            # Test memory transfer
            cpu_array = np.random.randn(1000, 1000).astype(np.float32)
            start_time = time.time()
            gpu_array = cp.asarray(cpu_array)
            cp.asnumpy(gpu_array)
            transfer_time = time.time() - start_time
            print(f"[OK] Memory transfer (1M elements): {transfer_time*1000:.1f}ms")

            return True
        else:
            print("[FAIL] CUDA not available")
            return False

    except ImportError:
        print("[FAIL] CuPy not installed")
        return False
    except Exception as e:
        print(f"[FAIL] CuPy error: {e}")
        return False

def test_numba():
    """Test Numba CUDA functionality"""
    print("\n" + "=" * 60)
    print("[TEST 3] Numba CUDA Support")
    print("=" * 60)

    try:
        from numba import cuda, types
        import numba

        print(f"[OK] Numba version: {numba.__version__}")
        print(f"[OK] CUDA available: {cuda.is_available()}")

        if cuda.is_available():
            print(f"[OK] CUDA devices: {len(cuda.list_devices())}")

            for i, device in enumerate(cuda.list_devices()):
                device.use()
                print(f"[OK] Device {i}: {device.name.decode('utf-8')}")
                print(f"[OK] Compute capability: {device.compute_capability}")
                print(f"[OK] Memory: {device.memory_size / 1e9:.1f} GB")

            # Performance test with custom kernel
            print("\nPerformance Test:")

            @cuda.jit
            def vector_add(a, b, c):
                idx = cuda.grid(1)
                if idx < a.size:
                    c[idx] = a[idx] + b[idx]

            N = 10000000  # 10M elements
            a = np.random.randn(N).astype(np.float32)
            b = np.random.randn(N).astype(np.float32)
            c = np.zeros(N, dtype=np.float32)

            # Transfer to GPU
            d_a = cuda.to_device(a)
            d_b = cuda.to_device(b)
            d_c = cuda.to_device(c)

            # Configure kernel
            threads_per_block = 256
            blocks_per_grid = (N + threads_per_block - 1) // threads_per_block

            start_time = time.time()
            vector_add[blocks_per_grid, threads_per_block](d_a, d_b, d_c)
            cuda.synchronize()
            elapsed = time.time() - start_time

            # Calculate performance
            gops = N / elapsed / 1e9
            print(f"[OK] Vector add ({N/1e6:.0f}M elements): {elapsed*1000:.1f}ms")
            print(f"[OK] Performance: {gops:.1f} GOPS")

            # Verify result
            result = d_c.copy_to_host()
            expected = a + b
            if np.allclose(result, expected, rtol=1e-5):
                print("[OK] Result verification: PASSED")
            else:
                print("[FAIL] Result verification: FAILED")

            return True
        else:
            print("[FAIL] CUDA not available")
            return False

    except ImportError:
        print("[FAIL] Numba not installed")
        return False
    except Exception as e:
        print(f"[FAIL] Numba error: {e}")
        return False

def main():
    """Run comprehensive GPU test suite"""
    print("COMPREHENSIVE GPU LIBRARIES TEST SUITE")
    print("Testing PyTorch, CuPy, and Numba GPU functionality")
    print("=" * 80)

    results = {
        'pytorch': test_pytorch(),
        'cupy': test_cupy(),
        'numba': test_numba()
    }

    print("\n" + "=" * 80)
    print("[FINAL RESULTS]")
    print("=" * 80)

    working_count = sum(results.values())
    total_count = len(results)

    print(f"Working libraries: {working_count}/{total_count}")
    print()

    for library, status in results.items():
        status_text = "WORKING" if status else "NOT WORKING"
        status_mark = "[OK]" if status else "[FAIL]"
        print(f"{status_mark} {library.capitalize()}: {status_text}")

    if working_count == total_count:
        print("\nALL GPU LIBRARIES ARE FULLY FUNCTIONAL!")
        print("Your system is ready for high-performance GPU computing!")
    elif working_count > 0:
        print(f"\n{working_count} out of {total_count} libraries working")
        print("Some GPU functionality available")
    else:
        print("\nNO GPU LIBRARIES WORKING")
        print("GPU acceleration not available")

    print("\n" + "=" * 80)

if __name__ == "__main__":
    main()
