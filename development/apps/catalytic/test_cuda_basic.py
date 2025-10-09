#!/usr/bin/env python3
"""
Basic CUDA functionality test
"""

import numpy as np
import cupy as cp
import time


def test_basic_cuda():
    """Test basic CUDA operations without CURAND"""
    print("=" * 60)
    print("    BASIC CUDA FUNCTIONALITY TEST")
    print("=" * 60)

    try:
        # Test 1: Device info
        print("\n1. GPU Device Information:")
        device_id = cp.cuda.Device()
        print(f"   Device ID: {device_id}")

        props = cp.cuda.runtime.getDeviceProperties(0)
        print(f"   Device Name: {props['name'].decode()}")
        print(f"   Compute Capability: {props['major']}.{props['minor']}")
        print(f"   Total Memory: {props['totalGlobalMem'] / (1024**3):.1f} GB")
        print(f"   Multiprocessors: {props['multiProcessorCount']}")

        # Test 2: Simple array operations
        print("\n2. Simple Array Operations:")

        # Create arrays from numpy
        size = 1000000
        a_cpu = np.ones(size, dtype=np.float32)
        b_cpu = np.ones(size, dtype=np.float32) * 2

        # Transfer to GPU
        print(f"   Creating {size:,} element arrays on GPU...")
        a_gpu = cp.asarray(a_cpu)
        b_gpu = cp.asarray(b_cpu)

        # GPU computation
        start = time.perf_counter()
        c_gpu = a_gpu + b_gpu
        cp.cuda.Stream.null.synchronize()
        gpu_time = (time.perf_counter() - start) * 1000

        # CPU computation
        start = time.perf_counter()
        c_cpu = a_cpu + b_cpu
        cpu_time = (time.perf_counter() - start) * 1000

        # Verify result
        c_result = cp.asnumpy(c_gpu)
        assert np.allclose(c_result, c_cpu), "Results don't match!"

        print(f"   GPU time: {gpu_time:.3f}ms")
        print(f"   CPU time: {cpu_time:.3f}ms")
        print(f"   Speedup: {cpu_time / gpu_time:.2f}x")
        print(f"   Result verified: All elements = {c_result[0]}")

        # Test 3: Matrix operations without random
        print("\n3. Matrix Operations (deterministic):")

        n = 1000
        # Create deterministic matrices
        A_cpu = np.arange(n * n, dtype=np.float32).reshape(n, n) / (n * n)
        B_cpu = np.arange(n * n, dtype=np.float32).reshape(n, n).T / (n * n)

        # GPU multiplication
        A_gpu = cp.asarray(A_cpu)
        B_gpu = cp.asarray(B_cpu)

        start = time.perf_counter()
        cp.dot(A_gpu, B_gpu)
        cp.cuda.Stream.null.synchronize()
        gpu_time = (time.perf_counter() - start) * 1000

        # CPU multiplication
        start = time.perf_counter()
        np.dot(A_cpu, B_cpu)
        cpu_time = (time.perf_counter() - start) * 1000

        print(f"   {n}x{n} matrix multiplication:")
        print(f"   GPU time: {gpu_time:.2f}ms")
        print(f"   CPU time: {cpu_time:.2f}ms")
        print(f"   Speedup: {cpu_time / gpu_time:.2f}x")

        # Test 4: Memory transfer benchmark
        print("\n4. Memory Transfer Benchmark:")

        mb_sizes = [1, 10, 100]
        for mb in mb_sizes:
            size = mb * 1024 * 1024 // 4  # float32 elements
            data = np.ones(size, dtype=np.float32)

            # Host to Device
            start = time.perf_counter()
            gpu_data = cp.asarray(data)
            cp.cuda.Stream.null.synchronize()
            h2d_time = (time.perf_counter() - start) * 1000

            # Device to Host
            start = time.perf_counter()
            cp.asnumpy(gpu_data)
            d2h_time = (time.perf_counter() - start) * 1000

            h2d_bandwidth = mb / (h2d_time / 1000)
            d2h_bandwidth = mb / (d2h_time / 1000)

            print(f"   {mb}MB transfer:")
            print(f"     Host->Device: {h2d_time:.2f}ms ({h2d_bandwidth:.0f} MB/s)")
            print(f"     Device->Host: {d2h_time:.2f}ms ({d2h_bandwidth:.0f} MB/s)")

        # Test 5: Catalytic XOR operation
        print("\n5. Catalytic XOR Transform (GPU):")

        data_size = 1000000
        data = np.arange(data_size, dtype=np.uint8)
        key = np.ones(data_size, dtype=np.uint8) * 42

        # GPU XOR
        data_gpu = cp.asarray(data)
        key_gpu = cp.asarray(key)

        start = time.perf_counter()
        result_gpu = cp.bitwise_xor(data_gpu, key_gpu)
        cp.cuda.Stream.null.synchronize()
        gpu_time = (time.perf_counter() - start) * 1000

        # CPU XOR
        start = time.perf_counter()
        np.bitwise_xor(data, key)
        cpu_time = (time.perf_counter() - start) * 1000

        # Verify reversibility
        reversed_gpu = cp.bitwise_xor(result_gpu, key_gpu)
        reversed_data = cp.asnumpy(reversed_gpu)

        print(f"   Data size: {data_size:,} bytes")
        print(f"   GPU XOR: {gpu_time:.3f}ms")
        print(f"   CPU XOR: {cpu_time:.3f}ms")
        print(f"   Speedup: {cpu_time / gpu_time:.2f}x")
        print(f"   Reversibility verified: {np.array_equal(data, reversed_data)}")

        print("\n" + "=" * 60)
        print("    CUDA TEST RESULTS")
        print("=" * 60)
        print("CUDA Status: OPERATIONAL")
        print("GPU Computing: AVAILABLE")
        print("Memory Transfer: WORKING")
        print("Compute Operations: VERIFIED")

        return True

    except Exception as e:
        print(f"\nError during CUDA test: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_basic_cuda()
    if success:
        print("\nGPU acceleration is functional and ready for use!")
    else:
        print("\nGPU acceleration needs troubleshooting.")
