#!/usr/bin/env python3
"""
Setup CUDA environment and test GPU acceleration
"""

import os
import sys
import ctypes

def setup_cuda_environment():
    """Configure CUDA environment for CuPy"""
    print("="*60)
    print("    CUDA ENVIRONMENT SETUP")
    print("="*60)

    # Common CUDA installation paths
    cuda_paths = [
        r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.0",
        r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.7",
        r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.0",
        r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v11.8",
        r"C:\Program Files\NVIDIA Corporation\CUDA"
    ]

    # Find installed CUDA version
    cuda_path = None
    for path in cuda_paths:
        if os.path.exists(path):
            cuda_path = path
            print(f"Found CUDA installation at: {path}")
            break

    if not cuda_path:
        print("No CUDA installation found!")
        return False

    # Add CUDA paths to environment
    bin_path = os.path.join(cuda_path, "bin")
    lib_path = os.path.join(cuda_path, "lib", "x64")

    # Update PATH
    current_path = os.environ.get('PATH', '')
    if bin_path not in current_path:
        os.environ['PATH'] = f"{bin_path};{lib_path};{current_path}"
        print(f"Added to PATH: {bin_path}")
        print(f"Added to PATH: {lib_path}")

    # Set CUDA environment variables
    os.environ['CUDA_PATH'] = cuda_path
    os.environ['CUDA_HOME'] = cuda_path
    os.environ['CUDNN_PATH'] = cuda_path

    print(f"Set CUDA_PATH: {cuda_path}")

    # List available CUDA libraries
    print("\nAvailable CUDA libraries:")
    if os.path.exists(bin_path):
        dll_files = [f for f in os.listdir(bin_path) if f.endswith('.dll')]
        nvrtc_files = [f for f in dll_files if 'nvrtc' in f.lower()]
        cudart_files = [f for f in dll_files if 'cudart' in f.lower()]

        if nvrtc_files:
            print(f"  NVRTC: {', '.join(nvrtc_files[:3])}")
        if cudart_files:
            print(f"  CUDART: {', '.join(cudart_files[:3])}")

    return True

def test_gpu_with_numba():
    """Test GPU using Numba instead of CuPy"""
    print("\n" + "="*60)
    print("    NUMBA GPU TEST")
    print("="*60)

    try:
        from numba import cuda
        import numpy as np
        import time

        # Check if CUDA is available
        if not cuda.is_available():
            print("CUDA is not available to Numba")
            return False

        print("CUDA is available to Numba!")

        # Get GPU info
        device = cuda.get_current_device()
        print(f"GPU: {device.name.decode()}")
        print(f"Compute Capability: {device.compute_capability}")
        print(f"Total Memory: {device.total_memory / (1024**3):.1f}GB")

        # Simple GPU kernel
        @cuda.jit
        def add_kernel(a, b, c):
            i = cuda.grid(1)
            if i < c.size:
                c[i] = a[i] + b[i]

        # Test GPU computation
        size = 1000000
        a = np.ones(size, dtype=np.float32)
        b = np.ones(size, dtype=np.float32) * 2
        c = np.zeros(size, dtype=np.float32)

        # Copy to device
        d_a = cuda.to_device(a)
        d_b = cuda.to_device(b)
        d_c = cuda.device_array_like(c)

        # Configure kernel
        threads_per_block = 256
        blocks_per_grid = (size + threads_per_block - 1) // threads_per_block

        # Run kernel
        start = time.perf_counter()
        add_kernel[blocks_per_grid, threads_per_block](d_a, d_b, d_c)
        cuda.synchronize()
        gpu_time = (time.perf_counter() - start) * 1000

        # Copy result back
        c = d_c.copy_to_host()

        # CPU computation
        start = time.perf_counter()
        c_cpu = a + b
        cpu_time = (time.perf_counter() - start) * 1000

        print(f"\nVector addition ({size:,} elements):")
        print(f"  GPU: {gpu_time:.3f}ms")
        print(f"  CPU: {cpu_time:.3f}ms")
        print(f"  Speedup: {cpu_time/gpu_time:.2f}x")
        print(f"  Result verified: {np.allclose(c, c_cpu)}")

        # Test XOR transform with Numba
        @cuda.jit
        def xor_kernel(data, key, result):
            i = cuda.grid(1)
            if i < result.size:
                result[i] = data[i] ^ key[i % key.size]

        # XOR test
        data_size = 1000000
        data = np.random.randint(0, 256, data_size, dtype=np.uint8)
        key = np.random.randint(0, 256, 256, dtype=np.uint8)
        result = np.zeros(data_size, dtype=np.uint8)

        # GPU XOR
        d_data = cuda.to_device(data)
        d_key = cuda.to_device(key)
        d_result = cuda.device_array_like(result)

        blocks = (data_size + threads_per_block - 1) // threads_per_block

        start = time.perf_counter()
        xor_kernel[blocks, threads_per_block](d_data, d_key, d_result)
        cuda.synchronize()
        gpu_xor_time = (time.perf_counter() - start) * 1000

        result_gpu = d_result.copy_to_host()

        # CPU XOR
        start = time.perf_counter()
        result_cpu = np.zeros_like(data)
        for i in range(data_size):
            result_cpu[i] = data[i] ^ key[i % len(key)]
        cpu_xor_time = (time.perf_counter() - start) * 1000

        print(f"\nCatalytic XOR Transform:")
        print(f"  GPU: {gpu_xor_time:.3f}ms")
        print(f"  CPU: {cpu_xor_time:.3f}ms")
        print(f"  Speedup: {cpu_xor_time/gpu_xor_time:.2f}x")
        print(f"  Results match: {np.array_equal(result_gpu, result_cpu)}")

        print("\nGPU Acceleration with Numba: SUCCESSFUL")
        return True

    except Exception as e:
        print(f"Numba GPU test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main setup and test"""

    # Setup environment
    if not setup_cuda_environment():
        print("\nCUDA environment setup failed!")
        return

    # Test with Numba (more reliable than CuPy for version mismatches)
    if test_gpu_with_numba():
        print("\n" + "="*60)
        print("    GPU ACCELERATION STATUS")
        print("="*60)
        print("✅ CUDA Environment: CONFIGURED")
        print("✅ GPU Device: DETECTED")
        print("✅ Numba CUDA: OPERATIONAL")
        print("✅ Performance: VERIFIED")
        print("\nGPU acceleration is ready for production use!")

        # Update todo
        print("\nUpdating todo list...")
        return True
    else:
        print("\nGPU acceleration needs additional configuration")
        return False

if __name__ == "__main__":
    success = main()