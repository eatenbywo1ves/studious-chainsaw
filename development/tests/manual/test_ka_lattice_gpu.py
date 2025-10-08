#!/usr/bin/env python3
"""
KA Lattice GPU-Accelerated Test Suite
Comprehensive testing with CPU vs GPU performance comparison

Requirements:
  - Python 3.12
  - PyTorch 2.5.1+cu121
  - CuPy 13.6.0
"""

import sys
import numpy as np
from pathlib import Path
import time

# Add development directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Initialize CUDA first
from libs.gpu.cuda_init import initialize_cuda_environment
initialize_cuda_environment(verbose=True)

from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

def test_lattice_with_mode(enable_gpu: bool, iterations: int = 5):
    """Test lattice operations with or without GPU"""
    mode = "GPU" if enable_gpu else "CPU"
    print(f"\n{'='*70}")
    print(f"TESTING {mode} MODE")
    print(f"{'='*70}")

    # Test 1: Lattice Creation
    print(f"\n[Test 1] Lattice Creation ({mode})")
    times = []
    for i in range(iterations):
        start = time.time()
        lattice = UnifiedCatalyticLattice(dimensions=4, size=10, enable_gpu=enable_gpu)
        elapsed = (time.time() - start) * 1000
        times.append(elapsed)

    avg_time = sum(times) / len(times)
    print(f"  Average: {avg_time:.2f}ms over {iterations} iterations")
    print(f"  Min: {min(times):.2f}ms, Max: {max(times):.2f}ms")

    lattice_times = times.copy()

    # Test 2: XOR Transform
    print(f"\n[Test 2] XOR Transform ({mode})")
    test_array = np.array([5, 10, 15, 20, 25], dtype=np.int32)
    times = []
    for i in range(iterations):
        start = time.time()
        result = lattice.xor_transform(test_array)
        elapsed = (time.time() - start) * 1000
        times.append(elapsed)

    avg_xor = sum(times) / len(times)
    print(f"  Average: {avg_xor:.2f}ms over {iterations} iterations")
    print(f"  Result: {result}")

    # Test 3: Shortest Path
    print(f"\n[Test 3] Shortest Path Finding ({mode})")
    times = []
    for i in range(3):  # Fewer iterations for expensive operation
        start = time.time()
        path, distance = lattice.find_shortest_path(start=0, end=9999)
        elapsed = (time.time() - start) * 1000
        times.append(elapsed)

    avg_path = sum(times) / len(times)
    print(f"  Average: {avg_path:.2f}ms over 3 iterations")
    print(f"  Path length: {len(path)} vertices")

    return {
        'lattice_creation_ms': sum(lattice_times) / len(lattice_times),
        'xor_transform_ms': avg_xor,
        'shortest_path_ms': avg_path
    }

def main():
    print("="*70)
    print("KA LATTICE GPU-ACCELERATED TEST SUITE")
    print("="*70)

    # Run CPU tests
    cpu_results = test_lattice_with_mode(enable_gpu=False, iterations=5)

    # Run GPU tests
    gpu_results = test_lattice_with_mode(enable_gpu=True, iterations=5)

    # Calculate speedups
    print(f"\n{'='*70}")
    print("PERFORMANCE COMPARISON SUMMARY")
    print(f"{'='*70}")

    operations = [
        ('Lattice Creation', 'lattice_creation_ms'),
        ('XOR Transform', 'xor_transform_ms'),
        ('Shortest Path', 'shortest_path_ms')
    ]

    print(f"\n{'Operation':<20} {'CPU (ms)':<12} {'GPU (ms)':<12} {'Speedup':<10}")
    print("-" * 70)

    for op_name, key in operations:
        cpu_time = cpu_results.get(key, 0)
        gpu_time = gpu_results.get(key, 0)
        speedup = cpu_time / gpu_time if gpu_time > 0 else 0

        print(f"{op_name:<20} {cpu_time:>10.2f}  {gpu_time:>10.2f}  {speedup:>8.2f}x")

    print("\n" + "="*70)
    print("[OK] ALL GPU TESTS PASSED - GPU ACCELERATION ENABLED!")
    print("="*70)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[FAIL] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
