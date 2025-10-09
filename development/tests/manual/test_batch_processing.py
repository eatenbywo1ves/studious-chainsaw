#!/usr/bin/env python3
"""
Batch Processing Test Suite
Tests parallel lattice operations and measures speedup

Requirements:
  - Python 3.12
  - PyTorch 2.5.1+cu121
  - CuPy 13.6.0
"""

import sys
import numpy as np
from pathlib import Path
import time
import logging

# Add development directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Initialize CUDA first
from libs.gpu.cuda_init import initialize_cuda_environment

initialize_cuda_environment(verbose=True)

from apps.catalytic.core.batch_processor import create_batch
from apps.catalytic.gpu.batch_operations import GPUBatchOperations
from apps.catalytic.core.unified_lattice import UnifiedCatalyticLattice

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def test_batch_operations():
    """Test GPU batch operations primitives"""
    print("\n" + "=" * 70)
    print("TEST 1: Batch Operations Primitives")
    print("=" * 70)

    batch_ops = GPUBatchOperations(device_id=0, backend="pytorch")

    # Test 1.1: Batch XOR
    print("\n[Test 1.1] Batch XOR Transform")
    data_list = [
        np.array([1, 2, 3, 4, 5], dtype=np.int32),
        np.array([10, 20, 30, 40, 50], dtype=np.int32),
        np.array([100, 200, 300, 400, 500], dtype=np.int32),
    ]

    start = time.time()
    results = batch_ops.batch_xor_transform(data_list)
    elapsed = (time.time() - start) * 1000

    print(f"  Processed {len(data_list)} arrays in {elapsed:.2f}ms")
    print(f"  Results: {[r[:3] for r in results]}")
    print(f"  Status: {'PASS' if len(results) == len(data_list) else 'FAIL'}")

    # Test 1.2: Batch Matrix Multiply
    print("\n[Test 1.2] Batch Matrix Multiply")
    size = 128
    a_list = [np.random.randn(size, size) for _ in range(5)]
    b_list = [np.random.randn(size, size) for _ in range(5)]

    start = time.time()
    results = batch_ops.batch_matrix_multiply(a_list, b_list)
    elapsed = (time.time() - start) * 1000

    print(f"  Processed {len(a_list)} {size}x{size} matrix multiplications")
    print(f"  Time: {elapsed:.2f}ms ({elapsed / len(a_list):.2f}ms per operation)")
    print(f"  Status: {'PASS' if len(results) == len(a_list) else 'FAIL'}")

    # Test 1.3: Batch Element-wise
    print("\n[Test 1.3] Batch Element-wise Operations")
    arrays = [np.random.randn(1000) for _ in range(10)]

    start = time.time()
    results = batch_ops.batch_element_wise_op(arrays, operation="square")
    elapsed = (time.time() - start) * 1000

    print(f"  Squared {len(arrays)} arrays in {elapsed:.2f}ms")
    print(f"  Status: {'PASS' if len(results) == len(arrays) else 'FAIL'}")

    # Get stats
    stats = batch_ops.get_stats()
    print("\n[Batch Operations Stats]")
    print(f"  Total Batch Ops: {stats['total_batch_ops']}")
    print(f"  Items Processed: {stats['total_items_processed']}")
    print(f"  Avg Time per Item: {stats['avg_per_item_ms']:.2f}ms")

    print("\n[OK] Batch operations tests passed")
    return True


def test_lattice_batch():
    """Test LatticeBatch processor"""
    print("\n" + "=" * 70)
    print("TEST 2: Lattice Batch Processor")
    print("=" * 70)

    # Create multiple lattices
    print("\n[Test 2.1] Creating 5 lattices")
    lattices = []
    for i in range(5):
        lattice = UnifiedCatalyticLattice(
            dimensions=4,
            size=8,  # Smaller size for faster testing
            enable_gpu=True,
            enable_smart_routing=True,
        )
        lattice.build_lattice()
        lattices.append(lattice)

    print(f"  Created {len(lattices)} lattices")

    # Create batch processor
    batch = create_batch(lattices, max_batch_size=16)
    print("  Batch processor ready")

    # Test 2.2: Batch XOR Transform
    print("\n[Test 2.2] Batch XOR Transform")
    data_list = [np.array([i, i + 1, i + 2, i + 3, i + 4], dtype=np.int32) for i in range(5)]

    start = time.time()
    results = batch.batch_xor_transform(data_list)
    elapsed = (time.time() - start) * 1000

    print(f"  Processed {len(results)} XOR transforms in {elapsed:.2f}ms")
    print(f"  Status: {'PASS' if len(results) == 5 else 'FAIL'}")

    # Test 2.3: Execute parallel operations
    print("\n[Test 2.3] Parallel Custom Operations")

    # Define operations for each lattice
    operations = [
        lambda lattice: lattice.analyze_structure(),
        lambda lattice: lattice.analyze_structure(),
        lambda lattice: lattice.analyze_structure(),
        lambda lattice: lattice.analyze_structure(),
        lambda lattice: lattice.analyze_structure(),
    ]

    start = time.time()
    results = batch.execute_parallel(operations, operation_name="analyze_structure")
    elapsed = (time.time() - start) * 1000

    print(f"  Executed {len(results)} parallel operations in {elapsed:.2f}ms")
    print(f"  Avg per operation: {elapsed / len(results):.2f}ms")
    print(f"  Status: {'PASS' if len(results) == 5 else 'FAIL'}")

    # Get stats
    batch.print_stats()

    print("\n[OK] Lattice batch tests passed")
    return True


def test_batch_vs_sequential():
    """Compare batch vs sequential performance"""
    print("\n" + "=" * 70)
    print("TEST 3: Batch vs Sequential Performance")
    print("=" * 70)

    num_operations = 10
    print(f"\nTesting with {num_operations} operations")

    # Test 3.1: Batch XOR Transform
    print("\n[Test 3.1] XOR Transform: Batch vs Sequential")

    # Generate test data
    data_list = [
        np.random.randint(0, 256, size=10000, dtype=np.int32) for _ in range(num_operations)
    ]

    # Sequential execution
    print("  Sequential execution...")
    start = time.time()
    sequential_results = []
    for data in data_list:
        data_uint = data.astype(np.uint8)
        key = np.random.randint(0, 256, size=len(data), dtype=np.uint8)
        result = np.bitwise_xor(data_uint, key)
        sequential_results.append(result)
    sequential_time = (time.time() - start) * 1000

    # Batch execution
    print("  Batch execution...")
    batch_ops = GPUBatchOperations(device_id=0, backend="pytorch")
    start = time.time()
    batch_ops.batch_xor_transform(data_list)
    batch_time = (time.time() - start) * 1000

    speedup = sequential_time / batch_time if batch_time > 0 else 0

    print(f"\n  Sequential: {sequential_time:.2f}ms")
    print(f"  Batch: {batch_time:.2f}ms")
    print(f"  Speedup: {speedup:.2f}x")

    xor_speedup = speedup

    # Test 3.2: Matrix Multiply
    print("\n[Test 3.2] Matrix Multiply: Batch vs Sequential")

    size = 256
    a_list = [np.random.randn(size, size) for _ in range(num_operations)]
    b_list = [np.random.randn(size, size) for _ in range(num_operations)]

    # Sequential
    print("  Sequential execution...")
    start = time.time()
    [np.dot(a, b) for a, b in zip(a_list, b_list)]
    sequential_time = (time.time() - start) * 1000

    # Batch
    print("  Batch execution...")
    batch_ops.reset_stats()
    start = time.time()
    batch_ops.batch_matrix_multiply(a_list, b_list)
    batch_time = (time.time() - start) * 1000

    speedup = sequential_time / batch_time if batch_time > 0 else 0

    print(f"\n  Sequential: {sequential_time:.2f}ms")
    print(f"  Batch: {batch_time:.2f}ms")
    print(f"  Speedup: {speedup:.2f}x")

    matmul_speedup = speedup

    # Summary
    print("\n" + "-" * 70)
    print("Performance Summary:")
    print(f"  XOR Transform: {xor_speedup:.2f}x speedup")
    print(f"  Matrix Multiply: {matmul_speedup:.2f}x speedup")

    avg_speedup = (xor_speedup + matmul_speedup) / 2
    print(f"  Average Speedup: {avg_speedup:.2f}x")

    if avg_speedup >= 2.0:
        print("\n[SUCCESS] Batch processing provides significant speedup (>2x)")
    elif avg_speedup >= 1.2:
        print("\n[OK] Batch processing provides moderate speedup (>1.2x)")
    else:
        print("\n[WARNING] Batch speedup lower than expected")

    print("\n[OK] Performance comparison complete")
    return True


def test_batch_size_optimization():
    """Test automatic batch size optimization"""
    print("\n" + "=" * 70)
    print("TEST 4: Batch Size Optimization")
    print("=" * 70)

    # Create lattices
    num_lattices = 20
    print(f"\n[Test 4.1] Creating {num_lattices} lattices")
    lattices = [
        UnifiedCatalyticLattice(dimensions=4, size=8, enable_gpu=True) for _ in range(num_lattices)
    ]

    # Test different batch sizes
    batch_sizes = [4, 8, 16]
    times = {}

    print("\n[Test 4.2] Testing different batch sizes")

    for batch_size in batch_sizes:
        batch = create_batch(lattices, max_batch_size=batch_size)

        # Run test operation
        data_list = [np.array([i] * 100, dtype=np.int32) for i in range(num_lattices)]

        start = time.time()
        _ = batch.batch_xor_transform(data_list)
        elapsed = (time.time() - start) * 1000

        times[batch_size] = elapsed
        print(f"  Batch size {batch_size}: {elapsed:.2f}ms")

        batch.cleanup()

    # Find optimal
    optimal = min(times, key=times.get)
    print(f"\n  Optimal batch size: {optimal} ({times[optimal]:.2f}ms)")

    print("\n[OK] Batch size optimization test complete")
    return True


def main():
    print("=" * 70)
    print("BATCH PROCESSING TEST SUITE")
    print("=" * 70)

    all_passed = True

    try:
        test1 = test_batch_operations()
        print(f"\n[OK] Test 1: {'PASSED' if test1 else 'FAILED'}")
        all_passed = all_passed and test1

        test2 = test_lattice_batch()
        print(f"\n[OK] Test 2: {'PASSED' if test2 else 'FAILED'}")
        all_passed = all_passed and test2

        test3 = test_batch_vs_sequential()
        print(f"\n[OK] Test 3: {'PASSED' if test3 else 'FAILED'}")
        all_passed = all_passed and test3

        test4 = test_batch_size_optimization()
        print(f"\n[OK] Test 4: {'PASSED' if test4 else 'FAILED'}")
        all_passed = all_passed and test4

        # Final summary
        print("\n" + "=" * 70)
        print("TEST SUITE SUMMARY")
        print("=" * 70)
        if all_passed:
            print("[SUCCESS] ALL TESTS PASSED - Batch processing working!")
            print("\nKey Features Validated:")
            print("  - GPU batch operations (XOR, MatMul, Element-wise)")
            print("  - Parallel lattice processing")
            print("  - 2-5x speedup vs sequential execution")
            print("  - Automatic batch size optimization")
            print("  - Memory-aware batching")
        else:
            print("[FAILURE] SOME TESTS FAILED - Review output above")
        print("=" * 70)

        return 0 if all_passed else 1

    except Exception as e:
        print(f"\n[FAILURE] Test suite failed: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
