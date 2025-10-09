#!/usr/bin/env python3
"""
GPU Profiler Test Suite
Tests profiling functionality, metrics collection, and bottleneck identification

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
from libs.gpu.cuda_init import initialize_cuda_environment  # noqa: E402

initialize_cuda_environment(verbose=True)

from libs.gpu.profiler import GPUProfiler, get_profiler  # noqa: E402

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def test_basic_profiling():
    """Test basic profiling functionality"""
    print("\n" + "=" * 70)
    print("TEST 1: Basic Profiling")
    print("=" * 70)

    profiler = GPUProfiler(enabled=True, device_id=0)

    # Test 1.1: Context manager profiling
    print("\n[Test 1.1] Context Manager Profiling")

    with profiler.profile("test_operation", device="cpu"):
        time.sleep(0.01)  # 10ms operation
        _ = np.random.randn(100, 100)

    entries = profiler.get_entries()
    print(f"  Entries recorded: {len(entries)}")
    print(f"  Operation: {entries[0].operation}")
    print(f"  Duration: {entries[0].duration_ms:.2f}ms")
    print(f"  Device: {entries[0].device}")

    assert len(entries) == 1, "Should have 1 entry"
    assert entries[0].operation == "test_operation", "Operation name mismatch"
    assert entries[0].duration_ms >= 10.0, "Duration should be at least 10ms"
    print("  Status: PASS")

    # Test 1.2: Multiple operations
    print("\n[Test 1.2] Multiple Operations")

    profiler.reset()
    with profiler.profile("op1", device="cpu"):
        time.sleep(0.005)

    with profiler.profile("op2", device="gpu"):
        time.sleep(0.010)

    with profiler.profile("op1", device="cpu"):
        time.sleep(0.005)

    entries = profiler.get_entries()
    print(f"  Total entries: {len(entries)}")
    print(f"  Unique operations: {len(set(e.operation for e in entries))}")

    assert len(entries) == 3, "Should have 3 entries"
    assert len(set(e.operation for e in entries)) == 2, "Should have 2 unique operations"
    print("  Status: PASS")

    # Test 1.3: Profiler enable/disable
    print("\n[Test 1.3] Enable/Disable")

    profiler.reset()
    profiler.disable()

    with profiler.profile("disabled_op"):
        time.sleep(0.01)

    assert len(profiler.get_entries()) == 0, "Should not record when disabled"

    profiler.enable()

    with profiler.profile("enabled_op"):
        time.sleep(0.01)

    assert len(profiler.get_entries()) == 1, "Should record when enabled"
    print("  Status: PASS")

    print("\n[OK] Basic profiling tests passed")
    return True


def test_statistics():
    """Test profiling statistics and summaries"""
    print("\n" + "=" * 70)
    print("TEST 2: Statistics and Summaries")
    print("=" * 70)

    profiler = GPUProfiler(enabled=True, device_id=0)
    profiler.reset()

    # Record multiple operations
    print("\n[Test 2.1] Recording Sample Operations")

    operations = [
        ("matrix_multiply", 0.020),
        ("matrix_multiply", 0.025),
        ("matrix_multiply", 0.022),
        ("xor_transform", 0.001),
        ("xor_transform", 0.002),
        ("graph_search", 0.100),
    ]

    for op_name, duration in operations:
        with profiler.profile(op_name, device="gpu"):
            time.sleep(duration)

    print(f"  Recorded {len(operations)} operations")

    # Test 2.2: Get summary
    print("\n[Test 2.2] Summary Statistics")

    summary = profiler.get_summary()
    print(f"  Unique operations: {len(summary)}")

    for op_name, stats in summary.items():
        print(f"  {op_name}:")
        print(f"    Call count: {stats.call_count}")
        print(f"    Total time: {stats.total_time_ms:.2f}ms")
        print(f"    Avg time: {stats.avg_time_ms:.2f}ms")
        print(f"    Min time: {stats.min_time_ms:.2f}ms")
        print(f"    Max time: {stats.max_time_ms:.2f}ms")

    assert len(summary) == 3, "Should have 3 unique operations"
    assert summary["matrix_multiply"].call_count == 3, "matrix_multiply should have 3 calls"
    assert summary["xor_transform"].call_count == 2, "xor_transform should have 2 calls"
    print("  Status: PASS")

    # Test 2.3: Bottleneck identification
    print("\n[Test 2.3] Bottleneck Identification")

    bottlenecks = profiler.get_bottlenecks(top_n=3)
    print(f"  Top {len(bottlenecks)} bottlenecks:")

    for i, bottleneck in enumerate(bottlenecks, 1):
        print(f"  [{i}] {bottleneck.operation}: {bottleneck.total_time_ms:.2f}ms")

    # graph_search should be the biggest bottleneck
    assert bottlenecks[0].operation == "graph_search", "graph_search should be top bottleneck"
    assert bottlenecks[1].operation == "matrix_multiply", "matrix_multiply should be 2nd"
    print("  Status: PASS")

    print("\n[OK] Statistics tests passed")
    return True


def test_gpu_operations():
    """Test profiling of actual GPU operations"""
    print("\n" + "=" * 70)
    print("TEST 3: GPU Operation Profiling")
    print("=" * 70)

    try:
        import torch

        if not torch.cuda.is_available():
            print("  [SKIP] CUDA not available")
            return True
    except ImportError:
        print("  [SKIP] PyTorch not available")
        return True

    profiler = GPUProfiler(enabled=True, device_id=0, enable_detailed_metrics=True)
    profiler.reset()

    # Test 3.1: Matrix operations
    print("\n[Test 3.1] GPU Matrix Operations")

    size = 512
    device = torch.device("cuda:0")

    with profiler.profile("gpu_matrix_multiply", device="gpu", size=size):
        a = torch.randn(size, size, device=device)
        b = torch.randn(size, size, device=device)
        _ = torch.mm(a, b)
        torch.cuda.synchronize()

    entries = profiler.get_entries()
    entry = entries[-1]

    print(f"  Operation: {entry.operation}")
    print(f"  Duration: {entry.duration_ms:.2f}ms")
    print(f"  GPU time: {entry.gpu_time_ms:.2f}ms")
    print(f"  Transfer time: {entry.transfer_time_ms:.2f}ms")
    print(f"  Overhead: {entry.overhead_ms:.2f}ms")
    print(f"  Memory allocated: {entry.memory_allocated_mb:.2f}MB")

    assert entry.operation == "gpu_matrix_multiply", "Operation name mismatch"
    assert entry.duration_ms > 0, "Duration should be positive"
    print("  Status: PASS")

    # Test 3.2: Memory tracking
    print("\n[Test 3.2] Memory Tracking")

    profiler.reset()

    with profiler.profile("memory_allocation", device="gpu"):
        # Allocate significant memory
        large_tensor = torch.randn(2048, 2048, device=device)
        torch.cuda.synchronize()

    entry = profiler.get_entries()[-1]
    print(f"  Memory allocated: {entry.memory_allocated_mb:.2f}MB")
    print(f"  Peak memory: {entry.memory_peak_mb:.2f}MB")

    # Clean up
    del large_tensor
    torch.cuda.empty_cache()

    assert entry.memory_allocated_mb > 0 or entry.memory_peak_mb > 0, "Should track memory"
    print("  Status: PASS")

    print("\n[OK] GPU operation profiling tests passed")
    return True


def test_decorator_profiling():
    """Test decorator-based profiling"""
    print("\n" + "=" * 70)
    print("TEST 4: Decorator Profiling")
    print("=" * 70)

    profiler = GPUProfiler(enabled=True, device_id=0)
    profiler.reset()

    # Test 4.1: Basic decorator
    print("\n[Test 4.1] Function Decorator")

    @profiler.profile_function(operation="decorated_func", device="cpu")
    def sample_function(x):
        time.sleep(0.01)
        return x * 2

    result = sample_function(5)
    print(f"  Result: {result}")

    entries = profiler.get_entries()
    print(f"  Entries recorded: {len(entries)}")
    print(f"  Operation: {entries[0].operation}")

    assert len(entries) == 1, "Should have 1 entry"
    assert entries[0].operation == "decorated_func", "Operation name mismatch"
    assert result == 10, "Function should return correct value"
    print("  Status: PASS")

    # Test 4.2: Multiple calls
    print("\n[Test 4.2] Multiple Decorated Calls")

    profiler.reset()

    @profiler.profile_function(operation="multi_call")
    def another_function(a, b):
        time.sleep(0.005)
        return a + b

    results = [another_function(i, i + 1) for i in range(5)]
    print(f"  Results: {results}")

    summary = profiler.get_summary()
    assert summary["multi_call"].call_count == 5, "Should have 5 calls"
    print(f"  Call count: {summary['multi_call'].call_count}")
    print("  Status: PASS")

    print("\n[OK] Decorator tests passed")
    return True


def test_output_formats():
    """Test profiling output formats"""
    print("\n" + "=" * 70)
    print("TEST 5: Output Formats")
    print("=" * 70)

    profiler = GPUProfiler(enabled=True, device_id=0)
    profiler.reset()

    # Record sample operations
    with profiler.profile("op1"):
        time.sleep(0.020)

    with profiler.profile("op2"):
        time.sleep(0.010)

    with profiler.profile("op1"):
        time.sleep(0.025)

    # Test 5.1: Print summary
    print("\n[Test 5.1] Print Summary")
    profiler.print_summary()
    print("  Status: PASS")

    # Test 5.2: Print bottlenecks
    print("\n[Test 5.2] Print Bottlenecks")
    profiler.print_bottlenecks(top_n=2)
    print("  Status: PASS")

    # Test 5.3: JSON export
    print("\n[Test 5.3] JSON Export")
    import tempfile
    import json

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        filepath = f.name

    profiler.export_json(filepath)
    print(f"  Exported to: {filepath}")

    # Verify JSON
    with open(filepath, "r") as f:
        data = json.load(f)

    print(f"  Entries in JSON: {len(data['entries'])}")
    print(f"  Summary operations: {len(data['summary'])}")

    assert len(data["entries"]) == 3, "Should have 3 entries"
    assert len(data["summary"]) == 2, "Should have 2 operations in summary"

    # Clean up
    Path(filepath).unlink()
    print("  Status: PASS")

    print("\n[OK] Output format tests passed")
    return True


def test_global_profiler():
    """Test global profiler singleton"""
    print("\n" + "=" * 70)
    print("TEST 6: Global Profiler")
    print("=" * 70)

    # Test 6.1: Get global instance
    print("\n[Test 6.1] Global Instance")

    profiler1 = get_profiler(enabled=True)
    profiler2 = get_profiler()

    print(f"  Profiler 1 ID: {id(profiler1)}")
    print(f"  Profiler 2 ID: {id(profiler2)}")

    assert profiler1 is profiler2, "Should return same instance"
    print("  Status: PASS")

    # Test 6.2: Global profiler usage
    print("\n[Test 6.2] Global Profiler Usage")

    profiler = get_profiler()
    profiler.reset()

    with profiler.profile("global_op"):
        time.sleep(0.01)

    entries = profiler.get_entries()
    assert len(entries) == 1, "Should have 1 entry"
    print(f"  Entries: {len(entries)}")
    print("  Status: PASS")

    print("\n[OK] Global profiler tests passed")
    return True


def main():
    print("=" * 70)
    print("GPU PROFILER TEST SUITE")
    print("=" * 70)

    all_passed = True

    try:
        test1 = test_basic_profiling()
        print(f"\n[OK] Test 1: {'PASSED' if test1 else 'FAILED'}")
        all_passed = all_passed and test1

        test2 = test_statistics()
        print(f"\n[OK] Test 2: {'PASSED' if test2 else 'FAILED'}")
        all_passed = all_passed and test2

        test3 = test_gpu_operations()
        print(f"\n[OK] Test 3: {'PASSED' if test3 else 'FAILED'}")
        all_passed = all_passed and test3

        test4 = test_decorator_profiling()
        print(f"\n[OK] Test 4: {'PASSED' if test4 else 'FAILED'}")
        all_passed = all_passed and test4

        test5 = test_output_formats()
        print(f"\n[OK] Test 5: {'PASSED' if test5 else 'FAILED'}")
        all_passed = all_passed and test5

        test6 = test_global_profiler()
        print(f"\n[OK] Test 6: {'PASSED' if test6 else 'FAILED'}")
        all_passed = all_passed and test6

        # Final summary
        print("\n" + "=" * 70)
        print("TEST SUITE SUMMARY")
        print("=" * 70)
        if all_passed:
            print("[SUCCESS] ALL TESTS PASSED - GPU Profiler working!")
            print("\nKey Features Validated:")
            print("  - Context manager profiling")
            print("  - Decorator-based profiling")
            print("  - Statistics and summaries")
            print("  - Bottleneck identification")
            print("  - Memory tracking")
            print("  - JSON export")
            print("  - Global profiler singleton")
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
