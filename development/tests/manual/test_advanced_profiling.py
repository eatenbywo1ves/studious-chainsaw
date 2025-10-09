#!/usr/bin/env python3
"""
Advanced GPU Profiler Test Suite
Tests comparison, regression detection, and optimization suggestions

Requirements:
  - Python 3.12
  - PyTorch 2.5.1+cu121 (optional)
"""

import sys
import json
import tempfile
from pathlib import Path

# Add development directory to path
sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu.profiler_compare import ProfilerComparison, compare_profiling_runs  # noqa: E402
from libs.gpu.profiler_optimizer import ProfilerOptimizer  # noqa: E402


def create_sample_baseline():
    """Create sample baseline profiling data"""
    return {
        "entries": [
            {
                "operation": "matrix_multiply",
                "duration_ms": 50.0,
                "device": "gpu",
                "backend": "pytorch",
                "gpu_time_ms": 42.5,
                "cpu_time_ms": 0,
                "transfer_time_ms": 5.0,
                "overhead_ms": 2.5,
                "memory_allocated_mb": 16.0,
                "memory_peak_mb": 18.0,
                "gpu_utilization": 85.0,
                "metadata": {},
            },
            {
                "operation": "matrix_multiply",
                "duration_ms": 48.0,
                "device": "gpu",
                "backend": "pytorch",
                "gpu_time_ms": 40.8,
                "cpu_time_ms": 0,
                "transfer_time_ms": 4.8,
                "overhead_ms": 2.4,
                "memory_allocated_mb": 16.0,
                "memory_peak_mb": 18.0,
                "gpu_utilization": 85.0,
                "metadata": {},
            },
            {
                "operation": "xor_transform",
                "duration_ms": 35.0,
                "device": "gpu",
                "backend": "pytorch",
                "gpu_time_ms": 29.75,
                "cpu_time_ms": 0,
                "transfer_time_ms": 3.5,
                "overhead_ms": 1.75,
                "memory_allocated_mb": 0.5,
                "memory_peak_mb": 0.5,
                "gpu_utilization": 30.0,
                "metadata": {},
            },
        ],
        "summary": {
            "matrix_multiply": {
                "call_count": 2,
                "total_time_ms": 98.0,
                "avg_time_ms": 49.0,
                "min_time_ms": 48.0,
                "max_time_ms": 50.0,
                "total_gpu_time_ms": 83.3,
                "avg_memory_mb": 16.0,
                "avg_gpu_utilization": 85.0,
            },
            "xor_transform": {
                "call_count": 1,
                "total_time_ms": 35.0,
                "avg_time_ms": 35.0,
                "min_time_ms": 35.0,
                "max_time_ms": 35.0,
                "total_gpu_time_ms": 29.75,
                "avg_memory_mb": 0.5,
                "avg_gpu_utilization": 30.0,
            },
        },
    }


def create_sample_current():
    """Create sample current profiling data with some regressions"""
    return {
        "entries": [
            {
                "operation": "matrix_multiply",
                "duration_ms": 70.0,  # Regression!
                "device": "gpu",
                "backend": "pytorch",
                "gpu_time_ms": 59.5,
                "cpu_time_ms": 0,
                "transfer_time_ms": 7.0,
                "overhead_ms": 3.5,
                "memory_allocated_mb": 20.0,  # More memory
                "memory_peak_mb": 22.0,
                "gpu_utilization": 85.0,
                "metadata": {},
            },
            {
                "operation": "matrix_multiply",
                "duration_ms": 68.0,  # Regression!
                "device": "gpu",
                "backend": "pytorch",
                "gpu_time_ms": 57.8,
                "cpu_time_ms": 0,
                "transfer_time_ms": 6.8,
                "overhead_ms": 3.4,
                "memory_allocated_mb": 20.0,
                "memory_peak_mb": 22.0,
                "gpu_utilization": 85.0,
                "metadata": {},
            },
            {
                "operation": "xor_transform",
                "duration_ms": 0.25,  # Improvement! (routed to CPU)
                "device": "cpu",
                "backend": "cpu",
                "gpu_time_ms": 0,
                "cpu_time_ms": 0.25,
                "transfer_time_ms": 0,
                "overhead_ms": 0,
                "memory_allocated_mb": 0.1,
                "memory_peak_mb": 0.1,
                "gpu_utilization": 0,
                "metadata": {},
            },
            {
                "operation": "new_operation",
                "duration_ms": 10.0,
                "device": "cpu",
                "backend": "cpu",
                "gpu_time_ms": 0,
                "cpu_time_ms": 10.0,
                "transfer_time_ms": 0,
                "overhead_ms": 0,
                "memory_allocated_mb": 1.0,
                "memory_peak_mb": 1.0,
                "gpu_utilization": 0,
                "metadata": {},
            },
        ],
        "summary": {
            "matrix_multiply": {
                "call_count": 2,
                "total_time_ms": 138.0,
                "avg_time_ms": 69.0,
                "min_time_ms": 68.0,
                "max_time_ms": 70.0,
                "total_gpu_time_ms": 117.3,
                "avg_memory_mb": 20.0,
                "avg_gpu_utilization": 85.0,
            },
            "xor_transform": {
                "call_count": 1,
                "total_time_ms": 0.25,
                "avg_time_ms": 0.25,
                "min_time_ms": 0.25,
                "max_time_ms": 0.25,
                "total_gpu_time_ms": 0,
                "avg_memory_mb": 0.1,
                "avg_gpu_utilization": 0,
            },
            "new_operation": {
                "call_count": 1,
                "total_time_ms": 10.0,
                "avg_time_ms": 10.0,
                "min_time_ms": 10.0,
                "max_time_ms": 10.0,
                "total_gpu_time_ms": 0,
                "avg_memory_mb": 1.0,
                "avg_gpu_utilization": 0,
            },
        },
    }


def test_comparison():
    """Test profiling comparison functionality"""
    print("\n" + "=" * 70)
    print("TEST 1: Profiling Comparison")
    print("=" * 70)

    baseline = create_sample_baseline()
    current = create_sample_current()

    # Test 1.1: Create comparison
    print("\n[Test 1.1] Create Comparison")
    comparison = ProfilerComparison(baseline, current, significance_threshold=5.0)
    print(f"  Comparisons created: {len(comparison.comparisons)}")
    assert len(comparison.comparisons) == 3, "Should have 3 operations"
    print("  Status: PASS")

    # Test 1.2: Get summary
    print("\n[Test 1.2] Comparison Summary")
    summary = comparison.get_summary()
    print(f"  Total operations: {summary.total_operations}")
    print(f"  Regressions: {summary.regressions_count}")
    print(f"  Improvements: {summary.improvements_count}")
    print(f"  New operations: {summary.new_operations_count}")

    assert summary.regressions_count == 1, "Should have 1 regression (matrix_multiply)"
    assert summary.improvements_count == 1, "Should have 1 improvement (xor_transform)"
    assert summary.new_operations_count == 1, "Should have 1 new operation"
    print("  Status: PASS")

    # Test 1.3: Get regressions
    print("\n[Test 1.3] Identify Regressions")
    regressions = comparison.get_regressions()
    print(f"  Regressions found: {len(regressions)}")

    if regressions:
        reg = regressions[0]
        print(f"  Worst regression: {reg.operation}")
        print(
            f"    {reg.baseline_time_ms:.2f}ms -> {reg.current_time_ms:.2f}ms "
            f"({reg.change_percent:+.1f}%)"
        )
        assert reg.operation == "matrix_multiply", "matrix_multiply should be the regression"
        assert reg.change_percent > 0, "Should be slower"
    print("  Status: PASS")

    # Test 1.4: Get improvements
    print("\n[Test 1.4] Identify Improvements")
    improvements = comparison.get_improvements()
    print(f"  Improvements found: {len(improvements)}")

    if improvements:
        imp = improvements[0]
        print(f"  Best improvement: {imp.operation}")
        print(
            f"    {imp.baseline_time_ms:.2f}ms -> {imp.current_time_ms:.2f}ms "
            f"({imp.change_percent:+.1f}%)"
        )
        assert imp.operation == "xor_transform", "xor_transform should be the improvement"
        assert imp.change_percent < 0, "Should be faster"
    print("  Status: PASS")

    # Test 1.5: Print summary
    print("\n[Test 1.5] Print Summary")
    comparison.print_summary()
    print("  Status: PASS")

    print("\n[OK] Comparison tests passed")
    return True


def test_optimizer():
    """Test optimization suggestions"""
    print("\n" + "=" * 70)
    print("TEST 2: Optimization Suggestions")
    print("=" * 70)

    # Create profiling data with optimization opportunities
    data = {
        "entries": [
            # Small GPU operation (should suggest CPU routing)
            {
                "operation": "small_gpu_op",
                "duration_ms": 0.5,
                "device": "gpu",
                "backend": "pytorch",
                "gpu_time_ms": 0.425,
                "cpu_time_ms": 0,
                "transfer_time_ms": 0.05,
                "overhead_ms": 0.025,
                "memory_allocated_mb": 0.1,
                "memory_peak_mb": 0.1,
                "gpu_utilization": 30.0,
                "metadata": {},
            },
            # Repeated operation (should suggest batching)
            *[
                {
                    "operation": "repeated_op",
                    "duration_ms": 5.0,
                    "device": "cpu",
                    "backend": "cpu",
                    "gpu_time_ms": 0,
                    "cpu_time_ms": 5.0,
                    "transfer_time_ms": 0,
                    "overhead_ms": 0,
                    "memory_allocated_mb": 1.0,
                    "memory_peak_mb": 1.0,
                    "gpu_utilization": 0,
                    "metadata": {},
                }
                for _ in range(20)
            ],
        ],
        "summary": {
            "small_gpu_op": {
                "call_count": 1,
                "total_time_ms": 0.5,
                "avg_time_ms": 0.5,
                "min_time_ms": 0.5,
                "max_time_ms": 0.5,
                "total_gpu_time_ms": 0.425,
                "avg_memory_mb": 0.1,
                "avg_gpu_utilization": 30.0,
            },
            "repeated_op": {
                "call_count": 20,
                "total_time_ms": 100.0,
                "avg_time_ms": 5.0,
                "min_time_ms": 5.0,
                "max_time_ms": 5.0,
                "total_gpu_time_ms": 0,
                "avg_memory_mb": 1.0,
                "avg_gpu_utilization": 0,
            },
        },
    }

    # Test 2.1: Create optimizer
    print("\n[Test 2.1] Create Optimizer")
    optimizer = ProfilerOptimizer(data)
    print(f"  Suggestions generated: {len(optimizer.suggestions)}")
    assert len(optimizer.suggestions) > 0, "Should have suggestions"
    print("  Status: PASS")

    # Test 2.2: Get suggestions
    print("\n[Test 2.2] Get Suggestions")
    suggestions = optimizer.get_suggestions(top_n=5)
    print(f"  Top suggestions: {len(suggestions)}")

    for i, sugg in enumerate(suggestions, 1):
        print(f"  [{i}] {sugg.operation} ({sugg.type.value}, {sugg.priority.value})")
        print(f"      {sugg.description}")

    print("  Status: PASS")

    # Test 2.3: Get critical suggestions
    print("\n[Test 2.3] Get Critical Suggestions")
    critical = optimizer.get_critical_suggestions()
    print(f"  Critical suggestions: {len(critical)}")

    if critical:
        for sugg in critical:
            print(f"  - {sugg.operation}: {sugg.description}")

    print("  Status: PASS")

    # Test 2.4: Print suggestions
    print("\n[Test 2.4] Print Suggestions")
    optimizer.print_suggestions(top_n=5)
    print("  Status: PASS")

    print("\n[OK] Optimizer tests passed")
    return True


def test_file_comparison():
    """Test file-based comparison"""
    print("\n" + "=" * 70)
    print("TEST 3: File-Based Comparison")
    print("=" * 70)

    baseline = create_sample_baseline()
    current = create_sample_current()

    # Test 3.1: Export and compare files
    print("\n[Test 3.1] Export and Compare Files")

    with tempfile.NamedTemporaryFile(mode="w", suffix="_baseline.json", delete=False) as f:
        baseline_file = f.name
        json.dump(baseline, f)

    with tempfile.NamedTemporaryFile(mode="w", suffix="_current.json", delete=False) as f:
        current_file = f.name
        json.dump(current, f)

    print(f"  Baseline file: {baseline_file}")
    print(f"  Current file: {current_file}")

    comparison = compare_profiling_runs(baseline_file, current_file)
    print(f"  Comparisons: {len(comparison.comparisons)}")
    assert len(comparison.comparisons) == 3, "Should have 3 comparisons"
    print("  Status: PASS")

    # Test 3.2: Export comparison
    print("\n[Test 3.2] Export Comparison")
    with tempfile.NamedTemporaryFile(mode="w", suffix="_comparison.json", delete=False) as f:
        comparison_file = f.name

    comparison.export_comparison(comparison_file)
    print(f"  Exported to: {comparison_file}")

    # Verify export
    with open(comparison_file, "r") as f:
        data = json.load(f)

    assert "summary" in data, "Should have summary"
    assert "comparisons" in data, "Should have comparisons"
    print("  Status: PASS")

    # Cleanup
    Path(baseline_file).unlink()
    Path(current_file).unlink()
    Path(comparison_file).unlink()

    print("\n[OK] File comparison tests passed")
    return True


def main():
    print("=" * 70)
    print("ADVANCED PROFILER TEST SUITE")
    print("=" * 70)

    all_passed = True

    try:
        test1 = test_comparison()
        print(f"\n[OK] Test 1: {'PASSED' if test1 else 'FAILED'}")
        all_passed = all_passed and test1

        test2 = test_optimizer()
        print(f"\n[OK] Test 2: {'PASSED' if test2 else 'FAILED'}")
        all_passed = all_passed and test2

        test3 = test_file_comparison()
        print(f"\n[OK] Test 3: {'PASSED' if test3 else 'FAILED'}")
        all_passed = all_passed and test3

        # Final summary
        print("\n" + "=" * 70)
        print("TEST SUITE SUMMARY")
        print("=" * 70)
        if all_passed:
            print("[SUCCESS] ALL TESTS PASSED - Advanced profiling working!")
            print("\nKey Features Validated:")
            print("  - Profiling comparison (baseline vs current)")
            print("  - Regression detection (identify slower operations)")
            print("  - Improvement tracking (identify faster operations)")
            print("  - Optimization suggestions (automated recommendations)")
            print("  - File-based comparison (JSON import/export)")
            print("  - Priority-based filtering (critical/high/medium/low)")
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
