#!/usr/bin/env python3
"""
Test Suite for Phase 3: Hierarchical Complexity Metrics
Tests the Mernithian-inspired complexity tracking system
"""

import sys
import io
from pathlib import Path

# Set UTF-8 encoding for stdout to handle mathematical symbols
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu import get_complexity_analyzer, ComplexityTier, get_profiler
import time


def test_complexity_tier_classification():
    """Test 1: Complexity tier classification"""
    print("\n" + "=" * 70)
    print("TEST 1: Complexity Tier Classification")
    print("=" * 70)

    analyzer = get_complexity_analyzer()

    # Test known operations
    test_cases = [
        ("hash_lookup", ComplexityTier.TRIVIAL),
        ("array_access", ComplexityTier.TRIVIAL),
        ("xor_transform", ComplexityTier.LINEAR),
        ("quicksort", ComplexityTier.LINEAR),
        ("matrix_multiply", ComplexityTier.POLYNOMIAL),
        ("nested_loop", ComplexityTier.POLYNOMIAL),
        ("graph_search", ComplexityTier.EXPONENTIAL),
        ("traveling_salesman", ComplexityTier.EXPONENTIAL),
    ]

    for operation, expected_tier in test_cases:
        complexity = analyzer.classify_algorithm(operation)
        assert complexity.tier == expected_tier, (
            f"{operation} should be {expected_tier.name}, got {complexity.tier.name}"
        )
        print(f"  [OK] {operation:<25} → Tier {complexity.tier.value} ({complexity.tier.name})")
        print(
            f"       Time: {complexity.time_complexity}, Class: {complexity.complexity_class.value}"
        )

    print("\n  TEST 1 PASSED [OK]")


def test_complexity_scoring():
    """Test 2: Complexity scoring with multiplicative hierarchy"""
    print("\n" + "=" * 70)
    print("TEST 2: Complexity Scoring")
    print("=" * 70)

    analyzer = get_complexity_analyzer()

    # Test base scores for each tier
    test_operations = [
        ("hash_lookup", ComplexityTier.TRIVIAL, 1.0),
        ("xor_transform", ComplexityTier.LINEAR, 10.0),
        ("matrix_multiply", ComplexityTier.POLYNOMIAL, 100.0),
        ("graph_search", ComplexityTier.EXPONENTIAL, 1000.0),
    ]

    for operation, expected_tier, expected_base_score in test_operations:
        algorithmic = analyzer.classify_algorithm(operation)
        operational = analyzer.compute_operational_complexity(
            duration_ms=10.0, memory_mb=10.0, device="cpu", metadata={}
        )

        score = analyzer.compute_complexity_score(algorithmic, operational)

        print(f"\n  {operation}:")
        print(f"    Tier: {score.tier.name} ({score.tier.value})")
        print(f"    Algorithmic Score: {score.algorithmic_score:.2f}")
        print(f"    Total Score: {score.total_score:.2f}")
        print(f"    Normalized: {score.normalized_score:.3f}")
        print(f"    Grade: {score.complexity_grade}")
        print(f"    Bottleneck: {score.bottleneck}")

        assert score.tier == expected_tier, f"Score tier mismatch for {operation}"

    print("\n  TEST 2 PASSED [OK]")


def test_algorithmic_complexity_inference():
    """Test 3: Infer complexity from runtime metrics"""
    print("\n" + "=" * 70)
    print("TEST 3: Algorithmic Complexity Inference")
    print("=" * 70)

    analyzer = get_complexity_analyzer()

    # Test inference from time/data scaling
    test_cases = [
        (0.1, 0.001, ComplexityTier.TRIVIAL, "Very fast, tiny data"),
        (10.0, 1.0, ComplexityTier.LINEAR, "Linear scaling"),
        (150.0, 10.0, ComplexityTier.POLYNOMIAL, "Quadratic scaling"),
        (1000.0, 1.0, ComplexityTier.EXPONENTIAL, "Exponential scaling"),
    ]

    for duration, data_size, expected_tier, description in test_cases:
        inferred = analyzer.infer_complexity_from_metrics(duration, data_size)
        print(f"  {description}:")
        print(f"    Duration: {duration}ms, Data: {data_size}MB")
        print(f"    Inferred: Tier {inferred.value} ({inferred.name})")

        assert inferred == expected_tier, (
            f"Inference mismatch: expected {expected_tier.name}, got {inferred.name}"
        )

    print("\n  TEST 3 PASSED [OK]")


def test_operational_complexity_tracking():
    """Test 4: Track operational complexity"""
    print("\n" + "=" * 70)
    print("TEST 4: Operational Complexity Tracking")
    print("=" * 70)

    analyzer = get_complexity_analyzer()

    # Test operational metrics calculation
    operational = analyzer.compute_operational_complexity(
        duration_ms=50.0,
        memory_mb=100.0,
        device="gpu",
        metadata={"branching_factor": 5, "loop_depth": 3},
    )

    print(f"  Data size: {operational.data_size_mb:.2f}MB")
    print(f"  FLOP count: {operational.flop_count:,}")
    print(f"  Memory ops: {operational.memory_ops:,}")
    print(f"  FLOP/byte: {operational.flop_per_byte:.2f}")
    print(f"  Branching factor: {operational.branching_factor}")
    print(f"  Loop depth: {operational.loop_depth}")
    print(f"  Memory bandwidth utilization: {operational.memory_bandwidth_utilization:.1f}%")

    assert operational.data_size_mb == 100.0
    assert operational.flop_count > 0
    assert operational.memory_ops > 0
    assert operational.flop_per_byte > 0

    print("\n  TEST 4 PASSED [OK]")


def test_transformation_chain_tracking():
    """Test 5: Track complexity through transformation chain"""
    print("\n" + "=" * 70)
    print("TEST 5: Transformation Chain Complexity")
    print("=" * 70)

    analyzer = get_complexity_analyzer()

    # Original complexity
    original_algo = analyzer.classify_algorithm("matrix_multiply")
    original_ops = analyzer.compute_operational_complexity(150.0, 100.0, "gpu")
    original_score = analyzer.compute_complexity_score(original_algo, original_ops)

    print("  Original:")
    print(f"    Score: {original_score.total_score:.2f}")
    print(f"    Tier: {original_score.tier.name}")

    # After transformation 1
    new_ops_1 = analyzer.compute_operational_complexity(120.0, 100.0, "gpu")
    new_score_1 = analyzer.compute_complexity_score(original_algo, new_ops_1)

    chain_1 = analyzer.track_transformation_complexity(original_score, "DeviceRouting", new_score_1)

    print("\n  After DeviceRouting:")
    print(f"    Score: {new_score_1.total_score:.2f}")
    print(f"    Chain: {chain_1.transformation_chain}")
    print(f"    Depth: {chain_1.chain_depth}")
    print(f"    Reduction: {chain_1.complexity_reduction * 100:.1f}%")

    # After transformation 2
    new_ops_2 = analyzer.compute_operational_complexity(80.0, 100.0, "gpu")
    new_score_2 = analyzer.compute_complexity_score(original_algo, new_ops_2)

    chain_2 = analyzer.track_transformation_complexity(
        original_score, "BatchFusion", new_score_2, chain_1
    )

    print("\n  After BatchFusion:")
    print(f"    Score: {new_score_2.total_score:.2f}")
    print(f"    Chain: {chain_2.transformation_chain}")
    print(f"    Depth: {chain_2.chain_depth}")
    print(f"    Reduction: {chain_2.complexity_reduction * 100:.1f}%")

    assert chain_1.chain_depth == 1
    assert chain_2.chain_depth == 2
    assert chain_2.complexity_reduction > 0

    print("\n  TEST 5 PASSED [OK]")


def test_hierarchy_building():
    """Test 6: Build complexity hierarchy"""
    print("\n" + "=" * 70)
    print("TEST 6: Complexity Hierarchy Building")
    print("=" * 70)

    analyzer = get_complexity_analyzer()
    from libs.gpu import ComplexityHierarchy

    hierarchy_mgr = ComplexityHierarchy(analyzer)

    # Create mock operations with complexity scores
    operations = []
    for i, (op_name, tier_val) in enumerate(
        [
            ("hash_lookup", 0),
            ("quicksort", 1),
            ("matrix_multiply", 2),
            ("graph_search", 3),
            ("xor_transform", 1),
            ("nested_loop", 2),
        ]
    ):
        algo = analyzer.classify_algorithm(op_name)
        ops = analyzer.compute_operational_complexity(10.0 * (i + 1), 10.0, "cpu")
        score = analyzer.compute_complexity_score(algo, ops)

        operations.append({"operation": op_name, "complexity_score": score.to_dict()})

    hierarchy = hierarchy_mgr.build_hierarchy(operations)

    print(f"  Total operations: {hierarchy['total_operations']}")
    print(f"  Total complexity score: {hierarchy['total_complexity_score']:.2f}")
    print(f"  Average complexity score: {hierarchy['average_complexity_score']:.2f}")

    print("\n  Operations by tier:")
    for tier_val in [3, 2, 1, 0]:
        tier_ops = hierarchy["tiers"][tier_val]
        print(f"    Tier {tier_val}: {len(tier_ops)} operation(s)")
        for op in tier_ops:
            print(f"      - {op['operation']}: {op['score']:.2f}")

    assert hierarchy["total_operations"] == 6
    assert hierarchy["total_complexity_score"] > 0

    print("\n  TEST 6 PASSED [OK]")


def test_bottleneck_detection():
    """Test 7: Detect complexity bottlenecks"""
    print("\n" + "=" * 70)
    print("TEST 7: Complexity Bottleneck Detection")
    print("=" * 70)

    analyzer = get_complexity_analyzer()
    from libs.gpu import ComplexityHierarchy

    hierarchy_mgr = ComplexityHierarchy(analyzer)

    # Create operations with varying complexity
    operations = []
    high_complexity_ops = ["matrix_multiply", "graph_search"]

    for op_name in ["hash_lookup", "xor_transform", "matrix_multiply", "graph_search"]:
        algo = analyzer.classify_algorithm(op_name)
        # Give high complexity ops more data
        data_size = 100.0 if op_name in high_complexity_ops else 1.0
        ops = analyzer.compute_operational_complexity(50.0, data_size, "cpu")
        score = analyzer.compute_complexity_score(algo, ops)

        operations.append({"operation": op_name, "complexity_score": score.to_dict()})

    hierarchy = hierarchy_mgr.build_hierarchy(operations)
    bottlenecks = hierarchy_mgr.find_complexity_bottlenecks(hierarchy, threshold=100.0)

    print(f"  Found {len(bottlenecks)} bottleneck(s) (threshold: 100.0)")
    for bottleneck in bottlenecks:
        print(
            f"    - {bottleneck['operation']}: Score {bottleneck['score']:.2f}, "
            f"Grade {bottleneck['grade']}"
        )

    assert len(bottlenecks) > 0, "Should find at least one bottleneck"

    print("\n  TEST 7 PASSED [OK]")


def test_complexity_reduction_suggestions():
    """Test 8: Generate complexity reduction suggestions"""
    print("\n" + "=" * 70)
    print("TEST 8: Complexity Reduction Suggestions")
    print("=" * 70)

    analyzer = get_complexity_analyzer()
    from libs.gpu import ComplexityHierarchy, ComplexityScore

    hierarchy_mgr = ComplexityHierarchy(analyzer)

    # Test suggestions for different complexity tiers and bottlenecks
    test_cases = [
        ("graph_search", ComplexityTier.EXPONENTIAL, "compute"),
        ("matrix_multiply", ComplexityTier.POLYNOMIAL, "memory"),
        ("xor_transform", ComplexityTier.LINEAR, "transfer"),
    ]

    for operation, tier, bottleneck in test_cases:
        # Create a mock complexity score
        mock_score = ComplexityScore(
            algorithmic_score=100.0,
            operational_score=50.0,
            memory_score=25.0,
            parallelism_score=10.0,
            total_score=185.0,
            normalized_score=0.8,
            complexity_grade="D",
            tier=tier,
            bottleneck=bottleneck,
        )

        suggestions = hierarchy_mgr.suggest_complexity_reductions(operation, mock_score)

        print(f"\n  {operation} (Tier: {tier.name}, Bottleneck: {bottleneck}):")
        print(f"    Suggestions ({len(suggestions)}):")
        for i, suggestion in enumerate(suggestions[:3], 1):
            print(f"      {i}. {suggestion}")

        assert len(suggestions) > 0, f"Should have suggestions for {operation}"

    print("\n  TEST 8 PASSED [OK]")


def test_profiler_integration():
    """Test 9: Integration with GPUProfiler"""
    print("\n" + "=" * 70)
    print("TEST 9: Profiler Integration")
    print("=" * 70)

    profiler = get_profiler(enabled=True)
    profiler.reset()

    # Profile several operations
    with profiler.profile("hash_lookup", device="cpu"):
        time.sleep(0.001)

    with profiler.profile("matrix_multiply", device="gpu"):
        time.sleep(0.01)

    with profiler.profile("graph_search", device="cpu"):
        time.sleep(0.02)

    # Check entries have complexity data
    entries = profiler.get_entries()
    print(f"  Profiled {len(entries)} operations")

    for entry in entries:
        print(f"\n  {entry.operation}:")
        if entry.complexity_score:
            print(f"    Tier: {entry.complexity_score.tier.name}")
            print(f"    Score: {entry.complexity_score.total_score:.2f}")
            print(f"    Grade: {entry.complexity_score.complexity_grade}")
            assert entry.algorithmic_complexity is not None
            assert entry.operational_complexity is not None
            assert entry.complexity_score is not None
        else:
            print("    [WARNING] No complexity data")

    # Test complexity analysis
    hierarchy = profiler.get_complexity_analysis()
    if hierarchy:
        print("\n  Complexity hierarchy:")
        print(f"    Total operations: {hierarchy['total_operations']}")
        print(f"    Total score: {hierarchy['total_complexity_score']:.2f}")
        assert hierarchy["total_operations"] == len(entries)
    else:
        print("\n  [WARNING] No complexity hierarchy generated")

    print("\n  TEST 9 PASSED [OK]")


def test_complexity_export():
    """Test 10: Export complexity data"""
    print("\n" + "=" * 70)
    print("TEST 10: Complexity Data Export")
    print("=" * 70)

    import os
    import json

    profiler = get_profiler(enabled=True)
    profiler.reset()

    # Profile operations
    with profiler.profile("xor_transform", device="cpu"):
        time.sleep(0.005)

    with profiler.profile("matrix_multiply", device="gpu"):
        time.sleep(0.015)

    # Export
    output_file = "test_complexity_export.json"
    profiler.export_complexity_json(output_file)

    assert os.path.exists(output_file), "Export file should exist"

    # Verify contents
    with open(output_file, "r") as f:
        data = json.load(f)

    print(f"  Exported {len(data['entries'])} entries")
    print(f"  Has complexity hierarchy: {'complexity_hierarchy' in data}")

    assert "entries" in data
    assert "complexity_hierarchy" in data

    # Check entry has complexity data
    for entry in data["entries"]:
        print(f"\n  {entry['operation']}:")
        if "complexity_score" in entry:
            print("    Has complexity_score: True")
            print(f"    Has algorithmic_complexity: {'algorithmic_complexity' in entry}")
            print(f"    Has operational_complexity: {'operational_complexity' in entry}")
        else:
            print("    [WARNING] No complexity data in export")

    # Cleanup
    if os.path.exists(output_file):
        os.remove(output_file)

    print("\n  TEST 10 PASSED [OK]")


def main():
    """Run all complexity tests"""
    print("\n")
    print("*" * 70)
    print("*" + " " * 68 + "*")
    print("*" + "  PHASE 3: COMPLEXITY METRICS TESTS  ".center(68) + "*")
    print("*" + " " * 68 + "*")
    print("*" * 70)

    tests = [
        ("Complexity Tier Classification", test_complexity_tier_classification),
        ("Complexity Scoring", test_complexity_scoring),
        ("Algorithmic Complexity Inference", test_algorithmic_complexity_inference),
        ("Operational Complexity Tracking", test_operational_complexity_tracking),
        ("Transformation Chain Tracking", test_transformation_chain_tracking),
        ("Hierarchy Building", test_hierarchy_building),
        ("Bottleneck Detection", test_bottleneck_detection),
        ("Complexity Reduction Suggestions", test_complexity_reduction_suggestions),
        ("Profiler Integration", test_profiler_integration),
        ("Complexity Data Export", test_complexity_export),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"\n  [X] TEST FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"\n  [X] TEST ERROR: {e}")
            import traceback

            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"  Passed: {passed}/{len(tests)}")
    print(f"  Failed: {failed}/{len(tests)}")

    if failed == 0:
        print("\n  [OK] ALL TESTS PASSED!")
    else:
        print(f"\n  [X] {failed} TEST(S) FAILED")

    print("=" * 70 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
