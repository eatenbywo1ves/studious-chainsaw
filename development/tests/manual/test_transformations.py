#!/usr/bin/env python3
"""
Test Suite for Phase 2: Transformation Equivalence Framework
Tests the Mernithian-inspired E₁ ⟷ᵀ E₂ transformation system
"""

import sys
import io
from pathlib import Path

# Set UTF-8 encoding for stdout to handle mathematical symbols
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu import (
    get_transformation_catalog
)


def test_transformation_catalog():
    """Test 1: Catalog initialization and rule loading"""
    print("\n" + "="*70)
    print("TEST 1: Transformation Catalog Initialization")
    print("="*70)

    catalog = get_transformation_catalog()
    assert catalog is not None, "Catalog should be initialized"

    # Check standard rules are loaded
    expected_rules = [
        "SmallGPUToCPU",
        "LargeCPUToGPU",
        "BatchFusion",
        "MemoryPooling",
        "PrecisionReduction",
        "KernelFusion"
    ]

    for rule_name in expected_rules:
        rule = catalog.get_rule(rule_name)
        assert rule is not None, f"Rule {rule_name} should exist"
        print(f"  [OK] {rule_name}: {rule.transformation_type.value}")

    print(f"\n  Total rules loaded: {len(catalog.rules)}")
    print("  TEST 1 PASSED [OK]")


def test_small_gpu_to_cpu_transformation():
    """Test 2: SmallGPUToCPU transformation rule"""
    print("\n" + "="*70)
    print("TEST 2: SmallGPUToCPU Transformation")
    print("="*70)

    catalog = get_transformation_catalog()
    rule = catalog.get_rule("SmallGPUToCPU")

    # Test applicable context (small data, transfer-bound)
    applicable_context = {
        'data_size_mb': 0.5,              # Small data
        'transfer_time_ratio': 0.4,       # Transfer-bound
        'flop_per_byte': 1.5,             # Not compute-bound
        'operation_type': 'xor_transform'
    }

    assert rule.is_applicable(applicable_context), \
        "Rule should apply to small transfer-bound operations"

    speedup = rule.estimate_speedup(applicable_context)
    print(f"  Context: {applicable_context['data_size_mb']:.1f}MB, "
          f"{applicable_context['transfer_time_ratio']*100:.0f}% transfer time")
    print(f"  Estimated speedup: {speedup:.1f}x")
    print(f"  Expected range: {rule.expected_speedup_range[0]:.1f}x - "
          f"{rule.expected_speedup_range[1]:.1f}x")

    # Test non-applicable context (large data)
    non_applicable_context = {
        'data_size_mb': 150.0,            # Large data
        'transfer_time_ratio': 0.1,
        'flop_per_byte': 1.0,
        'operation_type': 'matrix_multiply'
    }

    assert not rule.is_applicable(non_applicable_context), \
        "Rule should not apply to large operations"

    print("  [OK] Correctly rejects large data operations")
    print("  TEST 2 PASSED [OK]")


def test_batch_fusion_transformation():
    """Test 3: BatchFusion transformation rule"""
    print("\n" + "="*70)
    print("TEST 3: BatchFusion Transformation")
    print("="*70)

    catalog = get_transformation_catalog()
    rule = catalog.get_rule("BatchFusion")

    # Test applicable context (multiple independent ops)
    applicable_context = {
        'similar_ops_count': 10,          # Multiple similar operations
        'has_dependencies': False,        # Independent
        'data_size_mb': 5.0,
        'operation_type': 'transform'
    }

    assert rule.is_applicable(applicable_context), \
        "Rule should apply to multiple independent operations"

    speedup = rule.estimate_speedup(applicable_context)
    print(f"  Context: {applicable_context['similar_ops_count']} independent operations")
    print(f"  Estimated speedup: {speedup:.1f}x")

    # Test proof structure
    assert rule.proof.theorem, "Should have formal theorem"
    assert len(rule.proof.assumptions) > 0, "Should have assumptions"
    assert len(rule.proof.proof_sketch) > 0, "Should have proof sketch"
    assert len(rule.proof.invariants) > 0, "Should have invariants"

    print(f"  Theorem: {rule.proof.theorem[:80]}...")
    print(f"  Assumptions: {len(rule.proof.assumptions)}")
    print(f"  Proof steps: {len(rule.proof.proof_sketch)}")
    print(f"  Invariants: {len(rule.proof.invariants)}")

    print("  TEST 3 PASSED [OK]")


def test_transformation_applicability():
    """Test 4: Find applicable transformations for various contexts"""
    print("\n" + "="*70)
    print("TEST 4: Transformation Applicability Analysis")
    print("="*70)

    catalog = get_transformation_catalog()

    # Test scenario 1: Small GPU operation (XOR-like)
    context1 = {
        'data_size_mb': 0.1,
        'transfer_time_ratio': 0.5,
        'flop_per_byte': 1.0,
        'operation_type': 'xor'
    }

    applicable1 = catalog.find_applicable_transformations(context1)
    print("\n  Scenario 1: Small GPU operation (0.1MB)")
    print(f"  Applicable transformations: {len(applicable1)}")
    for rule, speedup in applicable1:
        print(f"    - {rule.name}: {speedup:.1f}x speedup")

    assert len(applicable1) > 0, "Should find at least one applicable transformation"
    assert any(r.name == "SmallGPUToCPU" for r, _ in applicable1), \
        "Should suggest SmallGPUToCPU"

    # Test scenario 2: Multiple batching opportunity
    context2 = {
        'similar_ops_count': 20,
        'has_dependencies': False,
        'data_size_mb': 10.0
    }

    applicable2 = catalog.find_applicable_transformations(context2)
    print("\n  Scenario 2: Multiple independent operations")
    print(f"  Applicable transformations: {len(applicable2)}")
    for rule, speedup in applicable2:
        print(f"    - {rule.name}: {speedup:.1f}x speedup")

    assert any(r.name == "BatchFusion" for r, _ in applicable2), \
        "Should suggest BatchFusion"

    # Test scenario 3: Large CPU operation
    context3 = {
        'data_size_mb': 200.0,
        'flop_per_byte': 15.0,           # Compute-bound
        'transfer_time_ratio': 0.1,
        'device': 'cpu'
    }

    applicable3 = catalog.find_applicable_transformations(context3)
    print("\n  Scenario 3: Large compute-bound CPU operation")
    print(f"  Applicable transformations: {len(applicable3)}")
    for rule, speedup in applicable3:
        print(f"    - {rule.name}: {speedup:.1f}x speedup")

    assert any(r.name == "LargeCPUToGPU" for r, _ in applicable3), \
        "Should suggest LargeCPUToGPU"

    print("\n  TEST 4 PASSED [OK]")


def test_transformation_verification():
    """Test 5: Verify transformation correctness"""
    print("\n" + "="*70)
    print("TEST 5: Transformation Verification")
    print("="*70)

    catalog = get_transformation_catalog()

    # Simulate before/after metrics for SmallGPUToCPU
    before_metrics = {
        'duration_ms': 10.0,
        'memory_peak_mb': 0.5,
        'error': None
    }

    after_metrics = {
        'duration_ms': 1.0,              # 10x speedup
        'memory_peak_mb': 0.5,           # Neutral memory
        'error': None                     # No errors
    }

    report = catalog.verify_transformation("SmallGPUToCPU", before_metrics, after_metrics)

    print("  Rule: SmallGPUToCPU")
    print(f"  Performance improvement: {report['performance_improvement']:.1f}x")
    print(f"  Correctness check: {report['correctness_check']}")
    print(f"  Invariants preserved: {len(report['invariants_preserved'])}")

    if report['warnings']:
        print("  Warnings:")
        for warning in report['warnings']:
            print(f"    - {warning}")

    assert report['correctness_check'], "Transformation should be correct"
    assert report['performance_improvement'] > 5.0, "Should achieve significant speedup"

    print("  TEST 5 PASSED [OK]")


def test_transformation_report_generation():
    """Test 6: Generate transformation analysis report"""
    print("\n" + "="*70)
    print("TEST 6: Transformation Report Generation")
    print("="*70)

    catalog = get_transformation_catalog()

    # Context with multiple applicable transformations
    context = {
        'data_size_mb': 0.5,
        'transfer_time_ratio': 0.4,
        'flop_per_byte': 1.5,
        'similar_ops_count': 5,
        'has_dependencies': False,
        'alloc_frequency': 150,
        'data_reuse_count': 5
    }

    report = catalog.generate_transformation_report(context)

    print("\n" + report)

    assert "TRANSFORMATION ANALYSIS REPORT" in report, "Should contain report header"
    assert "Theorem:" in report, "Should include formal theorems"
    assert "Assumptions:" in report, "Should include assumptions"

    print("  TEST 6 PASSED [OK]")


def test_optimizer_integration():
    """Test 7: Integration with ProfilerOptimizer"""
    print("\n" + "="*70)
    print("TEST 7: ProfilerOptimizer Integration")
    print("="*70)

    from libs.gpu import ProfilerOptimizer

    # Create sample profiling data
    profiling_data = {
        'summary': {
            'xor_transform': {
                'call_count': 1,
                'avg_time_ms': 0.5,
                'total_time_ms': 0.5,
                'min_time_ms': 0.5,
                'max_time_ms': 0.5,
                'total_gpu_time_ms': 0.0,
                'avg_memory_mb': 0.1,
                'avg_gpu_utilization': 0.0
            },
            'matrix_multiply': {
                'call_count': 15,
                'avg_time_ms': 5.0,
                'total_time_ms': 75.0,
                'min_time_ms': 4.8,
                'max_time_ms': 5.2,
                'total_gpu_time_ms': 70.0,
                'avg_memory_mb': 10.0,
                'avg_gpu_utilization': 85.0
            }
        },
        'entries': [
            {
                'operation': 'xor_transform',
                'duration_ms': 0.5,
                'device': 'gpu',
                'memory_allocated_mb': 0.1,
                'gpu_utilization': 0.0
            },
            {
                'operation': 'matrix_multiply',
                'duration_ms': 5.0,
                'device': 'gpu',
                'memory_allocated_mb': 10.0,
                'gpu_utilization': 85.0
            }
        ]
    }

    optimizer = ProfilerOptimizer(profiling_data)
    suggestions = optimizer.get_suggestions()

    print(f"\n  Generated {len(suggestions)} suggestions")

    # Check that suggestions have transformation information
    transformation_suggestions = [s for s in suggestions if s.transformation_rule]
    print(f"  Suggestions with transformation rules: {len(transformation_suggestions)}")

    for sugg in transformation_suggestions:
        print(f"\n  Operation: {sugg.operation}")
        print(f"    Transformation: {sugg.transformation_rule}")
        if sugg.formal_theorem:
            print(f"    Theorem: {sugg.formal_theorem[:60]}...")
        print(f"    Assumptions: {len(sugg.assumptions)}")
        print(f"    Invariants: {len(sugg.invariants)}")

    assert len(transformation_suggestions) > 0, \
        "Should have suggestions with transformation rules"

    print("\n  TEST 7 PASSED [OK]")


def test_proof_structure():
    """Test 8: Verify proof structure completeness"""
    print("\n" + "="*70)
    print("TEST 8: Proof Structure Verification")
    print("="*70)

    catalog = get_transformation_catalog()

    all_rules_have_proofs = True
    for rule_name, rule in catalog.rules.items():
        has_theorem = bool(rule.proof.theorem)
        has_assumptions = len(rule.proof.assumptions) > 0
        has_proof_sketch = len(rule.proof.proof_sketch) > 0
        has_invariants = len(rule.proof.invariants) > 0

        print(f"\n  {rule_name}:")
        print(f"    Theorem: {'[OK]' if has_theorem else '[X]'}")
        print(f"    Assumptions: {len(rule.proof.assumptions)}")
        print(f"    Proof steps: {len(rule.proof.proof_sketch)}")
        print(f"    Invariants: {len(rule.proof.invariants)}")

        if not (has_theorem and has_assumptions and has_proof_sketch and has_invariants):
            all_rules_have_proofs = False
            print("    [WARNING] Incomplete proof structure")

    assert all_rules_have_proofs, "All rules should have complete proof structures"

    print("\n  All rules have complete proof structures [OK]")
    print("  TEST 8 PASSED [OK]")


def main():
    """Run all transformation framework tests"""
    print("\n")
    print("*"*70)
    print("*" + " "*68 + "*")
    print("*" + "  PHASE 2: TRANSFORMATION FRAMEWORK TESTS  ".center(68) + "*")
    print("*" + " "*68 + "*")
    print("*"*70)

    tests = [
        ("Catalog Initialization", test_transformation_catalog),
        ("SmallGPUToCPU Rule", test_small_gpu_to_cpu_transformation),
        ("BatchFusion Rule", test_batch_fusion_transformation),
        ("Applicability Analysis", test_transformation_applicability),
        ("Verification", test_transformation_verification),
        ("Report Generation", test_transformation_report_generation),
        ("Optimizer Integration", test_optimizer_integration),
        ("Proof Structure", test_proof_structure)
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

    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"  Passed: {passed}/{len(tests)}")
    print(f"  Failed: {failed}/{len(tests)}")

    if failed == 0:
        print("\n  [OK] ALL TESTS PASSED!")
    else:
        print(f"\n  [X] {failed} TEST(S) FAILED")

    print("="*70 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
