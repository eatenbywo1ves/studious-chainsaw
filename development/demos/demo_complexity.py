#!/usr/bin/env python3
"""
Demo: Hierarchical Complexity Metrics (Phase 3)
Demonstrates Mernithian-inspired complexity tracking system
"""

import sys
import io
from pathlib import Path
import time

# Set UTF-8 encoding for stdout to handle mathematical symbols
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu import get_profiler, get_complexity_analyzer


def demo_basic_complexity_tracking():
    """Demo 1: Basic complexity tracking"""
    print("="*70)
    print("DEMO 1: Basic Complexity Tracking")
    print("="*70)

    profiler = get_profiler(enabled=True)
    profiler.reset()

    print("\nProfiling operations with automatic complexity tracking...")

    # Profile operations of different complexities
    operations = [
        ("hash_lookup", 0.001, "cpu"),
        ("xor_transform", 0.003, "cpu"),
        ("quicksort", 0.005, "cpu"),
        ("matrix_multiply", 0.02, "gpu"),
        ("nested_loop", 0.015, "gpu"),
        ("graph_search", 0.03, "cpu"),
    ]

    for op_name, sleep_time, device in operations:
        with profiler.profile(op_name, device=device):
            time.sleep(sleep_time)

    print("\n" + "="*70)
    profiler.print_complexity_summary()


def demo_complexity_hierarchy():
    """Demo 2: Complexity hierarchy visualization"""
    print("\n" + "="*70)
    print("DEMO 2: Complexity Hierarchy with Mernithian Symbols")
    print("="*70)

    analyzer = get_complexity_analyzer()

    print("\nMernithian Complexity Tiers:")
    print("  ⊕  Tier 0 (Trivial)    - O(1), O(log n)     - Base Score: 1")
    print("  ⊘  Tier 1 (Linear)     - O(n), O(n log n)   - Score: 10")
    print("  ⊗  Tier 2 (Polynomial) - O(n²), O(n³)       - Score: 100")
    print("  ⊙  Tier 3 (Exponential)- O(2ⁿ), O(n!)       - Score: 1000")

    print("\nOperation Classification Examples:")
    operations = [
        'hash_lookup',
        'xor_transform',
        'quicksort',
        'matrix_multiply',
        'bubble_sort',
        'graph_search',
        'traveling_salesman'
    ]

    for op in operations:
        complexity = analyzer.classify_algorithm(op)
        symbols = {
            0: "⊕",
            1: "⊘",
            2: "⊗",
            3: "⊙"
        }
        symbol = symbols[complexity.tier.value]

        print(f"  {symbol}  {op:<25} {complexity.time_complexity:<12} "
              f"({complexity.complexity_class.value})")


def demo_transformation_complexity():
    """Demo 3: Complexity through transformation pipeline"""
    print("\n" + "="*70)
    print("DEMO 3: Complexity Evolution Through Transformations")
    print("="*70)

    analyzer = get_complexity_analyzer()

    # Original operation
    print("\nOriginal Operation: matrix_multiply (GPU)")
    algo = analyzer.classify_algorithm('matrix_multiply')
    ops_original = analyzer.compute_operational_complexity(150.0, 100.0, 'gpu')
    score_original = analyzer.compute_complexity_score(algo, ops_original)

    print(f"  Tier: {score_original.tier.name}")
    print(f"  Complexity Score: {score_original.total_score:.2f}")
    print(f"  Grade: {score_original.complexity_grade}")
    print(f"  Time Complexity: {algo.time_complexity}")

    # After transformation 1: Device routing
    print("\n→ Transformation 1: Device Routing")
    ops_1 = analyzer.compute_operational_complexity(130.0, 100.0, 'gpu')
    score_1 = analyzer.compute_complexity_score(algo, ops_1)
    chain_1 = analyzer.track_transformation_complexity(
        score_original,
        "DeviceRouting",
        score_1
    )

    print(f"  New Score: {score_1.total_score:.2f}")
    print(f"  Complexity Reduction: {chain_1.complexity_reduction*100:.1f}%")
    print(f"  Chain Depth: {chain_1.chain_depth}")

    # After transformation 2: Batch fusion
    print("\n→ Transformation 2: Batch Fusion")
    ops_2 = analyzer.compute_operational_complexity(100.0, 100.0, 'gpu')
    score_2 = analyzer.compute_complexity_score(algo, ops_2)
    chain_2 = analyzer.track_transformation_complexity(
        score_original,
        "BatchFusion",
        score_2,
        chain_1
    )

    print(f"  New Score: {score_2.total_score:.2f}")
    print(f"  Complexity Reduction: {chain_2.complexity_reduction*100:.1f}%")
    print(f"  Chain Depth: {chain_2.chain_depth}")
    print(f"  Transformation Chain: {' → '.join(chain_2.transformation_chain)}")

    # After transformation 3: Kernel fusion
    print("\n→ Transformation 3: Kernel Fusion")
    ops_3 = analyzer.compute_operational_complexity(70.0, 100.0, 'gpu')
    score_3 = analyzer.compute_complexity_score(algo, ops_3)
    chain_3 = analyzer.track_transformation_complexity(
        score_original,
        "KernelFusion",
        score_3,
        chain_2
    )

    print(f"  Final Score: {score_3.total_score:.2f}")
    print(f"  Total Complexity Reduction: {chain_3.complexity_reduction*100:.1f}%")
    print(f"  Final Chain Depth: {chain_3.chain_depth}")
    print(f"  Full Chain: {' → '.join(chain_3.transformation_chain)}")


def demo_bottleneck_identification():
    """Demo 4: Identify and suggest fixes for bottlenecks"""
    print("\n" + "="*70)
    print("DEMO 4: Bottleneck Identification and Optimization Suggestions")
    print("="*70)

    profiler = get_profiler(enabled=True)
    profiler.reset()

    print("\nProfiling mixed workload...")

    # Mix of operations - some are bottlenecks
    with profiler.profile("hash_lookup", device="cpu"):
        time.sleep(0.001)

    with profiler.profile("matrix_multiply", device="gpu"):
        time.sleep(0.025)

    with profiler.profile("xor_transform", device="cpu"):
        time.sleep(0.002)

    with profiler.profile("graph_search", device="cpu"):
        time.sleep(0.035)

    with profiler.profile("nested_loop", device="gpu"):
        time.sleep(0.020)

    # Analyze and show bottlenecks
    hierarchy = profiler.get_complexity_analysis()
    if hierarchy:
        analyzer = get_complexity_analyzer()
        from libs.gpu import ComplexityHierarchy

        hierarchy_mgr = ComplexityHierarchy(analyzer)
        bottlenecks = hierarchy_mgr.find_complexity_bottlenecks(hierarchy, threshold=50.0)

        if bottlenecks:
            print(f"\nFound {len(bottlenecks)} complexity bottleneck(s) (threshold: 50.0):\n")
            for i, bottleneck in enumerate(bottlenecks, 1):
                print(f"{i}. {bottleneck['operation']}")
                print(f"   Score: {bottleneck['score']:.2f}")
                print(f"   Grade: {bottleneck['grade']}")
                print(f"   Tier: {bottleneck['tier']}")

                # Get suggestions
                from libs.gpu import ComplexityScore
                mock_score = ComplexityScore(
                    algorithmic_score=100.0,
                    operational_score=50.0,
                    memory_score=25.0,
                    parallelism_score=10.0,
                    total_score=bottleneck['score'],
                    normalized_score=0.7,
                    complexity_grade=bottleneck['grade'],
                    tier=bottleneck['tier'],
                    bottleneck=bottleneck['bottleneck']
                )

                suggestions = hierarchy_mgr.suggest_complexity_reductions(
                    bottleneck['operation'],
                    mock_score
                )

                if suggestions:
                    print("   Optimization Suggestions:")
                    for suggestion in suggestions[:3]:
                        print(f"     • {suggestion}")
                print()


def demo_complexity_export():
    """Demo 5: Export complexity data for visualization"""
    print("\n" + "="*70)
    print("DEMO 5: Export Complexity Data")
    print("="*70)

    profiler = get_profiler(enabled=True)
    profiler.reset()

    print("\nProfiling operations...")

    operations = [
        ("hash_lookup", 0.001, "cpu"),
        ("matrix_multiply", 0.015, "gpu"),
        ("graph_search", 0.025, "cpu"),
    ]

    for op_name, sleep_time, device in operations:
        with profiler.profile(op_name, device=device):
            time.sleep(sleep_time)

    # Export with complexity data
    output_file = "demo_complexity_export.json"
    profiler.export_complexity_json(output_file)

    print(f"\n✓ Exported complexity data to: {output_file}")
    print("  Contains:")
    print("    - Operation entries with complexity metrics")
    print("    - Algorithmic complexity (Big-O classification)")
    print("    - Operational complexity (runtime metrics)")
    print("    - Complexity scores and grades")
    print("    - Complexity hierarchy tree")


def demo_multiplicative_scaling():
    """Demo 6: Show multiplicative scaling across tiers"""
    print("\n" + "="*70)
    print("DEMO 6: Multiplicative Complexity Scaling")
    print("="*70)

    analyzer = get_complexity_analyzer()

    print("\nComplexity scaling demonstration:")
    print("Each tier represents ~10x increase in computational cost\n")

    test_ops = [
        ('hash_lookup', 0),
        ('xor_transform', 1),
        ('matrix_multiply', 2),
        ('graph_search', 3)
    ]

    print(f"{'Operation':<20} {'Tier':<8} {'Symbol':<8} {'Base Score':<12} {'Ratio to Tier 0'}")
    print("-" * 70)

    symbols = {0: "⊕", 1: "⊘", 2: "⊗", 3: "⊙"}
    base_scores = {0: 1.0, 1: 10.0, 2: 100.0, 3: 1000.0}

    for op_name, tier_val in test_ops:
        analyzer.classify_algorithm(op_name)
        base_score = base_scores[tier_val]
        ratio = base_score / base_scores[0]
        symbol = symbols[tier_val]

        print(f"{op_name:<20} {tier_val:<8} {symbol:<8} {base_score:<12.1f} {ratio:>12.0f}x")

    print("\nThis multiplicative hierarchy allows:")
    print("  • Quick identification of high-complexity operations")
    print("  • Quantification of optimization impact")
    print("  • Prioritization of optimization efforts")


def main():
    """Run all complexity demos"""
    print("\n")
    print("*"*70)
    print("*" + " "*68 + "*")
    print("*" + "  MERNITHIAN COMPLEXITY TRACKING - PHASE 3 DEMO  ".center(68) + "*")
    print("*" + " "*68 + "*")
    print("*"*70)
    print()

    demos = [
        demo_basic_complexity_tracking,
        demo_complexity_hierarchy,
        demo_transformation_complexity,
        demo_bottleneck_identification,
        demo_complexity_export,
        demo_multiplicative_scaling
    ]

    for demo in demos:
        try:
            demo()
        except Exception as e:
            print(f"\n[ERROR] Demo failed: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "="*70)
    print("DEMO COMPLETE!")
    print("="*70)
    print("\nPhase 3 Features Demonstrated:")
    print("  ✓ Automatic complexity classification (4-tier hierarchy)")
    print("  ✓ Multiplicative complexity scoring (1x → 10x → 100x → 1000x)")
    print("  ✓ Transformation chain complexity tracking")
    print("  ✓ Bottleneck identification and optimization suggestions")
    print("  ✓ Complexity data export (JSON)")
    print("  ✓ Mernithian symbolic notation (⊕ ⊘ ⊗ ⊙)")
    print("\nNext: Integrate with visualization (profiler_visualization_v2.html)")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
