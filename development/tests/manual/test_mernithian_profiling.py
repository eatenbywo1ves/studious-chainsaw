#!/usr/bin/env python3
"""
Mernithian GPU Profiling Test Suite
Tests glyph-based visualization system inspired by Mernithian logographic framework

Requirements:
  - Python 3.12
  - NumPy
  - GPU profiling modules
"""

import sys
import json
import tempfile
from pathlib import Path

# Add development directory to path
sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu import (
    get_profiler,
    get_glyph_analyzer,
    GlyphShape,
    IterationMarker
)


def test_glyph_shape_mapping():
    """Test glyph shape determination for different operation types"""
    print("\n" + "="*70)
    print("TEST 1: Glyph Shape Mapping")
    print("="*70)

    analyzer = get_glyph_analyzer()

    test_cases = [
        ("matrix_multiply", GlyphShape.CIRCLE),
        ("batch_process", GlyphShape.CIRCLE),
        ("xor_transform", GlyphShape.DIAMOND),
        ("graph_search", GlyphShape.HEXAGON),
        ("path_finding", GlyphShape.HEXAGON),
        ("random_generation", GlyphShape.STAR),
        ("memory_allocation", GlyphShape.TRIANGLE),
        ("routing", GlyphShape.SQUARE),
    ]

    print("\n[Test 1.1] Shape Determination")
    passed = 0
    for operation, expected_shape in test_cases:
        shape = analyzer.determine_shape(operation)
        status = "PASS" if shape == expected_shape else "FAIL"
        print(f"  {operation:<25} -> {shape.value:<10} "
              f"(expected: {expected_shape.value}) [{status}]")
        if shape == expected_shape:
            passed += 1

    assert passed == len(test_cases), f"Only {passed}/{len(test_cases)} shape tests passed"
    print(f"\n  Status: PASS ({passed}/{len(test_cases)})")
    print("\n[OK] Glyph shape mapping tests passed")
    return True


def test_performance_color_encoding():
    """Test color encoding based on performance"""
    print("\n" + "="*70)
    print("TEST 2: Performance Color Encoding")
    print("="*70)

    analyzer = get_glyph_analyzer()

    test_cases = [
        (0.5, "#00ff00", "excellent"),     # <1ms
        (5.0, "#7fff00", "good"),          # 1-10ms
        (25.0, "#ffff00", "moderate"),     # 10-50ms
        (75.0, "#ffa500", "slow"),         # 50-100ms
        (150.0, "#ff0000", "critical"),    # >100ms
    ]

    print("\n[Test 2.1] Color Determination")
    passed = 0
    for duration_ms, expected_color, category in test_cases:
        color = analyzer.determine_color(duration_ms)
        status = "PASS" if color == expected_color else "FAIL"
        print(f"  {duration_ms:>6.1f}ms -> {color} ({category:<10}) [{status}]")
        if color == expected_color:
            passed += 1

    assert passed == len(test_cases), f"Only {passed}/{len(test_cases)} color tests passed"
    print(f"\n  Status: PASS ({passed}/{len(test_cases)})")
    print("\n[OK] Color encoding tests passed")
    return True


def test_memory_size_encoding():
    """Test size encoding based on memory usage"""
    print("\n" + "="*70)
    print("TEST 3: Memory Size Encoding")
    print("="*70)

    analyzer = get_glyph_analyzer()

    test_cases = [
        (0.5, "tiny"),      # <1MB
        (5.0, "small"),     # 1-10MB
        (50.0, "medium"),   # 10-100MB
        (500.0, "large"),   # 100-1000MB
        (1500.0, "huge"),   # >1000MB
    ]

    print("\n[Test 3.1] Size Determination")
    passed = 0
    for memory_mb, expected_size in test_cases:
        size = analyzer.determine_size(memory_mb)
        status = "PASS" if size.value == expected_size else "FAIL"
        print(f"  {memory_mb:>7.1f}MB -> {size.value:<10} [{status}]")
        if size.value == expected_size:
            passed += 1

    assert passed == len(test_cases), f"Only {passed}/{len(test_cases)} size tests passed"
    print(f"\n  Status: PASS ({passed}/{len(test_cases)})")
    print("\n[OK] Size encoding tests passed")
    return True


def test_device_border_style():
    """Test border style encoding based on device"""
    print("\n" + "="*70)
    print("TEST 4: Device Border Style Encoding")
    print("="*70)

    analyzer = get_glyph_analyzer()

    test_cases = [
        ("cpu", "solid"),
        ("gpu", "dashed"),
        ("hybrid", "dotted"),
        ("GPU", "dashed"),  # Case insensitive
        ("CPU", "solid"),
    ]

    print("\n[Test 4.1] Border Style Determination")
    passed = 0
    for device, expected_style in test_cases:
        style = analyzer.determine_device_style(device)
        status = "PASS" if style.value == expected_style else "FAIL"
        print(f"  {device:<10} -> {style.value:<10} [{status}]")
        if style.value == expected_style:
            passed += 1

    assert passed == len(test_cases), f"Only {passed}/{len(test_cases)} style tests passed"
    print(f"\n  Status: PASS ({passed}/{len(test_cases)})")
    print("\n[OK] Border style encoding tests passed")
    return True


def test_iteration_markers():
    """Test iteration marker determination based on optimization level"""
    print("\n" + "="*70)
    print("TEST 5: Iteration Markers (Optimization Levels)")
    print("="*70)

    analyzer = get_glyph_analyzer()

    test_cases = [
        ({}, IterationMarker.BASE, 0, "base"),
        ({"smart_routed": True}, IterationMarker.ROUTED, 1, "routed"),
        ({"batched": True}, IterationMarker.BATCHED, 2, "batched"),
        ({"fully_optimized": True}, IterationMarker.OPTIMIZED, 3, "optimized"),
        ({"smart_routed": True, "batched": True}, IterationMarker.OPTIMIZED, 3, "optimized"),
    ]

    print("\n[Test 5.1] Iteration Marker Determination")
    passed = 0
    for metadata, expected_marker, expected_level, description in test_cases:
        marker, level = analyzer.determine_iteration_marker(metadata)
        marker_match = marker == expected_marker
        level_match = level == expected_level
        status = "PASS" if (marker_match and level_match) else "FAIL"
        print(f"  {description:<15} -> {marker.value:<12} (level {level}) [{status}]")
        if marker_match and level_match:
            passed += 1

    assert passed == len(test_cases), f"Only {passed}/{len(test_cases)} marker tests passed"
    print(f"\n  Status: PASS ({passed}/{len(test_cases)})")
    print("\n[OK] Iteration marker tests passed")
    return True


def test_glyph_notation():
    """Test glyph notation generation"""
    print("\n" + "="*70)
    print("TEST 6: Glyph Notation (Mernithian Style)")
    print("="*70)

    analyzer = get_glyph_analyzer()

    # Create glyphs with different characteristics
    test_cases = [
        ("matrix_multiply", 45.0, 16.0, "gpu", {}, "O+", "base compute"),
        ("xor_transform", 0.25, 0.1, "cpu", {"smart_routed": True}, "<>/", "routed transform"),
        ("batch_process", 120.0, 64.0, "gpu", {"batched": True}, "Ox", "batched compute"),
        ("graph_search", 75.0, 2.5, "cpu", {"fully_optimized": True}, "#o", "optimized graph"),
    ]

    print("\n[Test 6.1] Notation Generation")
    passed = 0
    for op, duration, memory, device, metadata, expected_notation, description in test_cases:
        glyph = analyzer.create_glyph(op, duration, memory, device, metadata)
        notation = glyph.get_notation()
        status = "PASS" if notation == expected_notation else "FAIL"
        print(f"  {description:<25} -> {notation:<6} (expected: {expected_notation}) [{status}]")
        if notation == expected_notation:
            passed += 1

    assert passed == len(test_cases), f"Only {passed}/{len(test_cases)} notation tests passed"
    print(f"\n  Status: PASS ({passed}/{len(test_cases)})")
    print("\n[OK] Glyph notation tests passed")
    return True


def test_profiler_glyph_integration():
    """Test integration of glyph system with GPU profiler"""
    print("\n" + "="*70)
    print("TEST 7: Profiler-Glyph Integration")
    print("="*70)

    profiler = get_profiler(enabled=True)
    profiler.reset()

    print("\n[Test 7.1] Profile Operations")
    # Profile some operations
    with profiler.profile("matrix_multiply", device="gpu", smart_routed=False):
        import time
        time.sleep(0.01)  # Simulate work

    with profiler.profile("xor_transform", device="cpu", smart_routed=True, speedup=180):
        import time
        time.sleep(0.001)  # Simulate work

    print(f"  Profiled {len(profiler.get_entries())} operations")
    assert len(profiler.get_entries()) == 2, "Should have 2 profiled operations"
    print("  Status: PASS")

    print("\n[Test 7.2] Generate Glyphs from Profiling Data")
    glyphs = profiler.get_glyphs()
    assert glyphs is not None, "Should be able to generate glyphs"
    assert len(glyphs) == 2, f"Should have 2 glyphs, got {len(glyphs)}"
    print(f"  Generated {len(glyphs)} glyphs")
    for glyph in glyphs:
        print(f"    {glyph.get_notation():<10} {glyph.operation_name:<20} {glyph.duration_ms:.2f}ms")
    print("  Status: PASS")

    print("\n[Test 7.3] Print Glyph Summary")
    profiler.print_glyph_summary()
    print("  Status: PASS")

    print("\n[Test 7.4] Export Glyphs to JSON")
    with tempfile.NamedTemporaryFile(mode='w', suffix='_glyphs.json', delete=False) as f:
        glyph_file = f.name

    profiler.export_glyphs_json(glyph_file)

    # Verify export
    with open(glyph_file, 'r') as f:
        data = json.load(f)

    assert 'glyphs' in data, "Should have glyphs key"
    assert 'glyph_count' in data, "Should have glyph_count key"
    assert data['glyph_count'] == 2, f"Should have 2 glyphs, got {data['glyph_count']}"

    print(f"  Exported to: {glyph_file}")
    print(f"  Glyph count: {data['glyph_count']}")

    # Check glyph structure
    glyph_data = data['glyphs'][0]
    required_keys = ['operation', 'shape', 'color', 'size', 'border',
                     'iteration', 'glyph_notation', 'duration_ms', 'memory_mb']
    for key in required_keys:
        assert key in glyph_data, f"Glyph data missing key: {key}"

    print("  Glyph data structure valid")
    print("  Status: PASS")

    # Cleanup
    Path(glyph_file).unlink()

    print("\n[OK] Profiler-glyph integration tests passed")
    return True


def test_complex_profiling_scenario():
    """Test complex profiling scenario with multiple optimization levels"""
    print("\n" + "="*70)
    print("TEST 8: Complex Profiling Scenario")
    print("="*70)

    profiler = get_profiler(enabled=True)
    profiler.reset()

    print("\n[Test 8.1] Profile Multiple Operations")
    # Base operations
    with profiler.profile("op1", device="gpu"):
        pass

    # Routed operations
    with profiler.profile("op2", device="cpu", smart_routed=True):
        pass

    # Batched operations
    with profiler.profile("op3", device="gpu", batched=True):
        pass

    # Fully optimized
    with profiler.profile("op4", device="gpu", smart_routed=True, batched=True):
        pass

    print(f"  Profiled {len(profiler.get_entries())} operations")

    print("\n[Test 8.2] Verify Optimization Levels")
    glyphs = profiler.get_glyphs()
    assert len(glyphs) == 4, f"Should have 4 glyphs, got {len(glyphs)}"

    # Check optimization levels
    levels = [g.optimization_level for g in glyphs]
    print(f"  Optimization levels: {levels}")

    # Should have one of each level 0-3
    expected_levels = [0, 1, 2, 3]
    for expected in expected_levels:
        assert expected in levels, f"Missing optimization level {expected}"

    print("  Status: PASS")

    print("\n[Test 8.3] Export and Verify")
    with tempfile.NamedTemporaryFile(mode='w', suffix='_complex.json', delete=False) as f:
        complex_file = f.name

    profiler.export_glyphs_json(complex_file)

    with open(complex_file, 'r') as f:
        data = json.load(f)

    # Verify glyph count by optimization level
    glyph_data = data['glyphs']
    by_level = {}
    for g in glyph_data:
        level = g['optimization_level']
        by_level[level] = by_level.get(level, 0) + 1

    print(f"  Glyphs by optimization level: {by_level}")
    for level in range(4):
        assert level in by_level, f"Missing optimization level {level}"
        assert by_level[level] == 1, f"Expected 1 glyph at level {level}, got {by_level[level]}"

    print("  Status: PASS")

    # Cleanup
    Path(complex_file).unlink()

    print("\n[OK] Complex scenario tests passed")
    return True


def test_visualization_data_generation():
    """Test data generation for visualization"""
    print("\n" + "="*70)
    print("TEST 9: Visualization Data Generation")
    print("="*70)

    # Create sample profiling data
    profiling_data = {
        "entries": [
            {
                "operation": "matrix_multiply",
                "duration_ms": 45.2,
                "device": "gpu",
                "backend": "pytorch",
                "memory_allocated_mb": 16.5,
                "metadata": {"smart_routed": False}
            },
            {
                "operation": "xor_transform",
                "duration_ms": 0.25,
                "device": "cpu",
                "backend": "cpu",
                "memory_allocated_mb": 0.1,
                "metadata": {"smart_routed": True, "speedup": 180}
            }
        ]
    }

    print("\n[Test 9.1] Generate Glyphs from Data")
    analyzer = get_glyph_analyzer()
    glyphs = analyzer.analyze_profiling_data(profiling_data)

    assert len(glyphs) == 2, f"Should have 2 glyphs, got {len(glyphs)}"
    print(f"  Generated {len(glyphs)} glyphs")

    for glyph in glyphs:
        print(f"    {glyph.get_notation():<10} "
              f"{glyph.operation_name:<20} "
              f"{glyph.duration_ms:.2f}ms "
              f"({glyph.color})")

    print("  Status: PASS")

    print("\n[Test 9.2] Export for Visualization")
    with tempfile.NamedTemporaryFile(mode='w', suffix='_viz.json', delete=False) as f:
        viz_file = f.name

    analyzer.export_glyphs_json(glyphs, viz_file)

    # Verify
    with open(viz_file, 'r') as f:
        data = json.load(f)

    assert 'glyph_count' in data, "Should have glyph_count"
    assert 'glyphs' in data, "Should have glyphs array"
    assert data['glyph_count'] == 2, "Should have 2 glyphs"

    print(f"  Exported to: {viz_file}")
    print("  Status: PASS")

    # Cleanup
    Path(viz_file).unlink()

    print("\n[OK] Visualization data generation tests passed")
    return True


def main():
    print("="*70)
    print("MERNITHIAN GPU PROFILING TEST SUITE")
    print("Phase 1: Symbolic Performance Representation")
    print("="*70)

    all_passed = True

    try:
        test1 = test_glyph_shape_mapping()
        all_passed = all_passed and test1

        test2 = test_performance_color_encoding()
        all_passed = all_passed and test2

        test3 = test_memory_size_encoding()
        all_passed = all_passed and test3

        test4 = test_device_border_style()
        all_passed = all_passed and test4

        test5 = test_iteration_markers()
        all_passed = all_passed and test5

        test6 = test_glyph_notation()
        all_passed = all_passed and test6

        test7 = test_profiler_glyph_integration()
        all_passed = all_passed and test7

        test8 = test_complex_profiling_scenario()
        all_passed = all_passed and test8

        test9 = test_visualization_data_generation()
        all_passed = all_passed and test9

        # Final summary
        print("\n" + "="*70)
        print("TEST SUITE SUMMARY")
        print("="*70)
        if all_passed:
            print("[SUCCESS] ALL PHASE 1 TESTS PASSED")
            print("\nKey Features Validated:")
            print("  - Glyph shape mapping (6 shapes: O, ^, [], <>, #, *)")
            print("  - Performance color encoding (5 levels)")
            print("  - Memory size encoding (5 categories)")
            print("  - Device border styles (solid, dashed, dotted)")
            print("  - Iteration markers (4 levels: +, /, x, o)")
            print("  - Mernithian-style notation generation")
            print("  - Profiler integration (context manager)")
            print("  - JSON export with glyph metadata")
            print("  - Visualization data generation")
            print("\nPhase 1 (Symbolic Performance Representation) COMPLETE!")
        else:
            print("[FAILURE] SOME TESTS FAILED - Review output above")
        print("="*70)

        return 0 if all_passed else 1

    except Exception as e:
        print(f"\n[FAILURE] Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
