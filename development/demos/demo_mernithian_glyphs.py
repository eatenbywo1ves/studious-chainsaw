#!/usr/bin/env python3
"""
Demo: Mernithian-Inspired GPU Profiling
Shows how to use the glyph-based visualization system
"""

import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu import get_profiler, get_glyph_analyzer


def demo_basic_profiling():
    """Demo basic profiling with glyph generation"""
    print("="*70)
    print("DEMO 1: Basic Profiling with Glyphs")
    print("="*70)

    profiler = get_profiler(enabled=True)
    profiler.reset()

    # Profile various operations
    print("\nProfiling operations...")

    # Base operation (no optimization)
    with profiler.profile("matrix_multiply", device="gpu"):
        time.sleep(0.01)  # Simulate work

    # Routed operation (smart routing)
    with profiler.profile("xor_transform", device="cpu", smart_routed=True, speedup=180):
        time.sleep(0.001)  # Simulate work

    # Batched operation
    with profiler.profile("batch_process", device="gpu", batched=True):
        time.sleep(0.05)  # Simulate work

    # Fully optimized
    with profiler.profile("graph_search", device="cpu", smart_routed=True, batched=True):
        time.sleep(0.02)  # Simulate work

    print("\n" + "="*70)
    profiler.print_glyph_summary()

    # Export with glyphs
    output_file = "demo_profile_glyphs.json"
    profiler.export_glyphs_json(output_file)
    print(f"\nExported profiling data with glyphs to: {output_file}")
    print("Open profiler_visualization_v2.html and load this file!")


def demo_glyph_analyzer():
    """Demo direct glyph analyzer usage"""
    print("\n" + "="*70)
    print("DEMO 2: Direct Glyph Analyzer Usage")
    print("="*70)

    analyzer = get_glyph_analyzer()

    # Create glyphs for different scenarios
    scenarios = [
        ("Fast CPU operation", 0.5, 0.1, "cpu", {}, "Excellent performance"),
        ("GPU compute", 45.0, 16.0, "gpu", {}, "Moderate performance"),
        ("Routed transform", 0.25, 0.1, "cpu", {"smart_routed": True, "speedup": 180},
         "Optimized with 180x speedup"),
        ("Batched processing", 120.0, 64.0, "gpu", {"batched": True},
         "Batch optimized"),
        ("Fully optimized", 10.0, 2.0, "gpu", {"smart_routed": True, "batched": True},
         "All optimizations applied"),
    ]

    print("\nGlyph Generation Examples:\n")
    print(f"{'Notation':<12} {'Operation':<25} {'Time':<12} {'Memory':<12} {'Description'}")
    print("-"*90)

    for name, duration, memory, device, metadata, description in scenarios:
        glyph = analyzer.create_glyph(name, duration, memory, device, metadata)
        notation = glyph.get_notation()

        print(f"{notation:<12} {name:<25} {duration:>6.2f}ms     {memory:>6.2f}MB     {description}")


def demo_glyph_notation():
    """Demo Mernithian notation system"""
    print("\n" + "="*70)
    print("DEMO 3: Mernithian Glyph Notation System")
    print("="*70)

    print("\nShape Symbols:")
    print("  O   = Circle    (Compute operations)")
    print("  ^   = Triangle  (Memory operations)")
    print("  []  = Square    (Control flow)")
    print("  <>  = Diamond   (Transform operations)")
    print("  #   = Hexagon   (Graph algorithms)")
    print("  *   = Star      (Random generation)")

    print("\nIteration Markers (Optimization Levels):")
    print("  +   = Base       (No optimization)")
    print("  /   = Routed     (Smart routing)")
    print("  x   = Batched    (Batch processing)")
    print("  o   = Optimized  (Full optimization)")

    print("\nExample Interpretations:")
    print("  O+  = Base compute operation (no optimization)")
    print("  O/  = Compute with smart routing")
    print("  Ox  = Batched compute operation")
    print("  Oo  = Fully optimized compute")
    print("  <>/ = Routed transform (like XOR on CPU)")
    print("  #o  = Optimized graph algorithm")
    print("  ^x  = Batched memory operation")

    print("\nColor Encoding:")
    print("  Green       (<1ms)    - Excellent")
    print("  Yellow-Green(1-10ms)  - Good")
    print("  Yellow      (10-50ms) - Moderate")
    print("  Orange      (50-100ms)- Slow")
    print("  Red         (>100ms)  - Critical")


def main():
    """Run all demos"""
    print("\n")
    print("*"*70)
    print("*" + " "*68 + "*")
    print("*" + "  MERNITHIAN-INSPIRED GPU PROFILING - PHASE 1 DEMO  ".center(68) + "*")
    print("*" + " "*68 + "*")
    print("*"*70)
    print()

    demo_basic_profiling()
    demo_glyph_analyzer()
    demo_glyph_notation()

    print("\n" + "="*70)
    print("DEMO COMPLETE!")
    print("="*70)
    print("\nNext Steps:")
    print("1. Open profiler_visualization_v2.html in your browser")
    print("2. Load demo_profile_glyphs.json to see the glyph visualization")
    print("3. Explore the different views:")
    print("   - Glyph View: Visual symbolic representation")
    print("   - Traditional View: Standard charts")
    print("   - Timeline View: Glyph-based timeline")
    print("   - Legend View: Complete glyph system reference")
    print("\n")


if __name__ == "__main__":
    main()
