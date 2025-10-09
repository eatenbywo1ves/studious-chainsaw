#!/usr/bin/env python3
"""
Demo: SVG Glyph Generation - Comprehensive Reference
Generates proper multi-shape SVG output showcasing the complete Mernithian visual language
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu import get_glyph_analyzer, GlyphShape, IterationMarker, GlyphRenderer, DeviceStyle


def create_reference_glyphs():
    """Create glyphs demonstrating all combinations"""
    analyzer = get_glyph_analyzer()

    # Define comprehensive test cases covering all visual encodings
    test_cases = [
        # Shape: CIRCLE (Compute operations)
        ("matrix_multiply", 45.20, 16.0, "gpu", {}, "Base compute operation"),
        ("matrix_multiply_routed", 22.60, 16.0, "cpu", {"smart_routed": True}, "Routed compute"),
        ("matrix_multiply_batched", 15.0, 64.0, "gpu", {"batched": True}, "Batched compute"),
        (
            "matrix_multiply_optimized",
            8.0,
            32.0,
            "gpu",
            {"smart_routed": True, "batched": True},
            "Fully optimized compute",
        ),
        # Shape: DIAMOND (Transform operations)
        (
            "xor_transform",
            0.25,
            0.1,
            "cpu",
            {"smart_routed": True, "speedup": 180},
            "Fast XOR transform",
        ),
        ("transform_base", 5.0, 0.5, "gpu", {}, "Base transform"),
        (
            "transform_optimized",
            1.2,
            0.3,
            "cpu",
            {"smart_routed": True, "batched": True},
            "Optimized transform",
        ),
        # Shape: HEXAGON (Graph algorithms)
        ("graph_search", 75.30, 8.0, "cpu", {"smart_routed": True}, "Routed graph search"),
        ("path_finding", 120.0, 12.0, "gpu", {}, "Base pathfinding"),
        (
            "graph_algorithm_optimized",
            25.0,
            6.0,
            "hybrid",
            {"batched": True},
            "Batched graph algorithm",
        ),
        # Shape: STAR (Random generation)
        ("random_generation", 12.50, 2.0, "gpu", {}, "Base random generation"),
        (
            "random_generation_fast",
            0.8,
            1.0,
            "cpu",
            {"smart_routed": True},
            "Fast random generation",
        ),
        # Shape: TRIANGLE (Memory operations)
        ("memory_allocation", 35.0, 128.0, "gpu", {}, "GPU memory allocation"),
        (
            "memory_transfer",
            18.0,
            64.0,
            "hybrid",
            {"smart_routed": True},
            "Optimized memory transfer",
        ),
        ("memory_pooling", 8.0, 256.0, "gpu", {"batched": True}, "Memory pooling"),
        # Shape: SQUARE (Control flow)
        ("routing_decision", 0.5, 0.1, "cpu", {}, "Base routing"),
        ("smart_scheduling", 0.3, 0.1, "cpu", {"smart_routed": True}, "Smart scheduling"),
        # Performance extremes
        (
            "ultra_fast",
            0.1,
            0.05,
            "cpu",
            {"smart_routed": True, "batched": True},
            "Excellent performance",
        ),
        ("critical_slow", 150.0, 512.0, "gpu", {}, "Critical performance"),
    ]

    glyphs = []
    for name, duration, memory, device, metadata, description in test_cases:
        glyph = analyzer.create_glyph(name, duration, memory, device, metadata)
        glyphs.append((glyph, description))

    return glyphs


def generate_individual_svg_files(glyphs, output_dir="glyph_svgs"):
    """Generate individual SVG files for each glyph"""
    import os

    os.makedirs(output_dir, exist_ok=True)
    renderer = GlyphRenderer()

    print(f"\nGenerating {len(glyphs)} individual SVG files...")
    print("=" * 80)

    for i, (glyph, description) in enumerate(glyphs, 1):
        svg_content = renderer.render_glyph_svg(glyph)
        filename = f"{output_dir}/{glyph.operation_name}.svg"

        with open(filename, "w") as f:
            f.write(svg_content)

        print(
            f"[{i:2d}/{len(glyphs)}] {glyph.get_notation():<8} {glyph.operation_name:<35} -> {filename}"
        )

    print(f"\nAll SVG files generated in: {output_dir}/")


def generate_reference_sheet_svg(glyphs, output_file="glyph_reference_sheet.svg"):
    """Generate a comprehensive reference sheet showing all glyphs"""
    renderer = GlyphRenderer()

    # SVG setup
    width = 1200
    height = len(glyphs) * 100 + 150

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        "<defs>",
        "  <style>",
        "    .title { font-family: Arial, sans-serif; font-size: 24px; font-weight: bold; fill: #333; }",
        "    .subtitle { font-family: Arial, sans-serif; font-size: 14px; fill: #666; }",
        "    .glyph-label { font-family: monospace; font-size: 16px; font-weight: bold; fill: #333; }",
        "    .glyph-info { font-family: Arial, sans-serif; font-size: 12px; fill: #666; }",
        "  </style>",
        "</defs>",
        "",
        "<!-- Header -->",
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f5f5f5"/>',
        '<text x="600" y="40" class="title" text-anchor="middle">Mernithian Glyph Reference Sheet</text>',
        '<text x="600" y="65" class="subtitle" text-anchor="middle">Complete Visual Language for GPU Performance Profiling</text>',
        '<line x1="50" y1="80" x2="1150" y2="80" stroke="#ccc" stroke-width="2"/>',
        "",
        "<!-- Legend -->",
        '<text x="70" y="110" class="glyph-label">Notation</text>',
        '<text x="200" y="110" class="glyph-label">Glyph</text>',
        '<text x="350" y="110" class="glyph-label">Operation</text>',
        '<text x="650" y="110" class="glyph-label">Performance</text>',
        '<text x="850" y="110" class="glyph-label">Memory</text>',
        '<text x="1000" y="110" class="glyph-label">Device</text>',
        '<line x1="50" y1="120" x2="1150" y2="120" stroke="#ccc" stroke-width="1"/>',
        "",
    ]

    # Render each glyph
    y_offset = 150
    for glyph, description in glyphs:
        # Notation
        notation = glyph.get_notation()
        svg_parts.append(f'<text x="70" y="{y_offset + 25}" class="glyph-label">{notation}</text>')

        # Render glyph shape
        shape_svg = renderer.render_shape_svg(
            glyph.shape,
            40,  # size
            glyph.color,
            glyph.border_style,
        )
        # Wrap in group with transform
        svg_parts.append(f'<g transform="translate(200, {y_offset})">')
        svg_parts.append(shape_svg)

        # Render iteration marker
        marker_svg = renderer.render_iteration_marker_svg(glyph.iteration_marker, 40, 40, 40)
        svg_parts.append(marker_svg)
        svg_parts.append("</g>")

        # Operation name
        svg_parts.append(
            f'<text x="350" y="{y_offset + 25}" class="glyph-info">{glyph.operation_name}</text>'
        )
        svg_parts.append(
            f'<text x="350" y="{y_offset + 42}" class="glyph-info" style="font-size: 10px; fill: #999;">{description}</text>'
        )

        # Performance
        perf_label = f"{glyph.duration_ms:.2f}ms"
        if glyph.speedup:
            perf_label += f" ({glyph.speedup}x)"
        svg_parts.append(
            f'<text x="650" y="{y_offset + 25}" class="glyph-info">{perf_label}</text>'
        )

        # Memory
        svg_parts.append(
            f'<text x="850" y="{y_offset + 25}" class="glyph-info">{glyph.memory_mb:.2f}MB ({glyph.size.value})</text>'
        )

        # Device
        device_label = f"{glyph.device} ({glyph.border_style.value})"
        svg_parts.append(
            f'<text x="1000" y="{y_offset + 25}" class="glyph-info">{device_label}</text>'
        )

        # Separator
        svg_parts.append(
            f'<line x1="50" y1="{y_offset + 60}" x2="1150" y2="{y_offset + 60}" stroke="#e0e0e0" stroke-width="1"/>'
        )

        y_offset += 100

    # Footer
    svg_parts.append("")
    svg_parts.append("<!-- Footer -->")
    svg_parts.append(
        f'<text x="600" y="{height - 30}" class="subtitle" text-anchor="middle">Generated by Mernithian GPU Profiler - Phase 1 Visual Symbols</text>'
    )
    svg_parts.append("")
    svg_parts.append("</svg>")

    # Write to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(svg_parts))

    print(f"\nReference sheet generated: {output_file}")
    print(f"  Dimensions: {width}x{height}px")
    print(f"  Glyphs: {len(glyphs)}")


def generate_shape_showcase_svg(output_file="glyph_shape_showcase.svg"):
    """Generate SVG showcasing all 6 shapes with all 4 iteration markers"""
    get_glyph_analyzer()
    renderer = GlyphRenderer()

    shapes = [
        (GlyphShape.CIRCLE, "Circle", "Compute operations"),
        (GlyphShape.TRIANGLE, "Triangle", "Memory operations"),
        (GlyphShape.SQUARE, "Square", "Control flow"),
        (GlyphShape.DIAMOND, "Diamond", "Transforms"),
        (GlyphShape.HEXAGON, "Hexagon", "Graph algorithms"),
        (GlyphShape.STAR, "Star", "Random generation"),
    ]

    markers = [
        (IterationMarker.BASE, "+", "Base (no optimization)"),
        (IterationMarker.ROUTED, "/", "Routed (smart routing)"),
        (IterationMarker.BATCHED, "x", "Batched (batch processing)"),
        (IterationMarker.OPTIMIZED, "o", "Optimized (full optimization)"),
    ]

    colors = ["#ff0000", "#ffa500", "#ffff00", "#00ff00"]  # Critical to Excellent

    width = 1400
    height = 900

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        "<defs>",
        "  <style>",
        "    .title { font-family: Arial, sans-serif; font-size: 28px; font-weight: bold; fill: #333; }",
        "    .shape-label { font-family: Arial, sans-serif; font-size: 14px; font-weight: bold; fill: #333; }",
        "    .marker-label { font-family: monospace; font-size: 18px; font-weight: bold; fill: #333; }",
        "  </style>",
        "</defs>",
        "",
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#fafafa"/>',
        '<text x="700" y="50" class="title" text-anchor="middle">Mernithian Shape & Iteration Matrix</text>',
        '<text x="700" y="80" class="shape-label" text-anchor="middle">6 Shapes × 4 Iteration Markers = 24 Core Glyphs</text>',
        "",
    ]

    # Column headers (iteration markers)
    for i, (marker, symbol, desc) in enumerate(markers):
        x = 300 + i * 250
        svg_parts.append(
            f'<text x="{x}" y="130" class="marker-label" text-anchor="middle">{symbol}</text>'
        )
        svg_parts.append(
            f'<text x="{x}" y="150" class="shape-label" text-anchor="middle" style="font-size: 11px;">{desc}</text>'
        )

    # Render grid
    y_offset = 200
    for row, (shape, shape_name, shape_desc) in enumerate(shapes):
        # Row label
        svg_parts.append(
            f'<text x="100" y="{y_offset + 40}" class="shape-label">{shape_name}</text>'
        )
        svg_parts.append(
            f'<text x="100" y="{y_offset + 58}" class="shape-label" style="font-size: 10px; fill: #999;">{shape_desc}</text>'
        )

        # Render each iteration marker variant
        for col, (marker, symbol, _) in enumerate(markers):
            x = 300 + col * 250
            color = colors[col]  # Different color per optimization level

            svg_parts.append(f'<g transform="translate({x - 40}, {y_offset})">')

            # Render shape
            shape_svg = renderer.render_shape_svg(
                shape, 40, color, DeviceStyle.GPU if row % 2 == 0 else DeviceStyle.CPU
            )
            svg_parts.append(shape_svg)

            # Render iteration marker
            marker_svg = renderer.render_iteration_marker_svg(marker, 40, 40, 40)
            svg_parts.append(marker_svg)

            svg_parts.append("</g>")

        y_offset += 120

    svg_parts.append(
        f'<text x="700" y="{height - 30}" class="shape-label" text-anchor="middle" style="font-size: 12px; fill: #999;">Border: Solid=CPU, Dashed=GPU, Dotted=Hybrid | Colors: Performance-based encoding</text>'
    )
    svg_parts.append("</svg>")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(svg_parts))

    print(f"\nShape showcase generated: {output_file}")
    print("  Matrix: 6 shapes × 4 markers = 24 core glyph variants")


def print_glyph_table(glyphs):
    """Print formatted table of all glyphs"""
    print("\n" + "=" * 100)
    print("COMPREHENSIVE GLYPH CATALOG")
    print("=" * 100)
    print(
        f"\n{'Notation':<10} {'Shape':<12} {'Opt Level':<12} {'Operation':<35} {'Time':<12} {'Memory':<12}"
    )
    print("-" * 100)

    for glyph, description in glyphs:
        shape_name = glyph.shape.value.capitalize()
        opt_level = f"L{glyph.optimization_level} ({glyph.iteration_marker.value})"

        print(
            f"{glyph.get_notation():<10} {shape_name:<12} {opt_level:<12} "
            f"{glyph.operation_name:<35} {glyph.duration_ms:>7.2f}ms   {glyph.memory_mb:>7.2f}MB"
        )


def main():
    """Run complete SVG generation demo"""
    print("\n" + "*" * 100)
    print("*" + " " * 98 + "*")
    print("*" + "  MERNITHIAN SVG GLYPH GENERATION - COMPREHENSIVE REFERENCE DEMO".center(98) + "*")
    print("*" + " " * 98 + "*")
    print("*" * 100)

    # Step 1: Create reference glyphs
    print("\n[STEP 1] Creating reference glyph set...")
    glyphs = create_reference_glyphs()
    print(f"Created {len(glyphs)} reference glyphs covering all visual encodings")

    # Step 2: Print table
    print_glyph_table(glyphs)

    # Step 3: Generate individual SVG files
    print("\n[STEP 2] Generating individual SVG files...")
    generate_individual_svg_files(glyphs)

    # Step 4: Generate reference sheet
    print("\n[STEP 3] Generating comprehensive reference sheet...")
    generate_reference_sheet_svg(glyphs)

    # Step 5: Generate shape showcase matrix
    print("\n[STEP 4] Generating shape × iteration matrix...")
    generate_shape_showcase_svg()

    # Summary
    print("\n" + "=" * 100)
    print("DEMO COMPLETE!")
    print("=" * 100)
    print("\nGenerated Files:")
    print("  1. glyph_svgs/ - Directory with individual SVG files for each glyph")
    print("  2. glyph_reference_sheet.svg - Comprehensive catalog with all glyphs")
    print("  3. glyph_shape_showcase.svg - 6×4 matrix showing all shape/marker combinations")
    print("\nNext Steps:")
    print("  - Open SVG files in browser or image viewer")
    print("  - Use reference sheet for documentation")
    print("  - Compare with profiling_glyphs.svg to see improvements")
    print("  - Integrate into HTML visualizations\n")


if __name__ == "__main__":
    main()
