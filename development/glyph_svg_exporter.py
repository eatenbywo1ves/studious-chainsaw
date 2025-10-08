#!/usr/bin/env python3
"""
Glyph SVG Exporter - Standalone Utility
Converts profiling JSON files to SVG galleries and reference documentation
"""

import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Tuple

sys.path.insert(0, str(Path(__file__).parent))

from libs.gpu import (
    get_glyph_analyzer,
    GlyphDescriptor,
    GlyphRenderer
)


class SVGGalleryGenerator:
    """Generates SVG galleries from profiling data"""

    def __init__(self):
        self.analyzer = get_glyph_analyzer()
        self.renderer = GlyphRenderer()

    def load_profiling_json(self, filepath: str) -> Dict:
        """Load profiling data from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return data

    def extract_glyphs_from_json(self, data: Dict) -> List[Tuple[GlyphDescriptor, str]]:
        """Extract glyphs from profiling data"""
        glyphs = []

        # Check if glyphs are already included
        if 'glyphs' in data:
            print(f"Found pre-generated glyphs: {data['glyph_count']}")
            # Reconstruct GlyphDescriptor objects
            for glyph_dict in data['glyphs']:
                # This is for visualization only, we'll regenerate from entries
                pass

        # Generate from entries
        if 'entries' in data:
            print(f"Generating glyphs from {len(data['entries'])} profiling entries...")
            for entry in data['entries']:
                glyph = self.analyzer.create_glyph(
                    operation_name=entry['operation'],
                    duration_ms=entry['duration_ms'],
                    memory_mb=entry.get('memory_allocated_mb', 0.0),
                    device=entry['device'],
                    metadata=entry.get('metadata', {})
                )
                description = entry.get('metadata', {}).get('description', '')
                glyphs.append((glyph, description))

        return glyphs

    def generate_timeline_svg(
        self,
        glyphs: List[Tuple[GlyphDescriptor, str]],
        output_file: str,
        title: str = "GPU Profiling Timeline"
    ):
        """Generate timeline-style SVG with glyphs"""
        width = 1600
        height = max(800, len(glyphs) * 80 + 200)

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
            '<defs>',
            '  <style>',
            '    .title { font-family: Arial, sans-serif; font-size: 24px; font-weight: bold; fill: #333; }',
            '    .timeline-label { font-family: monospace; font-size: 14px; fill: #333; }',
            '    .timeline-time { font-family: monospace; font-size: 12px; fill: #666; }',
            '    .timeline-bar { fill: #e0e0e0; }',
            '  </style>',
            '</defs>',
            '',
            f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f9f9f9"/>',
            f'<text x="{width/2}" y="40" class="title" text-anchor="middle">{title}</text>',
            '<line x1="100" y1="80" x2="1500" y2="80" stroke="#ccc" stroke-width="2"/>',
            ''
        ]

        # Calculate time scale
        total_time = sum(glyph.duration_ms for glyph, _ in glyphs)
        max_bar_width = 1200
        time_scale = max_bar_width / total_time if total_time > 0 else 1

        y_offset = 120
        cumulative_time = 0

        for glyph, description in glyphs:
            # Glyph
            svg_parts.append(f'<g transform="translate(120, {y_offset})">')
            shape_svg = self.renderer.render_shape_svg(
                glyph.shape, 30, glyph.color, glyph.border_style
            )
            svg_parts.append(shape_svg)
            marker_svg = self.renderer.render_iteration_marker_svg(
                glyph.iteration_marker, 30, 30, 30
            )
            svg_parts.append(marker_svg)
            svg_parts.append('</g>')

            # Operation name and notation
            svg_parts.append(f'<text x="220" y="{y_offset + 20}" class="timeline-label">{glyph.get_notation()}</text>')
            svg_parts.append(f'<text x="280" y="{y_offset + 20}" class="timeline-label">{glyph.operation_name}</text>')

            # Time bar
            bar_width = glyph.duration_ms * time_scale
            bar_x = 800
            svg_parts.append(f'<rect x="{bar_x}" y="{y_offset + 5}" width="{bar_width}" height="30" '
                           f'fill="{glyph.color}" opacity="0.6" stroke="#333" stroke-width="1"/>')

            # Time label
            svg_parts.append(f'<text x="{bar_x + bar_width + 10}" y="{y_offset + 25}" '
                           f'class="timeline-time">{glyph.duration_ms:.2f}ms</text>')

            # Memory label
            svg_parts.append(f'<text x="1450" y="{y_offset + 25}" '
                           f'class="timeline-time">{glyph.memory_mb:.1f}MB</text>')

            cumulative_time += glyph.duration_ms
            y_offset += 70

        # Footer with total time
        svg_parts.append(f'<text x="{width/2}" y="{height - 30}" class="timeline-label" '
                        f'text-anchor="middle">Total Time: {total_time:.2f}ms</text>')
        svg_parts.append('</svg>')

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(svg_parts))

        print(f"Timeline SVG generated: {output_file}")

    def generate_performance_heatmap_svg(
        self,
        glyphs: List[Tuple[GlyphDescriptor, str]],
        output_file: str
    ):
        """Generate performance heatmap with glyphs"""
        # Group by optimization level
        by_level = {0: [], 1: [], 2: [], 3: []}
        for glyph, desc in glyphs:
            by_level[glyph.optimization_level].append((glyph, desc))

        width = 1400
        height = 800

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
            '<defs>',
            '  <style>',
            '    .title { font-family: Arial, sans-serif; font-size: 24px; font-weight: bold; fill: #333; }',
            '    .level-title { font-family: Arial, sans-serif; font-size: 16px; font-weight: bold; fill: #333; }',
            '    .glyph-label { font-family: monospace; font-size: 11px; fill: #666; }',
            '  </style>',
            '</defs>',
            '',
            f'<rect x="0" y="0" width="{width}" height="{height}" fill="white"/>',
            '<text x="700" y="40" class="title" text-anchor="middle">Performance Optimization Heatmap</text>',
            ''
        ]

        level_names = ["Base (+)", "Routed (/)", "Batched (x)", "Optimized (o)"]
        level_colors = ["#ffebee", "#fff3e0", "#e8f5e9", "#c8e6c9"]

        for level_idx in range(4):
            x_offset = 50 + (level_idx % 2) * 680
            y_offset = 100 + (level_idx // 2) * 350

            # Level box
            svg_parts.append(f'<rect x="{x_offset}" y="{y_offset}" width="640" height="320" '
                           f'fill="{level_colors[level_idx]}" stroke="#999" stroke-width="2" rx="10"/>')

            # Level title
            svg_parts.append(f'<text x="{x_offset + 320}" y="{y_offset + 30}" '
                           f'class="level-title" text-anchor="middle">{level_names[level_idx]}</text>')

            # Render glyphs in this level
            glyphs_in_level = by_level[level_idx]
            glyph_x = x_offset + 50
            glyph_y = y_offset + 60

            for i, (glyph, desc) in enumerate(glyphs_in_level[:15]):  # Max 15 per level
                if i > 0 and i % 5 == 0:
                    glyph_x = x_offset + 50
                    glyph_y += 80

                # Render glyph
                svg_parts.append(f'<g transform="translate({glyph_x}, {glyph_y})">')
                shape_svg = self.renderer.render_shape_svg(
                    glyph.shape, 25, glyph.color, glyph.border_style
                )
                svg_parts.append(shape_svg)
                marker_svg = self.renderer.render_iteration_marker_svg(
                    glyph.iteration_marker, 25, 25, 25
                )
                svg_parts.append(marker_svg)
                svg_parts.append('</g>')

                # Label
                label = f"{glyph.duration_ms:.1f}ms"
                svg_parts.append(f'<text x="{glyph_x + 25}" y="{glyph_y + 75}" '
                               f'class="glyph-label" text-anchor="middle">{label}</text>')

                glyph_x += 120

        svg_parts.append('</svg>')

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(svg_parts))

        print(f"Heatmap SVG generated: {output_file}")

    def export_all_formats(self, json_file: str, output_prefix: str = "export"):
        """Export all SVG formats from a profiling JSON"""
        print(f"\n{'='*80}")
        print(f"Exporting SVG visualizations from: {json_file}")
        print(f"{'='*80}\n")

        # Load data
        data = self.load_profiling_json(json_file)
        glyphs = self.extract_glyphs_from_json(data)

        if not glyphs:
            print("No glyphs found in profiling data!")
            return

        print(f"Loaded {len(glyphs)} glyphs\n")

        # Generate timeline
        timeline_file = f"{output_prefix}_timeline.svg"
        self.generate_timeline_svg(glyphs, timeline_file, title=data.get('session_name', 'GPU Profiling Timeline'))

        # Generate heatmap
        heatmap_file = f"{output_prefix}_heatmap.svg"
        self.generate_performance_heatmap_svg(glyphs, heatmap_file)

        print(f"\n{'='*80}")
        print("Export complete!")
        print(f"{'='*80}\n")
        print("Generated files:")
        print(f"  - {timeline_file}")
        print(f"  - {heatmap_file}\n")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Export profiling JSON to SVG visualizations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export from demo profiling data
  python glyph_svg_exporter.py demo_profile_glyphs.json

  # Export with custom output prefix
  python glyph_svg_exporter.py my_profile.json --output my_viz

  # Export from proof library data
  python glyph_svg_exporter.py proof_library.json --output proofs
        """
    )

    parser.add_argument('json_file', help='Profiling JSON file to export')
    parser.add_argument('--output', '-o', default='export',
                       help='Output file prefix (default: export)')
    parser.add_argument('--timeline-only', action='store_true',
                       help='Generate only timeline visualization')
    parser.add_argument('--heatmap-only', action='store_true',
                       help='Generate only heatmap visualization')

    args = parser.parse_args()

    # Validate input file
    if not Path(args.json_file).exists():
        print(f"Error: File not found: {args.json_file}")
        sys.exit(1)

    # Create exporter
    exporter = SVGGalleryGenerator()

    # Export
    if args.timeline_only or args.heatmap_only:
        data = exporter.load_profiling_json(args.json_file)
        glyphs = exporter.extract_glyphs_from_json(data)

        if args.timeline_only:
            exporter.generate_timeline_svg(glyphs, f"{args.output}_timeline.svg")
        if args.heatmap_only:
            exporter.generate_performance_heatmap_svg(glyphs, f"{args.output}_heatmap.svg")
    else:
        exporter.export_all_formats(args.json_file, args.output)


if __name__ == "__main__":
    main()
