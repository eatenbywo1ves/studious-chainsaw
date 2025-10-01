"""
GPU Profiler Glyphs - Symbolic Visual Language for Performance Representation
Inspired by Mernithian logographic system for intuitive performance visualization
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json

logger = logging.getLogger(__name__)


class GlyphShape(Enum):
    """Base glyph shapes representing operation categories"""
    CIRCLE = "circle"      # Compute-intensive operations (matrix multiply, etc.)
    TRIANGLE = "triangle"  # Memory operations (allocation, transfer)
    SQUARE = "square"      # Control flow operations (routing, scheduling)
    DIAMOND = "diamond"    # Transform operations (XOR, conversions)
    HEXAGON = "hexagon"    # Graph algorithms (path finding, search)
    STAR = "star"          # Random generation operations


class IterationMarker(Enum):
    """
    Iteration markers showing optimization level
    Inspired by Mernithian: Base(+) -> Routed(/) -> Batched(x) -> Optimized(o)
    """
    BASE = "base"          # Level 0: No optimization (symbol: +)
    ROUTED = "routed"      # Level 1: Smart routing applied (symbol: /)
    BATCHED = "batched"    # Level 2: Batch processing applied (symbol: x)
    OPTIMIZED = "optimized"  # Level 3: Full optimization (symbol: o)


class PerformanceColor(Enum):
    """Color encoding for performance characteristics"""
    EXCELLENT = "#00ff00"  # Green: <1ms operations
    GOOD = "#7fff00"       # Yellow-green: 1-10ms operations
    MODERATE = "#ffff00"   # Yellow: 10-50ms operations
    SLOW = "#ffa500"       # Orange: 50-100ms operations
    CRITICAL = "#ff0000"   # Red: >100ms operations


class SizeCategory(Enum):
    """Size encoding for memory usage"""
    TINY = "tiny"          # <1MB
    SMALL = "small"        # 1-10MB
    MEDIUM = "medium"      # 10-100MB
    LARGE = "large"        # 100-1000MB
    HUGE = "huge"          # >1000MB


class DeviceStyle(Enum):
    """Border style encoding for device routing"""
    CPU = "solid"          # Solid border: CPU execution
    GPU = "dashed"         # Dashed border: GPU execution
    HYBRID = "dotted"      # Dotted border: Hybrid execution


@dataclass
class GlyphDescriptor:
    """Complete glyph description for an operation"""
    # Core identity
    operation_name: str
    shape: GlyphShape
    iteration_marker: IterationMarker

    # Performance encoding
    color: str  # Hex color code
    size: SizeCategory
    border_style: DeviceStyle

    # Metrics
    duration_ms: float
    memory_mb: float
    device: str

    # Optimization metadata
    optimization_level: int  # 0-3 corresponding to iteration markers
    speedup: Optional[float] = None  # If optimized, what speedup achieved

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON export"""
        return {
            'operation': self.operation_name,
            'shape': self.shape.value,
            'iteration': self.iteration_marker.value,
            'color': self.color,
            'size': self.size.value,
            'border': self.border_style.value,
            'duration_ms': self.duration_ms,
            'memory_mb': self.memory_mb,
            'device': self.device,
            'optimization_level': self.optimization_level,
            'speedup': self.speedup,
            'glyph_notation': self.get_notation()
        }

    def get_notation(self) -> str:
        """
        Get symbolic notation in Mernithian style
        Format: <shape><iteration_symbol>
        Example: "circle+" (base compute), "triangle/" (routed memory)
        """
        shape_symbols = {
            GlyphShape.CIRCLE: 'O',
            GlyphShape.TRIANGLE: '^',
            GlyphShape.SQUARE: '[]',
            GlyphShape.DIAMOND: '<>',
            GlyphShape.HEXAGON: '#',
            GlyphShape.STAR: '*'
        }

        iteration_symbols = {
            IterationMarker.BASE: '+',
            IterationMarker.ROUTED: '/',
            IterationMarker.BATCHED: 'x',
            IterationMarker.OPTIMIZED: 'o'
        }

        return (f"{shape_symbols[self.shape]}"
                f"{iteration_symbols[self.iteration_marker]}")


class GlyphAnalyzer:
    """
    Analyzes profiling data and generates symbolic glyph representations
    Maps operation characteristics to visual encoding
    """

    # Operation type to glyph shape mapping
    OPERATION_SHAPE_MAP = {
        'matrix_multiply': GlyphShape.CIRCLE,
        'matrix_add': GlyphShape.CIRCLE,
        'random_generation': GlyphShape.STAR,
        'xor_transform': GlyphShape.DIAMOND,
        'transform': GlyphShape.DIAMOND,
        'graph_search': GlyphShape.HEXAGON,
        'path_finding': GlyphShape.HEXAGON,
        'graph_algorithm': GlyphShape.HEXAGON,
        'memory_allocation': GlyphShape.TRIANGLE,
        'memory_transfer': GlyphShape.TRIANGLE,
        'batch_process': GlyphShape.CIRCLE,
        'routing': GlyphShape.SQUARE,
        'lattice_creation': GlyphShape.CIRCLE
    }

    def __init__(self):
        """Initialize glyph analyzer"""
        logger.info("GlyphAnalyzer initialized")

    def determine_shape(self, operation_name: str) -> GlyphShape:
        """
        Determine glyph shape based on operation name

        Args:
            operation_name: Name of the operation

        Returns:
            GlyphShape for the operation
        """
        operation_lower = operation_name.lower()

        # Check for exact matches
        if operation_lower in self.OPERATION_SHAPE_MAP:
            return self.OPERATION_SHAPE_MAP[operation_lower]

        # Check for partial matches
        for key, shape in self.OPERATION_SHAPE_MAP.items():
            if key in operation_lower:
                return shape

        # Default to circle for compute operations
        return GlyphShape.CIRCLE

    def determine_color(self, duration_ms: float) -> str:
        """
        Determine color based on operation duration

        Args:
            duration_ms: Duration in milliseconds

        Returns:
            Hex color code
        """
        if duration_ms < 1.0:
            return PerformanceColor.EXCELLENT.value
        elif duration_ms < 10.0:
            return PerformanceColor.GOOD.value
        elif duration_ms < 50.0:
            return PerformanceColor.MODERATE.value
        elif duration_ms < 100.0:
            return PerformanceColor.SLOW.value
        else:
            return PerformanceColor.CRITICAL.value

    def determine_size(self, memory_mb: float) -> SizeCategory:
        """
        Determine size category based on memory usage

        Args:
            memory_mb: Memory usage in MB

        Returns:
            SizeCategory
        """
        if memory_mb < 1.0:
            return SizeCategory.TINY
        elif memory_mb < 10.0:
            return SizeCategory.SMALL
        elif memory_mb < 100.0:
            return SizeCategory.MEDIUM
        elif memory_mb < 1000.0:
            return SizeCategory.LARGE
        else:
            return SizeCategory.HUGE

    def determine_device_style(self, device: str) -> DeviceStyle:
        """
        Determine border style based on execution device

        Args:
            device: Device name (cpu, gpu, hybrid)

        Returns:
            DeviceStyle
        """
        device_lower = device.lower()
        if 'gpu' in device_lower:
            return DeviceStyle.GPU
        elif 'hybrid' in device_lower or 'mixed' in device_lower:
            return DeviceStyle.HYBRID
        else:
            return DeviceStyle.CPU

    def determine_iteration_marker(
        self,
        metadata: Optional[Dict] = None
    ) -> Tuple[IterationMarker, int]:
        """
        Determine iteration marker based on optimization metadata

        Args:
            metadata: Operation metadata including optimization info

        Returns:
            Tuple of (IterationMarker, optimization_level)
        """
        if metadata is None:
            return IterationMarker.BASE, 0

        # Check for optimization flags
        is_routed = metadata.get('smart_routed', False)
        is_batched = metadata.get('batched', False)
        is_optimized = metadata.get('fully_optimized', False)

        if is_optimized or (is_routed and is_batched):
            return IterationMarker.OPTIMIZED, 3
        elif is_batched:
            return IterationMarker.BATCHED, 2
        elif is_routed:
            return IterationMarker.ROUTED, 1
        else:
            return IterationMarker.BASE, 0

    def create_glyph(
        self,
        operation_name: str,
        duration_ms: float,
        memory_mb: float,
        device: str,
        metadata: Optional[Dict] = None
    ) -> GlyphDescriptor:
        """
        Create complete glyph descriptor for an operation

        Args:
            operation_name: Name of operation
            duration_ms: Execution duration in ms
            memory_mb: Memory usage in MB
            device: Execution device
            metadata: Additional metadata

        Returns:
            GlyphDescriptor with complete visual encoding
        """
        shape = self.determine_shape(operation_name)
        color = self.determine_color(duration_ms)
        size = self.determine_size(memory_mb)
        border_style = self.determine_device_style(device)
        iteration_marker, opt_level = self.determine_iteration_marker(metadata)

        # Extract speedup if available
        speedup = metadata.get('speedup') if metadata else None

        return GlyphDescriptor(
            operation_name=operation_name,
            shape=shape,
            iteration_marker=iteration_marker,
            color=color,
            size=size,
            border_style=border_style,
            duration_ms=duration_ms,
            memory_mb=memory_mb,
            device=device,
            optimization_level=opt_level,
            speedup=speedup
        )

    def analyze_profiling_data(self, profiling_data: Dict) -> List[GlyphDescriptor]:
        """
        Analyze complete profiling data and generate glyphs for all operations

        Args:
            profiling_data: Profiling data dictionary (from profiler JSON export)

        Returns:
            List of GlyphDescriptor objects
        """
        glyphs = []
        entries = profiling_data.get('entries', [])

        for entry in entries:
            glyph = self.create_glyph(
                operation_name=entry['operation'],
                duration_ms=entry['duration_ms'],
                memory_mb=entry.get('memory_allocated_mb', 0.0),
                device=entry['device'],
                metadata=entry.get('metadata', {})
            )
            glyphs.append(glyph)

        logger.info(f"Generated {len(glyphs)} glyph descriptors")
        return glyphs

    def export_glyphs_json(self, glyphs: List[GlyphDescriptor], filepath: str):
        """
        Export glyph descriptors to JSON

        Args:
            glyphs: List of glyph descriptors
            filepath: Output file path
        """
        data = {
            'glyph_count': len(glyphs),
            'glyphs': [g.to_dict() for g in glyphs]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported {len(glyphs)} glyphs to {filepath}")


class GlyphRenderer:
    """
    Renders glyphs as SVG for visualization
    """

    # Size multipliers for size categories (base size = 30px)
    SIZE_MULTIPLIERS = {
        SizeCategory.TINY: 0.6,
        SizeCategory.SMALL: 0.8,
        SizeCategory.MEDIUM: 1.0,
        SizeCategory.LARGE: 1.3,
        SizeCategory.HUGE: 1.6
    }

    BASE_SIZE = 30  # Base size in pixels

    def __init__(self):
        """Initialize glyph renderer"""
        logger.info("GlyphRenderer initialized")

    def render_shape_svg(
        self,
        shape: GlyphShape,
        size: float,
        color: str,
        border_style: DeviceStyle
    ) -> str:
        """
        Render shape as SVG path

        Args:
            shape: Glyph shape
            size: Size in pixels
            color: Fill color (hex)
            border_style: Border style

        Returns:
            SVG path string
        """
        stroke_dasharray = ""
        if border_style == DeviceStyle.GPU:
            stroke_dasharray = 'stroke-dasharray="5,3"'
        elif border_style == DeviceStyle.HYBRID:
            stroke_dasharray = 'stroke-dasharray="2,2"'

        cx, cy = size, size  # Center

        if shape == GlyphShape.CIRCLE:
            return (f'<circle cx="{cx}" cy="{cy}" r="{size*0.4}" '
                   f'fill="{color}" stroke="#333" stroke-width="2" '
                   f'{stroke_dasharray}/>')

        elif shape == GlyphShape.TRIANGLE:
            points = [
                (cx, cy - size*0.4),
                (cx - size*0.35, cy + size*0.3),
                (cx + size*0.35, cy + size*0.3)
            ]
            points_str = ' '.join(f'{x},{y}' for x, y in points)
            return (f'<polygon points="{points_str}" '
                   f'fill="{color}" stroke="#333" stroke-width="2" '
                   f'{stroke_dasharray}/>')

        elif shape == GlyphShape.SQUARE:
            x, y = cx - size*0.35, cy - size*0.35
            w = size*0.7
            return (f'<rect x="{x}" y="{y}" width="{w}" height="{w}" '
                   f'fill="{color}" stroke="#333" stroke-width="2" '
                   f'{stroke_dasharray}/>')

        elif shape == GlyphShape.DIAMOND:
            points = [
                (cx, cy - size*0.4),
                (cx + size*0.4, cy),
                (cx, cy + size*0.4),
                (cx - size*0.4, cy)
            ]
            points_str = ' '.join(f'{x},{y}' for x, y in points)
            return (f'<polygon points="{points_str}" '
                   f'fill="{color}" stroke="#333" stroke-width="2" '
                   f'{stroke_dasharray}/>')

        elif shape == GlyphShape.HEXAGON:
            angles = [0, 60, 120, 180, 240, 300]
            points = [
                (cx + size*0.4*np.cos(np.radians(a)),
                 cy + size*0.4*np.sin(np.radians(a)))
                for a in angles
            ]
            points_str = ' '.join(f'{x},{y}' for x, y in points)
            return (f'<polygon points="{points_str}" '
                   f'fill="{color}" stroke="#333" stroke-width="2" '
                   f'{stroke_dasharray}/>')

        elif shape == GlyphShape.STAR:
            # 5-pointed star
            points = []
            for i in range(10):
                angle = (i * 36 - 90) * (3.14159 / 180)
                r = size*0.4 if i % 2 == 0 else size*0.2
                x = cx + r * np.cos(angle)
                y = cy + r * np.sin(angle)
                points.append((x, y))
            points_str = ' '.join(f'{x},{y}' for x, y in points)
            return (f'<polygon points="{points_str}" '
                   f'fill="{color}" stroke="#333" stroke-width="2" '
                   f'{stroke_dasharray}/>')

        return ""

    def render_iteration_marker_svg(
        self,
        marker: IterationMarker,
        x: float,
        y: float,
        size: float
    ) -> str:
        """
        Render iteration marker as SVG

        Args:
            marker: Iteration marker
            x, y: Position
            size: Size

        Returns:
            SVG string
        """
        marker_size = size * 0.3
        marker_x = x + size * 1.5
        marker_y = y + size * 0.3

        if marker == IterationMarker.BASE:
            # Plus symbol (+)
            return (f'<text x="{marker_x}" y="{marker_y}" '
                   f'font-size="{marker_size}" fill="#333" font-weight="bold">+</text>')
        elif marker == IterationMarker.ROUTED:
            # Slash (/)
            return (f'<text x="{marker_x}" y="{marker_y}" '
                   f'font-size="{marker_size}" fill="#333" font-weight="bold">/</text>')
        elif marker == IterationMarker.BATCHED:
            # X symbol (x)
            return (f'<text x="{marker_x}" y="{marker_y}" '
                   f'font-size="{marker_size}" fill="#333" font-weight="bold">x</text>')
        elif marker == IterationMarker.OPTIMIZED:
            # Circle (o)
            return (f'<text x="{marker_x}" y="{marker_y}" '
                   f'font-size="{marker_size}" fill="#333" font-weight="bold">o</text>')

        return ""

    def render_glyph_svg(self, glyph: GlyphDescriptor) -> str:
        """
        Render complete glyph as SVG

        Args:
            glyph: Glyph descriptor

        Returns:
            SVG string
        """
        # Calculate actual size
        multiplier = self.SIZE_MULTIPLIERS[glyph.size]
        actual_size = self.BASE_SIZE * multiplier

        # SVG container
        svg_width = actual_size * 2.5
        svg_height = actual_size * 2

        svg_parts = [
            f'<svg width="{svg_width}" height="{svg_height}" '
            f'xmlns="http://www.w3.org/2000/svg">'
        ]

        # Render shape
        shape_svg = self.render_shape_svg(
            glyph.shape,
            actual_size,
            glyph.color,
            glyph.border_style
        )
        svg_parts.append(shape_svg)

        # Render iteration marker
        marker_svg = self.render_iteration_marker_svg(
            glyph.iteration_marker,
            actual_size,
            actual_size,
            actual_size
        )
        svg_parts.append(marker_svg)

        svg_parts.append('</svg>')

        return '\n'.join(svg_parts)


# Global instance
_global_analyzer: Optional[GlyphAnalyzer] = None


def get_glyph_analyzer() -> GlyphAnalyzer:
    """
    Get global glyph analyzer instance (singleton)

    Returns:
        GlyphAnalyzer instance
    """
    global _global_analyzer

    if _global_analyzer is None:
        _global_analyzer = GlyphAnalyzer()

    return _global_analyzer


# Fix missing numpy import (needed for hexagon/star rendering)
try:
    import numpy as np
except ImportError:
    # Fallback: use math module
    import math
    class np:
        @staticmethod
        def cos(x):
            return math.cos(x)
        @staticmethod
        def sin(x):
            return math.sin(x)
        @staticmethod
        def radians(x):
            return math.radians(x)
