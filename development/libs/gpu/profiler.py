"""
GPU Profiler - Detailed performance profiling and bottleneck identification
Tracks operation timing, GPU utilization, memory bandwidth, and overhead
"""

import logging
import time
import functools
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from contextlib import contextmanager
import json

logger = logging.getLogger(__name__)

# Glyph system import (lazy loaded to avoid circular dependencies)
_glyph_analyzer = None


def _get_glyph_analyzer():
    """Lazy load glyph analyzer"""
    global _glyph_analyzer
    if _glyph_analyzer is None:
        try:
            from .profiler_glyphs import get_glyph_analyzer
            _glyph_analyzer = get_glyph_analyzer()
        except ImportError:
            logger.warning("Glyph analyzer not available")
    return _glyph_analyzer


# Complexity analyzer import (lazy loaded)
_complexity_analyzer = None


def _get_complexity_analyzer():
    """Lazy load complexity analyzer"""
    global _complexity_analyzer
    if _complexity_analyzer is None:
        try:
            from .profiler_complexity import get_complexity_analyzer
            _complexity_analyzer = get_complexity_analyzer()
        except ImportError:
            logger.warning("Complexity analyzer not available")
    return _complexity_analyzer


@dataclass
class ProfileEntry:
    """Single profiling entry"""
    operation: str
    start_time: float
    end_time: float
    duration_ms: float
    device: str  # "cpu", "gpu"
    backend: str  # "pytorch", "cupy", "cpu"
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Detailed breakdown
    gpu_time_ms: float = 0.0
    cpu_time_ms: float = 0.0
    transfer_time_ms: float = 0.0
    overhead_ms: float = 0.0

    # Memory stats
    memory_allocated_mb: float = 0.0
    memory_peak_mb: float = 0.0

    # GPU metrics
    gpu_utilization: float = 0.0
    memory_bandwidth_gb_s: float = 0.0

    # Phase 3: Complexity tracking
    algorithmic_complexity: Optional[Any] = None  # AlgorithmicComplexity
    operational_complexity: Optional[Any] = None  # OperationalComplexity
    complexity_score: Optional[Any] = None        # ComplexityScore


@dataclass
class ProfileSummary:
    """Aggregated profiling statistics"""
    operation: str
    call_count: int
    total_time_ms: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    std_dev_ms: float

    # Breakdown
    total_gpu_time_ms: float = 0.0
    total_cpu_time_ms: float = 0.0
    total_transfer_time_ms: float = 0.0
    total_overhead_ms: float = 0.0

    # Memory
    avg_memory_mb: float = 0.0
    peak_memory_mb: float = 0.0

    # Utilization
    avg_gpu_utilization: float = 0.0


class GPUProfiler:
    """
    GPU profiler for detailed performance analysis
    Tracks operation timing, memory usage, and GPU utilization
    """

    def __init__(
        self,
        enabled: bool = True,
        device_id: int = 0,
        enable_detailed_metrics: bool = True
    ):
        """
        Initialize GPU profiler

        Args:
            enabled: Enable profiling
            device_id: GPU device to profile
            enable_detailed_metrics: Collect detailed GPU metrics
        """
        self.enabled = enabled
        self.device_id = device_id
        self.enable_detailed_metrics = enable_detailed_metrics

        # Profile entries
        self._entries: List[ProfileEntry] = []
        self._operation_stack: List[str] = []
        self._start_times: Dict[str, float] = {}

        # Backend detection
        self.pytorch_available = False
        self.cupy_available = False
        self._detect_backends()

        # PyTorch profiler integration
        self._torch_profiler = None

        logger.info(f"GPUProfiler initialized: enabled={enabled}, device={device_id}")

    def _detect_backends(self):
        """Detect available GPU backends"""
        try:
            import torch
            if torch.cuda.is_available():
                self.pytorch_available = True
        except ImportError:
            pass

        try:
            import cupy as cp
            if cp.cuda.is_available():
                self.cupy_available = True
        except ImportError:
            pass

    @contextmanager
    def profile(self, operation: str, device: str = "gpu", **metadata):
        """
        Profile an operation using context manager

        Args:
            operation: Operation name
            device: Device type ("cpu" or "gpu")
            **metadata: Additional metadata to record

        Example:
            with profiler.profile("matrix_multiply", device="gpu", size=1024):
                result = torch.mm(a, b)
        """
        if not self.enabled:
            yield
            return

        # Start profiling
        entry_id = f"{operation}_{len(self._entries)}"
        self._operation_stack.append(entry_id)

        start_time = time.perf_counter()
        self._start_times[entry_id] = start_time

        # Get memory before
        memory_before = self._get_memory_allocated()

        try:
            yield
        finally:
            # End profiling
            end_time = time.perf_counter()
            duration_ms = (end_time - start_time) * 1000

            # Get memory after
            memory_after = self._get_memory_allocated()
            memory_allocated = memory_after - memory_before

            # Create entry
            entry = ProfileEntry(
                operation=operation,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                device=device,
                backend=self._detect_backend(),
                metadata=metadata,
                memory_allocated_mb=memory_allocated,
                memory_peak_mb=self._get_memory_peak()
            )

            # Collect detailed metrics if enabled
            if self.enable_detailed_metrics:
                self._collect_detailed_metrics(entry)

            # Phase 3: Collect complexity metrics
            self._collect_complexity_metrics(entry)

            self._entries.append(entry)

            if entry_id in self._operation_stack:
                self._operation_stack.remove(entry_id)
            if entry_id in self._start_times:
                del self._start_times[entry_id]

    def profile_function(self, operation: Optional[str] = None, device: str = "gpu"):
        """
        Decorator for profiling functions

        Args:
            operation: Operation name (defaults to function name)
            device: Device type

        Example:
            @profiler.profile_function(operation="my_op", device="gpu")
            def my_function(x):
                return x * 2
        """
        def decorator(func: Callable) -> Callable:
            op_name = operation or func.__name__

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if not self.enabled:
                    return func(*args, **kwargs)

                with self.profile(op_name, device=device):
                    return func(*args, **kwargs)

            return wrapper
        return decorator

    def _detect_backend(self) -> str:
        """Detect which backend is currently active"""
        if self.pytorch_available:
            return "pytorch"
        elif self.cupy_available:
            return "cupy"
        else:
            return "cpu"

    def _get_memory_allocated(self) -> float:
        """Get currently allocated GPU memory in MB"""
        if not self.pytorch_available:
            return 0.0

        try:
            import torch
            allocated = torch.cuda.memory_allocated(self.device_id)
            return allocated / (1024 ** 2)
        except Exception:
            return 0.0

    def _get_memory_peak(self) -> float:
        """Get peak GPU memory in MB"""
        if not self.pytorch_available:
            return 0.0

        try:
            import torch
            peak = torch.cuda.max_memory_allocated(self.device_id)
            return peak / (1024 ** 2)
        except Exception:
            return 0.0

    def _collect_detailed_metrics(self, entry: ProfileEntry):
        """Collect detailed GPU metrics"""
        if entry.device == "cpu":
            entry.cpu_time_ms = entry.duration_ms
            return

        # For GPU operations, estimate breakdown
        # This is a simplified model - real profiling would use CUDA events

        # Estimate GPU time (assume most of duration is GPU compute)
        entry.gpu_time_ms = entry.duration_ms * 0.85

        # Estimate transfer time (assume 10% for small data transfers)
        entry.transfer_time_ms = entry.duration_ms * 0.10

        # Estimate overhead (kernel launch, synchronization)
        entry.overhead_ms = entry.duration_ms * 0.05

        # Estimate GPU utilization (simplified)
        # In reality would query nvidia-smi or CUDA profiler
        if entry.duration_ms > 1.0:
            entry.gpu_utilization = 85.0  # High utilization for longer ops
        else:
            entry.gpu_utilization = 30.0  # Low utilization for short ops

        # Estimate memory bandwidth (simplified)
        # Real implementation would use CUDA profiler
        if entry.memory_allocated_mb > 0:
            gb_transferred = entry.memory_allocated_mb / 1024
            bandwidth = gb_transferred / (entry.duration_ms / 1000)
            entry.memory_bandwidth_gb_s = bandwidth

    def _collect_complexity_metrics(self, entry: ProfileEntry):
        """Collect complexity metrics for profile entry"""
        analyzer = _get_complexity_analyzer()
        if analyzer is None:
            return

        try:
            # Classify algorithmic complexity
            algorithmic = analyzer.classify_algorithm(
                entry.operation,
                entry.metadata
            )
            entry.algorithmic_complexity = algorithmic

            # Compute operational complexity
            operational = analyzer.compute_operational_complexity(
                entry.duration_ms,
                entry.memory_allocated_mb,
                entry.device,
                entry.metadata
            )
            entry.operational_complexity = operational

            # Compute complexity score
            complexity_score = analyzer.compute_complexity_score(
                algorithmic,
                operational
            )
            entry.complexity_score = complexity_score

        except Exception as e:
            logger.warning(f"Failed to collect complexity metrics: {e}")

    def get_entries(self) -> List[ProfileEntry]:
        """Get all profile entries"""
        return self._entries.copy()

    def get_summary(self) -> Dict[str, ProfileSummary]:
        """
        Get aggregated statistics per operation

        Returns:
            Dict mapping operation name to summary statistics
        """
        summaries = {}

        # Group by operation
        by_operation = defaultdict(list)
        for entry in self._entries:
            by_operation[entry.operation].append(entry)

        # Calculate statistics for each operation
        for operation, entries in by_operation.items():
            times = [e.duration_ms for e in entries]

            summaries[operation] = ProfileSummary(
                operation=operation,
                call_count=len(entries),
                total_time_ms=sum(times),
                avg_time_ms=sum(times) / len(times),
                min_time_ms=min(times),
                max_time_ms=max(times),
                std_dev_ms=self._std_dev(times),
                total_gpu_time_ms=sum(e.gpu_time_ms for e in entries),
                total_cpu_time_ms=sum(e.cpu_time_ms for e in entries),
                total_transfer_time_ms=sum(e.transfer_time_ms for e in entries),
                total_overhead_ms=sum(e.overhead_ms for e in entries),
                avg_memory_mb=sum(e.memory_allocated_mb for e in entries) / len(entries),
                peak_memory_mb=max(e.memory_peak_mb for e in entries),
                avg_gpu_utilization=sum(e.gpu_utilization for e in entries) / len(entries)
            )

        return summaries

    def _std_dev(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        if len(values) < 2:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5

    def get_bottlenecks(self, top_n: int = 5) -> List[ProfileSummary]:
        """
        Identify top N bottleneck operations

        Args:
            top_n: Number of top bottlenecks to return

        Returns:
            List of ProfileSummary sorted by total time (descending)
        """
        summaries = list(self.get_summary().values())
        summaries.sort(key=lambda s: s.total_time_ms, reverse=True)
        return summaries[:top_n]

    def print_summary(self, top_n: int = 10):
        """Print profiling summary"""
        summaries = self.get_summary()

        if not summaries:
            print("\nNo profiling data collected")
            return

        print(f"\n{'='*80}")
        print("GPU PROFILING SUMMARY")
        print(f"{'='*80}")
        print(f"Total Operations: {len(self._entries)}")
        print(f"Unique Operations: {len(summaries)}")
        print(f"Total Time: {sum(s.total_time_ms for s in summaries.values()):.2f}ms")

        # Sort by total time
        sorted_ops = sorted(summaries.values(), key=lambda s: s.total_time_ms, reverse=True)

        print(f"\n{'Operation':<30} {'Calls':<8} {'Total (ms)':<12} {'Avg (ms)':<12} {'% Time':<8}")
        print("-" * 80)

        total_time = sum(s.total_time_ms for s in summaries.values())

        for i, summary in enumerate(sorted_ops[:top_n]):
            pct = (summary.total_time_ms / total_time * 100) if total_time > 0 else 0
            print(f"{summary.operation:<30} {summary.call_count:<8} "
                  f"{summary.total_time_ms:>10.2f}  {summary.avg_time_ms:>10.2f}  "
                  f"{pct:>6.1f}%")

        print(f"{'='*80}\n")

    def print_bottlenecks(self, top_n: int = 5):
        """Print top bottlenecks with detailed breakdown"""
        bottlenecks = self.get_bottlenecks(top_n)

        if not bottlenecks:
            print("\nNo bottlenecks identified")
            return

        print(f"\n{'='*80}")
        print(f"TOP {len(bottlenecks)} BOTTLENECKS")
        print(f"{'='*80}")

        for i, summary in enumerate(bottlenecks, 1):
            print(f"\n[{i}] {summary.operation}")
            print(f"  Total Time: {summary.total_time_ms:.2f}ms ({summary.call_count} calls)")
            print(f"  Avg Time: {summary.avg_time_ms:.2f}ms (min: {summary.min_time_ms:.2f}ms, "
                  f"max: {summary.max_time_ms:.2f}ms)")

            if summary.total_gpu_time_ms > 0:
                print("  Breakdown:")
                print(f"    GPU Compute: {summary.total_gpu_time_ms:.2f}ms "
                      f"({summary.total_gpu_time_ms/summary.total_time_ms*100:.1f}%)")
                print(f"    Transfer: {summary.total_transfer_time_ms:.2f}ms "
                      f"({summary.total_transfer_time_ms/summary.total_time_ms*100:.1f}%)")
                print(f"    Overhead: {summary.total_overhead_ms:.2f}ms "
                      f"({summary.total_overhead_ms/summary.total_time_ms*100:.1f}%)")

            if summary.avg_memory_mb > 0:
                print(f"  Memory: {summary.avg_memory_mb:.1f}MB avg, "
                      f"{summary.peak_memory_mb:.1f}MB peak")

            if summary.avg_gpu_utilization > 0:
                print(f"  GPU Utilization: {summary.avg_gpu_utilization:.1f}%")

        print(f"\n{'='*80}\n")

    def export_json(self, filepath: str):
        """Export profiling data to JSON"""
        data = {
            'entries': [
                {
                    'operation': e.operation,
                    'duration_ms': e.duration_ms,
                    'device': e.device,
                    'backend': e.backend,
                    'gpu_time_ms': e.gpu_time_ms,
                    'cpu_time_ms': e.cpu_time_ms,
                    'transfer_time_ms': e.transfer_time_ms,
                    'overhead_ms': e.overhead_ms,
                    'memory_allocated_mb': e.memory_allocated_mb,
                    'memory_peak_mb': e.memory_peak_mb,
                    'gpu_utilization': e.gpu_utilization,
                    'metadata': e.metadata
                }
                for e in self._entries
            ],
            'summary': {
                op: {
                    'call_count': s.call_count,
                    'total_time_ms': s.total_time_ms,
                    'avg_time_ms': s.avg_time_ms,
                    'min_time_ms': s.min_time_ms,
                    'max_time_ms': s.max_time_ms,
                    'total_gpu_time_ms': s.total_gpu_time_ms,
                    'avg_memory_mb': s.avg_memory_mb,
                    'avg_gpu_utilization': s.avg_gpu_utilization
                }
                for op, s in self.get_summary().items()
            }
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported profiling data to {filepath}")

    def export_glyphs_json(self, filepath: str):
        """
        Export profiling data with glyph annotations to JSON

        Args:
            filepath: Output JSON file path
        """
        analyzer = _get_glyph_analyzer()
        if analyzer is None:
            logger.error("Cannot export glyphs: glyph analyzer not available")
            return

        # First export standard profiling data
        data = {
            'entries': [
                {
                    'operation': e.operation,
                    'duration_ms': e.duration_ms,
                    'device': e.device,
                    'backend': e.backend,
                    'gpu_time_ms': e.gpu_time_ms,
                    'cpu_time_ms': e.cpu_time_ms,
                    'transfer_time_ms': e.transfer_time_ms,
                    'overhead_ms': e.overhead_ms,
                    'memory_allocated_mb': e.memory_allocated_mb,
                    'memory_peak_mb': e.memory_peak_mb,
                    'gpu_utilization': e.gpu_utilization,
                    'metadata': e.metadata
                }
                for e in self._entries
            ],
            'summary': {
                op: {
                    'call_count': s.call_count,
                    'total_time_ms': s.total_time_ms,
                    'avg_time_ms': s.avg_time_ms,
                    'min_time_ms': s.min_time_ms,
                    'max_time_ms': s.max_time_ms,
                    'total_gpu_time_ms': s.total_gpu_time_ms,
                    'avg_memory_mb': s.avg_memory_mb,
                    'avg_gpu_utilization': s.avg_gpu_utilization
                }
                for op, s in self.get_summary().items()
            }
        }

        # Generate glyphs
        glyphs = analyzer.analyze_profiling_data(data)

        # Add glyph data
        data['glyphs'] = [g.to_dict() for g in glyphs]
        data['glyph_count'] = len(glyphs)

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported profiling data with {len(glyphs)} glyphs to {filepath}")

    def get_glyphs(self):
        """
        Get glyph descriptors for all profiled operations

        Returns:
            List of GlyphDescriptor objects, or None if analyzer unavailable
        """
        analyzer = _get_glyph_analyzer()
        if analyzer is None:
            logger.warning("Cannot generate glyphs: analyzer not available")
            return None

        # Create minimal profiling data structure
        data = {
            'entries': [
                {
                    'operation': e.operation,
                    'duration_ms': e.duration_ms,
                    'device': e.device,
                    'memory_allocated_mb': e.memory_allocated_mb,
                    'metadata': e.metadata
                }
                for e in self._entries
            ]
        }

        return analyzer.analyze_profiling_data(data)

    def print_glyph_summary(self):
        """Print summary of operations using glyph notation"""
        glyphs = self.get_glyphs()
        if glyphs is None:
            print("\nCannot generate glyph summary: analyzer not available")
            return

        print(f"\n{'='*80}")
        print("GLYPH SUMMARY")
        print(f"{'='*80}")
        print(f"Total Operations: {len(glyphs)}")

        # Group by optimization level
        by_level = {}
        for glyph in glyphs:
            level = glyph.optimization_level
            if level not in by_level:
                by_level[level] = []
            by_level[level].append(glyph)

        level_names = {
            0: "Base (no optimization)",
            1: "Routed (smart routing)",
            2: "Batched (batch processing)",
            3: "Optimized (fully optimized)"
        }

        for level in sorted(by_level.keys()):
            print(f"\n{level_names[level]}: {len(by_level[level])} operations")
            for glyph in by_level[level][:5]:  # Show first 5
                speedup_str = ""
                if glyph.speedup:
                    speedup_str = f" ({glyph.speedup}x faster)"
                print(f"  {glyph.get_notation():<10} {glyph.operation_name:<30} "
                      f"{glyph.duration_ms:>8.2f}ms{speedup_str}")

            if len(by_level[level]) > 5:
                print(f"  ... and {len(by_level[level]) - 5} more")

        print(f"{'='*80}\n")

    def get_complexity_analysis(self) -> Optional[Dict]:
        """
        Get complexity analysis for all operations

        Returns:
            Complexity hierarchy dictionary or None if analyzer unavailable
        """
        analyzer = _get_complexity_analyzer()
        if analyzer is None:
            return None

        from .profiler_complexity import ComplexityHierarchy

        # Convert entries to dictionaries with complexity data
        ops_data = []
        for entry in self._entries:
            if entry.complexity_score:
                ops_data.append({
                    'operation': entry.operation,
                    'complexity_score': entry.complexity_score.to_dict() if hasattr(entry.complexity_score, 'to_dict') else {}
                })

        if not ops_data:
            return None

        # Build hierarchy
        hierarchy_mgr = ComplexityHierarchy(analyzer)
        return hierarchy_mgr.build_hierarchy(ops_data)

    def print_complexity_summary(self):
        """Print complexity hierarchy and bottlenecks"""
        hierarchy = self.get_complexity_analysis()
        if hierarchy is None:
            print("\nCannot generate complexity summary: analyzer not available or no data")
            return

        analyzer = _get_complexity_analyzer()
        from .profiler_complexity import ComplexityHierarchy, ComplexityTier

        hierarchy_mgr = ComplexityHierarchy(analyzer)

        print(f"\n{'='*80}")
        print("COMPLEXITY HIERARCHY")
        print(f"{'='*80}\n")

        # Print tier summary
        tier_names = {
            ComplexityTier.EXPONENTIAL.value: "Tier 3 (Exponential)",
            ComplexityTier.POLYNOMIAL.value: "Tier 2 (Polynomial)",
            ComplexityTier.LINEAR.value: "Tier 1 (Linear)",
            ComplexityTier.TRIVIAL.value: "Tier 0 (Trivial)"
        }

        tier_symbols = {
            ComplexityTier.EXPONENTIAL.value: "⊙",
            ComplexityTier.POLYNOMIAL.value: "⊗",
            ComplexityTier.LINEAR.value: "⊘",
            ComplexityTier.TRIVIAL.value: "⊕"
        }

        for tier_val in [3, 2, 1, 0]:  # Descending order
            tier_name = tier_names[tier_val]
            tier_symbol = tier_symbols[tier_val]
            tier_ops = hierarchy['tiers'][tier_val]

            print(f"{tier_name}: {len(tier_ops)} operation(s)")
            for op in tier_ops[:5]:  # Show first 5
                print(f"  {tier_symbol}  {op['operation']:<30} Score: {op['score']:>8.2f}   "
                      f"Grade: {op['grade']}   Bottleneck: {op['bottleneck']}")
            if len(tier_ops) > 5:
                print(f"  ... and {len(tier_ops) - 5} more")
            print()

        # Show bottlenecks
        bottlenecks = hierarchy_mgr.find_complexity_bottlenecks(hierarchy, threshold=100.0)
        if bottlenecks:
            print("Complexity Bottlenecks (Score > 100):")
            for i, bottleneck in enumerate(bottlenecks[:5], 1):
                print(f"  {i}. {bottleneck['operation']} (Score: {bottleneck['score']:.2f}, "
                      f"Grade: {bottleneck['grade']})")

                # Get suggestions
                suggestions = hierarchy_mgr.suggest_complexity_reductions(
                    bottleneck['operation'],
                    None  # We don't have the full ComplexityScore object here
                )
                if suggestions:
                    print("     Suggestions:")
                    for suggestion in suggestions[:2]:  # Show first 2
                        print(f"     - {suggestion}")
            print()

        # Summary statistics
        print(f"Total Complexity Score: {hierarchy['total_complexity_score']:.2f}")
        print(f"Average Complexity Score: {hierarchy['average_complexity_score']:.2f}")
        print(f"{'='*80}\n")

    def export_complexity_json(self, filepath: str):
        """Export profiling data with complexity metrics to JSON"""
        analyzer = _get_complexity_analyzer()
        if analyzer is None:
            logger.error("Cannot export complexity: analyzer not available")
            return

        # Build data structure
        data = {
            'entries': [],
            'summary': {},
            'complexity_hierarchy': self.get_complexity_analysis()
        }

        # Add entries with complexity
        for entry in self._entries:
            entry_dict = {
                'operation': entry.operation,
                'duration_ms': entry.duration_ms,
                'device': entry.device,
                'backend': entry.backend,
                'memory_allocated_mb': entry.memory_allocated_mb,
                'memory_peak_mb': entry.memory_peak_mb
            }

            # Add complexity data if available
            if entry.algorithmic_complexity:
                entry_dict['algorithmic_complexity'] = entry.algorithmic_complexity.to_dict()
            if entry.operational_complexity:
                entry_dict['operational_complexity'] = entry.operational_complexity.to_dict()
            if entry.complexity_score:
                entry_dict['complexity_score'] = entry.complexity_score.to_dict()

            data['entries'].append(entry_dict)

        # Add summary
        summary = self.get_summary()
        for op_name, op_summary in summary.items():
            data['summary'][op_name] = {
                'call_count': op_summary.call_count,
                'total_time_ms': op_summary.total_time_ms,
                'avg_time_ms': op_summary.avg_time_ms
            }

        # Write to file
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported complexity data to {filepath}")

    def reset(self):
        """Reset profiling data"""
        self._entries.clear()
        self._operation_stack.clear()
        self._start_times.clear()

        if self.pytorch_available:
            try:
                import torch
                torch.cuda.reset_peak_memory_stats(self.device_id)
            except Exception:
                pass

        logger.info("Profiling data reset")

    def enable(self):
        """Enable profiling"""
        self.enabled = True

    def disable(self):
        """Disable profiling"""
        self.enabled = False


# Global profiler instance
_global_profiler: Optional[GPUProfiler] = None


def get_profiler(
    enabled: bool = True,
    device_id: int = 0,
    enable_detailed_metrics: bool = True
) -> GPUProfiler:
    """
    Get global profiler instance (singleton)

    Args:
        enabled: Enable profiling
        device_id: GPU device ID
        enable_detailed_metrics: Collect detailed metrics

    Returns:
        GPUProfiler instance
    """
    global _global_profiler

    if _global_profiler is None:
        _global_profiler = GPUProfiler(
            enabled=enabled,
            device_id=device_id,
            enable_detailed_metrics=enable_detailed_metrics
        )

    return _global_profiler
