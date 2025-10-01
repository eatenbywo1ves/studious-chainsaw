"""
GPU Profiler Comparison and Regression Detection
Compare profiling runs and identify performance changes
"""

import logging
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Type of performance change"""
    IMPROVEMENT = "improvement"
    REGRESSION = "regression"
    NO_CHANGE = "no_change"
    NEW_OPERATION = "new_operation"
    REMOVED_OPERATION = "removed_operation"


@dataclass
class OperationComparison:
    """Comparison of a single operation between two runs"""
    operation: str
    baseline_time_ms: float
    current_time_ms: float
    change_ms: float
    change_percent: float
    change_type: ChangeType
    baseline_calls: int
    current_calls: int
    is_significant: bool

    # Additional metrics
    baseline_memory_mb: float = 0.0
    current_memory_mb: float = 0.0
    memory_change_mb: float = 0.0


@dataclass
class ComparisonSummary:
    """Summary of comparison between two profiling runs"""
    total_operations: int
    regressions_count: int
    improvements_count: int
    unchanged_count: int
    new_operations_count: int
    removed_operations_count: int

    total_time_change_ms: float
    total_time_change_percent: float

    worst_regression: Optional[OperationComparison] = None
    best_improvement: Optional[OperationComparison] = None


class ProfilerComparison:
    """
    Compare two profiling runs to identify performance changes
    """

    def __init__(
        self,
        baseline_data: Dict,
        current_data: Dict,
        significance_threshold: float = 5.0  # 5% change is significant
    ):
        """
        Initialize profiler comparison

        Args:
            baseline_data: Baseline profiling data (JSON dict)
            current_data: Current profiling data (JSON dict)
            significance_threshold: Minimum % change to be considered significant
        """
        self.baseline = baseline_data
        self.current = current_data
        self.significance_threshold = significance_threshold

        self.comparisons: List[OperationComparison] = []
        self._analyze()

    def _analyze(self):
        """Analyze differences between baseline and current"""
        baseline_summary = self.baseline.get('summary', {})
        current_summary = self.current.get('summary', {})

        # Get all operation names
        all_ops = set(baseline_summary.keys()) | set(current_summary.keys())

        for op in all_ops:
            baseline_stats = baseline_summary.get(op)
            current_stats = current_summary.get(op)

            if baseline_stats and current_stats:
                # Operation exists in both runs
                comparison = self._compare_operation(op, baseline_stats, current_stats)
            elif baseline_stats and not current_stats:
                # Operation removed
                comparison = OperationComparison(
                    operation=op,
                    baseline_time_ms=baseline_stats['total_time_ms'],
                    current_time_ms=0.0,
                    change_ms=-baseline_stats['total_time_ms'],
                    change_percent=-100.0,
                    change_type=ChangeType.REMOVED_OPERATION,
                    baseline_calls=baseline_stats['call_count'],
                    current_calls=0,
                    is_significant=True,
                    baseline_memory_mb=baseline_stats.get('avg_memory_mb', 0.0),
                    current_memory_mb=0.0,
                    memory_change_mb=-baseline_stats.get('avg_memory_mb', 0.0)
                )
            else:  # current_stats and not baseline_stats
                # New operation
                comparison = OperationComparison(
                    operation=op,
                    baseline_time_ms=0.0,
                    current_time_ms=current_stats['total_time_ms'],
                    change_ms=current_stats['total_time_ms'],
                    change_percent=100.0,
                    change_type=ChangeType.NEW_OPERATION,
                    baseline_calls=0,
                    current_calls=current_stats['call_count'],
                    is_significant=True,
                    baseline_memory_mb=0.0,
                    current_memory_mb=current_stats.get('avg_memory_mb', 0.0),
                    memory_change_mb=current_stats.get('avg_memory_mb', 0.0)
                )

            self.comparisons.append(comparison)

    def _compare_operation(
        self,
        op: str,
        baseline: Dict,
        current: Dict
    ) -> OperationComparison:
        """Compare a single operation between runs"""
        baseline_time = baseline['total_time_ms']
        current_time = current['total_time_ms']

        change_ms = current_time - baseline_time
        change_percent = (change_ms / baseline_time * 100) if baseline_time > 0 else 0

        # Determine change type
        if abs(change_percent) < self.significance_threshold:
            change_type = ChangeType.NO_CHANGE
            is_significant = False
        elif change_percent > 0:
            change_type = ChangeType.REGRESSION
            is_significant = True
        else:
            change_type = ChangeType.IMPROVEMENT
            is_significant = True

        # Memory comparison
        baseline_mem = baseline.get('avg_memory_mb', 0.0)
        current_mem = current.get('avg_memory_mb', 0.0)
        memory_change = current_mem - baseline_mem

        return OperationComparison(
            operation=op,
            baseline_time_ms=baseline_time,
            current_time_ms=current_time,
            change_ms=change_ms,
            change_percent=change_percent,
            change_type=change_type,
            baseline_calls=baseline['call_count'],
            current_calls=current['call_count'],
            is_significant=is_significant,
            baseline_memory_mb=baseline_mem,
            current_memory_mb=current_mem,
            memory_change_mb=memory_change
        )

    def get_summary(self) -> ComparisonSummary:
        """Get summary of comparison"""
        regressions = [c for c in self.comparisons if c.change_type == ChangeType.REGRESSION]
        improvements = [c for c in self.comparisons if c.change_type == ChangeType.IMPROVEMENT]
        unchanged = [c for c in self.comparisons if c.change_type == ChangeType.NO_CHANGE]
        new_ops = [c for c in self.comparisons if c.change_type == ChangeType.NEW_OPERATION]
        removed_ops = [c for c in self.comparisons if c.change_type == ChangeType.REMOVED_OPERATION]

        # Calculate total time change
        total_change_ms = sum(c.change_ms for c in self.comparisons)

        baseline_total = sum(c.baseline_time_ms for c in self.comparisons)
        total_change_percent = (total_change_ms / baseline_total * 100) if baseline_total > 0 else 0

        # Find worst regression and best improvement
        worst_regression = (max(regressions, key=lambda c: c.change_percent)
                           if regressions else None)
        best_improvement = (min(improvements, key=lambda c: c.change_percent)
                           if improvements else None)

        return ComparisonSummary(
            total_operations=len(self.comparisons),
            regressions_count=len(regressions),
            improvements_count=len(improvements),
            unchanged_count=len(unchanged),
            new_operations_count=len(new_ops),
            removed_operations_count=len(removed_ops),
            total_time_change_ms=total_change_ms,
            total_time_change_percent=total_change_percent,
            worst_regression=worst_regression,
            best_improvement=best_improvement
        )

    def get_regressions(self, top_n: Optional[int] = None) -> List[OperationComparison]:
        """Get performance regressions sorted by severity"""
        regressions = [c for c in self.comparisons if c.change_type == ChangeType.REGRESSION]
        regressions.sort(key=lambda c: c.change_percent, reverse=True)
        return regressions[:top_n] if top_n else regressions

    def get_improvements(self, top_n: Optional[int] = None) -> List[OperationComparison]:
        """Get performance improvements sorted by magnitude"""
        improvements = [c for c in self.comparisons if c.change_type == ChangeType.IMPROVEMENT]
        improvements.sort(key=lambda c: c.change_percent)
        return improvements[:top_n] if top_n else improvements

    def print_summary(self):
        """Print comparison summary"""
        summary = self.get_summary()

        print(f"\n{'='*80}")
        print("PROFILING COMPARISON SUMMARY")
        print(f"{'='*80}")
        print(f"Total Operations: {summary.total_operations}")
        print(f"  Regressions: {summary.regressions_count}")
        print(f"  Improvements: {summary.improvements_count}")
        print(f"  Unchanged: {summary.unchanged_count}")
        print(f"  New: {summary.new_operations_count}")
        print(f"  Removed: {summary.removed_operations_count}")

        print(f"\nOverall Performance Change: {summary.total_time_change_ms:+.2f}ms "
              f"({summary.total_time_change_percent:+.1f}%)")

        if summary.worst_regression:
            reg = summary.worst_regression
            print(f"\nWorst Regression: {reg.operation}")
            print(f"  {reg.baseline_time_ms:.2f}ms -> {reg.current_time_ms:.2f}ms "
                  f"({reg.change_percent:+.1f}%)")

        if summary.best_improvement:
            imp = summary.best_improvement
            print(f"\nBest Improvement: {imp.operation}")
            print(f"  {imp.baseline_time_ms:.2f}ms -> {imp.current_time_ms:.2f}ms "
                  f"({imp.change_percent:+.1f}%)")

        print(f"{'='*80}\n")

    def print_regressions(self, top_n: int = 5):
        """Print top regressions"""
        regressions = self.get_regressions(top_n)

        if not regressions:
            print("\nNo performance regressions detected!")
            return

        print(f"\n{'='*80}")
        print(f"TOP {len(regressions)} PERFORMANCE REGRESSIONS")
        print(f"{'='*80}")

        for i, reg in enumerate(regressions, 1):
            print(f"\n[{i}] {reg.operation}")
            print(f"  Baseline: {reg.baseline_time_ms:.2f}ms ({reg.baseline_calls} calls)")
            print(f"  Current:  {reg.current_time_ms:.2f}ms ({reg.current_calls} calls)")
            print(f"  Change:   {reg.change_ms:+.2f}ms ({reg.change_percent:+.1f}%)")

            if reg.memory_change_mb != 0:
                print(f"  Memory:   {reg.baseline_memory_mb:.1f}MB -> "
                      f"{reg.current_memory_mb:.1f}MB ({reg.memory_change_mb:+.1f}MB)")

        print(f"\n{'='*80}\n")

    def print_improvements(self, top_n: int = 5):
        """Print top improvements"""
        improvements = self.get_improvements(top_n)

        if not improvements:
            print("\nNo performance improvements detected!")
            return

        print(f"\n{'='*80}")
        print(f"TOP {len(improvements)} PERFORMANCE IMPROVEMENTS")
        print(f"{'='*80}")

        for i, imp in enumerate(improvements, 1):
            print(f"\n[{i}] {imp.operation}")
            print(f"  Baseline: {imp.baseline_time_ms:.2f}ms ({imp.baseline_calls} calls)")
            print(f"  Current:  {imp.current_time_ms:.2f}ms ({imp.current_calls} calls)")
            print(f"  Change:   {imp.change_ms:+.2f}ms ({imp.change_percent:+.1f}%)")

            if imp.memory_change_mb != 0:
                print(f"  Memory:   {imp.baseline_memory_mb:.1f}MB -> "
                      f"{imp.current_memory_mb:.1f}MB ({imp.memory_change_mb:+.1f}MB)")

        print(f"\n{'='*80}\n")

    def export_comparison(self, filepath: str):
        """Export comparison to JSON"""
        data = {
            'summary': {
                'total_operations': self.get_summary().total_operations,
                'regressions': self.get_summary().regressions_count,
                'improvements': self.get_summary().improvements_count,
                'unchanged': self.get_summary().unchanged_count,
                'new_operations': self.get_summary().new_operations_count,
                'removed_operations': self.get_summary().removed_operations_count,
                'total_change_ms': self.get_summary().total_time_change_ms,
                'total_change_percent': self.get_summary().total_time_change_percent
            },
            'comparisons': [
                {
                    'operation': c.operation,
                    'baseline_time_ms': c.baseline_time_ms,
                    'current_time_ms': c.current_time_ms,
                    'change_ms': c.change_ms,
                    'change_percent': c.change_percent,
                    'change_type': c.change_type.value,
                    'is_significant': c.is_significant,
                    'baseline_calls': c.baseline_calls,
                    'current_calls': c.current_calls
                }
                for c in self.comparisons
            ]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported comparison to {filepath}")


def compare_profiling_runs(
    baseline_file: str,
    current_file: str,
    significance_threshold: float = 5.0
) -> ProfilerComparison:
    """
    Compare two profiling runs from JSON files

    Args:
        baseline_file: Path to baseline profiling JSON
        current_file: Path to current profiling JSON
        significance_threshold: Minimum % change to be significant

    Returns:
        ProfilerComparison instance
    """
    with open(baseline_file, 'r') as f:
        baseline_data = json.load(f)

    with open(current_file, 'r') as f:
        current_data = json.load(f)

    return ProfilerComparison(baseline_data, current_data, significance_threshold)

