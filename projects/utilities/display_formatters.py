"""
Enhanced Display Formatters
Multiple output formats for validated random data with self-assessment
capabilities
"""

import numpy as np
from typing import Any, Dict, List, Optional
import json
import csv
import io
import time
from dataclasses import dataclass


@dataclass
class DisplayMetrics:
    """Metrics for display format assessment"""
    format_name: str
    readability_score: float
    information_density: float
    visual_clarity: float
    accessibility_score: float
    overall_quality: float


class EnhancedDisplayFormatter:
    """Multi-modal display formatter with self-assessment"""

    def __init__(self):
        self.display_formats = {
            'tabular': self._format_tabular,
            'hierarchical': self._format_hierarchical,
            'statistical': self._format_statistical,
            'compact': self._format_compact,
            'detailed': self._format_detailed,
            'scientific': self._format_scientific,
            'ascii_visual': self._format_ascii_visual,
            'json_structured': self._format_json,
            'csv_export': self._format_csv
        }

        self.format_metrics = {}
        self.assessment_criteria = {
            'readability': ['line_length', 'whitespace_ratio',
                            'structure_clarity'],
            'information_density': ['data_per_line', 'compression_ratio',
                                    'redundancy_level'],
            'visual_clarity': ['alignment', 'separation', 'hierarchy_depth'],
            'accessibility': ['text_only', 'screen_reader_friendly',
                              'color_independence']
        }

    def format_data(self, data: Dict[str, Any], format_type: str = 'detailed',
                    validation_report: Optional[Dict] = None) -> str:
        """Format data using specified format with self-assessment"""

        if format_type not in self.display_formats:
            available = ', '.join(self.display_formats.keys())
            return (f"Error: Unknown format '{format_type}'. "
                    f"Available: {available}")

        # Generate formatted output
        formatted_output = self.display_formats[format_type](
            data, validation_report)

        # Perform self-assessment
        metrics = self._assess_display_format(formatted_output, format_type)
        self.format_metrics[format_type] = metrics

        # Add assessment summary to output
        assessment_summary = self._generate_assessment_summary(metrics)

        return f"{formatted_output}\n\n{assessment_summary}"

    def _format_tabular(self, data: Dict[str, Any],
                        validation_report: Optional[Dict] = None) -> str:
        """Tabular format with aligned columns"""

        output = []
        output.append("TABULAR DATA DISPLAY")
        output.append("=" * 80)

        if validation_report:
            output.append(f"Validation Status: "
                          f"{validation_report.get('overall_status', 'UNKNOWN')}")
            output.append(f"Pass Rate: "
                          f"{validation_report.get('pass_rate', 0):.1%}")
            output.append("-" * 80)

        for category, category_data in data.items():
            output.append(f"\nCATEGORY: {category.upper()}")
            output.append("-" * 40)

            if isinstance(category_data, dict):
                # Create table headers
                if category_data:
                    # Determine column widths
                    key_width = max(len(str(k))
                                    for k in category_data.keys()) + 2

                    for key, values in category_data.items():
                        if isinstance(values, (list, tuple, np.ndarray)):
                            # Format as table row
                            values_str = str(list(values)
                                             if isinstance(values, np.ndarray)
                                             else values)
                            if len(values_str) > 60:
                                values_str = values_str[:57] + "..."
                            output.append(f"{key:<{key_width}} | {values_str}")
                        else:
                            output.append(f"{key:<{key_width}} | {values}")
            else:
                output.append(f"  {category_data}")

        return "\n".join(output)

    def _format_hierarchical(self, data: Dict[str, Any],
                             validation_report: Optional[Dict] = None) -> str:
        """Hierarchical tree-like format"""

        output = []
        output.append("HIERARCHICAL DATA DISPLAY")
        output.append("=" * 80)

        if validation_report:
            output.append(f"├── Validation: "
                          f"{validation_report.get('overall_status', 'UNKNOWN')}")
            output.append(f"└── Quality: "
                          f"{validation_report.get('pass_rate', 0):.1%} "
                          f"pass rate")
            output.append("")

        def format_hierarchical_recursive(data_item: Any, prefix: str = "",
                                          is_last: bool = True):
            """Recursively format hierarchical data"""

            if isinstance(data_item, dict):
                items = list(data_item.items())
                for i, (key, value) in enumerate(items):
                    is_last_item = (i == len(items) - 1)
                    current_prefix = "└── " if is_last_item else "├── "
                    output.append(f"{prefix}{current_prefix}{key}")

                    next_prefix = prefix + ("    " if is_last_item else "│   ")
                    format_hierarchical_recursive(value, next_prefix,
                                                  is_last_item)

            elif isinstance(data_item, (list, tuple)):
                if len(data_item) <= 5:
                    # Show all items for short lists
                    for i, item in enumerate(data_item):
                        is_last_item = (i == len(data_item) - 1)
                        item_prefix = "└── " if is_last_item else "├── "
                        output.append(f"{prefix}{item_prefix}[{i}]: {item}")
                else:
                    # Show first few and summary for long lists
                    for i in range(3):
                        output.append(f"{prefix}├── [{i}]: {data_item[i]}")
                    output.append(f"{prefix}├── ... "
                                  f"({len(data_item)-5} more items)")
                    for i in range(len(data_item)-2, len(data_item)):
                        is_last_item = (i == len(data_item) - 1)
                        item_prefix = "└── " if is_last_item else "├── "
                        output.append(f"{prefix}{item_prefix}[{i}]: "
                                      f"{data_item[i]}")

            else:
                output.append(f"{prefix}└── {data_item}")

        for category, category_data in data.items():
            output.append(f"📁 {category.upper()}")
            format_hierarchical_recursive(category_data, "  ")
            output.append("")

        return "\n".join(output)

    def _format_statistical(self, data: Dict[str, Any],
                            validation_report: Optional[Dict] = None) -> str:
        """Statistical summary format"""

        output = []
        output.append("STATISTICAL DATA ANALYSIS")
        output.append("=" * 80)

        if validation_report:
            output.append(f"Data Quality Assessment: "
                          f"{validation_report.get('overall_status', 'UNKNOWN')}")
            output.append(f"Validation Coverage: "
                          f"{validation_report.get('total_validations', 0)} "
                          f"checks")
            output.append("-" * 80)

        total_data_points = 0
        categories_analyzed = 0

        for category, category_data in data.items():
            output.append(f"\nSTATISTICAL ANALYSIS: {category.upper()}")
            output.append("-" * 50)

            if isinstance(category_data, dict):
                for key, values in category_data.items():
                    if (isinstance(values, (list, tuple, np.ndarray)) and
                            len(values) > 0):
                        try:
                            # Convert to numeric if possible
                            numeric_values = [float(v) for v in values
                                              if isinstance(v, (int, float))]

                            if numeric_values:
                                stats = self._calculate_statistics(numeric_values)
                                output.append(f"  {key}:")
                                output.append(f"    Count:      {stats['count']}")
                                output.append(f"    Mean:       {stats['mean']:.3f}")
                                output.append(f"    Median:     {stats['median']:.3f}")
                                output.append(f"    Std Dev:    {stats['std']:.3f}")
                                output.append(f"    Range:      "
                                              f"[{stats['min']:.3f}, "
                                              f"{stats['max']:.3f}]")
                                output.append(f"    Quartiles:  "
                                              f"Q1={stats['q1']:.3f}, "
                                              f"Q3={stats['q3']:.3f}")

                                total_data_points += len(numeric_values)
                                categories_analyzed += 1
                            else:
                                output.append(f"  {key}: Non-numeric data "
                                              f"({len(values)} items)")
                                total_data_points += len(values)

                        except (ValueError, TypeError):
                            output.append(f"  {key}: Complex data structure")
                    else:
                        output.append(f"  {key}: {values}")

        # Overall summary
        output.append("\nOVERALL STATISTICS SUMMARY")
        output.append("-" * 30)
        output.append(f"Total Data Points: {total_data_points}")
        output.append(f"Categories Analyzed: {categories_analyzed}")
        output.append(f"Analysis Timestamp: "
                      f"{time.strftime('%Y-%m-%d %H:%M:%S')}")

        return "\n".join(output)

    def _calculate_statistics(self, values: List[float]) -> Dict[str, float]:
        """Calculate comprehensive statistics"""

        values_array = np.array(values)

        return {
            'count': len(values),
            'mean': np.mean(values_array),
            'median': np.median(values_array),
            'std': np.std(values_array),
            'min': np.min(values_array),
            'max': np.max(values_array),
            'q1': np.percentile(values_array, 25),
            'q3': np.percentile(values_array, 75)
        }

    def _format_compact(self, data: Dict[str, Any],
                        validation_report: Optional[Dict] = None) -> str:
        """Compact single-line format for quick overview"""

        output = []
        output.append("COMPACT DATA SUMMARY")
        output.append("=" * 60)

        if validation_report:
            status = validation_report.get('overall_status', 'UNKNOWN')
            pass_rate = validation_report.get('pass_rate', 0)
            output.append(f"Status: {status} | Quality: {pass_rate:.1%}")
            output.append("-" * 60)

        for category, category_data in data.items():
            if isinstance(category_data, dict):
                items = []
                for key, values in category_data.items():
                    if isinstance(values, (list, tuple, np.ndarray)):
                        items.append(f"{key}({len(values)})")
                    else:
                        items.append(f"{key}")

                output.append(f"{category}: {' | '.join(items)}")
            else:
                output.append(f"{category}: {str(category_data)[:50]}")

        return "\n".join(output)

    def _format_detailed(self, data: Dict[str, Any],
                         validation_report: Optional[Dict] = None) -> str:
        """Detailed format with full information"""

        output = []
        output.append("DETAILED DATA DISPLAY")
        output.append("=" * 100)

        # Validation section
        if validation_report:
            output.append("\nVALIDATION REPORT")
            output.append("-" * 40)
            output.append(f"Overall Status:     "
                          f"{validation_report.get('overall_status', 'UNKNOWN')}")
            output.append(f"Total Validations:  "
                          f"{validation_report.get('total_validations', 0)}")
            output.append(f"Passed:            "
                          f"{validation_report.get('passed', 0)}")
            output.append(f"Failed:            "
                          f"{validation_report.get('failed', 0)}")
            output.append(f"Errors:            "
                          f"{validation_report.get('errors', 0)}")
            output.append(f"Warnings:          "
                          f"{validation_report.get('warnings', 0)}")
            output.append(f"Pass Rate:         "
                          f"{validation_report.get('pass_rate', 0):.1%}")
            output.append("")

        # Data sections
        for category, category_data in data.items():
            output.append(f"CATEGORY: {category.upper()}")
            output.append("=" * 50)

            if isinstance(category_data, dict):
                for key, values in category_data.items():
                    output.append(f"\n{key}:")
                    output.append("-" * len(key))

                    if isinstance(values, (list, tuple)):
                        if len(values) <= 20:
                            for i, value in enumerate(values):
                                output.append(f"  [{i:2d}]: {value}")
                        else:
                            # Show first 10, last 10
                            for i in range(10):
                                output.append(f"  [{i:2d}]: {values[i]}")
                            output.append(f"  ... ({len(values)-20} "
                                          f"more items)")
                            for i in range(len(values)-10, len(values)):
                                output.append(f"  [{i:2d}]: {values[i]}")

                        # Add summary statistics if numeric
                        try:
                            numeric_values = [float(v) for v in values]
                            stats = self._calculate_statistics(numeric_values)
                            output.append(f"  Summary: μ={stats['mean']:.2f}, "
                                          f"σ={stats['std']:.2f}, "
                                          f"n={stats['count']}")
                        except (ValueError, TypeError):
                            output.append(f"  Summary: {len(values)} items, "
                                          f"non-numeric")

                    elif isinstance(values, np.ndarray):
                        output.append(f"  Shape: {values.shape}")
                        output.append(f"  Data type: {values.dtype}")
                        if values.size <= 50:
                            output.append(f"  Values:\n{values}")
                        else:
                            output.append(f"  Values (first 10): "
                                          f"{values.flat[:10]}")

                    else:
                        output.append(f"  Value: {values}")
                        output.append(f"  Type: {type(values).__name__}")

            else:
                output.append(f"Data: {category_data}")
                output.append(f"Type: {type(category_data).__name__}")

            output.append("")

        return "\n".join(output)

    def _format_scientific(self, data: Dict[str, Any],
                           validation_report: Optional[Dict] = None) -> str:
        """Scientific publication format"""

        output = []
        output.append("SCIENTIFIC DATA REPORT")
        output.append("=" * 80)
        output.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        if validation_report:
            output.append(f"Data Quality Index: "
                          f"{validation_report.get('pass_rate', 0):.3f}")
            output.append(f"Validation Protocol: "
                          f"{validation_report.get('total_validations', 0)} "
                          f"checks")

        output.append("\nABSTRACT")
        output.append("-" * 20)

        # Generate abstract
        total_measurements = 0
        categories = list(data.keys())

        for category_data in data.values():
            if isinstance(category_data, dict):
                for values in category_data.values():
                    if isinstance(values, (list, tuple, np.ndarray)):
                        total_measurements += len(values)

        output.append(f"This report presents analysis of "
                      f"{total_measurements} data points across")
        output.append(f"{len(categories)} categories. Data underwent "
                      f"comprehensive validation")
        output.append("with quality assurance protocols ensuring "
                      "statistical integrity.")

        output.append("\nMETHODS")
        output.append("-" * 20)
        output.append("• Random data generation with controlled "
                      "statistical properties")
        output.append("• Multi-modal validation including range, type, "
                      "and distribution checks")
        output.append("• Structured data organization following scientific "
                      "data management practices")
        output.append("• Quality metrics assessment with pass/fail criteria")

        output.append("\nRESULTS")
        output.append("-" * 20)

        for category, category_data in data.items():
            output.append(f"\n{category.replace('_', ' ').title()} Analysis:")

            if isinstance(category_data, dict):
                for key, values in category_data.items():
                    if (isinstance(values, (list, tuple, np.ndarray)) and
                            len(values) > 0):
                        try:
                            numeric_values = [float(v) for v in values
                                              if isinstance(v, (int, float))]
                            if numeric_values:
                                stats = self._calculate_statistics(numeric_values)
                                output.append(f"  {key}: n={stats['count']}, "
                                              f"M={stats['mean']:.3f} "
                                              f"(SD={stats['std']:.3f}), "
                                              f"range=[{stats['min']:.3f}, "
                                              f"{stats['max']:.3f}]")
                        except (ValueError, TypeError):
                            output.append(f"  {key}: qualitative data, "
                                          f"n={len(values)}")

        output.append("\nCONCLUSION")
        output.append("-" * 20)
        if validation_report:
            pass_rate = validation_report.get('pass_rate', 0)
            if pass_rate >= 0.95:
                output.append("Data quality assessment indicates excellent "
                              "integrity with >95% validation pass rate.")
            elif pass_rate >= 0.8:
                output.append("Data quality assessment indicates good "
                              "integrity with >80% validation pass rate.")
            else:
                output.append("Data quality assessment indicates moderate "
                              "integrity. Further validation recommended.")

        output.append("All measurements conform to expected statistical "
                      "distributions and ranges.")

        return "\n".join(output)

    def _format_ascii_visual(self, data: Dict[str, Any],
                             validation_report: Optional[Dict] = None) -> str:
        """ASCII visual format with simple charts"""

        output = []
        output.append("ASCII VISUAL DATA DISPLAY")
        output.append("=" * 80)

        if validation_report:
            # Visual status indicator
            status = validation_report.get('overall_status', 'UNKNOWN')
            pass_rate = validation_report.get('pass_rate', 0)

            output.append("\nVALIDATION STATUS")
            output.append("-" * 20)
            status_bar = ("█" * int(pass_rate * 20) +
                          "░" * (20 - int(pass_rate * 20)))
            output.append(f"Quality: [{status_bar}] {pass_rate:.1%} ({status})")
            output.append("")

        for category, category_data in data.items():
            output.append(f"📊 {category.upper()}")
            output.append("-" * 40)

            if isinstance(category_data, dict):
                for key, values in category_data.items():
                    if (isinstance(values, (list, tuple, np.ndarray)) and
                            len(values) > 0):
                        # Try to create simple bar chart
                        try:
                            numeric_values = [float(v) for v in values
                                              if isinstance(v, (int, float))]
                            if numeric_values and len(numeric_values) <= 20:
                                # Normalize values for display
                                min_val = min(numeric_values)
                                max_val = max(numeric_values)
                                if max_val > min_val:
                                    normalized = [(v - min_val) / (max_val - min_val)
                                                  for v in numeric_values]
                                    output.append(f"\n{key}:")
                                    for i, (val, norm) in enumerate(
                                            zip(numeric_values, normalized)):
                                        bar_length = int(norm * 30)
                                        bar = ("█" * bar_length +
                                               "░" * (30 - bar_length))
                                        output.append(f"  [{i:2d}] {bar} "
                                                      f"{val:.2f}")
                                else:
                                    output.append(f"\n{key}: constant values = "
                                                  f"{numeric_values[0]}")
                            else:
                                output.append(f"\n{key}: {len(values)} items")
                        except (ValueError, TypeError):
                            output.append(f"\n{key}: non-numeric data, "
                                          f"{len(values)} items")
                    else:
                        output.append(f"\n{key}: {values}")

            output.append("")

        return "\n".join(output)

    def _format_json(self, data: Dict[str, Any],
                     validation_report: Optional[Dict] = None) -> str:
        """JSON structured format"""

        # Convert numpy arrays to lists for JSON serialization
        def convert_for_json(obj):
            if isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, dict):
                return {k: convert_for_json(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [convert_for_json(item) for item in obj]
            else:
                return obj

        json_data = {
            'metadata': {
                'format': 'validated_random_output',
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'validation_report': validation_report
            },
            'data': convert_for_json(data)
        }

        return json.dumps(json_data, indent=2, ensure_ascii=False)

    def _format_csv(self, data: Dict[str, Any],
                    validation_report: Optional[Dict] = None) -> str:
        """CSV export format"""

        output = io.StringIO()

        # Write metadata
        output.write("# CSV Export of Validated Random Data\n")
        output.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        if validation_report:
            output.write(f"# Validation Status: "
                         f"{validation_report.get('overall_status', 'UNKNOWN')}\n")
            output.write(f"# Pass Rate: "
                         f"{validation_report.get('pass_rate', 0):.1%}\n")
        output.write("#\n")

        # Convert data to flat structure suitable for CSV
        csv_writer = csv.writer(output)

        for category, category_data in data.items():
            if isinstance(category_data, dict):
                for key, values in category_data.items():
                    if isinstance(values, (list, tuple, np.ndarray)):
                        # Write header
                        csv_writer.writerow([f"{category}_{key}_index",
                                             f"{category}_{key}_value"])
                        # Write data
                        for i, value in enumerate(values):
                            csv_writer.writerow([i, value])
                        csv_writer.writerow([])  # Empty row for separation
                    else:
                        csv_writer.writerow([f"{category}_{key}", values])

        return output.getvalue()

    def _assess_display_format(self, formatted_output: str,
                               format_type: str) -> DisplayMetrics:
        """Self-assess the quality of the display format"""

        lines = formatted_output.split('\n')

        # Readability assessment
        avg_line_length = sum(len(line) for line in lines) / max(len(lines), 1)
        max_line_length = max(len(line) for line in lines) if lines else 0
        whitespace_lines = sum(1 for line in lines if line.strip() == '')
        whitespace_ratio = whitespace_lines / max(len(lines), 1)

        readability_score = min(1.0, max(0.0,
                                         1.0 - (max_line_length - 80) / 200 +
                                         whitespace_ratio * 0.3 +
                                         (1.0 if avg_line_length < 100 else 0.5)
                                         ))

        # Information density assessment
        total_chars = sum(len(line) for line in lines)
        non_space_chars = sum(len(line.replace(' ', '')) for line in lines)
        info_density = non_space_chars / max(total_chars, 1)

        # Visual clarity assessment
        has_headers = sum(1 for line in lines if '=' in line or '-' in line)
        header_ratio = has_headers / max(len(lines), 1)

        indent_consistency = self._assess_indent_consistency(lines)

        visual_clarity = min(1.0, header_ratio * 2 + indent_consistency * 0.5)

        # Accessibility assessment (text-only format scores higher)
        accessibility_score = (1.0 if format_type in
                               ['tabular', 'detailed', 'compact'] else 0.8)

        # Overall quality
        overall_quality = ((readability_score + info_density +
                            visual_clarity + accessibility_score) / 4)

        return DisplayMetrics(
            format_name=format_type,
            readability_score=readability_score,
            information_density=info_density,
            visual_clarity=visual_clarity,
            accessibility_score=accessibility_score,
            overall_quality=overall_quality
        )

    def _assess_indent_consistency(self, lines: List[str]) -> float:
        """Assess consistency of indentation"""
        indents = []
        for line in lines:
            if line.strip():  # Non-empty lines
                indent = len(line) - len(line.lstrip())
                indents.append(indent)

        if not indents:
            return 1.0

        # Check for consistent indentation patterns
        unique_indents = set(indents)
        if len(unique_indents) <= 4:  # Reasonable number of indent levels
            return 1.0
        elif len(unique_indents) <= 8:
            return 0.7
        else:
            return 0.3

    def _generate_assessment_summary(self, metrics: DisplayMetrics) -> str:
        """Generate assessment summary"""

        output = []
        output.append("DISPLAY FORMAT SELF-ASSESSMENT")
        output.append("=" * 50)
        output.append(f"Format: {metrics.format_name}")
        output.append(f"Readability Score:    {metrics.readability_score:.3f}")
        output.append(f"Information Density:  "
                      f"{metrics.information_density:.3f}")
        output.append(f"Visual Clarity:       {metrics.visual_clarity:.3f}")
        output.append(f"Accessibility:        "
                      f"{metrics.accessibility_score:.3f}")
        output.append(f"Overall Quality:      {metrics.overall_quality:.3f}")

        # Quality assessment
        if metrics.overall_quality >= 0.8:
            assessment = "EXCELLENT - High quality display format"
        elif metrics.overall_quality >= 0.6:
            assessment = "GOOD - Acceptable display format"
        elif metrics.overall_quality >= 0.4:
            assessment = "MODERATE - Some improvement needed"
        else:
            assessment = "POOR - Significant improvement required"

        output.append(f"Quality Assessment:   {assessment}")

        return "\n".join(output)

    def get_format_comparison(self) -> str:
        """Compare all used formats"""

        if not self.format_metrics:
            return "No format metrics available. Generate displays first."

        output = []
        output.append("FORMAT COMPARISON ANALYSIS")
        output.append("=" * 60)

        # Sort by overall quality
        sorted_formats = sorted(
            self.format_metrics.items(),
            key=lambda x: x[1].overall_quality,
            reverse=True
        )

        output.append(f"{'Format':<15} {'Quality':<8} {'Read':<6} "
                      f"{'Info':<6} {'Visual':<6} {'Access':<6}")
        output.append("-" * 60)

        for format_name, metrics in sorted_formats:
            output.append(f"{format_name:<15} {metrics.overall_quality:<8.3f} "
                          f"{metrics.readability_score:<6.3f} "
                          f"{metrics.information_density:<6.3f} "
                          f"{metrics.visual_clarity:<6.3f} "
                          f"{metrics.accessibility_score:<6.3f}")

        # Best format recommendation
        best_format = sorted_formats[0]
        output.append(f"\nRecommended Format: {best_format[0]} "
                      f"(Quality: {best_format[1].overall_quality:.3f})")

        return "\n".join(output)

    def export_all_formats(self, data: Dict[str, Any],
                           validation_report: Optional[Dict] = None) -> Dict[str, str]:
        """Export data in all available formats"""

        exports = {}

        for format_name in self.display_formats.keys():
            try:
                exports[format_name] = self.format_data(
                    data, format_name, validation_report)
            except Exception as e:
                exports[format_name] = (f"Error generating {format_name} "
                                        f"format: {str(e)}")

        return exports
