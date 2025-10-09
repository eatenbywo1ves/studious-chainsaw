#!/usr/bin/env python3
"""
GPU Baseline Measurement Script - B-MAD Phase 2
Collects performance metrics for NVIDIA GPU in containerized environment
"""

import subprocess
import json
import time
from dataclasses import dataclass, asdict
from typing import List
from datetime import datetime


@dataclass
class GPUMetrics:
    timestamp: float
    gpu_util: float
    memory_used: int
    memory_total: int
    memory_util: float
    temperature: int
    power_draw: float


def measure_gpu_baseline(duration_seconds: int = 60) -> List[GPUMetrics]:
    """Measure GPU performance baseline for B-MAD analysis."""

    metrics = []
    start_time = time.time()

    print(f"[MEASURE] Collecting GPU baseline metrics for {duration_seconds} seconds...")

    while time.time() - start_time < duration_seconds:
        try:
            # Query NVIDIA SMI via Docker (works on Windows)
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--gpus",
                    "all",
                    "nvidia/cuda:12.3.1-base-ubuntu22.04",
                    "nvidia-smi",
                    "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                values = result.stdout.strip().split(",")
                gpu_util = float(values[0].strip())
                mem_used = int(values[1].strip())
                mem_total = int(values[2].strip())
                mem_util = (mem_used / mem_total) * 100
                temp = int(values[3].strip())
                power = float(values[4].strip())

                metric = GPUMetrics(
                    timestamp=time.time(),
                    gpu_util=gpu_util,
                    memory_used=mem_used,
                    memory_total=mem_total,
                    memory_util=mem_util,
                    temperature=temp,
                    power_draw=power,
                )
                metrics.append(metric)

                # Progress indicator
                elapsed = int(time.time() - start_time)
                print(
                    f"\r[MEASURE] Progress: {elapsed}/{duration_seconds}s | "
                    f"GPU: {gpu_util:.1f}% | Mem: {mem_util:.1f}% | Temp: {temp}°C",
                    end="",
                    flush=True,
                )
        except Exception as e:
            print(f"\n[MEASURE] Warning: Failed to collect metric: {e}")

        time.sleep(2)  # Sample every 2 seconds

    print()  # New line after progress
    return metrics


def calculate_statistics(metrics: List[GPUMetrics]) -> dict:
    """Calculate baseline statistics for B-MAD analysis."""

    if not metrics:
        return {"error": "No metrics collected"}

    gpu_utils = [m.gpu_util for m in metrics]
    mem_utils = [m.memory_util for m in metrics]
    temps = [m.temperature for m in metrics]
    powers = [m.power_draw for m in metrics]

    def percentile(data: List[float], p: float) -> float:
        sorted_data = sorted(data)
        index = int(len(sorted_data) * p)
        return sorted_data[min(index, len(sorted_data) - 1)]

    stats = {
        "measurement_info": {
            "duration_seconds": len(metrics) * 2,
            "sample_count": len(metrics),
            "timestamp": datetime.now().isoformat(),
        },
        "gpu_utilization": {
            "mean": sum(gpu_utils) / len(gpu_utils),
            "min": min(gpu_utils),
            "max": max(gpu_utils),
            "p50": percentile(gpu_utils, 0.50),
            "p95": percentile(gpu_utils, 0.95),
            "p99": percentile(gpu_utils, 0.99),
        },
        "memory_utilization": {
            "mean": sum(mem_utils) / len(mem_utils),
            "min": min(mem_utils),
            "max": max(mem_utils),
            "p50": percentile(mem_utils, 0.50),
            "p95": percentile(mem_utils, 0.95),
        },
        "temperature": {
            "mean": sum(temps) / len(temps),
            "min": min(temps),
            "max": max(temps),
            "safe_threshold": 85,
            "status": "SAFE" if max(temps) < 85 else "WARNING",
        },
        "power_draw": {"mean": sum(powers) / len(powers), "min": min(powers), "max": max(powers)},
    }

    return stats


def generate_report(stats: dict, metrics: List[GPUMetrics]):
    """Generate human-readable report."""

    print("\n" + "=" * 70)
    print("  GPU BASELINE MEASUREMENT REPORT - B-MAD Phase 2")
    print("=" * 70)

    print("\nMeasurement Info:")
    print(f"  - Duration: {stats['measurement_info']['duration_seconds']}s")
    print(f"  - Samples: {stats['measurement_info']['sample_count']}")
    print(f"  - Timestamp: {stats['measurement_info']['timestamp']}")

    print("\nGPU Utilization:")
    print(f"  - Mean:  {stats['gpu_utilization']['mean']:.1f}%")
    print(
        f"  - Range: {stats['gpu_utilization']['min']:.1f}% - {stats['gpu_utilization']['max']:.1f}%"
    )
    print(f"  - P50:   {stats['gpu_utilization']['p50']:.1f}%")
    print(f"  - P95:   {stats['gpu_utilization']['p95']:.1f}%")
    print(f"  - P99:   {stats['gpu_utilization']['p99']:.1f}%")

    print("\nMemory Utilization:")
    print(f"  - Mean:  {stats['memory_utilization']['mean']:.1f}%")
    print(
        f"  - Range: {stats['memory_utilization']['min']:.1f}% - {stats['memory_utilization']['max']:.1f}%"
    )
    print(f"  - P95:   {stats['memory_utilization']['p95']:.1f}%")

    print("\nTemperature:")
    print(f"  - Mean: {stats['temperature']['mean']:.1f}°C")
    print(f"  - Max:  {stats['temperature']['max']}°C")
    print(
        f"  - Status: {stats['temperature']['status']} (threshold: {stats['temperature']['safe_threshold']}°C)"
    )

    print("\nPower Draw:")
    print(f"  - Mean: {stats['power_draw']['mean']:.1f}W")
    print(f"  - Max:  {stats['power_draw']['max']:.1f}W")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    print("=" * 70)
    print("  NVIDIA GPU Baseline Measurement - B-MAD Methodology")
    print("=" * 70)

    # Collect metrics
    metrics = measure_gpu_baseline(60)

    if not metrics:
        print("\n❌ Failed to collect metrics")
        exit(1)

    # Calculate statistics
    stats = calculate_statistics(metrics)

    # Generate report
    generate_report(stats, metrics)

    # Save detailed data
    output_data = {"statistics": stats, "raw_metrics": [asdict(m) for m in metrics]}

    output_file = "gpu_baseline_metrics.json"
    with open(output_file, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"\n✅ Baseline metrics saved to {output_file}")
    print("\n[B-MAD] Phase 2 (MEASURE) complete - Ready for Phase 3 (ANALYZE)")
