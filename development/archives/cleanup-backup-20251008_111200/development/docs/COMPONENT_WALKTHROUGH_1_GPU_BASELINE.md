# Component Walkthrough #1: GPU Baseline Measurement
## B-MAD Phase 2: Establishing Performance Baselines

**Purpose:** Collect GPU performance metrics to establish baseline for ML workload optimization
**Complexity:** Beginner
**Time:** 10 minutes
**Prerequisites:** Docker with GPU support, NVIDIA driver installed

---

## Overview

The GPU baseline measurement component establishes performance benchmarks **before** deploying ML workloads. This follows the B-MAD methodology's "Measure" phase, providing data for comparison during the "Analyze" phase.

### Why This Matters

Without baseline metrics, you cannot:
- Detect performance regressions
- Identify GPU bottlenecks
- Validate ML acceleration claims
- Troubleshoot thermal issues
- Plan capacity for multi-tenant deployments

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Host System (Windows)                   │
│                                                           │
│  ┌────────────────────────────────────────────────┐     │
│  │   measure_gpu_baseline.py                       │     │
│  │   (Python Script)                               │     │
│  └──────────────┬──────────────────────────────────┘     │
│                 │                                         │
│                 │ Spawns Docker containers               │
│                 ▼                                         │
│  ┌────────────────────────────────────────────────┐     │
│  │   Docker: nvidia/cuda:12.3.1-base              │     │
│  │                                                 │     │
│  │   nvidia-smi --query-gpu=...                   │     │
│  │   (GPU metrics query)                          │     │
│  └──────────────┬──────────────────────────────────┘     │
│                 │                                         │
│                 │ GPU Metrics (CSV)                       │
│                 ▼                                         │
│  ┌────────────────────────────────────────────────┐     │
│  │   GPUMetrics Dataclass                         │     │
│  │   - timestamp                                  │     │
│  │   - gpu_util (%)                               │     │
│  │   - memory_used (MB)                           │     │
│  │   - temperature (°C)                           │     │
│  │   - power_draw (W)                             │     │
│  └──────────────┬──────────────────────────────────┘     │
│                 │                                         │
│                 │ Aggregation                             │
│                 ▼                                         │
│  ┌────────────────────────────────────────────────┐     │
│  │   Statistics Calculator                        │     │
│  │   - Mean, Min, Max                             │     │
│  │   - Percentiles (P50, P95, P99)                │     │
│  │   - Safety checks (temp threshold)             │     │
│  └──────────────┬──────────────────────────────────┘     │
│                 │                                         │
│                 │ JSON Export                             │
│                 ▼                                         │
│  ┌────────────────────────────────────────────────┐     │
│  │   gpu_baseline_metrics.json                    │     │
│  │   {                                            │     │
│  │     "statistics": {...},                       │     │
│  │     "raw_metrics": [...]                       │     │
│  │   }                                            │     │
│  └────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────┘
```

---

## Implementation Walkthrough

### Step 1: Understanding the Measurement Strategy

**Question:** Why use Docker containers for GPU metrics instead of native nvidia-smi?

**Answer:** Cross-platform compatibility. On Windows:
- Native `nvidia-smi` works, but requires different path handling
- Docker approach is **identical** on Windows, Linux, and macOS
- Validates GPU passthrough works correctly (critical for ML deployment)
- Simulates actual ML workload environment

**Trade-off:** Slightly slower (2-3s per sample vs <1s native), but more reliable for production validation.

---

### Step 2: Code Walkthrough - Data Collection Loop

```python
# File: measure_gpu_baseline.py (lines 18-57)

def measure_gpu_baseline(duration_seconds: int = 60) -> List[GPUMetrics]:
    """Measure GPU performance baseline for B-MAD analysis."""

    metrics = []
    start_time = time.time()

    print(f"[MEASURE] Collecting GPU baseline metrics for {duration_seconds} seconds...")

    while time.time() - start_time < duration_seconds:
        try:
            # Query NVIDIA SMI via Docker (works on Windows)
            result = subprocess.run([
                'docker', 'run', '--rm', '--gpus', 'all',
                'nvidia/cuda:12.3.1-base-ubuntu22.04',
                'nvidia-smi',
                '--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw',
                '--format=csv,noheader,nounits'
            ], capture_output=True, text=True, timeout=10)
```

**Key Design Decisions:**

1. **`--rm` flag**: Containers are ephemeral, self-cleaning
   - Prevents Docker volume exhaustion
   - No manual cleanup needed

2. **`--gpus all` flag**: Requests GPU access
   - On Windows Docker Desktop, this triggers NVIDIA runtime
   - Validates GPU passthrough is functional

3. **`--query-gpu` parameters**: Specific metrics only
   - `utilization.gpu`: Compute engine usage (0-100%)
   - `memory.used/total`: VRAM allocation
   - `temperature.gpu`: Thermal monitoring
   - `power.draw`: Power consumption (important for cost/thermal)

4. **`--format=csv,noheader,nounits`**: Machine-readable output
   - Easy parsing (no regex needed)
   - Deterministic structure

**Example Output:**
```
0, 3274, 8192, 61, 36.5
```
Translates to:
- 0% GPU utilization (idle)
- 3274 MB memory used
- 8192 MB total memory
- 61°C temperature
- 36.5W power draw

---

### Step 3: Statistical Analysis

```python
# File: measure_gpu_baseline.py (lines 77-118)

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
        'gpu_utilization': {
            'mean': sum(gpu_utils) / len(gpu_utils),
            'min': min(gpu_utils),
            'max': max(gpu_utils),
            'p50': percentile(gpu_utils, 0.50),  # Median
            'p95': percentile(gpu_utils, 0.95),  # 95th percentile
            'p99': percentile(gpu_utils, 0.99)   # 99th percentile
        },
        # ... (temperature, memory, power stats)
    }
```

**Why Percentiles Matter:**

| Metric | Use Case |
|--------|----------|
| **Mean** | Average performance (can be misleading with outliers) |
| **P50 (Median)** | Typical performance (50% of samples below this) |
| **P95** | Performance guarantee for 95% of requests (SLA target) |
| **P99** | Worst-case excluding extreme outliers (critical for latency) |

**Example:** If P95 GPU utilization is 75%, it means:
- 95% of the time, GPU is ≤75% utilized
- Only 5% of samples exceed 75% (potential bottleneck)

**B-MAD Application:**
- **Measure:** Baseline P95 = 5% (mostly idle)
- **Analyze:** ML workload P95 = 85% (good utilization)
- **Deploy:** Set alert threshold at 90% (allow headroom)

---

### Step 4: Safety Checks

```python
'temperature': {
    'mean': sum(temps) / len(temps),
    'min': min(temps),
    'max': max(temps),
    'safe_threshold': 85,  # NVIDIA recommended
    'status': 'SAFE' if max(temps) < 85 else 'WARNING'
}
```

**NVIDIA GPU Temperature Guidelines:**

| Temp Range | Status | Action |
|------------|--------|--------|
| < 65°C | ✅ Excellent | No action needed |
| 65-75°C | ✅ Good | Normal operation |
| 75-85°C | ⚠️ Warm | Monitor cooling |
| 85-95°C | ❌ Hot | Reduce load, check fans |
| > 95°C | 🔥 Critical | Immediate shutdown risk |

**Our Baseline:** 61°C (Excellent)
- 24°C below safety threshold
- Plenty of thermal headroom for ML workloads
- GPU fans likely at low speed (quiet operation)

---

### Step 5: Data Export and Persistence

```python
# File: measure_gpu_baseline.py (lines 180-191)

output_data = {
    'statistics': stats,
    'raw_metrics': [asdict(m) for m in metrics]
}

output_file = 'gpu_baseline_metrics.json'
with open(output_file, 'w') as f:
    json.dump(output_data, f, indent=2)
```

**Why Save Both Statistics AND Raw Metrics?**

1. **Statistics** - For quick comparison
   - Used by deployment scripts to validate performance
   - Displayed in dashboards

2. **Raw Metrics** - For deep analysis
   - Time-series visualization
   - Identifying periodic patterns (e.g., thermal throttling)
   - Post-hoc analysis (e.g., "What happened at 21:35?")

**File Structure:**
```json
{
  "statistics": {
    "measurement_info": {
      "duration_seconds": 34,
      "sample_count": 17,
      "timestamp": "2025-10-06T21:41:46.294765"
    },
    "gpu_utilization": {
      "mean": 0.0,
      "p95": 0.0,
      "p99": 0.0
    },
    "temperature": {
      "max": 61,
      "status": "SAFE"
    }
  },
  "raw_metrics": [
    {
      "timestamp": 1728251466.1,
      "gpu_util": 0.0,
      "memory_used": 3274,
      "temperature": 61,
      "power_draw": 36.5
    },
    // ... 16 more samples
  ]
}
```

---

## Running the Component

### Basic Execution

```bash
cd C:/Users/Corbin/development
python measure_gpu_baseline.py
```

**Expected Output:**
```
======================================================================
  NVIDIA GPU Baseline Measurement - B-MAD Methodology
======================================================================
[MEASURE] Collecting GPU baseline metrics for 60 seconds...
[MEASURE] Progress: 5/60s | GPU: 0.0% | Mem: 40.0% | Temp: 61°C
[MEASURE] Progress: 10/60s | GPU: 0.0% | Mem: 40.0% | Temp: 61°C
...
======================================================================
  GPU BASELINE MEASUREMENT REPORT - B-MAD Phase 2
======================================================================

Measurement Info:
  - Duration: 60s
  - Samples: 30
  - Timestamp: 2025-10-06T21:41:46.294765

GPU Utilization:
  - Mean:  0.0%
  - P95:   0.0%

Temperature:
  - Max: 61°C
  - Status: SAFE (threshold: 85°C)

======================================================================

✅ Baseline metrics saved to gpu_baseline_metrics.json
```

---

### Advanced: Custom Duration

```bash
# Short test (30 seconds)
python -c "
from measure_gpu_baseline import measure_gpu_baseline, calculate_statistics
metrics = measure_gpu_baseline(30)
stats = calculate_statistics(metrics)
print(f'P95 GPU Util: {stats[\"gpu_utilization\"][\"p95\"]:.1f}%')
"

# Extended monitoring (5 minutes)
python -c "
from measure_gpu_baseline import measure_gpu_baseline
measure_gpu_baseline(300)  # 5 minutes = 150 samples @ 2s interval
"
```

---

## Interpreting Results

### Scenario 1: Idle Baseline (Expected)

```json
{
  "gpu_utilization": {
    "mean": 0.0,
    "p95": 0.0
  },
  "memory_utilization": {
    "mean": 40.0
  }
}
```

**Interpretation:**
- ✅ GPU is idle (good baseline)
- ✅ 40% memory = system overhead (drivers, desktop)
- ✅ ~60% memory available for ML workloads

**Action:** Proceed to ML deployment

---

### Scenario 2: Unexpected Load

```json
{
  "gpu_utilization": {
    "mean": 45.0,
    "max": 95.0
  },
  "temperature": {
    "max": 82
  }
}
```

**Interpretation:**
- ❌ GPU not idle (another process using GPU)
- ⚠️ Temperature elevated but safe

**Action:** Investigate running processes
```bash
# Check GPU processes
nvidia-smi

# Or via Docker
docker run --rm --gpus all nvidia/cuda:12.3.1-base-ubuntu22.04 nvidia-smi
```

**Common Culprits:**
- Chrome with hardware acceleration
- Video editing software
- Cryptocurrency miners
- Another ML workload

---

### Scenario 3: Thermal Warning

```json
{
  "temperature": {
    "max": 87,
    "status": "WARNING"
  }
}
```

**Interpretation:**
- ❌ GPU running hot even at idle
- Possible dust buildup or fan failure

**Action:**
1. Check GPU fans: `nvidia-smi --query-gpu=fan.speed --format=csv`
2. Clean GPU (compressed air)
3. Verify case airflow
4. Consider additional cooling before ML deployment

---

## Integration with B-MAD Methodology

### How This Component Fits

```
B-MAD Flow:
┌─────────────────────────────────────────────────┐
│ 1. BUILD                                        │
│    - Install NVIDIA driver                      │
│    - Configure Docker GPU support               │
│    └─> Prerequisites for measurement            │
└──────────────┬──────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│ 2. MEASURE ◄── YOU ARE HERE                    │
│    - Run measure_gpu_baseline.py                │
│    - Collect performance baselines              │
│    - Validate thermal safety                    │
│    └─> Creates: gpu_baseline_metrics.json       │
└──────────────┬──────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│ 3. ANALYZE                                      │
│    - Compare ML workload vs baseline            │
│    - Identify performance improvements          │
│    - Validate GPU acceleration claims           │
│    └─> Input: gpu_baseline_metrics.json         │
└──────────────┬──────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│ 4. DEPLOY                                       │
│    - Use baselines for alerting thresholds      │
│    - Monitor for performance regressions        │
│    └─> Reference: gpu_baseline_metrics.json     │
└─────────────────────────────────────────────────┘
```

---

## Troubleshooting

### Error: "nvidia-smi: command not found"

**Inside Docker container:**

```
docker: Error response from daemon: could not select device driver "" with capabilities: [[gpu]]
```

**Cause:** Docker GPU support not configured

**Fix:**
```bash
# Verify NVIDIA runtime exists
docker info | grep -i runtime

# Should show:
# Runtimes: nvidia runc

# If missing, restart Docker Desktop
```

---

### Error: "CUDA_VISIBLE_DEVICES" not working

**Symptom:** GPU metrics show all GPUs instead of specific GPU

**Cause:** Docker Desktop ignores CUDA_VISIBLE_DEVICES in some versions

**Fix:** Use `--gpus` device specification:
```bash
docker run --rm --gpus device=0 nvidia/cuda:12.3.1-base-ubuntu22.04 nvidia-smi
```

---

### Error: Timeout after 10 seconds

**Symptom:**
```
subprocess.TimeoutExpired: Command '['docker', 'run', ...]' timed out after 10 seconds
```

**Cause:** First container launch downloads image

**Fix:** Pre-pull image:
```bash
docker pull nvidia/cuda:12.3.1-base-ubuntu22.04

# Then re-run measurement script
python measure_gpu_baseline.py
```

---

## Production Considerations

### Automated Monitoring

Integrate into CI/CD for performance regression detection:

```yaml
# .github/workflows/gpu-benchmark.yml
name: GPU Performance Baseline

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

jobs:
  gpu-baseline:
    runs-on: self-hosted-gpu
    steps:
      - name: Measure GPU Baseline
        run: python measure_gpu_baseline.py

      - name: Compare to Previous Baseline
        run: |
          python -c "
          import json
          current = json.load(open('gpu_baseline_metrics.json'))
          previous = json.load(open('baselines/previous.json'))

          current_p95 = current['statistics']['gpu_utilization']['p95']
          previous_p95 = previous['statistics']['gpu_utilization']['p95']

          if abs(current_p95 - previous_p95) > 5.0:
              print(f'⚠️ GPU utilization changed: {previous_p95}% → {current_p95}%')
              exit(1)
          "
```

---

### Multi-GPU Environments

Modify script for per-GPU baselines:

```python
# Get GPU count
gpu_count = torch.cuda.device_count()

for gpu_id in range(gpu_count):
    metrics = measure_gpu_baseline_single(gpu_id, duration=60)

    with open(f'gpu_{gpu_id}_baseline.json', 'w') as f:
        json.dump(metrics, f, indent=2)
```

---

## Summary

**What We Built:**
- GPU performance measurement tool using Docker + nvidia-smi
- Statistical analysis with percentiles (P50, P95, P99)
- Safety checks for thermal thresholds
- JSON export for analysis and monitoring

**Key Takeaways:**
1. **Always measure before optimization** - Baseline prevents premature optimization
2. **Percentiles > Averages** - P95/P99 reveal true performance characteristics
3. **Thermal monitoring is critical** - GPU throttling can silently degrade performance
4. **Raw data + statistics** - Both are needed for comprehensive analysis

**Next Steps:**
- Proceed to Component #2: ML Container Image
- Use baseline metrics to validate ML acceleration
- Integrate into deployment monitoring

---

**Component Status:** ✅ Complete
**B-MAD Phase:** 2 (Measure)
**Files Created:** `measure_gpu_baseline.py`, `gpu_baseline_metrics.json`
**Time Investment:** 10 minutes
**ROI:** Critical for performance validation and troubleshooting
