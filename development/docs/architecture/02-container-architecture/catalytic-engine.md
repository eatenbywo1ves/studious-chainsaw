# Catalytic Engine Container

**C4 Model Level 2: Container Detail**

## Overview

The Catalytic Engine is the GPU-accelerated computing core of the platform, providing high-performance lattice operations with 649x speedup over CPU and 28,571x memory efficiency.

---

## Container Specifications

| Attribute | Value |
|-----------|-------|
| **Name** | Catalytic API |
| **Technology** | FastAPI (Python 3.11+), PyTorch, CuPy, Numba |
| **Port** | 8080 |
| **Protocol** | HTTP (REST API) |
| **GPU** | NVIDIA CUDA 12.1+ |
| **Replicas** | 2-10 (GPU-aware scaling) |
| **Image** | `catalytic/catalytic-api:latest` |

---

## Responsibilities

1. **GPU-Accelerated Computing**
   - Lattice structure operations (28,571x memory efficiency)
   - Batch processing with intelligent routing
   - Backend selection (PyTorch, CuPy, Numba, CPU fallback)

2. **Performance Optimization**
   - Memory-efficient data structures
   - Parallel processing across GPU cores
   - Result caching (Redis-backed)

3. **Computational Services**
   - Matrix operations (7.24 TFLOPS sustained)
   - Graph algorithms (iGraph integration)
   - Custom kernel execution (Numba JIT)

4. **Knowledge Acquisition (KA) Subsystem**
   - Lattice-based knowledge representation
   - Efficient storage and retrieval
   - Incremental learning support

---

## Technology Stack

### GPU Libraries

| Library | Version | Purpose | Performance |
|---------|---------|---------|-------------|
| **PyTorch** | 2.0+ | Deep learning, tensor ops | 7.24 TFLOPS |
| **CuPy** | 12.1+ | GPU NumPy replacement | 649x speedup |
| **Numba** | 0.57+ | JIT CUDA kernel compilation | Custom kernels |
| **iGraph** | 0.10.4 | Graph algorithms | CPU + GPU hybrid |

### Backend Selection Logic

```python
def select_backend(operation, data_size):
    if torch.cuda.is_available():
        if operation in ['matrix_mult', 'tensor_ops']:
            return 'pytorch'  # Best for deep learning ops
        elif operation in ['array_ops', 'fft', 'linalg']:
            return 'cupy'     # Best for NumPy-like ops
        elif operation in ['custom_kernel', 'specialized']:
            return 'numba'    # Best for custom CUDA kernels
    return 'cpu'  # Fallback
```

---

## Key Dependencies

### Internal Dependencies

| Dependency | Purpose | Protocol |
|------------|---------|----------|
| Redis | Result caching, job queue | TCP/6379 |
| (Optional) PostgreSQL | Persistent results storage | TCP/5432 |

### Hardware Dependencies

| Component | Requirement | Recommended |
|-----------|-------------|-------------|
| **GPU** | NVIDIA CUDA 12.1+ | RTX 3090 / A100 |
| **VRAM** | 8 GB minimum | 24+ GB |
| **CPU** | 8 cores | 16+ cores |
| **RAM** | 32 GB | 64+ GB |

---

## API Endpoints Summary

### Compute (`/compute/*`)
```
POST /compute/lattice    - Execute lattice operation
POST /compute/batch      - Batch processing
POST /compute/matrix     - Matrix operations
GET  /compute/status/{id} - Job status
GET  /compute/result/{id} - Retrieve result
```

### System (`/system/*`)
```
GET  /system/gpu         - GPU status and utilization
GET  /system/backends    - Available compute backends
GET  /system/memory      - Memory usage (GPU + CPU)
```

### Health (`/health/*`)
```
GET  /health             - Basic health
GET  /health/gpu         - GPU health and CUDA status
GET  /health/ready       - Readiness (GPU + Redis)
```

---

## Configuration

### Environment Variables

```bash
# GPU Configuration
CUDA_VISIBLE_DEVICES=0,1        # GPUs to use
PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:512

# Backend Selection
DEFAULT_BACKEND=pytorch         # pytorch, cupy, numba, cpu
ENABLE_MIXED_PRECISION=true     # FP16 for memory savings

# Redis (caching)
REDIS_URL=redis://redis:6379/1
RESULT_CACHE_TTL=3600           # 1 hour

# Performance
BATCH_SIZE=1024
MAX_CONCURRENT_JOBS=10
MEMORY_LIMIT_GB=20              # GPU memory limit
```

### Docker Compose Configuration

```yaml
catalytic_api:
  image: catalytic/catalytic-api:latest
  ports:
    - "8080:8080"
  environment:
    - CUDA_VISIBLE_DEVICES=0
    - DEFAULT_BACKEND=pytorch
  depends_on:
    - redis
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: 1
            capabilities: [gpu]
      limits:
        cpus: '8'
        memory: 32G
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8080/health/gpu"]
    interval: 30s
    timeout: 10s
    retries: 3
```

---

## Performance Characteristics

### Benchmark Results

| Operation | CPU Baseline | GPU (CuPy) | Speedup |
|-----------|--------------|------------|---------|
| Matrix Multiply (4096x4096) | 12.5s | 19ms | 658x |
| FFT (1M points) | 2.1s | 4.2ms | 500x |
| Element-wise ops (100M) | 850ms | 1.3ms | 654x |
| Graph traversal (1M nodes) | 45s | 120ms | 375x |

### Memory Efficiency

| Structure | Traditional | Lattice | Compression |
|-----------|-------------|---------|-------------|
| Sparse matrix (1M x 1M) | 8 GB | 280 KB | 28,571x |
| Knowledge graph (10M edges) | 2.4 GB | 45 MB | 53x |
| Time series (1B points) | 8 GB | 12 MB | 667x |

### Throughput

| Metric | Value |
|--------|-------|
| **Sustained TFLOPS** | 7.24 (FP32) |
| **Peak TFLOPS** | 35.6 (FP16 tensor cores) |
| **Memory Bandwidth** | 936 GB/s (A100) |
| **Ops per Second** | 10,000+ lattice ops |

---

## Scaling Strategy

### GPU-Aware Scaling

```yaml
# Kubernetes with GPU
apiVersion: apps/v1
kind: Deployment
metadata:
  name: catalytic-api
spec:
  replicas: 2  # Start with 2 GPU pods
  template:
    spec:
      containers:
      - name: catalytic-api
        resources:
          limits:
            nvidia.com/gpu: 1  # 1 GPU per pod
```

### Multi-GPU Support

```python
# Automatic device placement
if torch.cuda.device_count() > 1:
    model = nn.DataParallel(model)
    # or
    model = nn.DistributedDataParallel(model)
```

### Caching Strategy

- **Result Cache**: Redis with 1-hour TTL
- **Model Cache**: In-memory (loaded on startup)
- **Data Cache**: GPU memory LRU eviction

---

## Monitoring

### Prometheus Metrics

```python
# GPU metrics exposed at /metrics
gpu_utilization_percent        # Gauge: GPU core utilization
gpu_memory_used_bytes          # Gauge: VRAM usage
gpu_memory_total_bytes         # Gauge: Total VRAM
gpu_temperature_celsius        # Gauge: GPU temperature
lattice_operations_total       # Counter: ops processed
lattice_operation_duration_seconds  # Histogram: op latency
compute_backend_usage          # Counter: by backend type
batch_size_histogram           # Histogram: batch sizes
```

### GPU Health Endpoint

```bash
GET /health/gpu
{
  "status": "healthy",
  "cuda_available": true,
  "cuda_version": "12.1",
  "gpu_count": 1,
  "gpus": [
    {
      "id": 0,
      "name": "NVIDIA RTX 3090",
      "memory_total_gb": 24.0,
      "memory_used_gb": 8.5,
      "utilization_percent": 45,
      "temperature_c": 62
    }
  ]
}
```

### Alerting Rules

```yaml
# Critical: GPU memory > 90%
- alert: CatalyticGPUMemoryHigh
  expr: gpu_memory_used_bytes / gpu_memory_total_bytes > 0.9
  for: 5m
  labels:
    severity: critical

# Warning: GPU utilization < 20% (underutilized)
- alert: CatalyticGPUUnderutilized
  expr: gpu_utilization_percent < 20
  for: 30m
  labels:
    severity: warning

# Critical: GPU temperature > 85C
- alert: CatalyticGPUOverheating
  expr: gpu_temperature_celsius > 85
  for: 2m
  labels:
    severity: critical
```

---

## Disaster Recovery

### Stateless Design
- No persistent state in container
- All results cached in Redis (optional)
- Jobs can be resubmitted on failure

### GPU Failure Handling
```python
try:
    result = gpu_operation(data)
except torch.cuda.OutOfMemoryError:
    torch.cuda.empty_cache()
    result = cpu_fallback(data)  # Graceful degradation
```

### Recovery Time
- **RTO**: 5 minutes (GPU driver initialization)
- **RPO**: 0 (stateless, jobs can be retried)

---

## Related Documentation

- [Container Overview](container-overview.md)
- [GPU Acceleration Diagram](../03-component-architecture/gpu-acceleration.puml)
- [PyTorch ADR](../10-adrs/004-pytorch-gpu-acceleration.md)
- [CuPy ADR](../10-adrs/012-cupy-gpu-numpy.md)
- [Numba ADR](../10-adrs/015-numba-jit-compilation.md)
- [Performance Metrics](../09-quality-attributes/performance.md)

---

**Last Updated**: November 2025
