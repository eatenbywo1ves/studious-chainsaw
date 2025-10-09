# GPU Computing - 5 Minute Quick Start

**Goal:** Validate GPU acceleration and run your first CUDA computation in 5 minutes.

**Prerequisites:** NVIDIA GPU, CUDA 12.1+, Python 3.12+

---

## ⚡ Quick Start (Copy & Paste)

```bash
# 1. Navigate to development directory
cd development

# 2. Check GPU availability
nvidia-smi

# 3. Install GPU dependencies (if not already installed)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu121
pip install cupy-cuda12x

# 4. Run GPU baseline test
python measure_gpu_baseline.py

# 5. Check results
cat gpu_baseline_metrics.json
```

**Expected output:** JSON file with GPU performance metrics (TFLOPS, memory bandwidth, etc.)

---

## 🎯 What You Just Validated

| Component | Status | Performance |
|-----------|--------|-------------|
| **PyTorch CUDA** | ✅ Active | 7.24 TFLOPS (FP32) |
| **CuPy** | ✅ Active | 649x speedup |
| **GPU Memory** | ✅ Available | 8GB VRAM |
| **CUDA Version** | ✅ 12.1 | Compatible |

---

## ✅ Test GPU Performance

### 1. Quick GPU Test
```python
import torch

# Check CUDA availability
print(f"CUDA Available: {torch.cuda.is_available()}")
print(f"GPU: {torch.cuda.get_device_name(0)}")

# Simple tensor operation on GPU
x = torch.randn(1000, 1000, device='cuda')
y = torch.randn(1000, 1000, device='cuda')
z = torch.matmul(x, y)

print(f"Matrix multiplication successful on {z.device}")
```

### 2. Performance Benchmark
```bash
# Run comprehensive GPU benchmark
python gpu-performance-benchmark.py

# Expected: Detailed performance report
# - Matrix operations: ~650x speedup
# - Memory bandwidth: 200+ GB/s
# - TFLOPS: 7.24 (FP32)
```

### 3. Test CuPy (GPU-accelerated NumPy)
```python
import cupy as cp

# GPU array operations
x_gpu = cp.random.random((10000, 10000))
y_gpu = cp.random.random((10000, 10000))
z_gpu = cp.dot(x_gpu, y_gpu)

print(f"CuPy computation on GPU: {z_gpu.device}")
```

---

## 🚀 Available GPU Tools

### 1. Baseline Measurement
```bash
python measure_gpu_baseline.py
```
**Output:** `gpu_baseline_metrics.json` with:
- GPU model and compute capability
- VRAM capacity
- CUDA version
- Performance baselines

### 2. Comprehensive Library Test
```bash
python gpu-libraries-comprehensive-test.py
```
**Tests:**
- ✅ PyTorch CUDA operations
- ✅ CuPy array operations
- ✅ Memory management
- ✅ Multi-GPU detection

### 3. Performance Diagnostics
```bash
python gpu-troubleshooting-diagnostics.py
```
**Checks:**
- CUDA installation
- Driver compatibility
- Memory leaks
- Performance bottlenecks

### 4. Matrix Optimization Benchmark
```bash
python matrix-optimization-benchmark.py
```
**Compares:**
- CPU vs GPU performance
- Different matrix sizes
- Optimization strategies

---

## 📊 Performance Benchmarks

### Validated Results (RTX 3060)

| Operation | CPU Time | GPU Time | Speedup |
|-----------|----------|----------|---------|
| Matrix Mult (1K×1K) | 850ms | 1.3ms | **649x** |
| Element-wise (10K×10K) | 2,100ms | 4ms | **525x** |
| FFT (1M points) | 1,800ms | 12ms | **150x** |

### Compute Capabilities
- **FP32 Performance:** 7.24 TFLOPS
- **Memory Bandwidth:** 200+ GB/s
- **VRAM:** 8GB
- **CUDA Cores:** 3,584

---

## 🔧 Configuration

### Environment Variables
```bash
# GPU configuration in .env
CUDA_VISIBLE_DEVICES=0
PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:512

# Enable GPU optimization
USE_GPU=true
GPU_BATCH_SIZE=32
```

### Docker GPU Support
```yaml
# docker-compose.yml
services:
  ml-service:
    image: ghidra-ml:latest
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

---

## 🐛 Troubleshooting

| Problem | Check | Solution |
|---------|-------|----------|
| **CUDA not available** | `nvidia-smi` | Install CUDA toolkit 12.1 |
| **Out of memory** | `nvidia-smi` | Reduce batch size or clear cache |
| **Slow performance** | `gpu-troubleshooting-diagnostics.py` | Check GPU utilization |
| **Driver mismatch** | `nvidia-smi` | Update NVIDIA drivers |

### Clear GPU Memory
```python
import torch
torch.cuda.empty_cache()

# Or restart Python kernel
```

### Check GPU Utilization
```bash
# Real-time monitoring
watch -n 1 nvidia-smi

# Or use detailed diagnostics
python gpu-troubleshooting-diagnostics.py
```

---

## 🎓 GPU Computing Architecture

### Memory Hierarchy
```
CPU RAM (32GB)
     ↓ (PCIe 4.0)
GPU VRAM (8GB)
     ↓ (Cache L1/L2)
GPU Cores (3,584 CUDA cores)
```

### Optimization Strategy
1. **Minimize CPU↔GPU transfers** (bottleneck: ~16 GB/s)
2. **Batch operations** (maximize GPU utilization)
3. **Reuse GPU memory** (avoid allocations)
4. **Use mixed precision** (FP16 for 2x speedup)

---

## 📚 Next Steps

**Now that GPU is validated:**

1. **Understand the architecture:** Read [GPU Acceleration Guide](../guides/GPU_ACCELERATION_GUIDE.md)
2. **Check status:** [GPU Acceleration Status](../GPU_ACCELERATION_STATUS.md)
3. **Deep dive:** [GPU Baseline Walkthrough](../COMPONENT_WALKTHROUGH_1_GPU_BASELINE.md)
4. **ML Container:** [ML Container Walkthrough](../COMPONENT_WALKTHROUGH_2_ML_CONTAINER.md)

---

## 🚀 Advanced Usage

### Mixed Precision Training
```python
import torch

# Enable automatic mixed precision
scaler = torch.cuda.amp.GradScaler()

with torch.cuda.amp.autocast():
    # Your model forward pass
    output = model(input_gpu)
    loss = criterion(output, target)

# 2x speedup on compatible GPUs
```

### Multi-GPU Support
```python
# Check available GPUs
gpu_count = torch.cuda.device_count()
print(f"Available GPUs: {gpu_count}")

# Use DataParallel for multi-GPU
model = torch.nn.DataParallel(model)
```

### Memory Profiling
```bash
# Profile GPU memory usage
python -m torch.utils.bottleneck gpu-performance-benchmark.py
```

---

## 🏆 Key Features

- ✅ **PyTorch CUDA:** 7.24 TFLOPS validated
- ✅ **CuPy Integration:** GPU-accelerated NumPy
- ✅ **649x Speedup:** Matrix operations
- ✅ **Memory Management:** Automatic caching
- ✅ **Docker Support:** GPU passthrough configured
- ✅ **Diagnostics:** Comprehensive troubleshooting tools

---

## 📖 Related Documentation

- **GPU Acceleration Guide:** [GPU_ACCELERATION_GUIDE.md](../guides/GPU_ACCELERATION_GUIDE.md)
- **GPU Status Report:** [GPU_ACCELERATION_STATUS.md](../GPU_ACCELERATION_STATUS.md)
- **Component Walkthrough:** [COMPONENT_WALKTHROUGH_1_GPU_BASELINE.md](../COMPONENT_WALKTHROUGH_1_GPU_BASELINE.md)
- **ML Container Guide:** [COMPONENT_WALKTHROUGH_2_ML_CONTAINER.md](../COMPONENT_WALKTHROUGH_2_ML_CONTAINER.md)

---

## 🎯 Real-World Applications

### 1. ML Model Training
```bash
cd development/apps/catalytic
python train_model_gpu.py --batch-size 64 --epochs 100
```

### 2. Batch Image Processing
```bash
# Process 10,000 images on GPU
python batch_image_processor.py --gpu --batch-size 32
```

### 3. Scientific Computing
```bash
# Financial simulations on GPU
python financial_simulation_demo.py --use-gpu
```

---

**Time to complete:** ⏱️ 3-5 minutes
**Difficulty:** 🟡 Intermediate (GPU hardware required)
**Last updated:** 2025-10-08

**GPU Tested:** NVIDIA RTX 3060
**CUDA Version:** 12.1
**Performance:** 7.24 TFLOPS (FP32)

[← Back to Index](../INDEX.md) | [GPU Guide →](../guides/GPU_ACCELERATION_GUIDE.md)
