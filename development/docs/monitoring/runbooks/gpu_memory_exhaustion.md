# Alert Runbook: GPU Memory Exhaustion

## Alert Details

- **Alert Name**: GPUMemoryExhaustion
- **Severity**: Critical
- **Threshold**: GPU memory > 95%
- **Duration**: 2 minutes
- **Category**: Performance/Infrastructure

## Description

GPU memory usage has exceeded 95%, which can cause out-of-memory errors, failed model inference, or GPU driver crashes.

## Impact

- Failed GPU operations
- Model inference failures
- Application crashes
- Service degradation for GPU-dependent features
- Potential GPU driver instability

## Diagnosis

### Check GPU Memory Status

```bash
# Check NVIDIA GPU status
nvidia-smi

# Check GPU memory usage
nvidia-smi --query-gpu=memory.used,memory.free,memory.total --format=csv

# Monitor GPU processes
nvidia-smi pmon
```

### Check Application GPU Usage

```bash
# List processes using GPU
nvidia-smi --query-compute-apps=pid,name,used_memory --format=csv

# Check PyTorch GPU memory
docker exec catalytic-gpu python -c "import torch; print(torch.cuda.memory_summary())"
```

### Check for Memory Leaks

```bash
# Monitor GPU memory over time
watch -n 1 nvidia-smi

# Check application logs for GPU errors
docker logs catalytic-gpu --tail 200 | grep -i "cuda\|gpu\|memory"
```

## Resolution

### Immediate Actions

1. **Clear GPU Cache**
   ```python
   # In application
   import torch
   torch.cuda.empty_cache()
   ```

2. **Restart GPU Service**
   ```bash
   docker-compose restart gpu-service
   ```

3. **Kill Memory-Heavy Processes**
   ```bash
   # Identify heavy process
   nvidia-smi --query-compute-apps=pid,used_memory --format=csv

   # Kill specific process
   kill -9 <PID>
   ```

### Short-term Actions

1. **Optimize Model Loading**
   ```python
   # Use half precision
   model = model.half()  # FP16 instead of FP32

   # Enable gradient checkpointing
   model.gradient_checkpointing_enable()
   ```

2. **Implement Batch Size Reduction**
   ```python
   # Reduce batch size dynamically
   try:
       result = model(batch)
   except RuntimeError as e:
       if "out of memory" in str(e):
           torch.cuda.empty_cache()
           # Retry with smaller batch
           result = model(batch[:len(batch)//2])
   ```

3. **Clean Up Tensors**
   ```python
   # Delete unused tensors
   del large_tensor
   torch.cuda.empty_cache()

   # Use context managers
   with torch.no_grad():
       output = model(input)
   ```

### Long-term Actions

1. **Implement Model Quantization**
   ```python
   # Quantize model to reduce memory
   from torch.quantization import quantize_dynamic

   quantized_model = quantize_dynamic(
       model, {torch.nn.Linear}, dtype=torch.qint8
   )
   ```

2. **Use Model Parallelism**
   ```python
   # Split model across multiple GPUs
   model = torch.nn.DataParallel(model)
   ```

3. **Implement Memory Monitoring**
   ```python
   from prometheus_client import Gauge

   gpu_memory_gauge = Gauge('gpu_memory_used_bytes', 'GPU memory usage')

   def update_gpu_metrics():
       if torch.cuda.is_available():
           memory_allocated = torch.cuda.memory_allocated()
           gpu_memory_gauge.set(memory_allocated)
   ```

4. **Optimize Data Pipeline**
   ```python
   # Use data generators instead of loading all data
   # Implement prefetching
   # Use appropriate num_workers in DataLoader
   ```

## Prevention

1. **Set memory limits**
   ```python
   # Limit PyTorch memory allocation
   torch.cuda.set_per_process_memory_fraction(0.8)
   ```

2. **Implement proper cleanup**
   ```python
   # Always clear cache after batch processing
   torch.cuda.empty_cache()
   ```

3. **Use memory profiling**
   ```python
   # Profile memory usage
   from torch.profiler import profile, ProfilerActivity

   with profile(activities=[ProfilerActivity.CUDA]) as prof:
       model(input)

   print(prof.key_averages().table(sort_by="cuda_memory_usage"))
   ```

4. **Monitor GPU metrics**
   - GPU memory usage
   - GPU utilization
   - GPU temperature
   - CUDA errors

## Common Root Causes

- Memory leaks in model code
- Large batch sizes
- Model too large for GPU
- Not clearing intermediate tensors
- Multiple models loaded simultaneously
- No garbage collection of old tensors

## Escalation

- Level 1: On-call ML engineer
- Level 2: ML infrastructure team
- Level 3: CTO

## Related Alerts

- `HighCPUUsage`: Fallback to CPU when GPU OOM
- `HighMemoryUsage`: System memory also affected
- `HighErrorRate`: GPU failures cause API errors

## Additional Resources

- [PyTorch Memory Management]: https://pytorch.org/docs/stable/notes/cuda.html
- [NVIDIA GPU Monitoring]: https://developer.nvidia.com/nvidia-system-management-interface
- [GPU Logs]: `nvidia-smi dmon`

## Changelog

- 2025-10-06: Initial runbook creation
