# NVIDIA GPU Deployment - Complete Implementation Guide
## Component Walkthroughs for B-MAD Methodology

**Created:** October 6, 2025
**Status:** Ready for Execution
**Deployment Progress:** 75% Complete (Build & Measure phases done, Analyze & Deploy in progress)

---

## 📚 Documentation Structure

This implementation guide provides **step-by-step walkthroughs** for each component of the NVIDIA GPU deployment. Each walkthrough is self-contained and can be executed independently.

```
Implementation Guide
├── Component #1: GPU Baseline Measurement
│   ├── Purpose: Establish performance baselines
│   ├── Complexity: Beginner
│   ├── Time: 10 minutes
│   └── Status: ✅ COMPLETE
│
├── Component #2: ML Container Image
│   ├── Purpose: Build secure GPU-enabled container
│   ├── Complexity: Intermediate
│   ├── Time: 30-45 minutes
│   └── Status: 🔄 IN PROGRESS (building)
│
├── Component #3: Secure Deployment
│   ├── Purpose: Production deployment with CVE mitigation
│   ├── Complexity: Advanced
│   ├── Time: 20 minutes
│   └── Status: ⏳ READY (awaiting container build)
│
└── Component #4: Integration & Validation (Coming Soon)
    ├── Purpose: Wiz competition validation & Ghidra integration
    ├── Complexity: Advanced
    ├── Time: 30 minutes
    └── Status: ⏳ PENDING
```

---

## 🎯 Component #1: GPU Baseline Measurement

**File:** `COMPONENT_WALKTHROUGH_1_GPU_BASELINE.md`

### What You'll Learn

1. **Architecture:** How GPU metrics are collected via Docker containers
2. **Statistical Analysis:** Understanding percentiles (P50, P95, P99) for performance
3. **Safety Checks:** NVIDIA thermal guidelines and threshold management
4. **B-MAD Integration:** How baseline metrics feed into the Analyze phase

### Key Concepts Covered

```
Topics:
├── Cross-platform GPU measurement (Docker-based approach)
├── Statistical methods for performance analysis
├── Thermal safety thresholds (85°C safe limit)
├── Data persistence (JSON export for analysis)
└── Troubleshooting GPU access issues
```

### Practical Skills

| Skill | Application | Difficulty |
|-------|-------------|------------|
| **Docker GPU access** | Validate GPU passthrough works | Beginner |
| **Python subprocess** | Execute Docker commands programmatically | Beginner |
| **Statistical analysis** | Calculate percentiles from time-series data | Intermediate |
| **Performance benchmarking** | Establish baselines for comparison | Intermediate |

### Walkthrough Highlights

**Section 1:** Why use Docker for GPU metrics?
- **Answer:** Cross-platform compatibility (Windows/Linux/macOS identical)
- **Trade-off:** Slightly slower (2-3s per sample) but validates GPU passthrough

**Section 2:** Code walkthrough of data collection loop
- nvidia-smi query parameters explained
- CSV parsing strategy (no regex needed)
- Timeout handling for first container launch

**Section 3:** Statistical analysis implementation
- Percentile calculation (P50, P95, P99)
- Why percentiles matter for SLA guarantees
- B-MAD application: Measure → Analyze → Deploy thresholds

**Section 4:** Safety checks and thermal monitoring
- NVIDIA temperature guidelines (< 65°C excellent, 85°C threshold)
- Our baseline: 61°C (24°C below safety limit)
- Thermal headroom calculation for ML workloads

**Section 5:** Troubleshooting common issues
- "nvidia-smi: command not found" → GPU support not configured
- Timeout errors → Pre-pull Docker image
- Unexpected load → Identify GPU-using processes

### Success Criteria

After completing this walkthrough, you will:
- ✅ Understand Docker-based GPU measurement strategy
- ✅ Calculate performance percentiles (P50, P95, P99)
- ✅ Validate GPU thermal safety (< 85°C)
- ✅ Have baseline metrics saved: `gpu_baseline_metrics.json`

### Files Created

```
development/
├── measure_gpu_baseline.py         (252 lines, Python script)
└── gpu_baseline_metrics.json       (4.6KB, baseline data)
```

---

## 🐳 Component #2: ML Container Image Architecture

**File:** `COMPONENT_WALKTHROUGH_2_ML_CONTAINER.md`

### What You'll Learn

1. **Architecture Decision Trees:** Choosing base images, Python installation methods, PyTorch variants
2. **Security Hardening:** Non-root users, capability dropping, CVE mitigation
3. **Layer Optimization:** Docker build caching strategies
4. **Health Checks:** GPU validation via Python assertions

### Key Concepts Covered

```
Topics:
├── Dockerfile layer caching optimization
├── CUDA compatibility (12.3 base → 12.1 PyTorch)
├── Non-root user creation (UID 1000)
├── PyTorch GPU vs CPU builds (--index-url critical!)
├── Health check implementation for GPU validation
└── Security labels for CVE documentation
```

### Practical Skills

| Skill | Application | Difficulty |
|-------|-------------|------------|
| **Docker layer caching** | Optimize build times (30min → 1min) | Intermediate |
| **CUDA version compatibility** | Match driver/runtime/toolkit versions | Intermediate |
| **Security hardening** | Non-root users, minimal attack surface | Advanced |
| **PyTorch installation** | GPU builds via index URLs | Intermediate |
| **Health checks** | Automated GPU validation | Beginner |

### Walkthrough Highlights

**Section 1:** Architecture decision tree
- **Base image:** `cuda:*-base` vs `cuda:*-devel` vs `cuda:*-runtime`
- **Python:** APT packages vs Conda (size/speed trade-offs)
- **PyTorch:** pip vs conda vs build-from-source (30min vs 2hr)

**Section 2:** Dockerfile line-by-line explanation
- **Why UID 1000?** Standard first user, matches host
- **Why `--no-cache-dir`?** Saves 500MB image size
- **Why `update-alternatives`?** Ensures `python` command works

**Section 3:** PyTorch installation deep dive
- **CRITICAL:** `--index-url https://download.pytorch.org/whl/cu121`
- **Without this:** Downloads CPU-only PyTorch (silent failure!)
- **Verification:** `torch.cuda.is_available()` must return `True`

**Section 4:** Security hardening
- **USER ghidra:** Non-root execution (CVE-2025-23266 mitigation)
- **LABEL security.cve_mitigation:** Audit trail for compliance
- **VOLUME ["/tmp", "/models"]:** Read-only model protection

**Section 5:** Health checks
- **Purpose:** Validate GPU access on every restart
- **Implementation:** `python3 -c "import torch; assert torch.cuda.is_available()"`
- **Parameters:** 40s start period (PyTorch import is slow), 3 retries

**Section 6:** Troubleshooting
- **"CUDA not available"** → Check PyTorch build (CPU vs GPU)
- **Build hangs** → Pre-download PyTorch wheel (2.3GB)
- **Permission denied** → Windows Docker Desktop admin mode

### Success Criteria

After completing this walkthrough, you will:
- ✅ Understand Docker layer caching optimization
- ✅ Know how to install GPU PyTorch correctly (`--index-url`)
- ✅ Implement security hardening (non-root user, minimal capabilities)
- ✅ Have container image: `ghidra-similarity:v1.0-gpu` (2.5GB)

### Files Created

```
development/
├── Dockerfile.ghidra-ml            (73 lines, secure container definition)
└── Image: ghidra-similarity:v1.0-gpu (2.5GB compressed)
```

---

## 🔐 Component #3: Secure Deployment with Docker Compose

**File:** `COMPONENT_WALKTHROUGH_3_DEPLOYMENT_SECURITY.md`

### What You'll Learn

1. **Defense-in-Depth:** 5-layer security architecture
2. **Capability Dropping:** Linux capabilities explained (40+ capabilities)
3. **Resource Limits:** Memory/CPU/GPU allocation strategies
4. **Volume Security:** Read-only mounts prevent model poisoning
5. **Network Isolation:** Custom bridge networks for containment

### Key Concepts Covered

```
Topics:
├── Linux capabilities (CAP_SYS_ADMIN, CAP_NET_BIND_SERVICE, etc.)
├── Resource limits (reservations vs limits)
├── Volume security (read-only bind mounts)
├── Network isolation (custom bridge networks)
├── Health checks (GPU + API validation)
└── CVE mitigation strategies (7 CVEs addressed)
```

### Practical Skills

| Skill | Application | Difficulty |
|-------|-------------|------------|
| **Docker Compose v3 GPU syntax** | Allocate GPUs to containers | Intermediate |
| **Capability management** | Drop/add Linux capabilities | Advanced |
| **Resource allocation** | Set memory/CPU limits | Intermediate |
| **Volume security** | Read-only mounts for immutability | Intermediate |
| **Network design** | Custom subnets for isolation | Intermediate |

### Walkthrough Highlights

**Section 1:** 5-layer security architecture
```
Layer 1: Docker security options (no-new-privileges)
Layer 2: Capability dropping (drop ALL, add NET_BIND_SERVICE)
Layer 3: Resource limits (6GB RAM, 4 CPU cores)
Layer 4: Network isolation (172.25.0.0/24 custom subnet)
Layer 5: Volume security (read-only /models, /data)
```

**Section 2:** GPU access configuration
- **Docker Compose v3.8+ syntax:** `deploy.resources.reservations.devices`
- **Old syntax (deprecated):** `runtime: nvidia`
- **Capabilities:** `gpu`, `utility`, `compute`, `graphics`, `video`, `display`

**Section 3:** Resource limits deep dive
| Limit Type | Value | Meaning |
|------------|-------|---------|
| **limits.memory: 6G** | Cannot exceed 6GB | Hard limit (OOM if violated) |
| **reservations.memory: 4G** | Guaranteed 4GB minimum | Soft guarantee (scheduler) |
| **limits.cpus: '4.0'** | Cannot use >400% CPU | Hard limit (throttled) |

**Section 4:** Capability dropping explained
- **cap_drop: ALL** → Removes all 40 Linux capabilities
- **cap_add: NET_BIND_SERVICE** → Selectively restores port binding
- **Security impact:** Even with container compromise, cannot mount filesystems, load kernel modules, bypass permissions

**Section 5:** Volume security matrix
| Volume | Access | Security Benefit |
|--------|--------|------------------|
| `/models` | Read-only | Cannot modify ML models (prevents backdoor) |
| `/app` | Read-only | Cannot modify code (prevents persistence) |
| `/tmp` | Read-write (tmpfs) | Ephemeral, in-memory (wiped on restart) |

**Section 6:** CVE mitigation validation
- **CVE-2025-23266:** LD_PRELOAD attack → Limited to non-root user
- **CVE-2024-0132:** Symlink attack → Read-only volumes prevent exploitation
- **CVE-2025-23267:** ldconfig attack → Not using WSL toolkit (N/A)

### Success Criteria

After completing this walkthrough, you will:
- ✅ Understand defense-in-depth security architecture
- ✅ Configure GPU access via Docker Compose v3.8+ syntax
- ✅ Implement capability dropping (reduce attack surface)
- ✅ Deploy stack: `docker compose -f docker-compose.ghidra-ml.yml up -d`

### Files Created

```
development/
├── docker-compose.ghidra-ml.yml    (120 lines, secure deployment config)
├── Network: ghidra-ml-network      (172.25.0.0/24 custom bridge)
└── Volume: similarity-cache        (Docker-managed tmpfs)
```

---

## 🏆 Component #4: Integration & Validation (Coming Soon)

**File:** `COMPONENT_WALKTHROUGH_4_INTEGRATION.md` (To Be Created)

### Planned Topics

1. **Wiz Competition Validation:**
   - CVE-2025-23266 exploit testing
   - CVE-2024-0132 symlink attack testing
   - Automated validation framework
   - Competition submission report generation

2. **Ghidra Plugin Integration:**
   - `GhidraSimilarity.py` script creation
   - FastAPI client for ML inference
   - GhidraGraph integration for visualization
   - Keyboard shortcut binding (Ctrl-Shift-S)

3. **Performance Validation:**
   - Compare ML workload vs baseline
   - GPU utilization measurement (target: 60-80%)
   - Inference latency benchmarking (<100ms per function)
   - Throughput testing (200 functions/second)

4. **Production Checklist:**
   - Final security audit (target: 95/100 score)
   - Monitoring dashboard configuration
   - Alert threshold tuning
   - Disaster recovery procedures

---

## 🚀 Quick Start Guide

For those who want to execute all components sequentially:

### Phase 1: Measure (10 minutes)

```bash
cd C:/Users/Corbin/development
python measure_gpu_baseline.py

# Output: gpu_baseline_metrics.json
```

### Phase 2: Build (30-45 minutes, one-time)

```bash
docker build -t ghidra-similarity:v1.0-gpu -f Dockerfile.ghidra-ml .

# Verify:
docker run --rm --gpus all ghidra-similarity:v1.0-gpu
# Should show: "CUDA Available: True"
```

### Phase 3: Deploy (5 minutes)

```bash
# Create directories
mkdir -p models data app

# Copy API code
cp docs/similarity_api.py app/

# Deploy stack
docker compose -f docker-compose.ghidra-ml.yml up -d

# Verify:
curl http://localhost:8080/health
# Should show: {"status":"healthy","gpu_available":true}
```

### Phase 4: Validate (10 minutes)

```bash
# Test inference endpoint
curl -X POST http://localhost:8080/api/similarity \
  -H "Content-Type: application/json" \
  -d '{
    "function_name": "test_func",
    "instructions": ["mov eax, 1", "ret"],
    "top_k": 5
  }'

# Check GPU metrics
curl http://localhost:9400/metrics | grep dcgm_gpu_utilization

# View monitoring dashboard
# Browser: http://localhost:8081
```

---

## 📖 Learning Path Recommendations

### For Beginners (Security Analysts, QA Engineers)

**Start with:**
1. Component #1 (GPU Baseline) - Learn fundamentals
2. Component #3 (Deployment) - Understand security architecture
3. Component #4 (Validation) - Hands-on testing

**Skip for now:**
- Component #2 (Container Image) - More advanced Docker concepts

### For Intermediate (DevOps Engineers, SREs)

**Recommended order:**
1. Component #2 (Container Image) - Docker optimization
2. Component #3 (Deployment) - Docker Compose security
3. Component #1 (Baseline) - Monitoring integration
4. Component #4 (Validation) - Production readiness

### For Advanced (Security Engineers, Architects)

**Focus areas:**
1. Component #3 (Deployment) - Defense-in-depth architecture
2. Component #4 (Validation) - CVE mitigation verification
3. Component #2 (Container Image) - Supply chain security
4. Component #1 (Baseline) - Performance SLA definition

---

## 🔍 Deep Dive Topics

Each walkthrough includes optional "Deep Dive" sections for advanced readers:

### Component #1 Deep Dives
- Multi-GPU baseline collection
- Automated CI/CD integration
- Performance regression detection

### Component #2 Deep Dives
- Multi-stage Docker builds (20-30% size reduction)
- Image signing with Docker Content Trust
- Vulnerability scanning with Trivy

### Component #3 Deep Dives
- Docker secrets management (vs environment variables)
- AppArmor/SELinux profiles
- Zero Trust network architecture with service mesh

---

## 📊 Progress Tracking

| Component | Documentation | Implementation | Testing | Status |
|-----------|---------------|----------------|---------|--------|
| **#1: Baseline** | ✅ Complete | ✅ Complete | ✅ Complete | ✅ DONE |
| **#2: Container** | ✅ Complete | 🔄 Building | ⏳ Pending | 🔄 90% |
| **#3: Deployment** | ✅ Complete | ⏳ Ready | ⏳ Pending | ⏳ 75% |
| **#4: Integration** | ⏳ Planned | ⏳ Pending | ⏳ Pending | ⏳ 0% |

---

## 🎓 Educational Features

Each walkthrough includes:

1. **✶ Insight Boxes:** Key educational points
   - Example: "Why percentiles matter more than averages for SLA guarantees"

2. **Architecture Diagrams:** Visual representations
   - ASCII art for component relationships
   - Decision trees for design choices

3. **Code Walkthroughs:** Line-by-line explanations
   - Not just "what" but "why"
   - Trade-offs and alternatives discussed

4. **Security Analysis:** CVE mitigation strategies
   - Which CVEs are addressed by each component
   - How defense-in-depth layers interact

5. **Troubleshooting Sections:** Common issues and solutions
   - Real error messages and fixes
   - Diagnostic commands for debugging

6. **Production Considerations:** Beyond development
   - CI/CD integration examples
   - Multi-GPU environments
   - Disaster recovery procedures

---

## 🔗 Cross-References

Components reference each other for integrated learning:

```
Component #1 (Baseline)
    └─> Feeds data to Component #3 (Deployment alerting)
    └─> Compared in Component #4 (Validation benchmarking)

Component #2 (Container)
    └─> Deployed by Component #3 (Docker Compose)
    └─> Tested in Component #4 (Integration testing)

Component #3 (Deployment)
    └─> Uses Component #2 (Container image)
    └─> Monitored via Component #1 (Baseline metrics)

Component #4 (Integration)
    └─> Validates Component #3 (Security testing)
    └─> Benchmarks against Component #1 (Performance comparison)
```

---

## 📚 Additional Resources

### Official Documentation
- [NVIDIA Container Toolkit Docs](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/)
- [Docker Compose v3 GPU Reference](https://docs.docker.com/compose/gpu-support/)
- [PyTorch Installation Guide](https://pytorch.org/get-started/locally/)

### Security Resources
- [NVIDIA Security Bulletins](https://nvidia.custhelp.com/app/answers/list/p/11/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Container Security Guide (SP 800-190)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

### Related Projects
- [GhidraGo Plugin Roadmap](../PLUGIN_ROADMAP_2025.md)
- [B-MAD Deployment Plan](../NVIDIA_BMAD_DEPLOYMENT_PLAN.md)
- [Wiz Competition Spec](../security/WIZ_ZERODAY_CLOUD_2025_SYSTEMATIC_PLAN.md)

---

## ✅ Completion Checklist

Use this checklist to track your implementation progress:

### Component #1: GPU Baseline
- [ ] Read walkthrough (30 min)
- [ ] Execute `measure_gpu_baseline.py` (10 min)
- [ ] Verify `gpu_baseline_metrics.json` created
- [ ] Understand P95/P99 percentiles
- [ ] Optional: Integrate into CI/CD

### Component #2: ML Container
- [ ] Read walkthrough (45 min)
- [ ] Build container image (30-45 min first time)
- [ ] Test GPU access in container
- [ ] Verify PyTorch CUDA build
- [ ] Optional: Multi-stage build optimization

### Component #3: Secure Deployment
- [ ] Read walkthrough (40 min)
- [ ] Create required directories (`models/`, `data/`, `app/`)
- [ ] Deploy Docker Compose stack (5 min)
- [ ] Verify health checks passing
- [ ] Test security controls (capability dropping, read-only volumes)
- [ ] Optional: Add Falco monitoring

### Component #4: Integration & Validation
- [ ] Read walkthrough (TBD)
- [ ] Execute Wiz competition validation
- [ ] Create Ghidra plugin script
- [ ] Benchmark inference performance
- [ ] Generate production readiness report

---

**Documentation Maintainer:** Catalytic Computing Team
**Last Updated:** October 6, 2025
**Next Review:** After Component #4 completion

---

**Ready to start? Pick a component based on your role:**
- **Security Analyst:** Start with Component #1, then #3
- **DevOps Engineer:** Start with Component #2, then #3
- **Software Engineer:** Start with Component #1, then #4
- **ML Engineer:** Start with Component #2, then #1
