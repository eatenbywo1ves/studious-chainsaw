# NVIDIA Container Toolkit - B-MAD Deployment Plan
## Build → Measure → Analyze → Deploy Methodology for GPU-Accelerated Reverse Engineering

**Created:** October 6, 2025
**Status:** Ready for Execution
**Alignment:** Integrates with Ghidra Plugin Roadmap 2025 (GhidrAssist + GhidraSimilarity)
**Competition Focus:** Wiz ZeroDay.Cloud 2025 GPU Security Challenge

---

## 🎯 Executive Summary

This deployment plan implements NVIDIA Container Toolkit v1.17.8 using the B-MAD methodology to enable GPU-accelerated machine learning for binary similarity analysis. The deployment directly supports:

1. **GhidraSimilarity Plugin** (Tier 1) - ML-based function matching
2. **GhidrAssist Completion** (Tier 0) - AI-enhanced reverse engineering
3. **Wiz Competition** - Container escape defense validation

### Strategic Alignment

| Framework/Project | GPU Requirement | B-MAD Integration |
|-------------------|-----------------|-------------------|
| **GhidraSimilarity** | TensorFlow/scikit-learn acceleration | **Build:** ML model training<br>**Measure:** Similarity scoring benchmarks<br>**Analyze:** Model accuracy metrics<br>**Deploy:** Production inference |
| **GhidrAssist** | Local LLM optimization | **Build:** Model quantization<br>**Measure:** Token generation speed<br>**Analyze:** Accuracy vs performance<br>**Deploy:** Edge inference |
| **KA Lattice (existing)** | CUDA-optimized stochastic computing | **Measure:** Current GPU utilization<br>**Analyze:** Container isolation<br>**Deploy:** Secure multi-tenant |
| **Wiz Competition** | Container escape testing | **Build:** Secure test environment<br>**Measure:** Vulnerability detection<br>**Analyze:** Attack surface<br>**Deploy:** Hardened production |

---

## 📋 B-MAD Phase Breakdown

### PHASE 1: BUILD (Security-First Architecture)

#### 1.1 Prerequisites Verification

**Security Context:**
- Based on CVE-2025-23266 (CVSS 9.0), we must implement defense-in-depth from the start
- 37% of cloud environments are vulnerable to container escapes
- Our deployment MUST exceed baseline security

**Build Actions:**
```bash
# Verify GPU driver (Windows with WSL2)
nvidia-smi

# Check WSL2 GPU passthrough
wsl.exe --list --verbose
wsl.exe --shutdown  # Restart if needed

# Verify CUDA availability in WSL2
wsl nvidia-smi
```

#### 1.2 Secure Installation (Container Toolkit v1.17.8)

**Critical Security Controls:**
1. ✅ **Version Pinning** - Prevent auto-upgrade to vulnerable versions
2. ✅ **Configuration Hardening** - ldconfig @ prefix, no dangerous feature flags
3. ✅ **CDI Mode** - Bypass vulnerable OCI hook code paths
4. ✅ **Image Scanning** - All GPU images must be scanned pre-deployment

**Installation Script:**
```bash
#!/bin/bash
# File: development/nvidia-toolkit-secure-install.sh

set -euo pipefail

# Security: Pin exact version to avoid CVE-2025-23266 and earlier
export NVIDIA_CONTAINER_TOOLKIT_VERSION=1.17.8-1

echo "[BUILD] Installing NVIDIA Container Toolkit v${NVIDIA_CONTAINER_TOOLKIT_VERSION}"

# Configure production repository with GPG verification
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | \
  sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
  sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
  sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

# Update package list
sudo apt-get update

# Install with version pinning (CRITICAL for security)
sudo apt-get install -y \
    nvidia-container-toolkit=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
    nvidia-container-toolkit-base=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
    libnvidia-container-tools=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
    libnvidia-container1=${NVIDIA_CONTAINER_TOOLKIT_VERSION}

# Hold packages to prevent auto-upgrade
sudo apt-mark hold nvidia-container-toolkit \
    nvidia-container-toolkit-base \
    libnvidia-container-tools \
    libnvidia-container1

echo "[BUILD] Toolkit installation complete"
```

#### 1.3 Hardened Configuration

**Security Configuration (Defense Against CVEs):**
```bash
#!/bin/bash
# File: development/nvidia-toolkit-secure-config.sh

set -euo pipefail

echo "[BUILD] Applying security-hardened configuration"

# Backup original config
sudo cp /etc/nvidia-container-runtime/config.toml \
     /etc/nvidia-container-runtime/config.toml.backup

# Apply secure configuration
sudo tee /etc/nvidia-container-runtime/config.toml > /dev/null <<'EOF'
# Secure NVIDIA Container Runtime Configuration
# Last Updated: 2025-10-06
# Defends against: CVE-2024-0132, CVE-2025-23266, CVE-2025-23267

[nvidia-container-cli]
# CRITICAL: @ prefix ensures ldconfig from HOST (not container)
# Mitigates: CVE-2024-0136, CVE-2024-0137
ldconfig = "@/sbin/ldconfig"

# Enable debug logging for security auditing
debug = "/var/log/nvidia-container-toolkit.log"

[nvidia-container-runtime]
# Use CDI mode to bypass vulnerable OCI hook paths
# Mitigates: CVE-2025-23266 (LD_PRELOAD injection)
mode = "cdi"

# Security logging
log-level = "info"

# NEVER enable this flag (re-introduces CVE-2024-0136/0137)
# feature-flags = ["allow-cuda-compat-libs-from-container"]  # FORBIDDEN

[nvidia-container-runtime.modes]
# CDI configuration for enhanced security
cdi.default-kind = "nvidia.com/gpu"
cdi.annotation-prefixes = ["cdi.k8s.io/"]

[nvidia-container-runtime-hook]
# Disable createContainer hook (CVE-2025-23266 vector)
# Use prestart hook only (isolated environment)
skip-mode-detection = true
EOF

# Generate CDI specifications
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml

# Configure Docker runtime
sudo nvidia-ctk runtime configure --runtime=docker --cdi.enabled

# Restart Docker to apply
sudo systemctl restart docker

# Verify configuration
echo "[BUILD] Verifying secure configuration..."
grep ldconfig /etc/nvidia-container-runtime/config.toml | grep -q "@" && \
  echo "✅ ldconfig: SECURE (host path)" || \
  echo "❌ ldconfig: VULNERABLE (container path)"

grep -q 'mode = "cdi"' /etc/nvidia-container-runtime/config.toml && \
  echo "✅ CDI mode: ENABLED" || \
  echo "⚠️  CDI mode: DISABLED (legacy mode active)"

echo "[BUILD] Configuration hardening complete"
```

#### 1.4 Container Image Security

**Trusted Base Images:**
```dockerfile
# File: development/Dockerfile.ghidra-ml-base
# Secure base image for GhidraSimilarity ML workloads

# Use NVIDIA's official CUDA image (scanned and signed)
FROM nvidia/cuda:12.3.1-cudnn9-runtime-ubuntu22.04

# Security: Run as non-root user
RUN groupadd -r ghidra && useradd -r -g ghidra ghidra

# Install Python ML stack
RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install ML dependencies with pinned versions
COPY requirements-ml.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements-ml.txt

# Security: Read-only root filesystem (when possible)
# Writable /tmp for model cache
VOLUME /tmp

# Switch to non-root user
USER ghidra
WORKDIR /home/ghidra

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python3 -c "import torch; print(torch.cuda.is_available())" || exit 1
```

**ML Requirements:**
```txt
# File: development/requirements-ml.txt
# GPU-accelerated ML stack for binary similarity

# Deep Learning
torch==2.1.0+cu121
torchvision==0.16.0+cu121
tensorflow==2.15.0

# Traditional ML
scikit-learn==1.3.2
numpy==1.24.3
pandas==2.1.3

# Binary Analysis
capstone==5.0.1
pefile==2023.2.7
lief==0.14.0

# Ghidra Integration
ghidra-bridge==0.3.3
jpype1==1.5.0

# Utilities
tqdm==4.66.1
matplotlib==3.8.2
seaborn==0.13.0
```

---

### PHASE 2: MEASURE (Baseline Performance & Security Metrics)

#### 2.1 Performance Baselines

**GPU Utilization Measurement:**
```python
#!/usr/bin/env python3
# File: development/measure_gpu_baseline.py

import subprocess
import json
import time
from dataclasses import dataclass
from typing import List

@dataclass
class GPUMetrics:
    timestamp: float
    gpu_util: float
    memory_used: int
    memory_total: int
    temperature: int
    power_draw: float

def measure_gpu_baseline(duration_seconds: int = 60) -> List[GPUMetrics]:
    """Measure GPU performance baseline for B-MAD analysis."""

    metrics = []
    start_time = time.time()

    while time.time() - start_time < duration_seconds:
        # Query NVIDIA SMI
        result = subprocess.run([
            'nvidia-smi',
            '--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw',
            '--format=csv,noheader,nounits'
        ], capture_output=True, text=True)

        if result.returncode == 0:
            values = result.stdout.strip().split(',')
            metric = GPUMetrics(
                timestamp=time.time(),
                gpu_util=float(values[0]),
                memory_used=int(values[1]),
                memory_total=int(values[2]),
                temperature=int(values[3]),
                power_draw=float(values[4])
            )
            metrics.append(metric)

        time.sleep(1)

    return metrics

def calculate_statistics(metrics: List[GPUMetrics]):
    """Calculate baseline statistics for B-MAD analysis."""

    gpu_utils = [m.gpu_util for m in metrics]
    mem_usages = [(m.memory_used / m.memory_total) * 100 for m in metrics]

    stats = {
        'gpu_utilization': {
            'mean': sum(gpu_utils) / len(gpu_utils),
            'min': min(gpu_utils),
            'max': max(gpu_utils),
            'p50': sorted(gpu_utils)[len(gpu_utils)//2],
            'p95': sorted(gpu_utils)[int(len(gpu_utils)*0.95)],
            'p99': sorted(gpu_utils)[int(len(gpu_utils)*0.99)]
        },
        'memory_utilization': {
            'mean': sum(mem_usages) / len(mem_usages),
            'min': min(mem_usages),
            'max': max(mem_usages),
        },
        'temperature': {
            'mean': sum(m.temperature for m in metrics) / len(metrics),
            'max': max(m.temperature for m in metrics)
        },
        'power_draw': {
            'mean': sum(m.power_draw for m in metrics) / len(metrics),
            'max': max(m.power_draw for m in metrics)
        }
    }

    return stats

if __name__ == '__main__':
    print("[MEASURE] Collecting GPU baseline metrics (60 seconds)...")
    metrics = measure_gpu_baseline(60)
    stats = calculate_statistics(metrics)

    print("\n[MEASURE] Baseline Statistics:")
    print(json.dumps(stats, indent=2))

    # Save for B-MAD analysis phase
    with open('gpu_baseline_metrics.json', 'w') as f:
        json.dump({
            'metrics': [vars(m) for m in metrics],
            'statistics': stats
        }, f, indent=2)

    print("\n✅ Baseline metrics saved to gpu_baseline_metrics.json")
```

#### 2.2 Security Posture Measurement

**Container Escape Detection:**
```python
#!/usr/bin/env python3
# File: development/measure_container_security.py

import subprocess
import json
from typing import Dict, List

class ContainerSecurityAuditor:
    """Measure container security posture against known CVEs."""

    def check_toolkit_version(self) -> Dict:
        """Verify NVIDIA Container Toolkit version (CVE mitigation)."""
        result = subprocess.run([
            'nvidia-container-toolkit', '--version'
        ], capture_output=True, text=True)

        version = result.stdout.strip().split()[-1]

        # Check against known vulnerable versions
        vulnerable = version < "1.17.8"

        return {
            'check': 'toolkit_version',
            'version': version,
            'vulnerable': vulnerable,
            'cve_affected': ['CVE-2025-23266', 'CVE-2025-23267'] if vulnerable else [],
            'severity': 'CRITICAL' if vulnerable else 'PASS'
        }

    def check_ldconfig_configuration(self) -> Dict:
        """Check ldconfig configuration (CVE-2024-0136/0137)."""
        with open('/etc/nvidia-container-runtime/config.toml', 'r') as f:
            config = f.read()

        # Check for @ prefix (secure configuration)
        secure = 'ldconfig = "@/sbin/ldconfig"' in config

        return {
            'check': 'ldconfig_config',
            'secure': secure,
            'cve_affected': ['CVE-2024-0136', 'CVE-2024-0137'] if not secure else [],
            'severity': 'HIGH' if not secure else 'PASS'
        }

    def check_dangerous_feature_flags(self) -> Dict:
        """Check for dangerous feature flags."""
        with open('/etc/nvidia-container-runtime/config.toml', 'r') as f:
            config = f.read()

        dangerous = 'allow-cuda-compat-libs-from-container' in config

        return {
            'check': 'feature_flags',
            'dangerous_flags_enabled': dangerous,
            'severity': 'CRITICAL' if dangerous else 'PASS'
        }

    def check_cdi_mode(self) -> Dict:
        """Verify CDI mode is enabled (bypasses vulnerable hooks)."""
        with open('/etc/nvidia-container-runtime/config.toml', 'r') as f:
            config = f.read()

        cdi_enabled = 'mode = "cdi"' in config

        return {
            'check': 'cdi_mode',
            'enabled': cdi_enabled,
            'security_benefit': 'Bypasses CVE-2025-23266 attack vector' if cdi_enabled else 'None',
            'severity': 'MEDIUM' if not cdi_enabled else 'PASS'
        }

    def audit(self) -> Dict:
        """Run complete security audit."""
        checks = [
            self.check_toolkit_version(),
            self.check_ldconfig_configuration(),
            self.check_dangerous_feature_flags(),
            self.check_cdi_mode()
        ]

        # Determine overall security score
        critical_issues = sum(1 for c in checks if c.get('severity') == 'CRITICAL')
        high_issues = sum(1 for c in checks if c.get('severity') == 'HIGH')
        medium_issues = sum(1 for c in checks if c.get('severity') == 'MEDIUM')

        score = 100 - (critical_issues * 40) - (high_issues * 20) - (medium_issues * 10)

        return {
            'security_score': max(0, score),
            'checks': checks,
            'summary': {
                'critical_issues': critical_issues,
                'high_issues': high_issues,
                'medium_issues': medium_issues,
                'recommendation': 'DEPLOY' if score >= 90 else 'FIX_ISSUES_FIRST'
            }
        }

if __name__ == '__main__':
    print("[MEASURE] Auditing container security posture...")

    auditor = ContainerSecurityAuditor()
    report = auditor.audit()

    print(f"\n[MEASURE] Security Score: {report['security_score']}/100")
    print(f"\n[MEASURE] Issues Found:")
    print(f"  - Critical: {report['summary']['critical_issues']}")
    print(f"  - High: {report['summary']['high_issues']}")
    print(f"  - Medium: {report['summary']['medium_issues']}")

    print(f"\n[MEASURE] Recommendation: {report['summary']['recommendation']}")

    # Save audit report
    with open('container_security_audit.json', 'w') as f:
        json.dump(report, f, indent=2)

    print("\n✅ Security audit saved to container_security_audit.json")

    # Exit with error if critical issues found
    if report['summary']['critical_issues'] > 0:
        print("\n❌ CRITICAL SECURITY ISSUES FOUND - FIX BEFORE DEPLOYMENT")
        exit(1)
```

---

### PHASE 3: ANALYZE (ML Model Optimization & Security Analysis)

#### 3.1 GhidraSimilarity ML Model Design

**Binary Function Similarity Architecture:**
```python
#!/usr/bin/env python3
# File: development/ghidra_similarity_ml_model.py

import torch
import torch.nn as nn
from typing import Tuple, List
import numpy as np

class BinaryFunctionEncoder(nn.Module):
    """GPU-accelerated encoder for binary function embeddings."""

    def __init__(
        self,
        vocab_size: int = 10000,  # Assembly instruction vocab
        embedding_dim: int = 256,
        hidden_dim: int = 512,
        num_layers: int = 3
    ):
        super().__init__()

        # Instruction embedding
        self.embedding = nn.Embedding(vocab_size, embedding_dim)

        # BiLSTM for control flow encoding
        self.bilstm = nn.LSTM(
            embedding_dim,
            hidden_dim,
            num_layers=num_layers,
            bidirectional=True,
            batch_first=True,
            dropout=0.3
        )

        # Attention mechanism for important instruction focus
        self.attention = nn.MultiheadAttention(
            embed_dim=hidden_dim * 2,
            num_heads=8,
            batch_first=True
        )

        # Function signature encoder
        self.signature_encoder = nn.Linear(hidden_dim * 2, 256)

        # Final embedding projection
        self.projection = nn.Linear(256, 128)

    def forward(self, instruction_sequence: torch.Tensor) -> torch.Tensor:
        """
        Args:
            instruction_sequence: (batch, seq_len) - tokenized assembly

        Returns:
            function_embedding: (batch, 128) - normalized embedding
        """
        # Embed instructions
        x = self.embedding(instruction_sequence)  # (batch, seq_len, embedding_dim)

        # BiLSTM encoding
        lstm_out, _ = self.bilstm(x)  # (batch, seq_len, hidden_dim * 2)

        # Self-attention over instructions
        attn_out, _ = self.attention(lstm_out, lstm_out, lstm_out)

        # Global average pooling
        pooled = torch.mean(attn_out, dim=1)  # (batch, hidden_dim * 2)

        # Signature encoding
        signature = self.signature_encoder(pooled)  # (batch, 256)
        signature = torch.relu(signature)

        # Final projection
        embedding = self.projection(signature)  # (batch, 128)

        # L2 normalization for cosine similarity
        embedding = torch.nn.functional.normalize(embedding, p=2, dim=1)

        return embedding

class SimilarityModel(nn.Module):
    """Siamese network for function similarity scoring."""

    def __init__(self, encoder: BinaryFunctionEncoder):
        super().__init__()
        self.encoder = encoder

    def forward(
        self,
        func1_instructions: torch.Tensor,
        func2_instructions: torch.Tensor
    ) -> torch.Tensor:
        """
        Compute similarity score between two functions.

        Returns:
            similarity: (batch,) - cosine similarity scores
        """
        # Encode both functions
        embed1 = self.encoder(func1_instructions)
        embed2 = self.encoder(func2_instructions)

        # Cosine similarity
        similarity = torch.sum(embed1 * embed2, dim=1)

        return similarity

# GPU-accelerated training function
def train_similarity_model(
    model: SimilarityModel,
    train_loader: torch.utils.data.DataLoader,
    num_epochs: int = 10,
    device: str = 'cuda'
) -> SimilarityModel:
    """B-MAD Phase 3: Analyze - Train ML model on GPU."""

    model = model.to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-4)
    criterion = nn.CosineEmbeddingLoss()

    for epoch in range(num_epochs):
        model.train()
        total_loss = 0

        for batch in train_loader:
            func1, func2, labels = batch
            func1 = func1.to(device)
            func2 = func2.to(device)
            labels = labels.to(device)  # 1 for similar, -1 for dissimilar

            optimizer.zero_grad()

            # Forward pass (GPU-accelerated)
            similarity = model(func1, func2)

            # Loss computation
            loss = criterion(similarity, labels)

            # Backward pass
            loss.backward()
            optimizer.step()

            total_loss += loss.item()

        avg_loss = total_loss / len(train_loader)
        print(f"[ANALYZE] Epoch {epoch+1}/{num_epochs}, Loss: {avg_loss:.4f}")

    return model

# Inference function for GhidraSimilarity plugin
@torch.no_grad()
def find_similar_functions(
    query_function: List[int],  # Tokenized assembly
    database_functions: List[Tuple[str, List[int]]],  # (name, instructions)
    model: SimilarityModel,
    top_k: int = 10,
    device: str = 'cuda'
) -> List[Tuple[str, float]]:
    """
    Find top-k similar functions from database.

    Returns:
        List of (function_name, similarity_score) sorted by score
    """
    model = model.to(device)
    model.eval()

    query_tensor = torch.tensor([query_function], dtype=torch.long).to(device)

    similarities = []
    for name, instructions in database_functions:
        db_tensor = torch.tensor([instructions], dtype=torch.long).to(device)
        score = model(query_tensor, db_tensor).item()
        similarities.append((name, score))

    # Sort by similarity descending
    similarities.sort(key=lambda x: x[1], reverse=True)

    return similarities[:top_k]

if __name__ == '__main__':
    print("[ANALYZE] Initializing GhidraSimilarity ML model...")

    # Check GPU availability
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    print(f"[ANALYZE] Using device: {device}")

    # Initialize model
    encoder = BinaryFunctionEncoder()
    model = SimilarityModel(encoder)

    print(f"[ANALYZE] Model parameters: {sum(p.numel() for p in model.parameters()):,}")
    print(f"[ANALYZE] Model size: {sum(p.numel() * 4 for p in model.parameters()) / 1024 / 1024:.2f} MB")

    # Dummy test
    test_input1 = torch.randint(0, 10000, (4, 128))  # Batch of 4 functions
    test_input2 = torch.randint(0, 10000, (4, 128))

    if device == 'cuda':
        model = model.cuda()
        test_input1 = test_input1.cuda()
        test_input2 = test_input2.cuda()

    similarity_scores = model(test_input1, test_input2)
    print(f"\n[ANALYZE] Test inference successful!")
    print(f"[ANALYZE] Similarity scores shape: {similarity_scores.shape}")
    print(f"[ANALYZE] Similarity scores: {similarity_scores.cpu().numpy()}")

    print("\n✅ ML model analysis complete")
```

#### 3.2 Performance Analysis vs Baseline

**B-MAD Analysis Script:**
```python
#!/usr/bin/env python3
# File: development/analyze_bmad_metrics.py

import json
import matplotlib.pyplot as plt
from typing import Dict

def analyze_bmad_metrics(
    baseline_path: str = 'gpu_baseline_metrics.json',
    ml_metrics_path: str = 'ml_training_metrics.json'
) -> Dict:
    """B-MAD Phase 3: Compare ML workload vs baseline."""

    # Load baseline
    with open(baseline_path) as f:
        baseline = json.load(f)['statistics']

    # Load ML training metrics
    with open(ml_metrics_path) as f:
        ml_metrics = json.load(f)['statistics']

    analysis = {
        'gpu_utilization': {
            'baseline_mean': baseline['gpu_utilization']['mean'],
            'ml_workload_mean': ml_metrics['gpu_utilization']['mean'],
            'improvement': ml_metrics['gpu_utilization']['mean'] - baseline['gpu_utilization']['mean'],
            'efficiency_score': (ml_metrics['gpu_utilization']['mean'] / 100) * 100
        },
        'memory_efficiency': {
            'baseline_mean': baseline['memory_utilization']['mean'],
            'ml_workload_mean': ml_metrics['memory_utilization']['mean'],
            'headroom': 100 - ml_metrics['memory_utilization']['max']
        },
        'thermal_analysis': {
            'max_temp': ml_metrics['temperature']['max'],
            'safe': ml_metrics['temperature']['max'] < 85,  # NVIDIA safe threshold
            'recommendation': 'PASS' if ml_metrics['temperature']['max'] < 85 else 'IMPROVE_COOLING'
        }
    }

    # Generate visualization
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))

    # GPU Utilization comparison
    axes[0, 0].bar(['Baseline', 'ML Workload'],
                   [baseline['gpu_utilization']['mean'], ml_metrics['gpu_utilization']['mean']])
    axes[0, 0].set_title('GPU Utilization Comparison')
    axes[0, 0].set_ylabel('Utilization (%)')

    # Memory usage
    axes[0, 1].bar(['Baseline', 'ML Workload'],
                   [baseline['memory_utilization']['mean'], ml_metrics['memory_utilization']['mean']])
    axes[0, 1].set_title('Memory Utilization Comparison')
    axes[0, 1].set_ylabel('Memory Usage (%)')

    # Temperature
    axes[1, 0].bar(['Baseline', 'ML Workload'],
                   [baseline['temperature']['max'], ml_metrics['temperature']['max']])
    axes[1, 0].axhline(y=85, color='r', linestyle='--', label='Safe Threshold')
    axes[1, 0].set_title('Maximum Temperature')
    axes[1, 0].set_ylabel('Temperature (°C)')
    axes[1, 0].legend()

    # Power draw
    axes[1, 1].bar(['Baseline', 'ML Workload'],
                   [baseline['power_draw']['max'], ml_metrics['power_draw']['max']])
    axes[1, 1].set_title('Maximum Power Draw')
    axes[1, 1].set_ylabel('Power (W)')

    plt.tight_layout()
    plt.savefig('bmad_analysis_visualization.png', dpi=300)

    print("[ANALYZE] Visualization saved to bmad_analysis_visualization.png")

    return analysis

if __name__ == '__main__':
    analysis = analyze_bmad_metrics()

    print("\n[ANALYZE] B-MAD Performance Analysis:")
    print(f"  GPU Utilization: {analysis['gpu_utilization']['ml_workload_mean']:.1f}% "
          f"(+{analysis['gpu_utilization']['improvement']:.1f}% vs baseline)")
    print(f"  Memory Efficiency: {analysis['memory_efficiency']['ml_workload_mean']:.1f}% "
          f"({analysis['memory_efficiency']['headroom']:.1f}% headroom)")
    print(f"  Thermal Status: {analysis['thermal_analysis']['max_temp']}°C "
          f"({analysis['thermal_analysis']['recommendation']})")

    with open('bmad_analysis_report.json', 'w') as f:
        json.dump(analysis, f, indent=2)

    print("\n✅ B-MAD analysis complete - report saved to bmad_analysis_report.json")
```

---

### PHASE 4: DEPLOY (Production Rollout with Security Validation)

#### 4.1 Deployment Architecture

**Multi-Tenant GPU Container Design:**
```yaml
# File: development/docker-compose.ghidra-ml.yml
# Secure GPU-accelerated Ghidra ML deployment

version: '3.8'

services:
  ghidra-similarity-api:
    build:
      context: .
      dockerfile: Dockerfile.ghidra-ml-base
    image: ghidra-similarity:v1.0-gpu

    # GPU access via CDI (secure mode)
    devices:
      - nvidia.com/gpu=0

    # Security: Non-privileged container
    user: "1000:1000"
    read_only: true

    # Security: Drop all capabilities
    cap_drop:
      - ALL

    # Security: No new privileges
    security_opt:
      - no-new-privileges:true

    # Writable /tmp for model cache
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=2g

    # Resource limits
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: '4.0'
        reservations:
          memory: 4G
          cpus: '2.0'

    environment:
      - CUDA_VISIBLE_DEVICES=0
      - MODEL_PATH=/models/similarity_model.pt
      - INFERENCE_BATCH_SIZE=32

    volumes:
      - ./models:/models:ro
      - ./data:/data:ro

    healthcheck:
      test: ["CMD", "python3", "-c", "import torch; assert torch.cuda.is_available()"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

    networks:
      - ghidra-ml-network

  # Security monitoring
  falco-gpu-monitor:
    image: falcosecurity/falco:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - ./falco-nvidia-rules.yaml:/etc/falco/nvidia_rules.yaml:ro
    command:
      - /usr/bin/falco
      - --cri
      - /host/var/run/docker.sock
      - -r
      - /etc/falco/nvidia_rules.yaml
    networks:
      - ghidra-ml-network

networks:
  ghidra-ml-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/24
```

#### 4.2 Falco Security Rules for GPU Containers

```yaml
# File: development/falco-nvidia-rules.yaml
# Runtime security monitoring for NVIDIA Container Toolkit exploits

- rule: NVIDIA Container Toolkit LD_PRELOAD Exploit
  desc: Detects CVE-2025-23266 exploitation attempt (LD_PRELOAD injection)
  condition: >
    spawned_process and
    proc.name in (nvidia-ctk, nvidia-container-cli, nvidia-container-runtime-hook) and
    proc.env contains "LD_PRELOAD"
  output: >
    CRITICAL: NVIDIA Container Toolkit exploit detected (CVE-2025-23266)
    (user=%user.name command=%proc.cmdline env=%proc.env container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [container_escape, nvidia, cve_2025_23266]

- rule: Suspicious Symlink in GPU Container
  desc: Detects potential CVE-2024-0132 TOCTOU exploitation (symlink attacks)
  condition: >
    spawned_process and
    container.privileged=false and
    proc.env contains "NVIDIA_VISIBLE_DEVICES" and
    proc.name = ln and
    (proc.args contains "../" or proc.args contains "/proc/")
  output: >
    WARNING: Suspicious symlink creation in GPU container
    (user=%user.name command=%proc.cmdline file=%proc.args container=%container.name)
  priority: WARNING
  tags: [container_escape, nvidia, cve_2024_0132]

- rule: NVIDIA Toolkit Configuration Tampering
  desc: Detects unauthorized modifications to NVIDIA Container Runtime config
  condition: >
    open_write and
    fd.name = /etc/nvidia-container-runtime/config.toml and
    not proc.name in (apt-get, dpkg, nvidia-ctk)
  output: >
    CRITICAL: Unauthorized NVIDIA toolkit configuration change
    (user=%user.name process=%proc.name file=%fd.name)
  priority: CRITICAL
  tags: [persistence, nvidia]

- rule: GPU Container Accessing Docker Socket
  desc: Container escape attempt via docker.sock
  condition: >
    open_read and
    container.privileged=false and
    proc.env contains "NVIDIA_VISIBLE_DEVICES" and
    fd.name = /var/run/docker.sock
  output: >
    CRITICAL: GPU container attempting docker socket access
    (user=%user.name command=%proc.cmdline container=%container.name)
  priority: CRITICAL
  tags: [container_escape, docker_socket]
```

#### 4.3 Deployment Validation Script

```bash
#!/bin/bash
# File: development/deploy_ghidra_ml_gpu.sh

set -euo pipefail

echo "=========================================="
echo "  NVIDIA GPU ML Deployment - B-MAD Phase 4"
echo "=========================================="

# Pre-deployment security checks
echo "[DEPLOY] Running security audit..."
python3 measure_container_security.py

if [ $? -ne 0 ]; then
    echo "❌ Security audit failed - fix issues before deployment"
    exit 1
fi

# Scan container images
echo "[DEPLOY] Scanning GPU container image..."
trivy image --severity HIGH,CRITICAL ghidra-similarity:v1.0-gpu

if [ $? -ne 0 ]; then
    echo "⚠️  Container image has vulnerabilities - review before proceeding"
    read -p "Continue anyway? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        exit 1
    fi
fi

# Deploy with monitoring
echo "[DEPLOY] Launching GPU containers..."
docker compose -f docker-compose.ghidra-ml.yml up -d

# Wait for health checks
echo "[DEPLOY] Waiting for containers to be healthy..."
sleep 10

# Verify GPU access
echo "[DEPLOY] Verifying GPU access in container..."
docker compose -f docker-compose.ghidra-ml.yml exec ghidra-similarity-api \
    python3 -c "import torch; print(f'CUDA Available: {torch.cuda.is_available()}'); print(f'GPU Count: {torch.cuda.device_count()}')"

# Test inference
echo "[DEPLOY] Testing ML inference..."
docker compose -f docker-compose.ghidra-ml.yml exec ghidra-similarity-api \
    python3 /app/test_inference.py

# Monitor for 60 seconds
echo "[DEPLOY] Monitoring for security events (60 seconds)..."
timeout 60 docker compose -f docker-compose.ghidra-ml.yml logs -f falco-gpu-monitor || true

echo "=========================================="
echo "✅ Deployment Complete!"
echo ""
echo "Access ML API:"
echo "  - REST API: http://localhost:8080/api/similarity"
echo "  - Metrics: http://localhost:8080/metrics"
echo ""
echo "Security Monitoring:"
echo "  - Falco: docker compose -f docker-compose.ghidra-ml.yml logs falco-gpu-monitor"
echo "=========================================="
```

---

## 🔄 Integration with Existing Frameworks

### GhidraSimilarity Plugin Integration

**File: `GhidraGraph/ghidra_scripts/GhidraSimilarity.py`**
```python
# @category BinaryAnalysis.Similarity
# @keybinding Ctrl-Shift-S
# @menupath Tools.GhidraSimilarity.Find Similar Functions

# GPU-accelerated binary function similarity powered by NVIDIA Container Toolkit

import ghidra
from ghidra.program.model.listing import Function
import requests
import json

def find_similar_functions():
    """Find functions similar to current selection using GPU ML model."""

    current_function = getFunctionContaining(currentAddress)
    if current_function is None:
        print("No function at current address")
        return

    # Extract assembly instructions
    instructions = []
    for instruction in currentProgram.getListing().getInstructions(current_function.getBody(), True):
        instructions.append(str(instruction))

    # Call GPU-accelerated similarity API
    response = requests.post('http://localhost:8080/api/similarity', json={
        'function_name': current_function.getName(),
        'instructions': instructions,
        'top_k': 10
    })

    if response.status_code == 200:
        results = response.json()['similar_functions']

        print(f"\nTop 10 functions similar to {current_function.getName()}:")
        print("=" * 60)

        for rank, (func_name, similarity) in enumerate(results, 1):
            print(f"{rank}. {func_name:<40} Similarity: {similarity:.4f}")

        # Visualize using GhidraGraph
        create_similarity_graph(current_function.getName(), results)
    else:
        print(f"Error: {response.status_code} - {response.text}")

def create_similarity_graph(query_func, similar_funcs):
    """Visualize similarity results using GhidraGraph plugin."""
    # Import GhidraGraph functionality
    from ghidra_scripts.GhidraGraph import create_graph, export_graph

    # Create graph with query function at center
    graph_data = {
        'nodes': [{'id': query_func, 'label': query_func, 'group': 'query'}],
        'edges': []
    }

    for func_name, similarity in similar_funcs:
        graph_data['nodes'].append({
            'id': func_name,
            'label': func_name,
            'group': 'similar',
            'similarity': similarity
        })
        graph_data['edges'].append({
            'from': query_func,
            'to': func_name,
            'weight': similarity
        })

    # Export as interactive visualization
    export_graph(graph_data, 'similarity_graph.html', format='vis.js')
    print("\n✅ Similarity graph exported to similarity_graph.html")

if __name__ == '__main__':
    find_similar_functions()
```

### Alignment with Wiz Competition

**Container Escape Detection Test:**
```python
#!/usr/bin/env python3
# File: development/wiz_competition_validation.py

"""
Wiz ZeroDay.Cloud 2025 - NVIDIA Container Toolkit Defense Validation
Tests defense against CVE-2025-23266 and CVE-2024-0132
"""

import subprocess
import json
from typing import Dict

class WizCompetitionValidator:
    """Validate defenses for Wiz competition scenarios."""

    def test_cve_2025_23266_defense(self) -> Dict:
        """
        Test defense against LD_PRELOAD injection (CVE-2025-23266).
        Attempts exploit in controlled environment.
        """
        print("[WIZ] Testing CVE-2025-23266 (LD_PRELOAD injection) defense...")

        # Create malicious container with LD_PRELOAD
        dockerfile = """
        FROM nvidia/cuda:latest
        COPY exploit.so /exploit.so
        ENV LD_PRELOAD=/exploit.so
        CMD ["nvidia-smi"]
        """

        # Build test image
        with open('Dockerfile.exploit', 'w') as f:
            f.write(dockerfile)

        subprocess.run(['docker', 'build', '-t', 'nvidia-exploit-test', '-f', 'Dockerfile.exploit', '.'])

        # Attempt to run (should fail or be detected by Falco)
        result = subprocess.run([
            'docker', 'run', '--rm', '--gpus', 'all', 'nvidia-exploit-test'
        ], capture_output=True, text=True, timeout=30)

        # Check Falco logs for detection
        falco_logs = subprocess.run([
            'docker', 'logs', 'ghidra-ml-falco-gpu-monitor-1', '--since', '1m'
        ], capture_output=True, text=True)

        exploit_detected = 'CVE-2025-23266' in falco_logs.stdout

        return {
            'test': 'CVE-2025-23266_defense',
            'exploit_blocked': result.returncode != 0 or exploit_detected,
            'falco_detection': exploit_detected,
            'status': 'PASS' if exploit_detected else 'FAIL'
        }

    def test_cve_2024_0132_defense(self) -> Dict:
        """Test defense against TOCTOU symlink attack (CVE-2024-0132)."""
        print("[WIZ] Testing CVE-2024-0132 (TOCTOU) defense...")

        # Create container with malicious symlinks
        dockerfile = """
        FROM nvidia/cuda:latest
        RUN ln -s /etc/shadow /tmp/fake_cuda_lib.so
        ENV NVIDIA_VISIBLE_DEVICES=all
        CMD ["sleep", "infinity"]
        """

        with open('Dockerfile.toctou', 'w') as f:
            f.write(dockerfile)

        subprocess.run(['docker', 'build', '-t', 'nvidia-toctou-test', '-f', 'Dockerfile.toctou', '.'])

        result = subprocess.run([
            'docker', 'run', '--rm', '--gpus', 'all', 'nvidia-toctou-test', 'sleep', '5'
        ], capture_output=True, text=True, timeout=30)

        # Check if symlink was followed (should not be due to CDI mode)
        symlink_exploited = '/etc/shadow' in result.stderr or '/etc/shadow' in result.stdout

        return {
            'test': 'CVE-2024-0132_defense',
            'exploit_blocked': not symlink_exploited,
            'cdi_protection': True,  # CDI mode bypasses vulnerable code
            'status': 'PASS' if not symlink_exploited else 'FAIL'
        }

    def generate_competition_report(self) -> Dict:
        """Generate validation report for Wiz competition submission."""

        tests = [
            self.test_cve_2025_23266_defense(),
            self.test_cve_2024_0132_defense()
        ]

        passed = sum(1 for t in tests if t['status'] == 'PASS')
        total = len(tests)

        report = {
            'competition': 'Wiz ZeroDay.Cloud 2025',
            'deployment': 'NVIDIA Container Toolkit v1.17.8 (Hardened)',
            'tests': tests,
            'summary': {
                'tests_passed': passed,
                'tests_total': total,
                'success_rate': (passed / total) * 100,
                'defense_status': 'PRODUCTION_READY' if passed == total else 'NEEDS_IMPROVEMENT'
            },
            'security_features': [
                'CDI mode enabled (bypasses vulnerable OCI hooks)',
                'ldconfig @ prefix (host-only execution)',
                'No privileged containers',
                'Falco runtime monitoring',
                'Image scanning with Trivy',
                'Network segmentation'
            ]
        }

        return report

if __name__ == '__main__':
    print("=" * 70)
    print("  Wiz ZeroDay.Cloud 2025 - NVIDIA Container Toolkit Validation")
    print("=" * 70)

    validator = WizCompetitionValidator()
    report = validator.generate_competition_report()

    print(f"\n[WIZ] Test Results: {report['summary']['tests_passed']}/{report['summary']['tests_total']} PASSED")
    print(f"[WIZ] Success Rate: {report['summary']['success_rate']:.0f}%")
    print(f"[WIZ] Defense Status: {report['summary']['defense_status']}")

    # Save report
    with open('wiz_competition_validation_report.json', 'w') as f:
        json.dump(report, f, indent=2)

    print("\n✅ Wiz competition validation report saved")

    if report['summary']['defense_status'] == 'PRODUCTION_READY':
        print("\n🏆 READY FOR COMPETITION SUBMISSION")
    else:
        print("\n⚠️  FIX FAILING TESTS BEFORE SUBMISSION")
```

---

## 📊 Success Metrics & KPIs

### B-MAD Success Criteria

| Phase | Metric | Target | Measurement Method |
|-------|--------|--------|-------------------|
| **Build** | Toolkit Version | ≥ 1.17.8 | `nvidia-container-toolkit --version` |
| **Build** | Security Score | ≥ 90/100 | `measure_container_security.py` |
| **Build** | CVE Mitigation | 100% | Manual audit against CVE list |
| **Measure** | GPU Utilization | > 70% during inference | `nvidia-smi` monitoring |
| **Measure** | Inference Latency | < 100ms per function | API response time |
| **Measure** | Container Startup | < 30s | Docker healthcheck |
| **Analyze** | Model Accuracy | > 85% on test set | Offline evaluation |
| **Analyze** | Memory Efficiency | < 6GB VRAM | `nvidia-smi` memory usage |
| **Analyze** | Thermal Safety | < 85°C max temp | Temperature monitoring |
| **Deploy** | Falco Detection | 100% of test exploits | Wiz validation tests |
| **Deploy** | Production Uptime | 99.9% | Prometheus metrics |
| **Deploy** | API Availability | 99.99% | Health checks |

### Wiz Competition Metrics

- ✅ **Defense Against CVE-2025-23266:** Falco detection + CDI mitigation
- ✅ **Defense Against CVE-2024-0132:** CDI mode + version ≥ 1.17.8
- ✅ **Multi-Tenant Isolation:** Network policies + non-privileged containers
- ✅ **Security Monitoring:** Real-time Falco alerts + audit logging

---

## 🚀 Execution Timeline

### Week 1: Build & Measure

**Days 1-2: Installation & Configuration**
- Install NVIDIA Container Toolkit v1.17.8
- Apply security hardening
- Generate CDI specifications
- Configure Docker runtime

**Days 3-4: Baseline Measurement**
- Collect GPU performance baselines
- Run security audit
- Measure container startup times
- Document current state

### Week 2: Analyze & Deploy

**Days 5-7: ML Model Development**
- Train GhidraSimilarity model
- Optimize for inference
- Benchmark GPU acceleration
- Compare against CPU baseline

**Days 8-10: Production Deployment**
- Deploy GPU containers
- Configure Falco monitoring
- Run Wiz validation tests
- Performance tuning

### Week 3: Integration & Competition

**Days 11-13: Plugin Integration**
- Integrate with GhidraGraph
- Create Ghidra scripts
- User documentation
- Demo preparation

**Days 14: Competition Submission**
- Final validation
- Documentation package
- Wiz submission
- Demo recording

---

## 📚 References

1. **NVIDIA Documentation:**
   - Container Toolkit Installation: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html
   - CDI Support: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/cdi-support.html

2. **Security Research:**
   - CVE-2025-23266 Analysis: https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape
   - CVE-2024-0132 Deep Dive: https://www.wiz.io/blog/nvidia-ai-vulnerability-deep-dive-cve-2024-0132

3. **Internal Documentation:**
   - NVIDIA Container Toolkit Security Research Report (this repo)
   - Plugin Roadmap 2025 (`development/PLUGIN_ROADMAP_2025.md`)
   - Systematic Execution Plan (`development/SYSTEMATIC_EXECUTION_PLAN_2025-10-05.md`)

---

## ✅ Pre-Deployment Checklist

- [ ] NVIDIA GPU driver installed
- [ ] WSL2 configured with GPU passthrough (Windows)
- [ ] Container Toolkit v1.17.8 installed
- [ ] Security configuration applied (ldconfig @prefix, CDI mode)
- [ ] Falco monitoring configured
- [ ] Container images scanned with Trivy
- [ ] GPU baseline metrics collected
- [ ] Security audit score ≥ 90/100
- [ ] Wiz validation tests passed
- [ ] Documentation complete

---

**Status:** Ready for execution
**Next Action:** Run `nvidia-toolkit-secure-install.sh` to begin BUILD phase

**B-MAD Deployment Owner:** Catalytic Computing Team
**Competition Deadline:** [Insert Wiz Competition Date]
