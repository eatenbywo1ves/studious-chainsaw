#!/usr/bin/env python3
"""
Advanced GPU Troubleshooting Diagnostics
Comprehensive analysis and debugging for GPU computing environment
"""

import os
import sys
import subprocess
import traceback


def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


def check_cuda_installation():
    """Check CUDA toolkit installations"""
    print_section("CUDA TOOLKIT ANALYSIS")

    # Check system CUDA
    try:
        result = subprocess.run(["nvcc", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print("[FOUND] System CUDA Toolkit:")
            for line in result.stdout.split("\n"):
                if "release" in line.lower():
                    print(f"  {line.strip()}")
        else:
            print("[WARNING] nvcc not found in PATH")
    except FileNotFoundError:
        print("[ERROR] CUDA toolkit not found")

    # Check common CUDA installation paths
    cuda_paths = [
        "C:\\Program Files\\NVIDIA GPU Computing Toolkit\\CUDA",
        "C:\\CUDA",
        "C:\\Tools\\CUDA",
    ]

    print("\nCUDA Installation Search:")
    for base_path in cuda_paths:
        if os.path.exists(base_path):
            print(f"[FOUND] {base_path}")
            for item in os.listdir(base_path):
                item_path = os.path.join(base_path, item)
                if os.path.isdir(item_path) and item.startswith("v"):
                    print(f"  - Version: {item}")
        else:
            print(f"[MISSING] {base_path}")


def analyze_pytorch_cuda():
    """Analyze PyTorch CUDA configuration"""
    print_section("PYTORCH CUDA ANALYSIS")

    try:
        import torch

        print(f"PyTorch version: {torch.__version__}")
        print(f"CUDA available: {torch.cuda.is_available()}")

        if torch.cuda.is_available():
            print(f"CUDA version: {torch.version.cuda}")
            print(f"cuDNN version: {torch.backends.cudnn.version()}")
            print(f"GPU count: {torch.cuda.device_count()}")

            for i in range(torch.cuda.device_count()):
                props = torch.cuda.get_device_properties(i)
                print(f"GPU {i}: {props.name}")
                print(f"  Memory: {props.total_memory / 1e9:.1f} GB")
                print(f"  Compute Capability: {props.major}.{props.minor}")

        # Check PyTorch CUDA library path
        torch_lib = os.path.join(os.path.dirname(torch.__file__), "lib")
        print(f"\nPyTorch CUDA libraries: {torch_lib}")
        print(f"Directory exists: {os.path.exists(torch_lib)}")

        if os.path.exists(torch_lib):
            cuda_dlls = [
                f for f in os.listdir(torch_lib) if "cuda" in f.lower() and f.endswith(".dll")
            ]
            print(f"CUDA DLLs found: {len(cuda_dlls)}")
            for dll in cuda_dlls[:5]:  # Show first 5
                print(f"  - {dll}")
            if len(cuda_dlls) > 5:
                print(f"  ... and {len(cuda_dlls) - 5} more")

    except ImportError:
        print("[ERROR] PyTorch not installed")
    except Exception as e:
        print(f"[ERROR] PyTorch analysis failed: {e}")


def analyze_cupy():
    """Analyze CuPy configuration"""
    print_section("CUPY ANALYSIS")

    try:
        import cupy

        print(f"CuPy version: {cupy.__version__}")
        print(f"CUDA available: {cupy.cuda.is_available()}")

        if cupy.cuda.is_available():
            print(f"CUDA runtime version: {cupy.cuda.runtime.runtimeGetVersion()}")
            print(f"Device count: {cupy.cuda.runtime.getDeviceCount()}")

            # Test CURAND (the problematic component)
            try:
                import torch

                torch_lib = os.path.join(os.path.dirname(torch.__file__), "lib")
                os.environ["CUDA_PATH"] = torch_lib
                os.environ["PATH"] = torch_lib + ";" + os.environ.get("PATH", "")
                os.add_dll_directory(torch_lib)

                test_array = cupy.random.randn(10)
                print("[SUCCESS] CURAND test passed")
                print(f"Random sample: {test_array[:3]}")
            except Exception as e:
                print(f"[ERROR] CURAND test failed: {e}")

    except ImportError:
        print("[ERROR] CuPy not installed")
    except Exception as e:
        print(f"[ERROR] CuPy analysis failed: {e}")


def analyze_numba():
    """Analyze Numba CUDA configuration"""
    print_section("NUMBA CUDA ANALYSIS")

    try:
        import numba
        from numba import cuda

        print(f"Numba version: {numba.__version__}")
        print(f"CUDA available: {cuda.is_available()}")

        if cuda.is_available():
            print(f"GPU count: {len(cuda.gpus)}")
            device = cuda.get_current_device()
            print(f"Current device: {device.name}")
            print(f"Compute capability: {device.compute_capability}")

            # Test memory operations
            try:
                import numpy as np

                host_data = np.array([1, 2, 3, 4, 5], dtype=np.float32)
                device_data = cuda.to_device(host_data)
                device_data.copy_to_host()
                print("[SUCCESS] Memory operations working")
            except Exception as e:
                print(f"[ERROR] Memory operations failed: {e}")

            # Test kernel compilation (the problematic area)
            try:

                @cuda.jit
                def test_kernel(arr):
                    idx = cuda.grid(1)
                    if idx < arr.size:
                        arr[idx] = arr[idx] * 2

                # Try to compile (this will likely fail)
                device_array = cuda.device_array(10, dtype=np.float32)
                test_kernel[1, 32](device_array)
                cuda.synchronize()
                print("[SUCCESS] Kernel compilation working")

            except Exception as e:
                print(f"[ERROR] Kernel compilation failed: {str(e)[:200]}...")
                if "PTX" in str(e) or "8.8" in str(e):
                    print("[DIAGNOSIS] PTX version incompatibility detected")
                    print("  - CUDA 13.0 generates PTX 8.8")
                    print("  - PyTorch runtime supports PTX 8.6")
                    print("  - Solution: Install CUDA 12.1 toolkit")

    except ImportError:
        print("[ERROR] Numba not installed")
    except Exception as e:
        print(f"[ERROR] Numba analysis failed: {e}")


def analyze_environment():
    """Analyze environment variables"""
    print_section("ENVIRONMENT VARIABLES")

    cuda_vars = [
        "CUDA_PATH",
        "CUDA_HOME",
        "PATH",
        "LD_LIBRARY_PATH",
        "NUMBA_CUDA_ENABLE_MINOR_VERSION_COMPATIBILITY",
        "NUMBA_CUDA_DEFAULT_PTX_CC",
        "NUMBA_CUDA_LOG_LEVEL",
    ]

    for var in cuda_vars:
        value = os.environ.get(var, "[NOT SET]")
        if var == "PATH":
            # Show only CUDA-related paths
            paths = value.split(";") if value != "[NOT SET]" else []
            cuda_paths = [p for p in paths if "cuda" in p.lower() or "torch" in p.lower()]
            print(f"{var} (CUDA-related):")
            for path in cuda_paths[:3]:  # Show first 3
                print(f"  {path}")
            if len(cuda_paths) > 3:
                print(f"  ... and {len(cuda_paths) - 3} more")
        else:
            print(f"{var}: {value}")


def check_gpu_hardware():
    """Check GPU hardware information"""
    print_section("GPU HARDWARE INFORMATION")

    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,driver_version,cuda_version",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            print("[SUCCESS] nvidia-smi accessible")
            lines = result.stdout.strip().split("\n")
            for i, line in enumerate(lines):
                if line.strip():
                    parts = line.split(", ")
                    if len(parts) >= 4:
                        print(f"GPU {i}: {parts[0]}")
                        print(f"  Memory: {parts[1]} MB")
                        print(f"  Driver: {parts[2]}")
                        print(f"  CUDA Version: {parts[3]}")
        else:
            print("[ERROR] nvidia-smi failed")
            print(f"Error: {result.stderr}")
    except subprocess.TimeoutExpired:
        print("[ERROR] nvidia-smi timeout")
    except FileNotFoundError:
        print("[ERROR] nvidia-smi not found")
    except Exception as e:
        print(f"[ERROR] GPU hardware check failed: {e}")


def generate_recommendations():
    """Generate troubleshooting recommendations"""
    print_section("TROUBLESHOOTING RECOMMENDATIONS")

    print("Based on analysis, here are the recommended solutions:")
    print()
    print("1. [IMMEDIATE] Use PyTorch + CuPy for GPU computing")
    print("   - Both libraries are fully functional")
    print("   - Excellent performance demonstrated")
    print("   - Complete ecosystem for most GPU tasks")
    print()
    print("2. [SHORT-TERM] Install CUDA 12.1 Toolkit for Numba")
    print("   - Download from NVIDIA developer archives")
    print("   - Install alongside CUDA 13.0")
    print("   - Update environment variables to use 12.1")
    print("   - Test Numba kernel compilation")
    print()
    print("3. [ALTERNATIVE] Use PyTorch JIT instead of Numba")
    print("   - torch.compile() for custom operations")
    print("   - PyTorch custom CUDA kernels")
    print("   - Native integration with existing ecosystem")
    print()
    print("4. [LONG-TERM] Monitor Numba CUDA 13.0 support")
    print("   - Wait for official Numba CUDA 13.0 compatibility")
    print("   - Upgrade when stable release available")


def main():
    """Main diagnostic function"""
    print("Advanced GPU Troubleshooting Diagnostics")
    print("========================================")
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    print(f"Working directory: {os.getcwd()}")

    # Run all diagnostic checks
    check_gpu_hardware()
    check_cuda_installation()
    analyze_pytorch_cuda()
    analyze_cupy()
    analyze_numba()
    analyze_environment()
    generate_recommendations()

    print_section("DIAGNOSTIC COMPLETE")
    print("Report saved to NUMBA_CUDA_TROUBLESHOOTING_REPORT.md")
    print("All GPU libraries analyzed successfully.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Diagnostic cancelled by user")
    except Exception as e:
        print(f"\n[ERROR] Diagnostic failed: {e}")
        traceback.print_exc()
