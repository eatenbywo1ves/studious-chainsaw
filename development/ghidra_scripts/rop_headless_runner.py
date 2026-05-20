#!/usr/bin/env python3
"""
Headless ROP Gadget Discovery Runner

Run ROP gadget analysis using Ghidra's headless analyzer.

Usage:
    python rop_headless_runner.py <binary_path> [--output-dir <dir>]

Requirements:
    - Ghidra installation
    - GHIDRA_INSTALL_DIR environment variable set

Author: Claude Code / Corbin
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def get_ghidra_path():
    """Get Ghidra installation directory."""
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir:
        # Try common locations
        common_paths = [
            "C:/Users/Corbin/development/ghidra_11.4.2_PUBLIC",
            "/opt/ghidra",
            os.path.expanduser("~/ghidra"),
        ]
        for path in common_paths:
            if os.path.exists(path):
                ghidra_dir = path
                break

    if not ghidra_dir or not os.path.exists(ghidra_dir):
        raise EnvironmentError(
            "GHIDRA_INSTALL_DIR not set and Ghidra not found in common locations"
        )

    return ghidra_dir


def detect_architecture(binary_path):
    """Detect binary architecture using file magic or ELF headers."""
    try:
        with open(binary_path, "rb") as f:
            magic = f.read(20)

        # ELF magic
        if magic[:4] == b"\x7fELF":
            bits = magic[4]  # 1 = 32-bit, 2 = 64-bit
            machine = magic[18:20]

            # Machine type (little-endian)
            machine_type = int.from_bytes(machine, "little")

            machine_map = {
                0x03: "x86",
                0x3E: "x86-64",
                0x28: "ARM",
                0xB7: "AARCH64",
                0x08: "MIPS",
            }

            return machine_map.get(machine_type, "unknown")

        # PE magic (MZ)
        elif magic[:2] == b"MZ":
            # Need to check PE header for machine type
            f.seek(0)
            data = f.read(1024)
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if pe_offset < len(data) - 6:
                machine = int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")
                pe_machines = {
                    0x014C: "x86",
                    0x8664: "x86-64",
                    0x01C0: "ARM",
                    0xAA64: "AARCH64",
                }
                return pe_machines.get(machine, "unknown")

        return "unknown"
    except Exception as e:
        print(f"[!] Architecture detection failed: {e}")
        return "unknown"


def run_ghidra_headless(binary_path, output_dir, script_path):
    """Run Ghidra headless analysis with ROP finder script."""
    ghidra_dir = get_ghidra_path()

    # Platform-specific headless analyzer
    if sys.platform == "win32":
        analyzer = os.path.join(ghidra_dir, "support", "analyzeHeadless.bat")
    else:
        analyzer = os.path.join(ghidra_dir, "support", "analyzeHeadless")

    if not os.path.exists(analyzer):
        raise FileNotFoundError(f"Ghidra headless analyzer not found: {analyzer}")

    # Create temporary project directory
    project_dir = tempfile.mkdtemp(prefix="ghidra_rop_")
    project_name = "rop_analysis"

    binary_name = Path(binary_path).stem

    # Build command
    cmd = [
        analyzer,
        project_dir,
        project_name,
        "-import",
        binary_path,
        "-postScript",
        script_path,
        output_dir,
        binary_name,
        "-deleteProject",  # Clean up after
    ]

    print("[*] Running Ghidra headless analysis...")
    print(f"[*] Binary: {binary_path}")
    print(f"[*] Output: {output_dir}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        if result.returncode != 0:
            print("[!] Ghidra analysis failed:")
            print(result.stderr)
            return False

        print(result.stdout)
        return True

    except subprocess.TimeoutExpired:
        print("[!] Analysis timed out after 10 minutes")
        return False
    except Exception as e:
        print(f"[!] Error running Ghidra: {e}")
        return False


def create_headless_script():
    """Create the headless post-script for ROP analysis."""
    script = '''# Headless ROP Analysis Script
# @author Claude Code
# @category ROP

import os
import sys
import json
from datetime import datetime

# Get arguments passed from command line
args = getScriptArgs()
output_dir = args[0] if len(args) > 0 else "."
binary_name = args[1] if len(args) > 1 else currentProgram.getName()

print("[*] Starting ROP gadget analysis...")
print(f"[*] Output directory: {output_dir}")

# Import the ROP finder
from rop_gadget_finder import RopGadgetFinder

# Run analysis
finder = RopGadgetFinder(currentProgram)
print(f"[*] Architecture detected: {finder.architecture}")

gadgets = finder.find_gadgets()
print(f"[+] Found {len(gadgets)} gadgets")

# Save reports
md_path = os.path.join(output_dir, f"{binary_name}_rop_report.md")
finder.generate_report(md_path)

json_path = os.path.join(output_dir, f"{binary_name}_rop_gadgets.json")
finder.export_json(json_path)

print(f"[+] Analysis complete!")
print(f"[+] Report: {md_path}")
print(f"[+] JSON: {json_path}")
'''
    return script


def main():
    parser = argparse.ArgumentParser(
        description="Run ROP gadget analysis using Ghidra headless analyzer"
    )
    parser.add_argument("binary", help="Path to binary to analyze")
    parser.add_argument(
        "--output-dir",
        "-o",
        default=".",
        help="Output directory for reports (default: current directory)",
    )
    parser.add_argument(
        "--architecture",
        "-a",
        choices=["ARM", "MIPS", "x86", "x86-64", "AARCH64", "auto"],
        default="auto",
        help="Binary architecture (default: auto-detect)",
    )

    args = parser.parse_args()

    # Validate binary path
    if not os.path.exists(args.binary):
        print(f"[!] Binary not found: {args.binary}")
        sys.exit(1)

    # Create output directory if needed
    os.makedirs(args.output_dir, exist_ok=True)

    # Detect architecture
    arch = args.architecture
    if arch == "auto":
        arch = detect_architecture(args.binary)
        print(f"[*] Detected architecture: {arch}")

    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_script = os.path.join(script_dir, "rop_gadget_finder.py")

    if not os.path.exists(main_script):
        print(f"[!] ROP finder script not found: {main_script}")
        sys.exit(1)

    # Create headless script
    headless_script_path = os.path.join(script_dir, "rop_headless_post.py")
    with open(headless_script_path, "w") as f:
        f.write(create_headless_script())

    # Run analysis
    success = run_ghidra_headless(
        args.binary, args.output_dir, headless_script_path
    )

    if success:
        print("\n[+] ROP analysis complete!")
        print(f"[+] Check {args.output_dir} for reports")
    else:
        print("\n[!] ROP analysis failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
