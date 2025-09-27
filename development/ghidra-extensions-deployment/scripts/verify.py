#!/usr/bin/env python3
"""
Ghidra Extensions Installation Verification Script
Verifies that extensions are properly installed and configured
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import List, Tuple


# Color codes for terminal output
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def print_success(message: str) -> None:
    """Print success message in green."""
    try:
        print(f"{Colors.GREEN}✓ {message}{Colors.ENDC}")
    except UnicodeEncodeError:
        print(f"{Colors.GREEN}[OK] {message}{Colors.ENDC}")


def print_error(message: str) -> None:
    """Print error message in red."""
    try:
        print(f"{Colors.RED}✗ {message}{Colors.ENDC}")
    except UnicodeEncodeError:
        print(f"{Colors.RED}[ERROR] {message}{Colors.ENDC}")


def print_warning(message: str) -> None:
    """Print warning message in yellow."""
    try:
        print(f"{Colors.YELLOW}⚠ {message}{Colors.ENDC}")
    except UnicodeEncodeError:
        print(f"{Colors.YELLOW}[WARNING] {message}{Colors.ENDC}")


def print_info(message: str) -> None:
    """Print info message in blue."""
    try:
        print(f"{Colors.BLUE}ℹ {message}{Colors.ENDC}")
    except UnicodeEncodeError:
        print(f"{Colors.BLUE}[INFO] {message}{Colors.ENDC}")


def find_ghidra_installation() -> str:
    """Find Ghidra installation directory."""
    # Check environment variable first
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if ghidra_dir and os.path.exists(ghidra_dir):
        return ghidra_dir

    # Search common locations
    if sys.platform == "win32":
        home = Path.home()
        search_paths = [
            # User development directories
            str(home / "development" / "ghidra*"),
            str(home / "dev" / "ghidra*"),
            str(home / "Downloads" / "ghidra*"),
            # System directories
            r"C:\ghidra*",
            r"C:\Tools\ghidra*",
            r"C:\Program Files\ghidra*",
            r"D:\ghidra*",
            r"D:\Tools\ghidra*",
        ]
    else:
        search_paths = [
            # User directories
            os.path.expanduser("~/development/ghidra*"),
            os.path.expanduser("~/dev/ghidra*"),
            os.path.expanduser("~/Downloads/ghidra*"),
            os.path.expanduser("~/ghidra*"),
            os.path.expanduser("~/tools/ghidra*"),
            # System directories
            "/opt/ghidra*",
            "/usr/local/ghidra*",
            "/Applications/ghidra*",
        ]

    for pattern in search_paths:
        try:
            paths = Path(pattern.replace("*", "")).parent.glob(Path(pattern).name)
            for path in paths:
                if path.is_dir():
                    run_script = (
                        "ghidraRun.bat" if sys.platform == "win32" else "ghidraRun"
                    )
                    if (path / run_script).exists():
                        return str(path)
        except (OSError, FileNotFoundError):
            # Skip paths that don't exist or can't be accessed
            continue

    return None


def get_ghidra_version(ghidra_dir: str) -> str:
    """Extract Ghidra version from application.properties."""
    props_file = Path(ghidra_dir) / "Ghidra" / "application.properties"
    if not props_file.exists():
        return "unknown"

    try:
        with open(props_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
    except (IOError, OSError):
        pass

    return "unknown"


def get_extensions_directory(ghidra_version: str) -> Path:
    """Get the user's Ghidra extensions directory."""
    home = Path.home()
    ghidra_dir = home / ".ghidra"

    # Try different version suffixes in order of preference
    version_suffixes = ["_DEV", "_PUBLIC", "_build", ""]

    for suffix in version_suffixes:
        candidate_dir = ghidra_dir / f".ghidra_{ghidra_version}{suffix}" / "Extensions"
        if candidate_dir.parent.exists():
            return candidate_dir

    # Fallback to the original _DEV pattern if nothing is found
    return ghidra_dir / f".ghidra_{ghidra_version}_DEV" / "Extensions"


def verify_extension(
    ext_dir: Path, ext_name: str, required_files: List[str]
) -> Tuple[bool, List[str]]:
    """Verify that an extension is properly installed."""
    ext_path = ext_dir / ext_name
    missing_files = []

    if not ext_path.exists():
        return False, [f"Extension directory '{ext_name}' not found"]

    for req_file in required_files:
        if not (ext_path / req_file).exists():
            missing_files.append(req_file)

    if missing_files:
        return False, missing_files

    return True, []


def verify_installation(verbose: bool = False) -> bool:
    """Verify complete installation."""
    print(f"{Colors.BOLD}Ghidra Extensions Installation Verification" f"{Colors.ENDC}")
    print("=" * 50)

    all_good = True

    # Step 1: Find Ghidra installation
    print("\n1. Checking Ghidra Installation")
    ghidra_dir = find_ghidra_installation()

    if not ghidra_dir:
        print_error("Ghidra installation not found")
        print_info("Please set GHIDRA_INSTALL_DIR environment variable")
        return False

    print_success(f"Found Ghidra at: {ghidra_dir}")

    # Step 2: Get version
    ghidra_version = get_ghidra_version(ghidra_dir)
    print_success(f"Ghidra version: {ghidra_version}")

    # Step 3: Check Extensions directory
    print("\n2. Checking Extensions Directory")
    extensions_dir = get_extensions_directory(ghidra_version)

    if not extensions_dir.exists():
        print_error(f"Extensions directory not found: {extensions_dir}")
        all_good = False
    else:
        print_success(f"Extensions directory: {extensions_dir}")

    if verbose and extensions_dir.exists():
        installed_extensions = [d.name for d in extensions_dir.iterdir() if d.is_dir()]
        if installed_extensions:
            print_info(f"Installed extensions: {', '.join(installed_extensions)}")

    # Step 4: Verify CryptoDetect
    print("\n3. Verifying CryptoDetect Extension")
    crypto_files = ["extension.properties"]
    crypto_success, crypto_missing = verify_extension(
        extensions_dir, "crypto_detect", crypto_files
    )

    if crypto_success:
        print_success("CryptoDetect extension installed correctly")
        if verbose:
            crypto_path = extensions_dir / "crypto_detect"
            print_info(f"  Location: {crypto_path}")
            java_files = list(crypto_path.rglob("*.java"))
            if java_files:
                print_info(f"  Source files: {len(java_files)} Java files found")
    else:
        print_error("CryptoDetect extension verification failed")
        for missing in crypto_missing:
            print_error(f"  Missing: {missing}")
        all_good = False

    # Step 5: Verify RetSync
    print("\n4. Verifying RetSync Extension")
    retsync_files = ["extension.properties"]
    retsync_success, retsync_missing = verify_extension(
        extensions_dir, "retsync", retsync_files
    )

    if retsync_success:
        print_success("RetSync extension installed correctly")
        if verbose:
            retsync_path = extensions_dir / "retsync"
            print_info(f"  Location: {retsync_path}")
            jar_files = list(retsync_path.rglob("*.jar"))
            if jar_files:
                print_info(f"  Library files: {len(jar_files)} JAR files found")
    else:
        print_error("RetSync extension verification failed")
        for missing in retsync_missing:
            print_error(f"  Missing: {missing}")
        all_good = False

    # Step 6: Check Java version
    print("\n5. Checking Java Environment")
    try:
        result = subprocess.run(["java", "-version"], capture_output=True, text=True)
        if result.returncode == 0:
            # Java version info goes to stderr
            java_output = (
                result.stderr.split("\n")[0]
                if result.stderr
                else result.stdout.split("\n")[0]
            )
            print_success(f"Java found: {java_output}")

            # Check for Java 17+
            version_text = result.stderr if result.stderr else result.stdout
            versions = [
                'version "17',
                'version "18',
                'version "19',
                'version "20',
                'version "21',
            ]
            if any(version in version_text for version in versions):
                print_success("Java version 17+ detected (recommended)")
            else:
                print_warning("Java 17+ is recommended for Ghidra 12.0+")
        else:
            print_error("Could not determine Java version")
            all_good = False
    except FileNotFoundError:
        print_error("Java not found in PATH")
        all_good = False

    # Step 7: Summary
    print("\n" + "=" * 50)
    if all_good:
        try:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ All checks passed!" f"{Colors.ENDC}")
        except UnicodeEncodeError:
            print(
                f"{Colors.GREEN}{Colors.BOLD}[SUCCESS] All checks passed!"
                f"{Colors.ENDC}"
            )
        print("\nNext steps:")
        print("1. Start Ghidra")
        print("2. Navigate to File -> Configure -> Extensions")
        print("3. Enable the extensions")
        print("4. Restart Ghidra")
    else:
        try:
            print(f"{Colors.RED}{Colors.BOLD}✗ Some checks failed" f"{Colors.ENDC}")
        except UnicodeEncodeError:
            print(
                f"{Colors.RED}{Colors.BOLD}[ERROR] Some checks failed" f"{Colors.ENDC}"
            )
        print("\nPlease run the installation script again or " "check the errors above")

    return all_good


def generate_report(output_file: str = None) -> None:
    """Generate a detailed verification report."""
    report_data = {
        "ghidra_installation": {},
        "extensions": {},
        "java_environment": {},
        "verification_status": "unknown",
    }

    # Save report to file if specified
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        print_info(f"Report saved to: {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Verify Ghidra extensions installation"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-r", "--report", type=str, help="Generate detailed report to file"
    )
    args = parser.parse_args()

    success = verify_installation(verbose=args.verbose)

    if args.report:
        generate_report(args.report)

    if not success:
        exit(1)


if __name__ == "__main__":
    main()
