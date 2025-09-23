#!/usr/bin/env python3
"""
Windows-compatible TMUX integration test
"""

import subprocess
import sys
from pathlib import Path


class WindowsTMUXTester:
    """Windows-compatible test suite for TMUX integration"""

    def __init__(self):
        self.dev_path = Path(__file__).parent

    def check_tmux_available(self):
        """Check if tmux is available"""
        print("Checking tmux availability...")

        # Check system tmux (via WSL or Git Bash)
        try:
            result = subprocess.run(["tmux", "-V"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[OK] System tmux found: {result.stdout.strip()}")
                return "system"
        except FileNotFoundError:
            print("[FAIL] System tmux not found")

        # Check custom tmux-clone
        tmux_clone_path = self.dev_path / "tmux-clone"
        if tmux_clone_path.exists():
            print("[OK] Custom tmux-clone directory found")

            # Check if binary exists or can be built
            bin_path = tmux_clone_path / "bin" / "tmux-clone"
            if bin_path.exists():
                print("[OK] tmux-clone binary exists")
                return "custom"
            else:
                print("[WARN] tmux-clone binary not built yet")
                makefile_path = tmux_clone_path / "Makefile"
                if makefile_path.exists():
                    print("[OK] tmux-clone can be built (Makefile exists)")
                    return "buildable"
        else:
            print("[FAIL] Custom tmux-clone not found")

        return None

    def test_configuration_files(self):
        """Test that all configuration files exist and are readable"""
        print("\nTesting configuration files...")

        config_files = [
            (".tmux.conf", "Main tmux configuration"),
            (".tmux-workflows/development-layout", "Development layout"),
            (".tmux-workflows/orchestrator-layout", "Orchestrator layout"),
            (".tmux-workflows/monitoring-layout", "Monitoring layout"),
            (".tmux-workflows/debug-layout", "Debug layout"),
        ]

        all_exist = True
        for relative_path, description in config_files:
            config_file = self.dev_path / relative_path
            if config_file.exists():
                try:
                    with open(config_file, "r", encoding="utf-8") as f:
                        content_length = len(f.read())
                    print(
                        f"[OK] {description}: {config_file.name} ({content_length} chars)"
                    )
                except Exception as e:
                    print(f"[FAIL] {description}: {config_file.name} - read error: {e}")
                    all_exist = False
            else:
                print(f"[FAIL] {description}: {config_file.name} - missing")
                all_exist = False

        return all_exist

    def test_workflow_layout_syntax(self):
        """Test workflow layout files for basic syntax"""
        print("\nTesting workflow layout syntax...")

        layout_files = [
            "development-layout",
            "orchestrator-layout",
            "monitoring-layout",
            "debug-layout",
        ]

        all_valid = True
        for layout_file in layout_files:
            layout_path = self.dev_path / ".tmux-workflows" / layout_file

            if not layout_path.exists():
                print(f"[FAIL] Layout missing: {layout_file}")
                all_valid = False
                continue

            try:
                with open(layout_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Basic checks for tmux commands
                required_commands = ["new-session", "new-window", "split-window"]
                missing_commands = []

                for cmd in required_commands:
                    if cmd not in content:
                        missing_commands.append(cmd)

                if missing_commands:
                    print(f"[WARN] {layout_file}: Missing commands: {missing_commands}")
                else:
                    print(f"[OK] {layout_file}: Contains required tmux commands")

            except Exception as e:
                print(f"[FAIL] {layout_file}: Read error: {e}")
                all_valid = False

        return all_valid

    def test_directory_structure(self):
        """Test that required directories exist"""
        print("\nTesting directory structure...")

        required_dirs = [
            ("shared/libraries", "Core libraries"),
            ("shared/orchestration", "Orchestration components"),
            ("shared/event_sourcing", "Event sourcing"),
            ("logs", "Log directory"),
            (".tmux-workflows", "TMUX workflow layouts"),
        ]

        all_exist = True
        for rel_path, description in required_dirs:
            dir_path = self.dev_path / rel_path

            if rel_path == "logs" and not dir_path.exists():
                try:
                    dir_path.mkdir(exist_ok=True)
                    print(f"[OK] {description}: Created {rel_path}/")
                except Exception as e:
                    print(f"[FAIL] {description}: Could not create {rel_path}/ - {e}")
                    all_exist = False
            elif dir_path.exists():
                print(f"[OK] {description}: {rel_path}/")
            else:
                print(f"[FAIL] {description}: {rel_path}/ - missing")
                all_exist = False

        return all_exist

    def test_tmux_clone_structure(self):
        """Test tmux-clone project structure"""
        print("\nTesting tmux-clone structure...")

        tmux_clone_path = self.dev_path / "tmux-clone"
        if not tmux_clone_path.exists():
            print("[FAIL] tmux-clone directory not found")
            return False

        required_files = ["README.md", "Makefile", "src/main.c", "include/tmux.h"]

        all_exist = True
        for file_path in required_files:
            full_path = tmux_clone_path / file_path
            if full_path.exists():
                print(f"[OK] {file_path}")
            else:
                print(f"[FAIL] {file_path} - missing")
                all_exist = False

        return all_exist

    def run_all_tests(self):
        """Run all tests"""
        print("Starting TMUX integration tests")
        print("=" * 50)

        # Check tmux availability first
        tmux_type = self.check_tmux_available()

        tests = [
            ("Directory Structure", self.test_directory_structure),
            ("Configuration Files", self.test_configuration_files),
            ("Workflow Layout Syntax", self.test_workflow_layout_syntax),
            ("TMUX-Clone Structure", self.test_tmux_clone_structure),
        ]

        passed = 0
        failed = 0

        for test_name, test_func in tests:
            print(f"\nRunning: {test_name}")
            try:
                result = test_func()

                if result:
                    passed += 1
                    print(f"[PASS] {test_name}")
                else:
                    failed += 1
                    print(f"[FAIL] {test_name}")

            except Exception as e:
                failed += 1
                print(f"[ERROR] {test_name} - {e}")

        print("\n" + "=" * 50)
        print("Test Results Summary")
        print("=" * 50)
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Success Rate: {passed / (passed + failed) * 100:.1f}%")

        if failed == 0:
            print("\nAll tests passed! TMUX integration is ready.")
            self.print_usage_instructions(tmux_type)
        else:
            print(f"\n{failed} tests failed. Check the errors above.")

        return failed == 0

    def print_usage_instructions(self, tmux_type):
        """Print usage instructions"""
        print("\nUsage Instructions:")
        print("=" * 30)

        if tmux_type == "system":
            tmux_cmd = "tmux"
        elif tmux_type == "custom":
            tmux_cmd = str(self.dev_path / "tmux-clone" / "bin" / "tmux-clone")
        elif tmux_type == "buildable":
            print("First, build tmux-clone:")
            print(f"  cd {self.dev_path / 'tmux-clone'}")
            print("  make")
            tmux_cmd = str(self.dev_path / "tmux-clone" / "bin" / "tmux-clone")
        else:
            print("No tmux available - install tmux or build tmux-clone")
            return

        config_path = self.dev_path / ".tmux.conf"

        print("\n1. Start tmux with custom config:")
        print(f"   {tmux_cmd} -f {config_path}")

        print("\n2. Key bindings (Prefix = Ctrl+a):")
        print("   Ctrl+a + W  -> Load development layout")
        print("   Ctrl+a + O  -> Load orchestrator layout")
        print("   Ctrl+a + M  -> Load monitoring layout")
        print("   Ctrl+a + D  -> Load debug layout")

        print("\n3. Your workflow architecture components will be")
        print("   organized across multiple tmux windows and panes")
        print("   for easy monitoring and debugging.")


def main():
    """Main test function"""
    tester = WindowsTMUXTester()
    success = tester.run_all_tests()

    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)
