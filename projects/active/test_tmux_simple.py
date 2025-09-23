#!/usr/bin/env python3
"""
Simplified TMUX integration test - focuses on configuration and basic functionality
without requiring full orchestrator dependencies
"""

import subprocess
import sys
from pathlib import Path


class SimpleTMUXTester:
    """Simplified test suite for TMUX integration"""

    def __init__(self):
        self.dev_path = Path(__file__).parent

    def check_tmux_available(self):
        """Check if tmux is available"""
        print("🔍 Checking tmux availability...")

        # Check system tmux
        try:
            result = subprocess.run(["tmux", "-V"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ System tmux found: {result.stdout.strip()}")
                return "system"
        except FileNotFoundError:
            print("❌ System tmux not found")

        # Check custom tmux-clone
        tmux_clone_path = self.dev_path / "tmux-clone"
        if tmux_clone_path.exists():
            print(f"✅ Custom tmux-clone directory found: {tmux_clone_path}")

            # Check if binary exists or can be built
            bin_path = tmux_clone_path / "bin" / "tmux-clone"
            if bin_path.exists():
                print("✅ tmux-clone binary exists")
                return "custom"
            else:
                print("⚠️ tmux-clone binary not built yet")
                makefile_path = tmux_clone_path / "Makefile"
                if makefile_path.exists():
                    print("✅ tmux-clone can be built (Makefile exists)")
                    return "buildable"
        else:
            print("❌ Custom tmux-clone not found")

        return None

    def test_configuration_files(self):
        """Test that all configuration files exist and are readable"""
        print("\n📁 Testing configuration files...")

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
                    # Try to read the file to ensure it's accessible
                    with open(config_file, "r") as f:
                        content_length = len(f.read())
                    print(
                        f"✅ {description}: {config_file.name} ({content_length} chars)"
                    )
                except Exception as e:
                    print(f"❌ {description}: {config_file.name} - read error: {e}")
                    all_exist = False
            else:
                print(f"❌ {description}: {config_file.name} - missing")
                all_exist = False

        return all_exist

    def test_tmux_configuration_syntax(self, tmux_type):
        """Test tmux configuration syntax"""
        print("\n🔧 Testing tmux configuration syntax...")

        config_path = self.dev_path / ".tmux.conf"

        if not config_path.exists():
            print(f"❌ Config file not found: {config_path}")
            return False

        if tmux_type is None:
            print("⚠️ Cannot test tmux config - no tmux installation found")
            return True  # Don't fail if no tmux available

        try:
            # Basic syntax check - try to source the config
            if tmux_type == "system":
                tmux_cmd = "tmux"
            else:
                tmux_cmd = str(self.dev_path / "tmux-clone" / "bin" / "tmux-clone")

            # Test config by trying to start tmux with config (in detached mode)
            result = subprocess.run(
                [
                    tmux_cmd,
                    "-f",
                    str(config_path),
                    "new-session",
                    "-d",
                    "-s",
                    "config-test",
                    "echo",
                    "config test",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Clean up test session
            subprocess.run(
                [tmux_cmd, "kill-session", "-t", "config-test"], capture_output=True
            )

            if result.returncode == 0:
                print("✅ TMUX configuration syntax valid")
                return True
            else:
                print(f"❌ TMUX configuration error: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            print("❌ TMUX configuration test timed out")
            return False
        except FileNotFoundError:
            print(f"❌ TMUX binary not found: {tmux_cmd}")
            return False
        except Exception as e:
            print(f"❌ Config syntax test failed: {e}")
            return False

    def test_workflow_layout_syntax(self):
        """Test workflow layout files for basic syntax"""
        print("\n📋 Testing workflow layout syntax...")

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
                print(f"❌ Layout missing: {layout_file}")
                all_valid = False
                continue

            try:
                with open(layout_path, "r") as f:
                    content = f.read()

                # Basic checks for tmux commands
                required_commands = ["new-session", "new-window", "split-window"]
                missing_commands = []

                for cmd in required_commands:
                    if cmd not in content:
                        missing_commands.append(cmd)

                if missing_commands:
                    print(f"⚠️ {layout_file}: Missing commands: {missing_commands}")
                else:
                    print(f"✅ {layout_file}: Contains required tmux commands")

            except Exception as e:
                print(f"❌ {layout_file}: Read error: {e}")
                all_valid = False

        return all_valid

    def test_directory_structure(self):
        """Test that required directories exist"""
        print("\n📂 Testing directory structure...")

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
                # Try to create logs directory
                try:
                    dir_path.mkdir(exist_ok=True)
                    print(f"✅ {description}: Created {rel_path}/")
                except Exception as e:
                    print(f"❌ {description}: Could not create {rel_path}/ - {e}")
                    all_exist = False
            elif dir_path.exists():
                print(f"✅ {description}: {rel_path}/")
            else:
                print(f"❌ {description}: {rel_path}/ - missing")
                all_exist = False

        return all_exist

    def test_tmux_clone_build(self):
        """Test if tmux-clone can be built"""
        print("\n🔨 Testing tmux-clone build capability...")

        tmux_clone_path = self.dev_path / "tmux-clone"
        if not tmux_clone_path.exists():
            print("❌ tmux-clone directory not found")
            return False

        makefile_path = tmux_clone_path / "Makefile"
        if not makefile_path.exists():
            print("❌ Makefile not found")
            return False

        # Check if we have gcc
        try:
            result = subprocess.run(["gcc", "--version"], capture_output=True)
            if result.returncode == 0:
                print("✅ GCC compiler available")

                # Try a dry-run make to check dependencies
                try:
                    result = subprocess.run(
                        ["make", "-n"],
                        cwd=tmux_clone_path,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

                    if result.returncode == 0:
                        print("✅ tmux-clone build system ready")
                        return True
                    else:
                        print(f"❌ Build system issues: {result.stderr}")
                        return False

                except subprocess.TimeoutExpired:
                    print("❌ Build check timed out")
                    return False

            else:
                print("❌ GCC compiler not available")
                return False

        except FileNotFoundError:
            print("❌ GCC not found - cannot build tmux-clone")
            return False
        except Exception as e:
            print(f"❌ Build test error: {e}")
            return False

    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting simplified TMUX integration tests")
        print("=" * 50)

        # Check tmux availability first
        tmux_type = self.check_tmux_available()

        tests = [
            ("Directory Structure", lambda: self.test_directory_structure()),
            ("Configuration Files", lambda: self.test_configuration_files()),
            ("Workflow Layout Syntax", lambda: self.test_workflow_layout_syntax()),
            (
                "TMUX Config Syntax",
                lambda: self.test_tmux_configuration_syntax(tmux_type),
            ),
            ("TMUX-Clone Build", lambda: self.test_tmux_clone_build()),
        ]

        passed = 0
        failed = 0

        for test_name, test_func in tests:
            print(f"\n🧪 Running: {test_name}")
            try:
                result = test_func()

                if result:
                    passed += 1
                    print(f"✅ {test_name} - PASSED")
                else:
                    failed += 1
                    print(f"❌ {test_name} - FAILED")

            except Exception as e:
                failed += 1
                print(f"❌ {test_name} - ERROR: {e}")

        print("\n" + "=" * 50)
        print("🏁 Test Results Summary")
        print("=" * 50)
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"📊 Success Rate: {passed / (passed + failed) * 100:.1f}%")

        if failed == 0:
            print("\n🎉 All tests passed! TMUX integration is ready to use.")
            self.print_usage_instructions(tmux_type)
        else:
            print(f"\n⚠️ {failed} tests failed. Check the errors above.")

        return failed == 0

    def print_usage_instructions(self, tmux_type):
        """Print usage instructions"""
        print("\n💡 Usage Instructions:")
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
            print("⚠️ No tmux available - install tmux or build tmux-clone")
            return

        config_path = self.dev_path / ".tmux.conf"

        print("\n1. Start tmux with custom config:")
        print(f"   {tmux_cmd} -f {config_path}")

        print("\n2. Or create a named session:")
        print(f"   {tmux_cmd} -f {config_path} new-session -s workflow-dev")

        print("\n3. Key bindings (Prefix = Ctrl+a):")
        print("   Ctrl+a + W  → Load development layout")
        print("   Ctrl+a + O  → Load orchestrator layout")
        print("   Ctrl+a + M  → Load monitoring layout")
        print("   Ctrl+a + D  → Load debug layout")
        print("   Ctrl+a + |  → Split window vertically")
        print("   Ctrl+a + -  → Split window horizontally")
        print("   Alt+arrows  → Switch between panes")

        print("\n4. Quick service commands:")
        print("   Ctrl+a + S  → Service status")
        print("   Ctrl+a + Q  → Queue status")
        print("   Ctrl+a + K  → Kubernetes status")
        print("   Ctrl+a + L  → View logs")


def main():
    """Main test function"""
    tester = SimpleTMUXTester()
    success = tester.run_all_tests()

    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n❌ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)
