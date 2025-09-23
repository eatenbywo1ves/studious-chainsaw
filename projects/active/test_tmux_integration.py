#!/usr/bin/env python3
"""
Test script for TMUX integration with workflow architecture
Tests the TMUXAgentManager integration with existing orchestrator
"""

from libraries.service_discovery import get_service_discovery
from libraries.message_queue import get_message_broker
from libraries.workflow_engine import WorkflowEngine
from orchestration.agent_orchestrator import AgentOrchestrator
from orchestration.tmux_agent_manager import TMUXAgentManager
import asyncio
import sys
import subprocess
from pathlib import Path

# Add shared directory to path
sys.path.insert(0, str(Path(__file__).parent / "shared"))


class TMUXIntegrationTester:
    """Test suite for TMUX integration"""

    def __init__(self):
        self.test_results = []
        self.orchestrator = None
        self.tmux_manager = None

    async def setup_test_environment(self):
        """Set up test environment"""
        print("🔧 Setting up test environment...")

        # Initialize orchestrator (without Kubernetes for testing)
        self.orchestrator = AgentOrchestrator(
            {
                "kubernetes_enabled": False,  # Disable K8s for local testing
                "redis_enabled": False,  # Disable Redis for local testing
            }
        )

        await self.orchestrator.initialize()

        # Initialize TMUX manager
        self.tmux_manager = TMUXAgentManager(self.orchestrator)

        print("✅ Test environment ready")
        return True

    def check_tmux_available(self):
        """Check if tmux is available"""
        print("🔍 Checking tmux availability...")

        # Check system tmux
        try:
            result = subprocess.run(["tmux", "-V"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ System tmux found: {result.stdout.strip()}")
                return True
        except FileNotFoundError:
            print("❌ System tmux not found")

        # Check custom tmux-clone
        tmux_clone_path = Path(__file__).parent / "tmux-clone" / "bin" / "tmux-clone"
        if tmux_clone_path.exists():
            print(f"✅ Custom tmux-clone found: {tmux_clone_path}")
            return True
        else:
            print(f"❌ Custom tmux-clone not found at: {tmux_clone_path}")

        return False

    async def test_tmux_session_creation(self):
        """Test basic tmux session creation"""
        print("\n📝 Testing TMUX session creation...")

        try:
            # Test development environment creation
            await self.tmux_manager.initialize()
            print("✅ TMUX manager initialization successful")

            # Create development environment
            dev_session = await self.tmux_manager.create_development_environment()
            print(f"✅ Development environment created: {dev_session}")

            return True
        except Exception as e:
            print(f"❌ TMUX session creation failed: {e}")
            return False

    async def test_workflow_monitoring_session(self):
        """Test workflow monitoring session creation"""
        print("\n📊 Testing workflow monitoring session...")

        try:
            # Create a mock workflow
            workflow_id = "test-workflow-123"

            # Create workflow session
            session_name = await self.tmux_manager.create_workflow_session(workflow_id)
            print(f"✅ Workflow monitoring session created: {session_name}")

            return True
        except Exception as e:
            print(f"❌ Workflow monitoring session failed: {e}")
            return False

    async def test_session_listing(self):
        """Test session listing functionality"""
        print("\n📋 Testing session listing...")

        try:
            sessions = await self.tmux_manager.list_sessions()
            print(f"✅ Found {len(sessions)} tmux sessions:")
            for session in sessions:
                print(
                    f"  - {session['name']}: {session['windows']} windows ({session['attached']})"
                )

            return True
        except Exception as e:
            print(f"❌ Session listing failed: {e}")
            return False

    def test_configuration_files(self):
        """Test that all configuration files exist"""
        print("\n📁 Testing configuration files...")

        config_files = [
            Path.home() / "development" / ".tmux.conf",
            Path.home() / "development" / ".tmux-workflows" / "development-layout",
            Path.home() / "development" / ".tmux-workflows" / "orchestrator-layout",
            Path.home() / "development" / ".tmux-workflows" / "monitoring-layout",
            Path.home() / "development" / ".tmux-workflows" / "debug-layout",
        ]

        all_exist = True
        for config_file in config_files:
            if config_file.exists():
                print(f"✅ {config_file.name}")
            else:
                print(f"❌ {config_file.name} - missing")
                all_exist = False

        return all_exist

    def test_workflow_engine_integration(self):
        """Test workflow engine integration"""
        print("\n⚙️ Testing workflow engine integration...")

        try:
            # Initialize workflow engine
            engine = WorkflowEngine(max_concurrent_tasks=5)

            # Test getting statistics (which tmux status bar uses)
            stats = engine.get_statistics()
            print(f"✅ Workflow engine stats: {stats}")

            return True
        except Exception as e:
            print(f"❌ Workflow engine integration failed: {e}")
            return False

    def test_message_broker_integration(self):
        """Test message broker integration"""
        print("\n📡 Testing message broker integration...")

        try:
            # Get message broker
            broker = get_message_broker()

            # Test getting statistics (which tmux status bar uses)
            stats = broker.get_statistics()
            print(f"✅ Message broker stats: {stats}")

            return True
        except Exception as e:
            print(f"❌ Message broker integration failed: {e}")
            return False

    def test_service_discovery_integration(self):
        """Test service discovery integration"""
        print("\n🔍 Testing service discovery integration...")

        try:
            # Get service discovery
            discovery = get_service_discovery()

            # Test getting statistics (which tmux status bar uses)
            stats = discovery.get_statistics()
            print(f"✅ Service discovery stats: {stats}")

            return True
        except Exception as e:
            print(f"❌ Service discovery integration failed: {e}")
            return False

    def test_tmux_configuration_syntax(self):
        """Test tmux configuration syntax"""
        print("\n🔧 Testing tmux configuration syntax...")

        try:
            # Test tmux config syntax
            config_path = Path.home() / "development" / ".tmux.conf"

            if not config_path.exists():
                print(f"❌ Config file not found: {config_path}")
                return False

            # Try to validate tmux config (this will only work if tmux is installed)
            result = subprocess.run(
                ["tmux", "-f", str(config_path), "-C", "list-sessions"],
                capture_output=True,
                text=True,
            )

            # If tmux exits cleanly, config is probably valid
            if result.returncode in [0, 1]:  # 1 is expected when no sessions exist
                print("✅ TMUX configuration syntax appears valid")
                return True
            else:
                print(f"❌ TMUX configuration syntax error: {result.stderr}")
                return False

        except FileNotFoundError:
            print("⚠️ Cannot test tmux config - tmux not installed")
            return True  # Don't fail test if tmux not available
        except Exception as e:
            print(f"❌ Config syntax test failed: {e}")
            return False

    async def run_all_tests(self):
        """Run all integration tests"""
        print("🚀 Starting TMUX integration tests")
        print("=" * 50)

        tests = [
            ("TMUX Availability", self.check_tmux_available),
            ("Configuration Files", self.test_configuration_files),
            ("TMUX Config Syntax", self.test_tmux_configuration_syntax),
            ("Workflow Engine Integration", self.test_workflow_engine_integration),
            ("Message Broker Integration", self.test_message_broker_integration),
            ("Service Discovery Integration", self.test_service_discovery_integration),
            ("Test Environment Setup", self.setup_test_environment),
            ("Session Creation", self.test_tmux_session_creation),
            ("Workflow Monitoring", self.test_workflow_monitoring_session),
            ("Session Listing", self.test_session_listing),
        ]

        passed = 0
        failed = 0

        for test_name, test_func in tests:
            print(f"\n🧪 Running: {test_name}")
            try:
                if asyncio.iscoroutinefunction(test_func):
                    result = await test_func()
                else:
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
            print("\nNext steps:")
            print("1. Start tmux with: tmux -f ~/.tmux.conf")
            print("2. Use Prefix + W for development layout")
            print("3. Use Prefix + O for orchestrator layout")
            print("4. Use Prefix + M for monitoring layout")
            print("5. Use Prefix + D for debug layout")
        else:
            print(f"\n⚠️ {failed} tests failed. Check the errors above.")

        return failed == 0


async def main():
    """Main test function"""
    tester = TMUXIntegrationTester()
    success = await tester.run_all_tests()

    if success:
        print("\n💡 Try these commands to get started:")
        print("tmux -f ~/development/.tmux.conf new-session -s workflow-dev")
        print("# Then press Ctrl+a followed by W to load development layout")

    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n❌ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)
