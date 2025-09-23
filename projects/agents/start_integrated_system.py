#!/usr/bin/env python
"""
Integrated Multi-Agent System Startup Script
Coordinates Director Agent, Observatory, and Redis communication
"""

import asyncio
import subprocess
import time
import sys
import os
from pathlib import Path

class IntegratedSystemManager:
    def __init__(self):
        self.processes = []
        self.redis_process = None
        self.observatory_process = None
        self.director_process = None

    def start_redis(self):
        """Start Redis server for agent communication"""
        try:
            print("🔴 Starting Redis server...")
            # Check if Redis is already running
            result = subprocess.run(['redis-cli', 'ping'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == 'PONG':
                print("✅ Redis is already running")
                return True

            # Start Redis server
            self.redis_process = subprocess.Popen(
                ['redis-server'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(2)

            # Verify Redis is running
            result = subprocess.run(['redis-cli', 'ping'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip() == 'PONG':
                print("✅ Redis server started successfully")
                return True
            else:
                print("❌ Failed to start Redis server")
                return False

        except FileNotFoundError:
            print("⚠️  Redis not found. Please install Redis first.")
            print("   Windows: winget install Redis.Redis")
            print("   Linux: sudo apt-get install redis-server")
            print("   Mac: brew install redis")
            return False

    def start_observatory(self):
        """Start Multi-Agent Observatory System"""
        try:
            print("🔭 Starting Multi-Agent Observatory...")

            # Change to observatory directory
            observatory_path = Path("multi-agent-observatory")
            if not observatory_path.exists():
                print(f"❌ Observatory directory not found at {observatory_path}")
                return False

            # Start the observatory using the shell script
            if sys.platform == "win32":
                # For Windows, we need to use Git Bash or WSL
                self.observatory_process = subprocess.Popen(
                    ['bash', 'scripts/start-all.sh'],
                    cwd=observatory_path,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={**os.environ, 'PORT': '8090'}
                )
            else:
                self.observatory_process = subprocess.Popen(
                    ['./scripts/start-all.sh'],
                    cwd=observatory_path,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={**os.environ, 'PORT': '8090'}
                )

            time.sleep(5)  # Wait for services to start
            print("✅ Observatory system started")
            return True

        except Exception as e:
            print(f"❌ Failed to start Observatory: {e}")
            return False

    def start_director_agent(self):
        """Start Director Agent with Observatory integration"""
        try:
            print("🎬 Starting Director Agent...")

            director_path = Path("director-agent")
            if not director_path.exists():
                print(f"❌ Director Agent directory not found at {director_path}")
                return False

            # Start the Director Agent with Observatory adapter
            self.director_process = subprocess.Popen(
                [sys.executable, 'start_agent_system.py'],
                cwd=director_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, 'OBSERVATORY_SERVER': 'ws://localhost:8090/ws'}
            )

            time.sleep(3)
            print("✅ Director Agent started with Observatory integration")
            return True

        except Exception as e:
            print(f"❌ Failed to start Director Agent: {e}")
            return False

    def check_system_health(self):
        """Check if all components are running"""
        health_status = {
            'redis': False,
            'observatory': False,
            'director': False
        }

        # Check Redis
        try:
            result = subprocess.run(['redis-cli', 'ping'], capture_output=True, text=True)
            health_status['redis'] = result.returncode == 0 and result.stdout.strip() == 'PONG'
        except:
            pass

        # Check Observatory (via HTTP health endpoint)
        try:
            import urllib.request
            response = urllib.request.urlopen('http://localhost:8090/health', timeout=2)
            health_status['observatory'] = response.status == 200
        except:
            pass

        # Check Director Agent process
        if self.director_process:
            health_status['director'] = self.director_process.poll() is None

        return health_status

    def start_all(self):
        """Start all components of the integrated system"""
        print("="*50)
        print("🚀 Starting Integrated Multi-Agent System")
        print("="*50)

        # Start Redis
        if not self.start_redis():
            print("⛔ Cannot proceed without Redis")
            return False

        # Start Observatory
        if not self.start_observatory():
            print("⛔ Cannot proceed without Observatory")
            return False

        # Start Director Agent
        if not self.start_director_agent():
            print("⚠️  Director Agent failed to start, but system can continue")

        print("\n" + "="*50)
        print("✨ Integrated System Started Successfully!")
        print("="*50)
        print("\n📍 Access Points:")
        print("  📊 Observatory Dashboard: http://localhost:3000")
        print("  🔌 Observatory API:       http://localhost:8090")
        print("  ❤️  Health Check:         http://localhost:8090/health")
        print("  🔴 Redis:                localhost:6379")
        print("\n📈 System Health:")

        health = self.check_system_health()
        for component, status in health.items():
            status_icon = "✅" if status else "❌"
            print(f"  {status_icon} {component.capitalize()}: {'Running' if status else 'Not Running'}")

        print("\nPress Ctrl+C to stop all components")

        try:
            # Keep the process running
            while True:
                time.sleep(10)
                # Periodically check health
                health = self.check_system_health()
                if not all(health.values()):
                    print("\n⚠️  Some components have stopped:")
                    for component, status in health.items():
                        if not status:
                            print(f"  ❌ {component.capitalize()} is not running")

        except KeyboardInterrupt:
            print("\n🛑 Shutting down integrated system...")
            self.shutdown()

    def shutdown(self):
        """Gracefully shutdown all components"""
        if self.director_process:
            print("Stopping Director Agent...")
            self.director_process.terminate()

        if self.observatory_process:
            print("Stopping Observatory...")
            self.observatory_process.terminate()

        if self.redis_process:
            print("Stopping Redis...")
            self.redis_process.terminate()

        # Wait for processes to terminate
        time.sleep(2)

        # Force kill if needed
        for process in [self.director_process, self.observatory_process, self.redis_process]:
            if process and process.poll() is None:
                process.kill()

        print("✅ All components stopped")

if __name__ == "__main__":
    manager = IntegratedSystemManager()
    manager.start_all()