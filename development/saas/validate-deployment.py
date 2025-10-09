#!/usr/bin/env python3
"""
Production Deployment Validation Script
Validates all services and endpoints are operational
"""

import os
import sys
import json
import subprocess
from datetime import datetime
import urllib.request
import urllib.error


# Color codes for output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RESET = "\033[0m"


def print_header(text):
    """Print section header"""
    print(f"\n{Colors.BLUE}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BLUE}{text:^70}{Colors.RESET}")
    print(f"{Colors.BLUE}{'=' * 70}{Colors.RESET}\n")


def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}[OK] {text}{Colors.RESET}")


def print_error(text):
    """Print error message"""
    print(f"{Colors.RED}[FAIL] {text}{Colors.RESET}")


def print_warning(text):
    """Print warning message"""
    print(f"{Colors.YELLOW}[WARN] {text}{Colors.RESET}")


def check_service(name, host, port, path="/"):
    """Check if a service is running and accessible"""
    try:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            status_code = response.getcode()
            if 200 <= status_code < 400:
                print_success(f"{name} is running on {host}:{port} (HTTP {status_code})")
                return True, status_code
            else:
                print_warning(f"{name} returned HTTP {status_code}")
                return True, status_code
    except urllib.error.HTTPError as e:
        if e.code in [302, 307, 308]:  # Redirects are OK
            print_success(f"{name} is running on {host}:{port} (HTTP {e.code} - redirect)")
            return True, e.code
        print_error(f"{name} returned HTTP {e.code}: {e.reason}")
        return False, e.code
    except urllib.error.URLError as e:
        print_error(f"{name} connection failed: {e.reason}")
        return False, None
    except Exception as e:
        print_error(f"{name} check failed: {str(e)}")
        return False, None


def check_redis():
    """Check Redis connection"""
    try:
        redis_cli = "C:/Program Files/Memurai/memurai-cli.exe"
        password = os.getenv("REDIS_PASSWORD", "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=")

        # Test PING
        result = subprocess.run(
            [redis_cli, "-a", password, "PING"], capture_output=True, text=True, timeout=5
        )

        if "PONG" in result.stdout:
            print_success("Redis is running and responding to PING")

            # Get INFO stats
            stats_result = subprocess.run(
                [redis_cli, "-a", password, "INFO", "stats"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            # Parse commands processed
            for line in stats_result.stdout.split("\n"):
                if line.startswith("total_commands_processed:"):
                    commands = line.split(":")[1].strip()
                    print(f"  Commands processed: {commands}")
                    break

            return True
        else:
            print_error("Redis did not respond with PONG")
            return False
    except Exception as e:
        print_error(f"Redis check failed: {str(e)}")
        return False


def check_database():
    """Check database connection"""
    try:
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            print_error("DATABASE_URL not set")
            return False

        if db_url.startswith("sqlite"):
            # Check if SQLite file exists
            db_path = db_url.replace("sqlite:///", "")
            if os.path.exists(db_path):
                size = os.path.getsize(db_path)
                print_success(f"SQLite database exists ({size:,} bytes)")
                return True
            else:
                print_error(f"SQLite database not found: {db_path}")
                return False
        elif db_url.startswith("postgresql"):
            print_warning("PostgreSQL connection test not implemented (requires psycopg2)")
            return True
        else:
            print_warning(f"Unknown database type: {db_url[:20]}...")
            return True
    except Exception as e:
        print_error(f"Database check failed: {str(e)}")
        return False


def check_backend_health():
    """Check backend health endpoint"""
    try:
        url = "http://localhost:8000/health"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())

            if data.get("status") == "healthy":
                print_success("Backend health check passed")

                # Display Redis info
                if "redis" in data:
                    redis_info = data["redis"]
                    if redis_info.get("connected"):
                        print(
                            f"  Redis: Connected ({redis_info.get('commands_processed', 0):,} commands)"
                        )
                    else:
                        print_warning("  Redis: Disconnected")

                return True
            else:
                print_error(f"Backend status: {data.get('status', 'unknown')}")
                return False
    except Exception as e:
        print_error(f"Backend health check failed: {str(e)}")
        return False


def check_environment():
    """Check environment variables"""
    required_vars = [
        "DATABASE_URL",
        "REDIS_HOST",
        "REDIS_PORT",
        "REDIS_PASSWORD",
        "JWT_PRIVATE_KEY_PATH",
        "JWT_PUBLIC_KEY_PATH",
    ]

    missing = []
    for var in required_vars:
        value = os.getenv(var)
        if value:
            print_success(f"{var} is set")
        else:
            print_error(f"{var} is NOT set")
            missing.append(var)

    return len(missing) == 0


def check_processes():
    """Check if backend and frontend processes are running"""
    try:
        # Check backend process (port 8000)
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5)

        backend_running = ":8000" in result.stdout
        frontend_running = ":3000" in result.stdout

        if backend_running:
            print_success("Backend process is running (port 8000)")
        else:
            print_error("Backend process not found (port 8000)")

        if frontend_running:
            print_success("Frontend process is running (port 3000)")
        else:
            print_warning("Frontend process not found (port 3000)")

        return backend_running
    except Exception as e:
        print_error(f"Process check failed: {str(e)}")
        return False


def main():
    """Run all validation checks"""
    print_header("PRODUCTION DEPLOYMENT VALIDATION")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    results = {}

    # Check environment variables
    print_header("ENVIRONMENT VARIABLES")
    results["environment"] = check_environment()

    # Check processes
    print_header("PROCESSES")
    results["processes"] = check_processes()

    # Check Redis
    print_header("REDIS")
    results["redis"] = check_redis()

    # Check database
    print_header("DATABASE")
    results["database"] = check_database()

    # Check backend service
    print_header("BACKEND API")
    backend_running, _ = check_service("Backend API", "localhost", 8000, "/health")
    results["backend_service"] = backend_running

    # Check backend health endpoint
    if backend_running:
        results["backend_health"] = check_backend_health()

    # Check frontend service
    print_header("FRONTEND")
    frontend_running, status = check_service("Frontend", "localhost", 3000)
    results["frontend"] = frontend_running

    # Summary
    print_header("VALIDATION SUMMARY")

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    print(f"\nPassed: {passed}/{total} checks\n")

    for check, status in results.items():
        if status:
            print_success(f"{check.replace('_', ' ').title()}")
        else:
            print_error(f"{check.replace('_', ' ').title()}")

    print(f"\n{Colors.BLUE}{'=' * 70}{Colors.RESET}\n")

    if passed == total:
        print_success("ALL CHECKS PASSED - DEPLOYMENT IS HEALTHY!\n")
        return 0
    else:
        print_error(f"VALIDATION FAILED - {total - passed} check(s) failed\n")
        return 1


if __name__ == "__main__":
    # Load environment variables
    from dotenv import load_dotenv

    env_path = os.path.join(os.path.dirname(__file__), ".env")
    load_dotenv(env_path)

    sys.exit(main())
