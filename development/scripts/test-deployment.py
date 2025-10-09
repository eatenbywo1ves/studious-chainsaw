#!/usr/bin/env python3
"""
Test Deployment Script for Grafana Dashboards

This script performs a comprehensive test of the dashboard deployment process
without requiring a running Grafana instance.
"""

import json
import sys
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def test_dashboard_structure():
    """Test dashboard file structure and content."""
    logger.info("🧪 Testing dashboard structure...")

    project_root = Path(__file__).parent.parent
    dashboards_dir = project_root / "monitoring" / "grafana" / "dashboards"

    if not dashboards_dir.exists():
        logger.error("❌ Dashboards directory not found")
        return False

    dashboard_files = list(dashboards_dir.glob("*.json"))
    if len(dashboard_files) != 2:
        logger.error(f"❌ Expected 2 dashboard files, found {len(dashboard_files)}")
        return False

    logger.info("✅ Found expected dashboard files")

    # Test each dashboard
    for dashboard_file in dashboard_files:
        logger.info(f"Testing {dashboard_file.name}...")

        with open(dashboard_file) as f:
            dashboard_data = json.load(f)

        dashboard = dashboard_data["dashboard"]

        # Check key properties
        if "title" not in dashboard:
            logger.error(f"❌ {dashboard_file.name}: Missing title")
            return False

        if "panels" not in dashboard or len(dashboard["panels"]) == 0:
            logger.error(f"❌ {dashboard_file.name}: No panels found")
            return False

        logger.info(
            f"✅ {dashboard_file.name}: {dashboard['title']} - {len(dashboard['panels'])} panels"
        )

    return True


def test_prometheus_queries():
    """Test Prometheus queries in dashboards."""
    logger.info("🔍 Testing Prometheus queries...")

    project_root = Path(__file__).parent.parent
    dashboards_dir = project_root / "monitoring" / "grafana" / "dashboards"

    total_queries = 0
    valid_queries = 0

    for dashboard_file in dashboards_dir.glob("*.json"):
        with open(dashboard_file) as f:
            dashboard_data = json.load(f)

        dashboard = dashboard_data["dashboard"]

        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []):
                if "expr" in target:
                    total_queries += 1
                    query = target["expr"]

                    # Basic query validation
                    if query.strip() and "(" in query and ")" in query:
                        valid_queries += 1
                    else:
                        logger.warning(f"⚠️ Potentially invalid query: {query[:50]}...")

    logger.info(f"✅ Validated {valid_queries}/{total_queries} Prometheus queries")
    return valid_queries == total_queries


def test_deployment_scripts():
    """Test deployment script availability."""
    logger.info("📋 Testing deployment scripts...")

    project_root = Path(__file__).parent.parent
    scripts_dir = project_root / "scripts"

    required_scripts = [
        "deploy-grafana-dashboards.py",
        "validate-dashboards.py",
        "setup-monitoring.py",
        "deploy-dashboards.sh",
        "deploy-dashboards.bat",
    ]

    for script in required_scripts:
        script_path = scripts_dir / script
        if not script_path.exists():
            logger.error(f"❌ Missing script: {script}")
            return False

        logger.info(f"✅ Found: {script}")

    return True


def test_provisioning_config():
    """Test Grafana provisioning configuration."""
    logger.info("⚙️ Testing provisioning configuration...")

    project_root = Path(__file__).parent.parent
    provisioning_dir = project_root / "monitoring" / "grafana" / "provisioning"

    # Test dashboard provisioning
    dashboard_config = provisioning_dir / "dashboards" / "dashboard-provisioning.yml"
    if not dashboard_config.exists():
        logger.error("❌ Dashboard provisioning config missing")
        return False

    # Test datasource config
    datasource_config = provisioning_dir / "datasources" / "datasources.yml"
    if not datasource_config.exists():
        logger.error("❌ Datasource config missing")
        return False

    logger.info("✅ Provisioning configurations found")
    return True


def test_docker_integration():
    """Test Docker Compose integration."""
    logger.info("🐳 Testing Docker integration...")

    project_root = Path(__file__).parent.parent
    compose_file = project_root / "docker-compose.yml"

    if not compose_file.exists():
        logger.error("❌ docker-compose.yml not found")
        return False

    # Check for Grafana volume mounts
    with open(compose_file) as f:
        content = f.read()

    if "grafana" not in content:
        logger.error("❌ Grafana service not found in docker-compose.yml")
        return False

    if "monitoring/grafana" not in content:
        logger.error("❌ Grafana monitoring directory not mounted")
        return False

    logger.info("✅ Docker integration configured")
    return True


def main():
    """Run all deployment tests."""
    logger.info("🚀 Starting comprehensive deployment test...")

    tests = [
        ("Dashboard Structure", test_dashboard_structure),
        ("Prometheus Queries", test_prometheus_queries),
        ("Deployment Scripts", test_deployment_scripts),
        ("Provisioning Config", test_provisioning_config),
        ("Docker Integration", test_docker_integration),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        logger.info(f"\n📋 Running: {test_name}")
        try:
            if test_func():
                passed += 1
                logger.info(f"✅ {test_name}: PASSED")
            else:
                failed += 1
                logger.error(f"❌ {test_name}: FAILED")
        except Exception as e:
            failed += 1
            logger.error(f"💥 {test_name}: ERROR - {e}")

    # Summary
    logger.info("\n" + "=" * 50)
    logger.info("🧪 TEST SUMMARY")
    logger.info("=" * 50)
    logger.info(f"✅ Tests passed: {passed}")
    logger.info(f"❌ Tests failed: {failed}")
    logger.info(f"📊 Success rate: {passed / (passed + failed) * 100:.1f}%")

    if failed == 0:
        logger.info("\n🎉 All tests passed! Deployment system is ready.")

        logger.info("\n📋 Next Steps:")
        logger.info("1. Set GRAFANA_API_KEY environment variable")
        logger.info("2. Start monitoring stack: docker compose --profile monitoring up -d")
        logger.info("3. Deploy dashboards: ./scripts/deploy-dashboards.sh")
        logger.info("4. Access Grafana: http://localhost:3000")

        return True
    else:
        logger.error(f"\n💥 {failed} tests failed. Please fix issues before deployment.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
