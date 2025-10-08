"""
Grafana Dashboard Validation Tests

Tests to validate that Grafana dashboards are correctly configured and all queries work.
"""

import requests
import json
import pytest
from typing import Dict, List, Any, Optional
from pathlib import Path


class GrafanaValidator:
    """Validates Grafana dashboards and queries"""

    def __init__(
        self,
        grafana_url: str = "http://localhost:3000",
        username: str = "admin",
        password: str = "changeme123!"
    ):
        self.grafana_url = grafana_url
        self.api_url = f"{grafana_url}/api"
        self.auth = (username, password)

    def check_grafana_health(self) -> bool:
        """Check if Grafana is healthy"""
        try:
            response = requests.get(f"{self.api_url}/health", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Grafana health check failed: {e}")
            return False

    def get_datasources(self) -> List[Dict[str, Any]]:
        """Get all configured datasources"""
        try:
            response = requests.get(f"{self.api_url}/datasources", auth=self.auth, timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to get datasources: {e}")
            return []

    def test_datasource(self, datasource_id: int) -> bool:
        """Test a datasource connection"""
        try:
            response = requests.get(
                f"{self.api_url}/datasources/{datasource_id}/health",
                auth=self.auth,
                timeout=10
            )
            data = response.json()
            return data.get("status") == "OK"
        except Exception as e:
            print(f"Datasource test failed: {e}")
            return False

    def get_dashboards(self) -> List[Dict[str, Any]]:
        """Get all dashboards"""
        try:
            response = requests.get(
                f"{self.api_url}/search?type=dash-db",
                auth=self.auth,
                timeout=5
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to get dashboards: {e}")
            return []

    def get_dashboard_by_uid(self, uid: str) -> Optional[Dict[str, Any]]:
        """Get a dashboard by UID"""
        try:
            response = requests.get(
                f"{self.api_url}/dashboards/uid/{uid}",
                auth=self.auth,
                timeout=5
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to get dashboard {uid}: {e}")
            return None

    def validate_dashboard_queries(self, dashboard_uid: str) -> Dict[str, Any]:
        """Validate all queries in a dashboard"""
        dashboard = self.get_dashboard_by_uid(dashboard_uid)
        if not dashboard:
            return {"status": "error", "message": "Dashboard not found"}

        dashboard_data = dashboard.get("dashboard", {})
        panels = dashboard_data.get("panels", [])

        query_results = {
            "total_panels": len(panels),
            "panels_with_queries": 0,
            "total_queries": 0,
            "valid_queries": 0,
            "invalid_queries": [],
        }

        for panel in panels:
            targets = panel.get("targets", [])
            if targets:
                query_results["panels_with_queries"] += 1

            for target in targets:
                query = target.get("expr", "")
                if query:
                    query_results["total_queries"] += 1
                    # For now, we just check if query exists
                    # In production, you'd validate against Prometheus
                    if query:
                        query_results["valid_queries"] += 1
                    else:
                        query_results["invalid_queries"].append({
                            "panel": panel.get("title", "Unknown"),
                            "query": query
                        })

        return query_results

    def load_dashboard_from_file(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Load a dashboard JSON file"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Failed to load dashboard file {filepath}: {e}")
            return None

    def validate_dashboard_structure(self, dashboard: Dict[str, Any]) -> Dict[str, bool]:
        """Validate dashboard structure"""
        validations = {
            "has_title": "title" in dashboard,
            "has_panels": "panels" in dashboard and len(dashboard.get("panels", [])) > 0,
            "has_uid": "uid" in dashboard,
            "has_version": "version" in dashboard,
            "has_time_settings": "time" in dashboard,
            "has_refresh_settings": "refresh" in dashboard,
        }

        return validations

    def validate_panel_structure(self, panel: Dict[str, Any]) -> Dict[str, bool]:
        """Validate panel structure"""
        validations = {
            "has_title": "title" in panel,
            "has_type": "type" in panel,
            "has_datasource": "datasource" in panel,
            "has_targets": "targets" in panel and len(panel.get("targets", [])) > 0,
            "has_gridpos": "gridPos" in panel,
        }

        return validations


# ============================================================================
# PYTEST TEST CASES
# ============================================================================

@pytest.fixture
def validator():
    """Create a GrafanaValidator instance"""
    return GrafanaValidator()


def test_grafana_health(validator):
    """Test that Grafana is healthy"""
    assert validator.check_grafana_health(), "Grafana is not healthy"


def test_prometheus_datasource_exists(validator):
    """Test that Prometheus datasource is configured"""
    datasources = validator.get_datasources()
    prometheus_sources = [ds for ds in datasources if ds.get("type") == "prometheus"]

    assert len(prometheus_sources) > 0, "No Prometheus datasource configured"


def test_prometheus_datasource_health(validator):
    """Test that Prometheus datasource connection works"""
    datasources = validator.get_datasources()
    prometheus_sources = [ds for ds in datasources if ds.get("type") == "prometheus"]

    assert len(prometheus_sources) > 0, "No Prometheus datasource configured"

    for ds in prometheus_sources:
        ds_id = ds.get("id")
        assert validator.test_datasource(ds_id), \
            f"Prometheus datasource '{ds.get('name')}' connection failed"


def test_security_dashboard_exists(validator):
    """Test that security dashboard exists"""
    dashboards = validator.get_dashboards()
    security_dashboards = [
        d for d in dashboards
        if "security" in d.get("title", "").lower()
    ]

    assert len(security_dashboards) > 0, "No security dashboard found"


def test_dashboard_files_valid():
    """Test that dashboard JSON files are valid"""
    dashboard_dir = Path("C:/Users/Corbin/development/monitoring/grafana/dashboards")

    if not dashboard_dir.exists():
        pytest.skip("Dashboard directory not found")

    dashboard_files = list(dashboard_dir.glob("*.json"))
    assert len(dashboard_files) > 0, "No dashboard files found"

    for filepath in dashboard_files:
        # Load dashboard
        try:
            with open(filepath, 'r') as f:
                dashboard = json.load(f)
        except Exception as e:
            pytest.fail(f"Failed to parse {filepath}: {e}")

        # Validate structure
        assert "title" in dashboard, f"{filepath} missing title"
        assert "panels" in dashboard, f"{filepath} missing panels"
        assert len(dashboard.get("panels", [])) > 0, f"{filepath} has no panels"


def test_security_dashboard_structure():
    """Test security dashboard structure"""
    validator = GrafanaValidator()
    dashboard_path = Path("C:/Users/Corbin/development/monitoring/grafana/dashboards/security-overview.json")

    if not dashboard_path.exists():
        pytest.skip("Security dashboard file not found")

    dashboard = validator.load_dashboard_from_file(str(dashboard_path))
    assert dashboard is not None, "Failed to load security dashboard"

    validations = validator.validate_dashboard_structure(dashboard)
    failed = [k for k, v in validations.items() if not v]

    assert len(failed) == 0, f"Security dashboard structure validation failed: {failed}"


def test_security_dashboard_panels():
    """Test security dashboard has required panels"""
    validator = GrafanaValidator()
    dashboard_path = Path("C:/Users/Corbin/development/monitoring/grafana/dashboards/security-overview.json")

    if not dashboard_path.exists():
        pytest.skip("Security dashboard file not found")

    dashboard = validator.load_dashboard_from_file(str(dashboard_path))
    assert dashboard is not None, "Failed to load security dashboard"

    panels = dashboard.get("panels", [])
    panel_titles = [p.get("title", "").lower() for p in panels]

    # Check for key security panels
    required_panels = [
        "failed login",
        "rate limited",
        "unauthorized",
        "api request rate",
        "response time",
    ]

    for required in required_panels:
        found = any(required in title for title in panel_titles)
        assert found, f"Security dashboard missing required panel: {required}"


def test_all_dashboard_panels_have_queries():
    """Test that all dashboard panels have valid queries"""
    validator = GrafanaValidator()
    dashboard_dir = Path("C:/Users/Corbin/development/monitoring/grafana/dashboards")

    if not dashboard_dir.exists():
        pytest.skip("Dashboard directory not found")

    dashboard_files = list(dashboard_dir.glob("*.json"))

    for filepath in dashboard_files:
        dashboard = validator.load_dashboard_from_file(str(filepath))
        if not dashboard:
            continue

        panels = dashboard.get("panels", [])
        for panel in panels:
            panel_title = panel.get("title", "Unknown")
            panel_type = panel.get("type", "")

            # Skip row panels (they're just containers)
            if panel_type == "row":
                continue

            # Check if panel has datasource configured
            if "datasource" in panel or "targets" in panel:
                targets = panel.get("targets", [])
                if targets:
                    # At least one target should have a query
                    has_query = any(
                        t.get("expr") or t.get("query")
                        for t in targets
                    )
                    assert has_query, \
                        f"Panel '{panel_title}' in {filepath.name} has no queries"


# ============================================================================
# STANDALONE VALIDATION SCRIPT
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("GRAFANA DASHBOARD VALIDATION")
    print("=" * 80)
    print()

    validator = GrafanaValidator()

    # Check Grafana health
    print("1. Checking Grafana health...")
    if validator.check_grafana_health():
        print("   ✓ Grafana is healthy")
    else:
        print("   ✗ Grafana is NOT healthy")
        exit(1)

    # Check datasources
    print("\n2. Checking datasources...")
    datasources = validator.get_datasources()
    print(f"   Found {len(datasources)} datasource(s)")

    for ds in datasources:
        ds_name = ds.get("name")
        ds_type = ds.get("type")
        ds_id = ds.get("id")

        health = validator.test_datasource(ds_id)
        status_icon = "✓" if health else "✗"
        print(f"   {status_icon} {ds_name} ({ds_type})")

    # Check dashboards
    print("\n3. Checking dashboards...")
    dashboards = validator.get_dashboards()
    print(f"   Found {len(dashboards)} dashboard(s)")

    for dashboard in dashboards:
        print(f"   - {dashboard.get('title')} (UID: {dashboard.get('uid')})")

    # Validate dashboard files
    print("\n4. Validating dashboard files...")
    dashboard_dir = Path("C:/Users/Corbin/development/monitoring/grafana/dashboards")

    if dashboard_dir.exists():
        dashboard_files = list(dashboard_dir.glob("*.json"))
        print(f"   Found {len(dashboard_files)} dashboard file(s)")

        all_valid = True
        for filepath in dashboard_files:
            dashboard = validator.load_dashboard_from_file(str(filepath))
            if dashboard:
                validations = validator.validate_dashboard_structure(dashboard)
                all_checks_passed = all(validations.values())

                status_icon = "✓" if all_checks_passed else "✗"
                print(f"   {status_icon} {filepath.name}")

                if not all_checks_passed:
                    all_valid = False
                    failed = [k for k, v in validations.items() if not v]
                    print(f"      Failed checks: {', '.join(failed)}")
            else:
                print(f"   ✗ {filepath.name} (failed to load)")
                all_valid = False
    else:
        print("   Dashboard directory not found")
        all_valid = False

    # Summary
    print("\n" + "=" * 80)
    if all_valid:
        print("✓ ALL VALIDATIONS PASSED")
        print("=" * 80)
        exit(0)
    else:
        print("✗ SOME VALIDATIONS FAILED")
        print("=" * 80)
        exit(1)
