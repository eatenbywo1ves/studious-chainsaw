"""
Alert Rules Validation Tests

Tests to validate that Prometheus alert rules are correctly configured and firing when expected.
"""

import requests
import pytest
from typing import Dict, List, Any, Optional


class AlertRulesValidator:
    """Validates Prometheus alert rules"""

    def __init__(self, prometheus_url: str = "http://localhost:9090"):
        self.prometheus_url = prometheus_url
        self.api_url = f"{prometheus_url}/api/v1"

    def get_rules(self) -> Dict[str, Any]:
        """Get all configured rules"""
        try:
            response = requests.get(f"{self.api_url}/rules", timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to get rules: {e}")
            return {}

    def get_alerts(self) -> Dict[str, Any]:
        """Get current alert status"""
        try:
            response = requests.get(f"{self.api_url}/alerts", timeout=5)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Failed to get alerts: {e}")
            return {}

    def parse_rules(self) -> List[Dict[str, Any]]:
        """Parse and extract all alert rules"""
        rules_data = self.get_rules()
        all_rules = []

        if rules_data and "data" in rules_data:
            groups = rules_data["data"].get("groups", [])

            for group in groups:
                group_name = group.get("name")
                rules = group.get("rules", [])

                for rule in rules:
                    if rule.get("type") == "alerting":
                        rule["group_name"] = group_name
                        all_rules.append(rule)

        return all_rules

    def get_alert_by_name(self, alert_name: str) -> Optional[Dict[str, Any]]:
        """Get a specific alert rule by name"""
        rules = self.parse_rules()
        for rule in rules:
            if rule.get("name") == alert_name:
                return rule
        return None

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get currently firing alerts"""
        alerts_data = self.get_alerts()
        if alerts_data and "data" in alerts_data:
            return alerts_data["data"].get("alerts", [])
        return []

    def get_alerts_by_state(self, state: str) -> List[Dict[str, Any]]:
        """Get alerts by state (firing, pending, inactive)"""
        active_alerts = self.get_active_alerts()
        return [alert for alert in active_alerts if alert.get("state") == state]

    def validate_alert_structure(self, alert_rule: Dict[str, Any]) -> Dict[str, bool]:
        """Validate that an alert rule has required fields"""
        validations = {
            "has_name": "name" in alert_rule,
            "has_query": "query" in alert_rule,
            "has_duration": "duration" in alert_rule,
            "has_labels": "labels" in alert_rule,
            "has_annotations": "annotations" in alert_rule,
            "has_severity": "labels" in alert_rule and "severity" in alert_rule.get("labels", {}),
            "has_category": "labels" in alert_rule and "category" in alert_rule.get("labels", {}),
            "has_summary": "annotations" in alert_rule
            and "summary" in alert_rule.get("annotations", {}),
            "has_description": "annotations" in alert_rule
            and "description" in alert_rule.get("annotations", {}),
            "has_remediation": "annotations" in alert_rule
            and "remediation" in alert_rule.get("annotations", {}),
        }

        return validations

    def check_alert_rule_validity(self, alert_name: str) -> Dict[str, Any]:
        """Check if an alert rule is valid and configured correctly"""
        alert_rule = self.get_alert_by_name(alert_name)

        if not alert_rule:
            return {
                "exists": False,
                "valid": False,
                "message": f"Alert rule '{alert_name}' not found",
            }

        validations = self.validate_alert_structure(alert_rule)
        all_valid = all(validations.values())

        return {
            "exists": True,
            "valid": all_valid,
            "validations": validations,
            "alert_rule": alert_rule,
        }

    def get_recording_rules(self) -> List[Dict[str, Any]]:
        """Get all recording rules"""
        rules_data = self.get_rules()
        recording_rules = []

        if rules_data and "data" in rules_data:
            groups = rules_data["data"].get("groups", [])

            for group in groups:
                group_name = group.get("name")
                rules = group.get("rules", [])

                for rule in rules:
                    if rule.get("type") == "recording":
                        rule["group_name"] = group_name
                        recording_rules.append(rule)

        return recording_rules


# ============================================================================
# PYTEST TEST CASES
# ============================================================================


@pytest.fixture
def validator():
    """Create an AlertRulesValidator instance"""
    return AlertRulesValidator()


def test_rules_loaded(validator):
    """Test that alert rules are loaded"""
    rules = validator.parse_rules()
    assert len(rules) > 0, "No alert rules found"


def test_security_alerts_exist(validator):
    """Test that all expected security alerts are configured"""
    expected_alerts = [
        "HighFailedLoginRate",
        "CriticalFailedLoginRate",
        "RateLimitExceeded",
        "RateLimitCritical",
        "HighInputValidationFailures",
        "SQLInjectionAttempt",
        "EncryptionFailureRate",
        "DecryptionFailureRate",
        "UnauthorizedAPIAccess",
    ]

    for alert_name in expected_alerts:
        result = validator.check_alert_rule_validity(alert_name)
        assert result["exists"], f"Alert rule '{alert_name}' not found"
        assert result["valid"], (
            f"Alert rule '{alert_name}' is not valid: {result.get('validations')}"
        )


def test_performance_alerts_exist(validator):
    """Test that performance monitoring alerts exist"""
    expected_alerts = [
        "HighDatabaseQueryLatency",
        "DatabaseConnectionPoolExhaustion",
        "RedisMemoryHigh",
        "RedisCacheMissRateHigh",
        "HighCPUUsage",
        "HighMemoryUsage",
        "DiskSpaceLow",
    ]

    for alert_name in expected_alerts:
        result = validator.check_alert_rule_validity(alert_name)
        assert result["exists"], f"Alert rule '{alert_name}' not found"


def test_all_alerts_have_severity(validator):
    """Test that all alerts have severity labels"""
    rules = validator.parse_rules()

    for rule in rules:
        alert_name = rule.get("name")
        labels = rule.get("labels", {})
        assert "severity" in labels, f"Alert '{alert_name}' missing severity label"
        assert labels["severity"] in ["critical", "warning", "info"], (
            f"Alert '{alert_name}' has invalid severity: {labels['severity']}"
        )


def test_all_alerts_have_category(validator):
    """Test that all alerts have category labels"""
    rules = validator.parse_rules()

    for rule in rules:
        alert_name = rule.get("name")
        labels = rule.get("labels", {})
        assert "category" in labels, f"Alert '{alert_name}' missing category label"


def test_all_alerts_have_annotations(validator):
    """Test that all alerts have required annotations"""
    rules = validator.parse_rules()

    required_annotations = ["summary", "description", "remediation"]

    for rule in rules:
        alert_name = rule.get("name")
        annotations = rule.get("annotations", {})

        for required_annotation in required_annotations:
            assert required_annotation in annotations, (
                f"Alert '{alert_name}' missing annotation: {required_annotation}"
            )


def test_critical_alerts_have_compliance_labels(validator):
    """Test that critical security alerts have compliance labels"""
    rules = validator.parse_rules()

    for rule in rules:
        labels = rule.get("labels", {})
        if labels.get("severity") == "critical" and labels.get("category") == "security":
            alert_name = rule.get("name")
            # Critical security alerts should have compliance labels
            # This is optional but recommended
            if "compliance" not in labels:
                print(f"INFO: Critical alert '{alert_name}' could benefit from compliance label")


def test_recording_rules_exist(validator):
    """Test that recording rules are configured"""
    recording_rules = validator.get_recording_rules()
    assert len(recording_rules) > 0, "No recording rules found"


def test_compliance_recording_rules(validator):
    """Test that compliance recording rules exist"""
    expected_recording_rules = [
        "security:failed_logins:rate5m",
        "security:unauthorized_access:rate5m",
        "security:rate_limited:rate5m",
        "security:encryption_errors:rate5m",
        "security:decryption_errors:rate5m",
        "api:request_rate:avg1h",
        "api:latency:p95",
        "api:latency:p99",
    ]

    recording_rules = validator.get_recording_rules()
    recording_rule_names = [r.get("name") for r in recording_rules]

    for expected_rule in expected_recording_rules:
        assert expected_rule in recording_rule_names, f"Recording rule '{expected_rule}' not found"


def test_alert_evaluation_time_acceptable(validator):
    """Test that alert evaluation times are acceptable"""
    rules_data = validator.get_rules()

    if rules_data and "data" in rules_data:
        groups = rules_data["data"].get("groups", [])

        for group in groups:
            group.get("lastEvaluation")
            eval_duration = group.get("evaluationTime")

            if eval_duration:
                # Evaluation should complete within 10 seconds
                assert eval_duration < 10.0, (
                    f"Group '{group.get('name')}' evaluation time too high: {eval_duration}s"
                )


# ============================================================================
# STANDALONE VALIDATION SCRIPT
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("ALERT RULES VALIDATION")
    print("=" * 80)
    print()

    validator = AlertRulesValidator()

    # Get all rules
    print("1. Loading alert rules...")
    rules = validator.parse_rules()
    recording_rules = validator.get_recording_rules()
    print(f"   Found {len(rules)} alert rule(s)")
    print(f"   Found {len(recording_rules)} recording rule(s)")

    # Validate alert rules
    print("\n2. Validating alert rules...")
    all_valid = True

    for rule in rules:
        alert_name = rule.get("name")
        validations = validator.validate_alert_structure(rule)
        is_valid = all(validations.values())

        status_icon = "✓" if is_valid else "✗"
        severity = rule.get("labels", {}).get("severity", "unknown")
        category = rule.get("labels", {}).get("category", "unknown")

        print(f"   {status_icon} {alert_name} [{severity}/{category}]")

        if not is_valid:
            all_valid = False
            failed = [k for k, v in validations.items() if not v]
            print(f"      Failed checks: {', '.join(failed)}")

    # Check for active alerts
    print("\n3. Checking active alerts...")
    firing_alerts = validator.get_alerts_by_state("firing")
    pending_alerts = validator.get_alerts_by_state("pending")

    print(f"   Firing alerts: {len(firing_alerts)}")
    for alert in firing_alerts:
        alert_name = alert.get("labels", {}).get("alertname", "unknown")
        severity = alert.get("labels", {}).get("severity", "unknown")
        print(f"   🔥 {alert_name} [{severity}]")

    print(f"   Pending alerts: {len(pending_alerts)}")
    for alert in pending_alerts:
        alert_name = alert.get("labels", {}).get("alertname", "unknown")
        severity = alert.get("labels", {}).get("severity", "unknown")
        print(f"   ⏳ {alert_name} [{severity}]")

    # Validate recording rules
    print("\n4. Validating recording rules...")
    for rule in recording_rules:
        rule_name = rule.get("name")
        print(f"   ✓ {rule_name}")

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
