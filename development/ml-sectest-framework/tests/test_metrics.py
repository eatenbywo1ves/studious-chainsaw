"""
Test suite for Prometheus Metrics
==================================
Tests for metrics collection and export functionality.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.metrics import (
    MetricsCollector,
    record_vulnerability,
    set_available_agents,
    initialize_framework_info
)


class TestMetricsCollector:
    """Tests for MetricsCollector decorators."""

    def test_track_scan_decorator(self):
        """Test scan tracking decorator."""

        @MetricsCollector.track_scan("test_challenge", parallel=False)
        def sample_scan():
            return {"status": "completed"}

        result = sample_scan()
        assert result["status"] == "completed"

    def test_track_agent_decorator(self):
        """Test agent tracking decorator."""

        @MetricsCollector.track_agent("TestAgent")
        def sample_agent_execution():
            return {"vulnerabilities": []}

        result = sample_agent_execution()
        assert "vulnerabilities" in result

    def test_track_scan_with_exception(self):
        """Test scan tracking handles exceptions."""

        @MetricsCollector.track_scan("test_challenge", parallel=False)
        def failing_scan():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_scan()


class TestMetricHelpers:
    """Tests for metric helper functions."""

    def test_record_vulnerability(self):
        """Test vulnerability recording."""
        record_vulnerability(
            vuln_type="prompt_injection",
            severity="high",
            agent_name="PromptInjectionAgent"
        )
        # Should not raise exception

    def test_set_available_agents(self):
        """Test setting available agents count."""
        set_available_agents(6)
        # Should not raise exception

    def test_initialize_framework_info(self):
        """Test framework info initialization."""
        initialize_framework_info("1.0.0")
        # Should not raise exception


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
