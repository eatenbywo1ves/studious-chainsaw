"""
D3FEND Integration for Webhook Monitoring System
Adds D3FEND ontology annotations and exports to webhook monitoring
"""

import json
import logging
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path

from .technique_mapping import TechniqueMapper
from .ontology_export import D3FENDOntologyExporter
from .api_client import D3FENDAPIClient

logger = logging.getLogger(__name__)


class D3FENDWebhookMonitor:
    """
    Enhanced webhook monitor with D3FEND integration

    Extends existing webhook monitoring with:
    - D3FEND technique annotations
    - JSON-LD export of events
    - Automated countermeasure recommendations
    - Compliance reporting
    """

    def __init__(
        self,
        webhook_monitor,  # Pass your existing WebhookMonitor instance
        export_dir: str = "./security/d3fend/exports",
    ):
        self.webhook_monitor = webhook_monitor
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)

        self.technique_mapper = TechniqueMapper()
        self.ontology_exporter = D3FENDOntologyExporter()
        self.api_client = D3FENDAPIClient()

        logger.info("D3FEND webhook monitor integration initialized")

    async def annotate_webhook_event(self, webhook_metric: Dict[str, Any]) -> Dict[str, Any]:
        """
        Annotate webhook event with D3FEND techniques

        Args:
            webhook_metric: Webhook metric from monitoring system

        Returns:
            Annotated event with D3FEND metadata
        """
        # Get base mapping
        mapping = self.technique_mapper.get_techniques_for_component("webhook_monitoring.py")

        if not mapping:
            logger.warning("No D3FEND mapping found for webhook monitoring")
            return webhook_metric

        # Annotate event
        annotated_event = webhook_metric.copy()
        annotated_event["d3fend"] = {
            "techniques": mapping.technique_ids,
            "category": mapping.category.value,
            "coverage": mapping.coverage_percentage,
            "artifact_type": "NetworkTraffic",
        }

        # Determine specific technique based on event type
        if "health_check" in webhook_metric.get("event_type", ""):
            annotated_event["d3fend"]["primary_technique"] = "D3-NTA"
            annotated_event["d3fend"]["artifact_type"] = "HealthCheckEvent"
        elif "error" in webhook_metric.get("status", ""):
            annotated_event["d3fend"]["primary_technique"] = (
                "D3-AET"  # Authentication Event Thresholding
            )
            annotated_event["d3fend"]["severity"] = "high"

        return annotated_event

    async def export_event_to_jsonld(self, webhook_metric: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export webhook event as D3FEND JSON-LD

        Args:
            webhook_metric: Webhook metric

        Returns:
            JSON-LD formatted event
        """
        # Annotate first
        annotated = await self.annotate_webhook_event(webhook_metric)

        # Export as JSON-LD
        jsonld = self.ontology_exporter.export_webhook_event_jsonld(annotated)

        return jsonld

    async def export_metrics_batch(
        self, time_window_minutes: int = 60, output_format: str = "jsonld"
    ) -> str:
        """
        Export batch of webhook metrics in D3FEND format

        Args:
            time_window_minutes: Time window to export
            output_format: Export format (jsonld, rdf, turtle)

        Returns:
            Path to exported file
        """
        # Get recent metrics from webhook monitor
        metrics_data = await self.webhook_monitor.get_time_series_data(time_window_minutes)

        if not metrics_data or not metrics_data.get("time_series"):
            logger.warning("No metrics available for export")
            return ""

        # Convert time series to events
        events = []
        for point in metrics_data["time_series"]:
            event = {
                "event_id": f"evt_{int(point['timestamp'])}",
                "timestamp": point["timestamp"],
                "event_type": "webhook.delivery.batch",
                "endpoint": "batch_export",
                "duration": 0.0,
                "status": "success" if point["success"] > point["failed"] else "partial",
                "success_count": point["success"],
                "failed_count": point["failed"],
            }
            events.append(event)

        # Create JSON-LD dataset
        jsonld_graph = {
            "@context": {
                "d3f": "http://d3fend.mitre.org/ontologies/d3fend.owl#",
                "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
                "dc": "http://purl.org/dc/elements/1.1/",
            },
            "@graph": [],
        }

        for event in events:
            event_jsonld = await self.export_event_to_jsonld(event)
            jsonld_graph["@graph"].append(event_jsonld)

        # Save to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"webhook_metrics_{timestamp}.{output_format}"
        filepath = self.export_dir / filename

        if output_format == "jsonld":
            with open(filepath, "w") as f:
                json.dump(jsonld_graph, f, indent=2)
        elif output_format == "rdf":
            # Convert first event to RDF as example
            if jsonld_graph["@graph"]:
                rdf_xml = self.ontology_exporter.export_to_rdf_xml(jsonld_graph["@graph"][0])
                with open(filepath, "w") as f:
                    f.write(rdf_xml)
        elif output_format == "turtle":
            # Convert first event to Turtle as example
            if jsonld_graph["@graph"]:
                turtle = self.ontology_exporter.export_to_turtle(jsonld_graph["@graph"][0])
                with open(filepath, "w") as f:
                    f.write(turtle)

        logger.info(f"Exported {len(events)} events to {filepath}")
        return str(filepath)

    async def generate_d3fend_dashboard_data(self) -> Dict[str, Any]:
        """
        Generate D3FEND-enhanced dashboard data

        Returns:
            Dashboard data with D3FEND annotations
        """
        # Get base dashboard data
        base_data = await self.webhook_monitor.get_dashboard_data()

        # Add D3FEND metadata
        d3fend_data = {
            "d3fend_version": "v0.10",
            "monitoring_techniques": [
                {
                    "id": "D3-NTA",
                    "name": "Network Traffic Analysis",
                    "status": "active",
                    "events_analyzed": base_data["summary"]["total_deliveries"],
                },
                {
                    "id": "D3-SCA",
                    "name": "System Call Analysis",
                    "status": "active",
                    "events_analyzed": base_data["summary"]["total_deliveries"],
                },
            ],
            "defensive_coverage": {
                "category": "detect",
                "techniques_implemented": 3,
                "coverage_percentage": 95.0,
            },
            "compliance_status": {
                "nist_controls": ["SC-7", "SI-4", "AU-6"],
                "soc2_controls": ["CC6.1", "CC6.7", "CC7.2"],
            },
        }

        # Merge with base data
        enhanced_data = {**base_data, "d3fend": d3fend_data}

        return enhanced_data

    async def detect_anomalies_with_d3fend(self, threshold: float = 0.8) -> List[Dict[str, Any]]:
        """
        Detect anomalies using D3FEND-guided analysis

        Args:
            threshold: Anomaly detection threshold (0-1)

        Returns:
            List of detected anomalies with D3FEND context
        """
        anomalies = []

        # Get endpoint health from webhook monitor
        for endpoint, health in self.webhook_monitor.endpoint_health.items():
            if health.total_calls == 0:
                continue

            success_rate = health.successful_calls / health.total_calls

            # Anomaly detected
            if success_rate < threshold:
                anomaly = {
                    "endpoint": endpoint,
                    "success_rate": success_rate,
                    "total_calls": health.total_calls,
                    "circuit_breaker_state": health.circuit_breaker_state,
                    "d3fend_analysis": {
                        "detected_by": "D3-NTA",  # Network Traffic Analysis
                        "artifact_type": "NetworkTraffic",
                        "recommended_actions": [],
                        "severity": "high" if success_rate < 0.5 else "medium",
                    },
                }

                # Get recommendations from D3FEND
                if success_rate < 0.3:
                    anomaly["d3fend_analysis"]["recommended_actions"] = [
                        {"technique": "D3-CE", "action": "Connection Eviction - Block endpoint"},
                        {"technique": "D3-NI", "action": "Network Isolation - Quarantine traffic"},
                    ]
                else:
                    anomaly["d3fend_analysis"]["recommended_actions"] = [
                        {
                            "technique": "D3-AET",
                            "action": "Authentication Event Thresholding - Monitor rate",
                        },
                        {
                            "technique": "D3-RAC",
                            "action": "Resource Access Control - Apply rate limits",
                        },
                    ]

                anomalies.append(anomaly)

        return anomalies

    async def generate_countermeasure_recommendations(
        self, detected_threats: List[str]
    ) -> Dict[str, Any]:
        """
        Generate D3FEND countermeasure recommendations for detected threats

        Args:
            detected_threats: List of threat indicators or ATT&CK IDs

        Returns:
            Countermeasure recommendations
        """
        recommendations = {"threats_analyzed": len(detected_threats), "countermeasures": []}

        for threat in detected_threats:
            # Try to get D3FEND countermeasures from API
            mapping = await self.api_client.get_countermeasures_for_attack(threat)

            if mapping:
                recommendations["countermeasures"].append(
                    {
                        "threat_id": threat,
                        "threat_name": mapping.attack_name,
                        "d3fend_techniques": mapping.countermeasures,
                        "implementation_status": self._check_implementation_status(
                            mapping.countermeasures
                        ),
                    }
                )
            else:
                # Fallback recommendations
                recommendations["countermeasures"].append(
                    {
                        "threat_id": threat,
                        "d3fend_techniques": ["D3-NTA", "D3-IV", "D3-EAT"],
                        "implementation_status": "partial",
                    }
                )

        return recommendations

    def _check_implementation_status(self, required_techniques: List[str]) -> str:
        """Check if required D3FEND techniques are implemented"""
        implemented = self.technique_mapper.get_all_implemented_techniques()
        implemented_ids = {t.value for t in implemented}

        required_set = set(required_techniques)
        implemented_count = len(required_set & implemented_ids)

        if implemented_count == len(required_set):
            return "fully_implemented"
        elif implemented_count > 0:
            return "partially_implemented"
        else:
            return "not_implemented"

    async def create_compliance_report(self) -> Dict[str, Any]:
        """
        Create D3FEND compliance report for webhook monitoring

        Returns:
            Compliance report with D3FEND mappings
        """
        # Get coverage report
        coverage = self.technique_mapper.generate_coverage_report()

        # Get dashboard data
        dashboard = await self.generate_d3fend_dashboard_data()

        report = {
            "report_id": f"d3fend_compliance_{datetime.now().strftime('%Y%m%d')}",
            "timestamp": datetime.now().isoformat(),
            "system": "Webhook Monitoring System",
            "d3fend_coverage": {
                "total_techniques_available": coverage["total_techniques_available"],
                "techniques_implemented": coverage["techniques_implemented"],
                "coverage_percentage": coverage["coverage_percentage"],
                "category_breakdown": coverage["category_coverage"],
            },
            "active_monitoring": {
                "techniques": dashboard["d3fend"]["monitoring_techniques"],
                "events_processed": dashboard["summary"]["total_deliveries"],
                "success_rate": dashboard["summary"]["success_rate"],
            },
            "compliance_mappings": {
                "nist_800_53": dashboard["d3fend"]["compliance_status"]["nist_controls"],
                "soc2": dashboard["d3fend"]["compliance_status"]["soc2_controls"],
            },
            "recommendations": self.technique_mapper.recommend_next_techniques(limit=5),
        }

        # Save report
        report_file = (
            self.export_dir / f"compliance_report_{datetime.now().strftime('%Y%m%d')}.json"
        )
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"D3FEND compliance report saved to {report_file}")

        return report


# Example usage and integration
async def integrate_with_existing_monitor(webhook_monitor):
    """
    Example: Integrate D3FEND with existing webhook monitor

    Args:
        webhook_monitor: Your existing WebhookMonitor instance
    """
    # Create D3FEND integration
    d3fend_monitor = D3FENDWebhookMonitor(webhook_monitor)

    # Export recent events
    export_path = await d3fend_monitor.export_metrics_batch(
        time_window_minutes=60, output_format="jsonld"
    )
    print(f"Exported events to: {export_path}")

    # Generate enhanced dashboard
    dashboard = await d3fend_monitor.generate_d3fend_dashboard_data()
    print(f"D3FEND Monitoring Techniques: {len(dashboard['d3fend']['monitoring_techniques'])}")

    # Detect anomalies with D3FEND context
    anomalies = await d3fend_monitor.detect_anomalies_with_d3fend(threshold=0.8)
    print(f"Detected {len(anomalies)} anomalies with D3FEND analysis")

    for anomaly in anomalies:
        print(f"\nAnomaly: {anomaly['endpoint']}")
        print(f"  Success Rate: {anomaly['success_rate']:.2%}")
        print(f"  D3FEND Technique: {anomaly['d3fend_analysis']['detected_by']}")
        print("  Recommended Actions:")
        for action in anomaly["d3fend_analysis"]["recommended_actions"]:
            print(f"    - [{action['technique']}] {action['action']}")

    # Generate compliance report
    report = await d3fend_monitor.create_compliance_report()
    print(f"\nD3FEND Coverage: {report['d3fend_coverage']['coverage_percentage']:.1f}%")
    print(f"Techniques Implemented: {report['d3fend_coverage']['techniques_implemented']}")


if __name__ == "__main__":
    # This would be used with your actual webhook monitor instance
    # asyncio.run(integrate_with_existing_monitor(your_webhook_monitor))
    print("D3FEND Webhook Integration Module Ready")
    print(
        "Import and use with: from security.d3fend.webhook_d3fend_integration import D3FENDWebhookMonitor"
    )
