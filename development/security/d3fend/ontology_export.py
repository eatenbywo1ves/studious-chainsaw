"""
D3FEND Ontology Export Module
Exports security artifacts in D3FEND-compliant RDF/OWL and JSON-LD formats
"""

import json
from typing import Dict, List, Any
from datetime import datetime
import hashlib
from .technique_mapping import D3FENDTechnique


class D3FENDOntologyExporter:
    """
    Export security artifacts in D3FEND ontology formats (JSON-LD, RDF/XML, Turtle)
    """

    # D3FEND ontology namespaces
    D3FEND_NS = "http://d3fend.mitre.org/ontologies/d3fend.owl#"
    RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
    RDFS_NS = "http://www.w3.org/2000/01/rdf-schema#"
    XSD_NS = "http://www.w3.org/2001/XMLSchema#"
    DC_NS = "http://purl.org/dc/elements/1.1/"

    def __init__(self, base_uri: str = "http://catalytic-computing.com/security/"):
        self.base_uri = base_uri

    def export_webhook_event_jsonld(self, webhook_metric: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export webhook metric as D3FEND JSON-LD Digital Event

        Maps to D3FEND Digital Artifact Ontology:
        - Digital Event
        - Network Traffic
        - Service Call
        """
        event_uri = f"{self.base_uri}events/{webhook_metric.get('event_id', 'unknown')}"

        jsonld = {
            "@context": {
                "d3f": self.D3FEND_NS,
                "rdf": self.RDF_NS,
                "rdfs": self.RDFS_NS,
                "xsd": self.XSD_NS,
                "dc": self.DC_NS,
                "timestamp": {"@id": "d3f:timestamp", "@type": "xsd:dateTime"},
                "eventType": {"@id": "d3f:eventType", "@type": "xsd:string"},
                "networkNode": {"@id": "d3f:networkNode", "@type": "xsd:anyURI"},
                "duration": {"@id": "d3f:duration", "@type": "xsd:float"},
                "status": {"@id": "d3f:status", "@type": "xsd:string"},
            },
            "@id": event_uri,
            "@type": ["d3f:DigitalEvent", "d3f:NetworkTraffic", "d3f:ServiceCall"],
            "timestamp": datetime.fromtimestamp(webhook_metric["timestamp"]).isoformat(),
            "eventType": webhook_metric["event_type"],
            "networkNode": webhook_metric["endpoint"],
            "duration": webhook_metric["duration"],
            "status": webhook_metric["status"],
            "dc:creator": "Catalytic Computing Webhook Monitor",
            "rdfs:label": f"Webhook Event: {webhook_metric['event_type']}",
            "d3f:defendsTechnique": [
                {"@id": f"{self.D3FEND_NS}D3-NTA"},  # Network Traffic Analysis
                {"@id": f"{self.D3FEND_NS}D3-SCA"},  # System Call Analysis
            ],
        }

        # Add error information if present
        if webhook_metric.get("error_message"):
            jsonld["d3f:errorMessage"] = webhook_metric["error_message"]
            jsonld["d3f:severity"] = "high"

        # Add retry information
        if webhook_metric.get("retry_count", 0) > 0:
            jsonld["d3f:retryCount"] = webhook_metric["retry_count"]

        return jsonld

    def export_security_event_jsonld(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        techniques: List[D3FENDTechnique],
        artifact_type: str = "DigitalEvent",
    ) -> Dict[str, Any]:
        """
        Export generic security event as D3FEND JSON-LD

        Args:
            event_type: Type of security event
            event_data: Event data dictionary
            techniques: List of D3FEND techniques this event relates to
            artifact_type: D3FEND artifact type (DigitalEvent, File, Process, etc.)
        """
        event_id = (
            event_data.get("event_id")
            or hashlib.sha256(f"{event_type}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        )
        event_uri = f"{self.base_uri}events/{event_id}"

        jsonld = {
            "@context": {
                "d3f": self.D3FEND_NS,
                "rdf": self.RDF_NS,
                "rdfs": self.RDFS_NS,
                "xsd": self.XSD_NS,
                "dc": self.DC_NS,
            },
            "@id": event_uri,
            "@type": f"d3f:{artifact_type}",
            "rdfs:label": f"{event_type} Event",
            "dc:created": datetime.now().isoformat(),
            "dc:creator": "Catalytic Computing Security System",
            "d3f:defendsTechnique": [
                {"@id": f"{self.D3FEND_NS}{tech.value}"} for tech in techniques
            ],
        }

        # Add event-specific data
        for key, value in event_data.items():
            if key not in ["event_id"]:
                # Convert to appropriate XSD type
                if isinstance(value, bool):
                    jsonld[f"d3f:{key}"] = {"@value": value, "@type": "xsd:boolean"}
                elif isinstance(value, int):
                    jsonld[f"d3f:{key}"] = {"@value": value, "@type": "xsd:integer"}
                elif isinstance(value, float):
                    jsonld[f"d3f:{key}"] = {"@value": value, "@type": "xsd:float"}
                else:
                    jsonld[f"d3f:{key}"] = str(value)

        return jsonld

    def export_compliance_check_jsonld(
        self,
        check_id: str,
        control_id: str,
        status: str,
        techniques: List[D3FENDTechnique],
        evidence: List[str],
    ) -> Dict[str, Any]:
        """
        Export compliance check as D3FEND JSON-LD

        Maps to D3FEND Asset Inventory and Security Control Mapping
        """
        check_uri = f"{self.base_uri}compliance/{check_id}"

        jsonld = {
            "@context": {
                "d3f": self.D3FEND_NS,
                "rdf": self.RDF_NS,
                "rdfs": self.RDFS_NS,
                "xsd": self.XSD_NS,
                "dc": self.DC_NS,
            },
            "@id": check_uri,
            "@type": ["d3f:SecurityControl", "d3f:ComplianceCheck"],
            "rdfs:label": f"Compliance Check: {control_id}",
            "d3f:controlId": control_id,
            "d3f:status": status,
            "dc:created": datetime.now().isoformat(),
            "d3f:defendsTechnique": [
                {"@id": f"{self.D3FEND_NS}{tech.value}"} for tech in techniques
            ],
            "d3f:evidence": evidence,
        }

        return jsonld

    def export_to_rdf_xml(self, jsonld_data: Dict[str, Any]) -> str:
        """
        Convert JSON-LD to RDF/XML format

        This is a simplified conversion. For production, use rdflib library.
        """
        jsonld_data.get("@context", {})
        rdf_id = jsonld_data.get("@id", "")
        rdf_type = jsonld_data.get("@type", "")

        rdf_types = [rdf_type] if isinstance(rdf_type, str) else rdf_type

        xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_parts.append("<rdf:RDF")
        xml_parts.append('  xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"')
        xml_parts.append('  xmlns:rdfs="http://www.w3.org/2000/01/rdf-schema#"')
        xml_parts.append('  xmlns:d3f="http://d3fend.mitre.org/ontologies/d3fend.owl#"')
        xml_parts.append('  xmlns:xsd="http://www.w3.org/2001/XMLSchema#"')
        xml_parts.append('  xmlns:dc="http://purl.org/dc/elements/1.1/">')

        # Description element
        xml_parts.append(f'  <rdf:Description rdf:about="{rdf_id}">')

        # Types
        for rdf_t in rdf_types:
            xml_parts.append(f'    <rdf:type rdf:resource="{rdf_t}"/>')

        # Properties
        for key, value in jsonld_data.items():
            if key not in ["@context", "@id", "@type"]:
                if isinstance(value, dict):
                    if "@id" in value:
                        xml_parts.append(f'    <{key} rdf:resource="{value["@id"]}"/>')
                    elif "@value" in value:
                        datatype = value.get("@type", "")
                        xml_parts.append(
                            f'    <{key} rdf:datatype="{datatype}">{value["@value"]}</{key}>'
                        )
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict) and "@id" in item:
                            xml_parts.append(f'    <{key} rdf:resource="{item["@id"]}"/>')
                else:
                    xml_parts.append(f"    <{key}>{value}</{key}>")

        xml_parts.append("  </rdf:Description>")
        xml_parts.append("</rdf:RDF>")

        return "\n".join(xml_parts)

    def export_to_turtle(self, jsonld_data: Dict[str, Any]) -> str:
        """
        Convert JSON-LD to Turtle (TTL) format

        This is a simplified conversion. For production, use rdflib library.
        """
        rdf_id = jsonld_data.get("@id", "")
        rdf_type = jsonld_data.get("@type", "")
        rdf_types = [rdf_type] if isinstance(rdf_type, str) else rdf_type

        turtle_parts = [
            "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .",
            "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .",
            "@prefix d3f: <http://d3fend.mitre.org/ontologies/d3fend.owl#> .",
            "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
            "@prefix dc: <http://purl.org/dc/elements/1.1/> .",
            "",
            f"<{rdf_id}>",
        ]

        # Types
        for idx, rdf_t in enumerate(rdf_types):
            prefix = "  a" if idx == 0 else "   "
            suffix = " ;" if idx < len(rdf_types) - 1 or len(jsonld_data) > 3 else " ."
            turtle_parts.append(f"{prefix} {rdf_t}{suffix}")

        # Properties
        props = [(k, v) for k, v in jsonld_data.items() if k not in ["@context", "@id", "@type"]]
        for idx, (key, value) in enumerate(props):
            suffix = " ;" if idx < len(props) - 1 else " ."

            if isinstance(value, dict):
                if "@id" in value:
                    turtle_parts.append(f"  {key} <{value['@id']}>{suffix}")
                elif "@value" in value:
                    turtle_parts.append(f'  {key} "{value["@value"]}"{suffix}')
            elif isinstance(value, list):
                items = []
                for item in value:
                    if isinstance(item, dict) and "@id" in item:
                        items.append(f"<{item['@id']}>")
                if items:
                    turtle_parts.append(f"  {key} {', '.join(items)}{suffix}")
            else:
                turtle_parts.append(f'  {key} "{value}"{suffix}')

        return "\n".join(turtle_parts)

    def export_system_inventory_jsonld(
        self, assets: List[Dict[str, Any]], network_map: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Export system inventory as D3FEND JSON-LD

        Implements D3-AI (Asset Inventory) and D3-NM (Network Mapping)
        """
        inventory_uri = f"{self.base_uri}inventory/{datetime.now().strftime('%Y%m%d')}"

        jsonld = {
            "@context": {
                "d3f": self.D3FEND_NS,
                "rdf": self.RDF_NS,
                "rdfs": self.RDFS_NS,
                "dc": self.DC_NS,
            },
            "@id": inventory_uri,
            "@type": "d3f:AssetInventory",
            "rdfs:label": "Catalytic Computing System Inventory",
            "dc:created": datetime.now().isoformat(),
            "d3f:defendsTechnique": [
                {"@id": f"{self.D3FEND_NS}D3-AI"},  # Asset Inventory
                {"@id": f"{self.D3FEND_NS}D3-NM"},  # Network Mapping
                {"@id": f"{self.D3FEND_NS}D3-SM"},  # System Mapping
            ],
            "d3f:assets": [],
        }

        # Add assets
        for asset in assets:
            asset_data = {
                "@id": f"{self.base_uri}assets/{asset.get('id', 'unknown')}",
                "@type": f"d3f:{asset.get('type', 'DigitalAsset')}",
                "rdfs:label": asset.get("name", "Unknown Asset"),
                "d3f:ipAddress": asset.get("ip_address"),
                "d3f:hostname": asset.get("hostname"),
            }
            jsonld["d3f:assets"].append(asset_data)

        # Add network topology
        if network_map:
            jsonld["d3f:networkTopology"] = {
                "@type": "d3f:NetworkTopology",
                "d3f:nodes": network_map.get("nodes", []),
                "d3f:connections": network_map.get("connections", []),
            }

        return jsonld

    def create_d3fend_dataset(
        self,
        webhook_events: List[Dict[str, Any]],
        compliance_checks: List[Dict[str, Any]],
        security_events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Create comprehensive D3FEND dataset from multiple sources

        Returns a complete JSON-LD graph
        """
        graph = {
            "@context": {
                "d3f": self.D3FEND_NS,
                "rdf": self.RDF_NS,
                "rdfs": self.RDFS_NS,
                "xsd": self.XSD_NS,
                "dc": self.DC_NS,
            },
            "@graph": [],
        }

        # Export webhook events
        for event in webhook_events:
            graph["@graph"].append(self.export_webhook_event_jsonld(event))

        # Export compliance checks
        for check in compliance_checks:
            techniques = [D3FENDTechnique.ASSET_INVENTORY, D3FENDTechnique.SYSTEM_MAPPING]
            graph["@graph"].append(
                self.export_compliance_check_jsonld(
                    check_id=check["check_id"],
                    control_id=check["control_id"],
                    status=check["status"],
                    techniques=techniques,
                    evidence=check.get("evidence", []),
                )
            )

        # Export security events
        for event in security_events:
            techniques = event.get("d3fend_techniques", [D3FENDTechnique.NETWORK_TRAFFIC_ANALYSIS])
            graph["@graph"].append(
                self.export_security_event_jsonld(
                    event_type=event["type"],
                    event_data=event["data"],
                    techniques=techniques,
                    artifact_type=event.get("artifact_type", "DigitalEvent"),
                )
            )

        return graph


# Example usage
if __name__ == "__main__":
    exporter = D3FENDOntologyExporter()

    # Example webhook event
    webhook_event = {
        "event_id": "evt_123456",
        "timestamp": datetime.now().timestamp(),
        "event_type": "api.request.completed",
        "endpoint": "https://api.catalytic-computing.com/v1/data",
        "duration": 0.145,
        "status": "success",
    }

    # Export as JSON-LD
    jsonld = exporter.export_webhook_event_jsonld(webhook_event)
    print("JSON-LD Export:")
    print(json.dumps(jsonld, indent=2))

    print("\n" + "=" * 70 + "\n")

    # Export as RDF/XML
    rdf_xml = exporter.export_to_rdf_xml(jsonld)
    print("RDF/XML Export:")
    print(rdf_xml)

    print("\n" + "=" * 70 + "\n")

    # Export as Turtle
    turtle = exporter.export_to_turtle(jsonld)
    print("Turtle Export:")
    print(turtle)
