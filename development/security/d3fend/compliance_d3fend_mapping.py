"""
D3FEND Mapping for Compliance Scanner
Maps SOC2, ISO27001, and NIST controls to D3FEND defensive techniques
"""

from typing import Dict, List
from dataclasses import dataclass
from .technique_mapping import D3FENDTechnique


@dataclass
class ComplianceToD3FENDMapping:
    """Mapping between compliance control and D3FEND technique"""
    control_framework: str  # SOC2, ISO27001, NIST, etc.
    control_id: str
    control_name: str
    d3fend_techniques: List[D3FENDTechnique]
    implementation_guidance: str


# Comprehensive mappings
COMPLIANCE_D3FEND_MAPPINGS: List[ComplianceToD3FENDMapping] = [

    # SOC2 Type II Controls to D3FEND
    ComplianceToD3FENDMapping(
        control_framework="SOC2",
        control_id="CC6.1",
        control_name="Logical and Physical Access Controls",
        d3fend_techniques=[
            D3FENDTechnique.USER_ACCOUNT_CONTROL,
            D3FENDTechnique.MULTI_FACTOR_AUTHENTICATION,
            D3FENDTechnique.NETWORK_ISOLATION,
            D3FENDTechnique.EXECUTION_ISOLATION
        ],
        implementation_guidance="Implement D3-UAC through RBAC policies, D3-MFA for authentication, "
                              "D3-NI for network segmentation, and D3-EI for workload isolation."
    ),

    ComplianceToD3FENDMapping(
        control_framework="SOC2",
        control_id="CC6.6",
        control_name="Logical and Physical Access Controls - Credentials",
        d3fend_techniques=[
            D3FENDTechnique.CREDENTIAL_HARDENING,
            D3FENDTechnique.STRONG_PASSWORD_POLICY,
            D3FENDTechnique.MULTI_FACTOR_AUTHENTICATION
        ],
        implementation_guidance="Implement D3-CH through secure credential storage, D3-SPP for "
                              "password complexity requirements, and D3-MFA for two-factor authentication."
    ),

    ComplianceToD3FENDMapping(
        control_framework="SOC2",
        control_id="CC6.7",
        control_name="Data Transmission and Storage Encryption",
        d3fend_techniques=[
            D3FENDTechnique.ENCRYPTION_IN_TRANSIT,
            D3FENDTechnique.ENCRYPTION_AT_REST
        ],
        implementation_guidance="Implement D3-EAT for TLS/SSL on all network communications and "
                              "D3-EAR for data-at-rest encryption using AES-256 or equivalent."
    ),

    ComplianceToD3FENDMapping(
        control_framework="SOC2",
        control_id="CC7.1",
        control_name="System Operations - Monitoring",
        d3fend_techniques=[
            D3FENDTechnique.NETWORK_TRAFFIC_ANALYSIS,
            D3FENDTechnique.SYSTEM_CALL_ANALYSIS,
            D3FENDTechnique.USER_BEHAVIOR_ANALYSIS
        ],
        implementation_guidance="Implement D3-NTA for network monitoring, D3-SCA for system activity "
                              "tracking, and D3-UBA for anomaly detection."
    ),

    ComplianceToD3FENDMapping(
        control_framework="SOC2",
        control_id="CC7.2",
        control_name="System Monitoring - Detection",
        d3fend_techniques=[
            D3FENDTechnique.FILE_ANALYSIS,
            D3FENDTechnique.PROCESS_ANALYSIS,
            D3FENDTechnique.AUTHENTICATION_EVENT_THRESHOLDING
        ],
        implementation_guidance="Implement D3-FA for file integrity monitoring, D3-PA for process "
                              "behavior analysis, and D3-AET for authentication monitoring."
    ),

    # ISO 27001 Controls to D3FEND
    ComplianceToD3FENDMapping(
        control_framework="ISO27001",
        control_id="A.9.1.2",
        control_name="Access to networks and network services",
        d3fend_techniques=[
            D3FENDTechnique.NETWORK_ISOLATION,
            D3FENDTechnique.RESOURCE_ACCESS_CONTROL,
            D3FENDTechnique.CREDENTIAL_TRANSMISSION_SCOPING
        ],
        implementation_guidance="Implement D3-NI through network segmentation, D3-RAC for access "
                              "control lists, and D3-CTS for secure credential transmission."
    ),

    ComplianceToD3FENDMapping(
        control_framework="ISO27001",
        control_id="A.10.1.1",
        control_name="Policy on the use of cryptographic controls",
        d3fend_techniques=[
            D3FENDTechnique.ENCRYPTION_AT_REST,
            D3FENDTechnique.ENCRYPTION_IN_TRANSIT,
            D3FENDTechnique.CREDENTIAL_HARDENING
        ],
        implementation_guidance="Implement comprehensive encryption policy using D3-EAR and D3-EAT, "
                              "with D3-CH for key management."
    ),

    ComplianceToD3FENDMapping(
        control_framework="ISO27001",
        control_id="A.12.4.1",
        control_name="Event logging",
        d3fend_techniques=[
            D3FENDTechnique.SYSTEM_CALL_ANALYSIS,
            D3FENDTechnique.FILE_ANALYSIS,
            D3FENDTechnique.NETWORK_TRAFFIC_ANALYSIS
        ],
        implementation_guidance="Implement comprehensive logging with D3-SCA for system events, "
                              "D3-FA for file operations, and D3-NTA for network activity."
    ),

    ComplianceToD3FENDMapping(
        control_framework="ISO27001",
        control_id="A.12.6.1",
        control_name="Management of technical vulnerabilities",
        d3fend_techniques=[
            D3FENDTechnique.ASSET_INVENTORY,
            D3FENDTechnique.SYSTEM_MAPPING,
            D3FENDTechnique.NETWORK_MAPPING
        ],
        implementation_guidance="Implement D3-AI for asset discovery, D3-SM for system mapping, "
                              "and D3-NM for network topology understanding to support vulnerability management."
    ),

    ComplianceToD3FENDMapping(
        control_framework="ISO27001",
        control_id="A.14.2.8",
        control_name="System security testing",
        d3fend_techniques=[
            D3FENDTechnique.INPUT_VALIDATION,
            D3FENDTechnique.FILE_ANALYSIS,
            D3FENDTechnique.PROCESS_ANALYSIS
        ],
        implementation_guidance="Implement security testing with D3-IV to test input validation, "
                              "D3-FA for file security checks, and D3-PA for process behavior validation."
    ),

    # NIST 800-53 Rev. 5 Controls to D3FEND
    ComplianceToD3FENDMapping(
        control_framework="NIST",
        control_id="AC-2",
        control_name="Account Management",
        d3fend_techniques=[
            D3FENDTechnique.USER_ACCOUNT_CONTROL,
            D3FENDTechnique.CREDENTIAL_HARDENING
        ],
        implementation_guidance="Implement D3-UAC for user account lifecycle management and D3-CH "
                              "for credential security."
    ),

    ComplianceToD3FENDMapping(
        control_framework="NIST",
        control_id="SC-7",
        control_name="Boundary Protection",
        d3fend_techniques=[
            D3FENDTechnique.NETWORK_ISOLATION,
            D3FENDTechnique.NETWORK_TRAFFIC_ANALYSIS
        ],
        implementation_guidance="Implement D3-NI for network segmentation and D3-NTA for boundary "
                              "monitoring and traffic analysis."
    ),

    ComplianceToD3FENDMapping(
        control_framework="NIST",
        control_id="SC-8",
        control_name="Transmission Confidentiality and Integrity",
        d3fend_techniques=[
            D3FENDTechnique.ENCRYPTION_IN_TRANSIT
        ],
        implementation_guidance="Implement D3-EAT using TLS 1.2+ for all network communications."
    ),

    ComplianceToD3FENDMapping(
        control_framework="NIST",
        control_id="SC-28",
        control_name="Protection of Information at Rest",
        d3fend_techniques=[
            D3FENDTechnique.ENCRYPTION_AT_REST
        ],
        implementation_guidance="Implement D3-EAR using AES-256 encryption for data at rest."
    ),

    ComplianceToD3FENDMapping(
        control_framework="NIST",
        control_id="SI-3",
        control_name="Malicious Code Protection",
        d3fend_techniques=[
            D3FENDTechnique.FILE_ANALYSIS,
            D3FENDTechnique.PROCESS_ANALYSIS,
            D3FENDTechnique.EXECUTION_ISOLATION
        ],
        implementation_guidance="Implement D3-FA for file scanning, D3-PA for process behavior "
                              "monitoring, and D3-EI for sandboxing."
    ),

    ComplianceToD3FENDMapping(
        control_framework="NIST",
        control_id="SI-4",
        control_name="Information System Monitoring",
        d3fend_techniques=[
            D3FENDTechnique.NETWORK_TRAFFIC_ANALYSIS,
            D3FENDTechnique.SYSTEM_CALL_ANALYSIS,
            D3FENDTechnique.USER_BEHAVIOR_ANALYSIS,
            D3FENDTechnique.AUTHENTICATION_EVENT_THRESHOLDING
        ],
        implementation_guidance="Implement comprehensive monitoring with D3-NTA, D3-SCA, D3-UBA, "
                              "and D3-AET for complete visibility."
    ),

    ComplianceToD3FENDMapping(
        control_framework="NIST",
        control_id="AU-6",
        control_name="Audit Review, Analysis, and Reporting",
        d3fend_techniques=[
            D3FENDTechnique.SYSTEM_CALL_ANALYSIS,
            D3FENDTechnique.AUTHENTICATION_EVENT_THRESHOLDING
        ],
        implementation_guidance="Implement D3-SCA for audit log analysis and D3-AET for "
                              "authentication event monitoring."
    ),
]


class ComplianceD3FENDMapper:
    """
    Maps compliance controls to D3FEND techniques
    """

    def __init__(self):
        self.mappings = {
            f"{m.control_framework}:{m.control_id}": m
            for m in COMPLIANCE_D3FEND_MAPPINGS
        }

    def get_d3fend_for_control(
        self,
        framework: str,
        control_id: str
    ) -> ComplianceToD3FENDMapping:
        """Get D3FEND techniques for a compliance control"""
        key = f"{framework}:{control_id}"
        return self.mappings.get(key)

    def get_controls_for_technique(
        self,
        technique: D3FENDTechnique
    ) -> List[ComplianceToD3FENDMapping]:
        """Get all compliance controls that map to a D3FEND technique"""
        return [
            m for m in COMPLIANCE_D3FEND_MAPPINGS
            if technique in m.d3fend_techniques
        ]

    def get_framework_coverage(
        self,
        framework: str
    ) -> Dict[str, any]:
        """Get D3FEND coverage for a compliance framework"""
        framework_mappings = [
            m for m in COMPLIANCE_D3FEND_MAPPINGS
            if m.control_framework == framework
        ]

        all_techniques = set()
        for mapping in framework_mappings:
            all_techniques.update(mapping.d3fend_techniques)

        return {
            "framework": framework,
            "total_controls": len(framework_mappings),
            "d3fend_techniques_covered": len(all_techniques),
            "techniques": [t.value for t in all_techniques],
            "controls": [
                {
                    "control_id": m.control_id,
                    "control_name": m.control_name,
                    "d3fend_techniques": [t.value for t in m.d3fend_techniques]
                }
                for m in framework_mappings
            ]
        }

    def generate_implementation_checklist(
        self,
        framework: str,
        implemented_techniques: List[str]
    ) -> Dict[str, any]:
        """Generate implementation checklist for compliance framework"""
        framework_mappings = [
            m for m in COMPLIANCE_D3FEND_MAPPINGS
            if m.control_framework == framework
        ]

        implemented_set = set(implemented_techniques)
        checklist = []

        for mapping in framework_mappings:
            required_techniques = {t.value for t in mapping.d3fend_techniques}
            implemented_count = len(required_techniques & implemented_set)
            total_count = len(required_techniques)

            status = "complete" if implemented_count == total_count else "partial" if implemented_count > 0 else "not_started"

            checklist.append({
                "control_id": mapping.control_id,
                "control_name": mapping.control_name,
                "status": status,
                "implementation_percentage": (implemented_count / total_count * 100) if total_count > 0 else 0,
                "required_techniques": list(required_techniques),
                "implemented_techniques": list(required_techniques & implemented_set),
                "missing_techniques": list(required_techniques - implemented_set),
                "guidance": mapping.implementation_guidance
            })

        return {
            "framework": framework,
            "total_controls": len(checklist),
            "complete_controls": len([c for c in checklist if c["status"] == "complete"]),
            "partial_controls": len([c for c in checklist if c["status"] == "partial"]),
            "not_started_controls": len([c for c in checklist if c["status"] == "not_started"]),
            "checklist": checklist
        }


# Annotate existing compliance checks with D3FEND
def annotate_compliance_check_with_d3fend(check_data: Dict) -> Dict:
    """
    Annotate a compliance check result with D3FEND information

    Args:
        check_data: Compliance check result from ComplianceScanner

    Returns:
        Annotated check with D3FEND metadata
    """
    mapper = ComplianceD3FENDMapper()

    # Extract framework and control ID from check_id
    # Format: "soc2_cc6_1" -> framework="SOC2", control_id="CC6.1"
    check_id = check_data.get("check_id", "")
    parts = check_id.split("_")

    if len(parts) >= 2:
        framework = parts[0].upper()
        control_id = "_".join(parts[1:]).replace("_", ".").upper()

        # Get D3FEND mapping
        mapping = mapper.get_d3fend_for_control(framework, control_id)

        if mapping:
            check_data["d3fend"] = {
                "techniques": [t.value for t in mapping.d3fend_techniques],
                "implementation_guidance": mapping.implementation_guidance,
                "control_name": mapping.control_name
            }

    return check_data


# Example usage
if __name__ == "__main__":
    import json

    mapper = ComplianceD3FENDMapper()

    # Get SOC2 coverage
    print("SOC2 D3FEND Coverage:")
    soc2_coverage = mapper.get_framework_coverage("SOC2")
    print(json.dumps(soc2_coverage, indent=2))

    print("\n" + "="*70 + "\n")

    # Generate implementation checklist
    implemented = ["D3-NTA", "D3-IV", "D3-EAT", "D3-EAR"]
    print("SOC2 Implementation Checklist:")
    checklist = mapper.generate_implementation_checklist("SOC2", implemented)
    print(json.dumps(checklist, indent=2))
