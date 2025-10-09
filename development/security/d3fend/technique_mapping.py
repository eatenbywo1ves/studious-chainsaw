"""
D3FEND Technique Mapping Module
Maps Catalytic Computing security components to D3FEND defensive techniques
"""

from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass


class D3FENDCategory(Enum):
    """D3FEND top-level defensive categories"""

    MODEL = "model"  # Asset inventory, system modeling
    HARDEN = "harden"  # Strengthen system resilience
    DETECT = "detect"  # Identify security breaches
    ISOLATE = "isolate"  # Contain and segregate threats
    DECEIVE = "deceive"  # Mislead adversaries
    EVICT = "evict"  # Remove threats
    RESTORE = "restore"  # Return to normal operations


class D3FENDTechnique(Enum):
    """D3FEND Defensive Techniques with official IDs"""

    # MODEL Category
    ASSET_INVENTORY = "D3-AI"
    SYSTEM_MAPPING = "D3-SM"
    NETWORK_MAPPING = "D3-NM"
    DEPENDENCY_MAPPING = "D3-DM"

    # HARDEN Category
    INPUT_VALIDATION = "D3-IV"
    ENCRYPTION_AT_REST = "D3-EAR"
    ENCRYPTION_IN_TRANSIT = "D3-EAT"
    STRONG_PASSWORD_POLICY = "D3-SPP"
    USER_ACCOUNT_CONTROL = "D3-UAC"
    CREDENTIAL_HARDENING = "D3-CH"
    MULTI_FACTOR_AUTHENTICATION = "D3-MFA"
    SESSION_TIMEOUT = "D3-ST"

    # DETECT Category
    NETWORK_TRAFFIC_ANALYSIS = "D3-NTA"
    FILE_ANALYSIS = "D3-FA"
    PROCESS_ANALYSIS = "D3-PA"
    USER_BEHAVIOR_ANALYSIS = "D3-UBA"
    SERVICE_BINARY_ANALYSIS = "D3-SBA"
    SYSTEM_CALL_ANALYSIS = "D3-SCA"
    AUTHENTICATION_EVENT_THRESHOLDING = "D3-AET"
    CREDENTIAL_TRANSMISSION_SCOPING = "D3-CTS"

    # ISOLATE Category
    EXECUTION_ISOLATION = "D3-EI"
    NETWORK_ISOLATION = "D3-NI"
    RESOURCE_ACCESS_CONTROL = "D3-RAC"
    SERVICE_DEPENDENCY_MAPPING = "D3-SDM"

    # DECEIVE Category
    DECOY_NETWORK = "D3-DN"
    DECOY_FILE = "D3-DF"
    DECOY_USER_CREDENTIAL = "D3-DUC"

    # EVICT Category
    CONNECTION_EVICTION = "D3-CE"
    PROCESS_EVICTION = "D3-PE"

    # RESTORE Category
    SYSTEM_CONFIGURATION_ROLLBACK = "D3-SCR"
    RESTORE_ACCESS = "D3-RA"


@dataclass
class TechniqueMapping:
    """Mapping between component and D3FEND technique"""

    component_file: str
    component_name: str
    d3fend_techniques: List[D3FENDTechnique]
    category: D3FENDCategory
    coverage_percentage: float  # 0-100
    implementation_notes: str

    @property
    def technique_ids(self) -> List[str]:
        """Get D3FEND technique IDs"""
        return [t.value for t in self.d3fend_techniques]


# Comprehensive mapping of Catalytic Computing components to D3FEND techniques
COMPONENT_TECHNIQUE_MAPPING: List[TechniqueMapping] = [
    # Webhook Monitoring System
    TechniqueMapping(
        component_file="webhook_monitoring.py",
        component_name="WebhookMonitor",
        d3fend_techniques=[
            D3FENDTechnique.NETWORK_TRAFFIC_ANALYSIS,
            D3FENDTechnique.SERVICE_BINARY_ANALYSIS,
            D3FENDTechnique.SYSTEM_CALL_ANALYSIS,
        ],
        category=D3FENDCategory.DETECT,
        coverage_percentage=95.0,
        implementation_notes="Real-time webhook event monitoring with Prometheus metrics, "
        "circuit breaker tracking, and anomaly detection. Maps to D3-NTA "
        "through endpoint health monitoring and request/response analysis.",
    ),
    # Webhook Manager
    TechniqueMapping(
        component_file="webhook_manager.py",
        component_name="WebhookManager",
        d3fend_techniques=[
            D3FENDTechnique.RESOURCE_ACCESS_CONTROL,
            D3FENDTechnique.EXECUTION_ISOLATION,
            D3FENDTechnique.CREDENTIAL_HARDENING,
        ],
        category=D3FENDCategory.ISOLATE,
        coverage_percentage=90.0,
        implementation_notes="Circuit breaker pattern implements D3-RAC by isolating failing "
        "endpoints. HMAC signature verification implements D3-CH. Implements "
        "priority-based queue isolation.",
    ),
    # Input Validation System
    TechniqueMapping(
        component_file="input_validation.py",
        component_name="SecurityInputValidator",
        d3fend_techniques=[
            D3FENDTechnique.INPUT_VALIDATION,
        ],
        category=D3FENDCategory.HARDEN,
        coverage_percentage=98.0,
        implementation_notes="Comprehensive input validation with SQL injection, XSS, command "
        "injection, and LDAP injection prevention. Implements D3-IV through "
        "regex pattern matching and sanitization.",
    ),
    # JWT Security Manager
    TechniqueMapping(
        component_file="jwt_security.py",
        component_name="JWTSecurityManager",
        d3fend_techniques=[
            D3FENDTechnique.STRONG_PASSWORD_POLICY,
            D3FENDTechnique.USER_ACCOUNT_CONTROL,
            D3FENDTechnique.SESSION_TIMEOUT,
            D3FENDTechnique.CREDENTIAL_HARDENING,
        ],
        category=D3FENDCategory.HARDEN,
        coverage_percentage=85.0,
        implementation_notes="JWT-based authentication with token expiry (D3-ST), claims "
        "validation (D3-UAC), and signature verification (D3-CH). "
        "NOTE: Token blacklist needs Redis for full D3-UAC compliance.",
    ),
    # Rate Limiting System
    TechniqueMapping(
        component_file="rate_limiting.py",
        component_name="AdvancedRateLimiter",
        d3fend_techniques=[
            D3FENDTechnique.RESOURCE_ACCESS_CONTROL,
            D3FENDTechnique.AUTHENTICATION_EVENT_THRESHOLDING,
        ],
        category=D3FENDCategory.ISOLATE,
        coverage_percentage=70.0,
        implementation_notes="Token bucket and sliding window rate limiting implements D3-RAC. "
        "Authentication attempt tracking implements D3-AET. "
        "NOTE: Needs Redis for distributed D3-RAC compliance.",
    ),
    # Compliance Scanner
    TechniqueMapping(
        component_file="compliance-scanner.py",
        component_name="ComplianceScanner",
        d3fend_techniques=[
            D3FENDTechnique.ASSET_INVENTORY,
            D3FENDTechnique.SYSTEM_MAPPING,
            D3FENDTechnique.NETWORK_MAPPING,
            D3FENDTechnique.ENCRYPTION_AT_REST,
            D3FENDTechnique.ENCRYPTION_IN_TRANSIT,
            D3FENDTechnique.NETWORK_ISOLATION,
        ],
        category=D3FENDCategory.MODEL,
        coverage_percentage=92.0,
        implementation_notes="SOC2/ISO27001 compliance checks implement D3-AI through asset "
        "discovery, D3-NM through network policy validation, and D3-EAR/D3-EAT "
        "through encryption verification. Implements D3-NI through network "
        "policy checks.",
    ),
    # Penetration Testing Suite
    TechniqueMapping(
        component_file="penetration-test.py",
        component_name="PenetrationTester",
        d3fend_techniques=[
            D3FENDTechnique.FILE_ANALYSIS,
            D3FENDTechnique.PROCESS_ANALYSIS,
            D3FENDTechnique.CREDENTIAL_TRANSMISSION_SCOPING,
        ],
        category=D3FENDCategory.DETECT,
        coverage_percentage=85.0,
        implementation_notes="Automated security testing implements D3-FA through vulnerability "
        "scanning, D3-PA through exploitation attempt detection, and D3-CTS "
        "through credential security validation.",
    ),
]


class TechniqueMapper:
    """
    Maps Catalytic Computing security components to D3FEND techniques
    """

    def __init__(self):
        self.mappings = {m.component_file: m for m in COMPONENT_TECHNIQUE_MAPPING}

    def get_techniques_for_component(self, component_file: str) -> Optional[TechniqueMapping]:
        """Get D3FEND techniques for a component"""
        return self.mappings.get(component_file)

    def get_components_by_category(self, category: D3FENDCategory) -> List[TechniqueMapping]:
        """Get all components in a D3FEND category"""
        return [m for m in COMPONENT_TECHNIQUE_MAPPING if m.category == category]

    def get_components_by_technique(self, technique: D3FENDTechnique) -> List[TechniqueMapping]:
        """Get all components implementing a specific technique"""
        return [m for m in COMPONENT_TECHNIQUE_MAPPING if technique in m.d3fend_techniques]

    def get_all_implemented_techniques(self) -> Set[D3FENDTechnique]:
        """Get all D3FEND techniques implemented across components"""
        techniques = set()
        for mapping in COMPONENT_TECHNIQUE_MAPPING:
            techniques.update(mapping.d3fend_techniques)
        return techniques

    def get_category_coverage(self) -> Dict[D3FENDCategory, float]:
        """Calculate average coverage percentage by category"""
        coverage = {}
        for category in D3FENDCategory:
            components = self.get_components_by_category(category)
            if components:
                avg_coverage = sum(c.coverage_percentage for c in components) / len(components)
                coverage[category] = avg_coverage
            else:
                coverage[category] = 0.0
        return coverage

    def generate_coverage_report(self) -> Dict[str, any]:
        """Generate comprehensive D3FEND coverage report"""
        implemented = self.get_all_implemented_techniques()
        total_techniques = len(D3FENDTechnique)

        return {
            "total_techniques_available": total_techniques,
            "techniques_implemented": len(implemented),
            "coverage_percentage": (len(implemented) / total_techniques * 100),
            "implemented_techniques": [t.value for t in implemented],
            "category_coverage": {
                cat.value: cov for cat, cov in self.get_category_coverage().items()
            },
            "component_mappings": [
                {
                    "component": m.component_name,
                    "file": m.component_file,
                    "category": m.category.value,
                    "techniques": m.technique_ids,
                    "coverage": m.coverage_percentage,
                    "notes": m.implementation_notes,
                }
                for m in COMPONENT_TECHNIQUE_MAPPING
            ],
        }

    def get_missing_categories(self) -> List[D3FENDCategory]:
        """Get D3FEND categories with no implementation"""
        implemented_categories = {m.category for m in COMPONENT_TECHNIQUE_MAPPING}
        return [cat for cat in D3FENDCategory if cat not in implemented_categories]

    def recommend_next_techniques(self, limit: int = 5) -> List[Dict[str, str]]:
        """Recommend next techniques to implement for better coverage"""
        implemented = self.get_all_implemented_techniques()
        missing_categories = self.get_missing_categories()

        recommendations = []

        # Prioritize missing categories
        for category in missing_categories:
            recommendations.append(
                {
                    "category": category.value,
                    "reason": f"No implementation in {category.value} category",
                    "priority": "HIGH",
                    "example_technique": self._get_example_technique_for_category(category),
                }
            )

        # Add technique recommendations for implemented categories
        if len(recommendations) < limit:
            for technique in D3FENDTechnique:
                if technique not in implemented and len(recommendations) < limit:
                    recommendations.append(
                        {
                            "technique": technique.value,
                            "category": self._get_category_for_technique(technique).value,
                            "reason": "Expand coverage in existing category",
                            "priority": "MEDIUM",
                        }
                    )

        return recommendations[:limit]

    def _get_example_technique_for_category(self, category: D3FENDCategory) -> str:
        """Get example technique for a category"""
        category_techniques = {
            D3FENDCategory.DECEIVE: "D3-DN (Decoy Network)",
            D3FENDCategory.EVICT: "D3-CE (Connection Eviction)",
            D3FENDCategory.RESTORE: "D3-SCR (System Configuration Rollback)",
        }
        return category_techniques.get(category, "Unknown")

    def _get_category_for_technique(self, technique: D3FENDTechnique) -> D3FENDCategory:
        """Infer category from technique"""
        technique_to_category = {
            # MODEL
            D3FENDTechnique.ASSET_INVENTORY: D3FENDCategory.MODEL,
            D3FENDTechnique.SYSTEM_MAPPING: D3FENDCategory.MODEL,
            # HARDEN
            D3FENDTechnique.INPUT_VALIDATION: D3FENDCategory.HARDEN,
            D3FENDTechnique.ENCRYPTION_AT_REST: D3FENDCategory.HARDEN,
            # DETECT
            D3FENDTechnique.NETWORK_TRAFFIC_ANALYSIS: D3FENDCategory.DETECT,
            D3FENDTechnique.FILE_ANALYSIS: D3FENDCategory.DETECT,
            # ISOLATE
            D3FENDTechnique.EXECUTION_ISOLATION: D3FENDCategory.ISOLATE,
            D3FENDTechnique.NETWORK_ISOLATION: D3FENDCategory.ISOLATE,
            # DECEIVE
            D3FENDTechnique.DECOY_NETWORK: D3FENDCategory.DECEIVE,
            # EVICT
            D3FENDTechnique.CONNECTION_EVICTION: D3FENDCategory.EVICT,
            # RESTORE
            D3FENDTechnique.SYSTEM_CONFIGURATION_ROLLBACK: D3FENDCategory.RESTORE,
        }
        return technique_to_category.get(technique, D3FENDCategory.MODEL)


# Example usage
if __name__ == "__main__":
    import json

    mapper = TechniqueMapper()

    # Generate coverage report
    report = mapper.generate_coverage_report()
    print("D3FEND Coverage Report:")
    print(json.dumps(report, indent=2))

    # Get recommendations
    print("\nRecommended Next Steps:")
    recommendations = mapper.recommend_next_techniques(limit=5)
    for rec in recommendations:
        print(
            f"- [{rec.get('priority', 'MEDIUM')}] {rec.get('category', rec.get('technique'))}: {rec['reason']}"
        )
