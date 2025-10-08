"""
D3FEND API Client
Interacts with MITRE D3FEND public API for technique validation and recommendations
"""

import aiohttp
import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from .technique_mapping import D3FENDCategory

logger = logging.getLogger(__name__)


@dataclass
class D3FENDTechniqueDetails:
    """D3FEND technique details from API"""
    id: str
    name: str
    definition: str
    category: str
    artifact_relationships: List[str]
    attack_mitigations: List[str]
    nist_mappings: List[str]


@dataclass
class ATT_CKMapping:
    """ATT&CK to D3FEND countermeasure mapping"""
    attack_id: str
    attack_name: str
    countermeasures: List[str]


class D3FENDAPIClient:
    """
    Client for MITRE D3FEND API

    Features:
    - Technique lookup and validation
    - ATT&CK to D3FEND countermeasure mapping
    - Digital artifact ontology queries
    - NIST 800-53 control mapping
    """

    BASE_URL = "https://d3fend.mitre.org/api/v1"
    ONTOLOGY_URL = "https://d3fend.mitre.org/ontologies/d3fend.owl"

    def __init__(self, timeout: int = 30):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.cache: Dict[str, Any] = {}

    async def get_technique(self, technique_id: str) -> Optional[D3FENDTechniqueDetails]:
        """
        Get D3FEND technique details

        Args:
            technique_id: D3FEND technique ID (e.g., "D3-NTA")

        Returns:
            D3FENDTechniqueDetails or None if not found
        """
        cache_key = f"technique:{technique_id}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Note: This is a placeholder - actual API endpoint may differ
                # Check D3FEND documentation for current API structure
                url = f"{self.BASE_URL}/technique/{technique_id}"

                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        details = D3FENDTechniqueDetails(
                            id=data.get('id', technique_id),
                            name=data.get('name', ''),
                            definition=data.get('definition', ''),
                            category=data.get('category', ''),
                            artifact_relationships=data.get('artifacts', []),
                            attack_mitigations=data.get('mitigates', []),
                            nist_mappings=data.get('nist_controls', [])
                        )

                        self.cache[cache_key] = details
                        return details

                    logger.warning(f"D3FEND API returned {response.status} for {technique_id}")
                    return None

        except Exception as e:
            logger.error(f"Error fetching D3FEND technique {technique_id}: {e}")
            return None

    async def get_countermeasures_for_attack(
        self,
        attack_id: str,
        attack_framework: str = "mitre-attack"
    ) -> Optional[ATT_CKMapping]:
        """
        Get D3FEND countermeasures for an ATT&CK technique

        Args:
            attack_id: ATT&CK technique ID (e.g., "T1566")
            attack_framework: Framework identifier (default: "mitre-attack")

        Returns:
            ATT_CKMapping with countermeasures
        """
        cache_key = f"attack:{attack_id}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Placeholder URL - check D3FEND docs for actual endpoint
                url = f"{self.BASE_URL}/attack/{attack_id}/countermeasures"

                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()

                        mapping = ATT_CKMapping(
                            attack_id=attack_id,
                            attack_name=data.get('attack_name', ''),
                            countermeasures=data.get('d3fend_techniques', [])
                        )

                        self.cache[cache_key] = mapping
                        return mapping

                    return None

        except Exception as e:
            logger.error(f"Error fetching countermeasures for {attack_id}: {e}")
            return None

    async def validate_technique_implementation(
        self,
        technique_id: str,
        implementation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate if implementation meets D3FEND technique requirements

        Args:
            technique_id: D3FEND technique ID
            implementation_data: Implementation details to validate

        Returns:
            Validation report
        """
        technique = await self.get_technique(technique_id)

        if not technique:
            return {
                "valid": False,
                "errors": [f"Unknown D3FEND technique: {technique_id}"]
            }

        validation_report = {
            "technique_id": technique_id,
            "technique_name": technique.name,
            "valid": True,
            "errors": [],
            "warnings": [],
            "recommendations": []
        }

        # Validate artifact coverage
        required_artifacts = set(technique.artifact_relationships)
        implemented_artifacts = set(implementation_data.get('artifacts', []))

        missing_artifacts = required_artifacts - implemented_artifacts
        if missing_artifacts:
            validation_report["warnings"].append(
                f"Missing artifact coverage: {', '.join(missing_artifacts)}"
            )

        # Validate against NIST controls
        if technique.nist_mappings:
            validation_report["nist_controls"] = technique.nist_mappings
            validation_report["recommendations"].append(
                f"Consider implementing NIST controls: {', '.join(technique.nist_mappings[:3])}"
            )

        return validation_report

    async def get_digital_artifacts(
        self,
        artifact_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get digital artifacts from D3FEND ontology

        Args:
            artifact_type: Filter by artifact type (e.g., "NetworkTraffic", "File")

        Returns:
            List of digital artifacts
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"{self.BASE_URL}/artifacts"
                params = {"type": artifact_type} if artifact_type else {}

                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    return []

        except Exception as e:
            logger.error(f"Error fetching digital artifacts: {e}")
            return []

    async def get_technique_by_category(
        self,
        category: D3FENDCategory
    ) -> List[Dict[str, Any]]:
        """
        Get all techniques in a D3FEND category

        Args:
            category: D3FEND category

        Returns:
            List of techniques in category
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"{self.BASE_URL}/techniques"
                params = {"category": category.value}

                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    return []

        except Exception as e:
            logger.error(f"Error fetching techniques for {category.value}: {e}")
            return []

    async def search_techniques(
        self,
        query: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Search D3FEND techniques by keyword

        Args:
            query: Search query
            limit: Maximum results to return

        Returns:
            List of matching techniques
        """
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"{self.BASE_URL}/search"
                params = {"q": query, "limit": limit}

                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        return await response.json()
                    return []

        except Exception as e:
            logger.error(f"Error searching D3FEND: {e}")
            return []

    async def get_nist_mapping(
        self,
        technique_id: str
    ) -> List[str]:
        """
        Get NIST 800-53 control mappings for a D3FEND technique

        Args:
            technique_id: D3FEND technique ID

        Returns:
            List of NIST 800-53 control IDs
        """
        technique = await self.get_technique(technique_id)
        return technique.nist_mappings if technique else []

    async def recommend_techniques_for_gaps(
        self,
        implemented_techniques: List[str],
        required_coverage: List[D3FENDCategory]
    ) -> Dict[str, Any]:
        """
        Recommend D3FEND techniques to fill coverage gaps

        Args:
            implemented_techniques: List of already implemented technique IDs
            required_coverage: Categories that need coverage

        Returns:
            Recommendations report
        """
        recommendations = {
            "implemented_count": len(implemented_techniques),
            "gap_categories": [],
            "recommended_techniques": []
        }

        implemented_set = set(implemented_techniques)

        for category in required_coverage:
            techniques = await self.get_technique_by_category(category)

            # Find techniques in this category not yet implemented
            category_gaps = [
                t for t in techniques
                if t.get('id') not in implemented_set
            ]

            if category_gaps:
                recommendations["gap_categories"].append({
                    "category": category.value,
                    "missing_count": len(category_gaps),
                    "priority": "HIGH" if category in [
                        D3FENDCategory.DETECT, D3FENDCategory.ISOLATE
                    ] else "MEDIUM"
                })

                # Add top 3 recommendations for this category
                for technique in category_gaps[:3]:
                    recommendations["recommended_techniques"].append({
                        "id": technique.get('id'),
                        "name": technique.get('name'),
                        "category": category.value,
                        "reason": f"Fill gap in {category.value} category"
                    })

        return recommendations

    async def download_ontology(
        self,
        output_format: str = "ttl"
    ) -> Optional[str]:
        """
        Download D3FEND ontology file

        Args:
            output_format: Format (ttl, owl, rdf, jsonld)

        Returns:
            Ontology content as string
        """
        format_urls = {
            "ttl": f"{self.ONTOLOGY_URL}?format=turtle",
            "owl": self.ONTOLOGY_URL,
            "rdf": f"{self.ONTOLOGY_URL}?format=rdf",
            "jsonld": f"{self.ONTOLOGY_URL}?format=jsonld"
        }

        url = format_urls.get(output_format, self.ONTOLOGY_URL)

        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        return await response.text()

                    logger.error(f"Failed to download ontology: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Error downloading D3FEND ontology: {e}")
            return None

    def clear_cache(self):
        """Clear the API response cache"""
        self.cache.clear()
        logger.info("D3FEND API cache cleared")


# Offline fallback data (when API is unavailable)
class D3FENDOfflineData:
    """
    Fallback D3FEND data when API is unavailable
    Based on D3FEND v0.10 ontology
    """

    TECHNIQUE_DATA = {
        "D3-NTA": {
            "name": "Network Traffic Analysis",
            "definition": "Analyzing network traffic to detect anomalies and threats",
            "category": "detect",
            "artifacts": ["NetworkTraffic", "NetworkNode", "NetworkConnection"]
        },
        "D3-IV": {
            "name": "Input Validation",
            "definition": "Validating input to prevent injection attacks",
            "category": "harden",
            "artifacts": ["UserInput", "APIRequest", "FormData"]
        },
        "D3-EAR": {
            "name": "Encryption at Rest",
            "definition": "Encrypting data when stored",
            "category": "harden",
            "artifacts": ["File", "Database", "Volume"]
        },
        "D3-EAT": {
            "name": "Encryption in Transit",
            "definition": "Encrypting data during transmission",
            "category": "harden",
            "artifacts": ["NetworkTraffic", "NetworkConnection"]
        },
        "D3-UAC": {
            "name": "User Account Control",
            "definition": "Managing user account permissions and access",
            "category": "harden",
            "artifacts": ["UserAccount", "Credential", "Permission"]
        },
    }

    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get technique data from offline cache"""
        return cls.TECHNIQUE_DATA.get(technique_id)


# Example usage
async def main():
    """Example D3FEND API client usage"""
    client = D3FENDAPIClient()

    # Get technique details
    print("Fetching D3-NTA (Network Traffic Analysis) details...")
    technique = await client.get_technique("D3-NTA")
    if technique:
        print(f"Technique: {technique.name}")
        print(f"Definition: {technique.definition}")
        print(f"Category: {technique.category}")
    else:
        print("Using offline fallback data...")
        offline_data = D3FENDOfflineData.get_technique("D3-NTA")
        print(json.dumps(offline_data, indent=2))

    # Get countermeasures for an attack
    print("\nFetching countermeasures for T1566 (Phishing)...")
    mapping = await client.get_countermeasures_for_attack("T1566")
    if mapping:
        print(f"Attack: {mapping.attack_name}")
        print(f"Countermeasures: {', '.join(mapping.countermeasures[:5])}")

    # Get recommendations
    print("\nGetting technique recommendations...")
    implemented = ["D3-NTA", "D3-IV"]
    required = [D3FENDCategory.DETECT, D3FENDCategory.HARDEN, D3FENDCategory.ISOLATE]
    recommendations = await client.recommend_techniques_for_gaps(implemented, required)
    print(json.dumps(recommendations, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
