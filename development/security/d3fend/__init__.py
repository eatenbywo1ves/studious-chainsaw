"""
D3FEND Integration Package
Provides MITRE D3FEND (Detection, Denial, and Disruption Framework Empowering Network Defense)
integration for Catalytic Computing security infrastructure.

This package enables:
- Mapping security controls to D3FEND taxonomy
- Exporting digital artifacts in D3FEND ontology format (RDF/OWL, JSON-LD)
- Integrating with D3FEND API for technique validation
- Automated defensive technique recommendations
"""

from .technique_mapping import (
    D3FENDTechnique,
    D3FENDCategory,
    TechniqueMapper,
    COMPONENT_TECHNIQUE_MAPPING,
)
from .api_client import D3FENDAPIClient
from .ontology_export import D3FENDOntologyExporter

__version__ = "1.0.0"
__all__ = [
    "D3FENDTechnique",
    "D3FENDCategory",
    "TechniqueMapper",
    "D3FENDAPIClient",
    "D3FENDOntologyExporter",
    "COMPONENT_TECHNIQUE_MAPPING",
]
