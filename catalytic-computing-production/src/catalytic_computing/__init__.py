"""
Catalytic Computing - Production-Ready Package
High-performance memory-efficient lattice computation using catalytic algorithms
"""

__version__ = "1.0.0"
__author__ = "Catalytic Computing Team"

from .core.lattice_core import CatalyticLatticeComputing
from .algorithms.quantum_lattice import QuantumCatalyticLattice
from .utils.logging import setup_logging
from .utils.monitoring import MetricsCollector

# Initialize logging
setup_logging()

__all__ = [
    "CatalyticLatticeComputing",
    "QuantumCatalyticLattice",
    "MetricsCollector",
    "__version__",
]