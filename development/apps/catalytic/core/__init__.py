"""
Core module for Catalytic Lattice Computing
Provides interfaces and base implementations
"""

from .interface import (
    ILatticeComputer,
    IPathFinder,
    ITransformer,
    IAnalyzer,
    LatticeMetrics
)

from .unified_lattice import UnifiedCatalyticLattice
from .builder import LatticeBuilder

__all__ = [
    'ILatticeComputer',
    'IPathFinder',
    'ITransformer',
    'IAnalyzer',
    'LatticeMetrics',
    'UnifiedCatalyticLattice',
    'LatticeBuilder'
]