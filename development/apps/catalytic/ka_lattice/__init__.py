"""
Knowledge-Augmented (KA) Lattice Framework
Production-ready catalytic computing with lifecycle management
"""

from .ka_core import KALatticeCore, LatticeState
from .production_cycle import ProductionCycleManager, CyclePhase
from .knowledge_base import KnowledgeStore, PatternLibrary
from .orchestrator import KALatticeOrchestrator

__all__ = [
    'KALatticeCore',
    'LatticeState',
    'ProductionCycleManager',
    'CyclePhase',
    'KnowledgeStore',
    'PatternLibrary',
    'KALatticeOrchestrator'
]

__version__ = '1.0.0'