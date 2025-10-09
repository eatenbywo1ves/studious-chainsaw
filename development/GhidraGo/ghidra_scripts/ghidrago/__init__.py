"""
GhidraGo - Professional Go Binary Analysis for Ghidra

A security-focused toolkit for reverse engineering Go binaries.
Implements robust exception handling and follows defensive security practices.

Version: 2.0.0
"""

from .exceptions import (
    GhidraGoError,
    MemoryAccessError,
    InvalidBinaryError,
    ParseError,
    UnsupportedVersionError,
    StructureNotFoundError,
    TypeResolutionError,
)

__all__ = [
    "GhidraGoError",
    "MemoryAccessError",
    "InvalidBinaryError",
    "ParseError",
    "UnsupportedVersionError",
    "StructureNotFoundError",
    "TypeResolutionError",
]

__version__ = "2.0.0"
__author__ = "Catalytic Computing"

# Version history
# 1.0.0-MVP: Function name recovery from PCLNTAB
# 1.1.0-dev: Type extraction, auto-analyzer, multi-platform support
# 2.0.0: Security-hardened exception handling, proper error propagation
