"""
GhidraGo Exception Hierarchy

Security-conscious exception handling for reverse engineering tools.
Specific exceptions enable better debugging and prevent masking critical failures.
"""


class GhidraGoError(Exception):
    """Base exception for all GhidraGo errors"""

    pass


class MemoryAccessError(GhidraGoError):
    """Failed to read from or write to program memory"""

    def __init__(self, address, reason=None):
        self.address = address
        self.reason = reason
        msg = f"Memory access failed at {address}"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class InvalidBinaryError(GhidraGoError):
    """Binary structure is invalid or corrupted"""

    def __init__(self, structure_type, reason):
        self.structure_type = structure_type
        self.reason = reason
        super().__init__(f"Invalid {structure_type}: {reason}")


class ParseError(GhidraGoError):
    """Failed to parse Go-specific data structures"""

    def __init__(self, structure_name, offset=None, reason=None):
        self.structure_name = structure_name
        self.offset = offset
        self.reason = reason
        msg = f"Failed to parse {structure_name}"
        if offset:
            msg += f" at offset {offset}"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class UnsupportedVersionError(GhidraGoError):
    """Go version is not supported by this script"""

    def __init__(self, version, supported_versions):
        self.version = version
        self.supported_versions = supported_versions
        super().__init__(
            f"Go version {version} not supported. Supported: {', '.join(supported_versions)}"
        )


class StructureNotFoundError(GhidraGoError):
    """Required Go structure not found in binary"""

    def __init__(self, structure_name):
        self.structure_name = structure_name
        super().__init__(f"Required structure not found: {structure_name}")


class TypeResolutionError(GhidraGoError):
    """Failed to resolve Go type information"""

    def __init__(self, type_name, reason=None):
        self.type_name = type_name
        self.reason = reason
        msg = f"Failed to resolve type '{type_name}'"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)
