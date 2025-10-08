# Security-Hardened Exception Handling

## Overview

GhidraGo v2.0.0 implements production-grade exception handling following defensive security principles. This is critical for tools that analyze potentially malicious binaries.

## Exception Hierarchy

```python
GhidraGoError (Base)
├── MemoryAccessError       # Failed to read/write program memory
├── InvalidBinaryError      # Binary structure is invalid/corrupted
├── ParseError              # Failed to parse Go data structures
├── UnsupportedVersionError # Unsupported Go version
├── StructureNotFoundError  # Required structure not found
└── TypeResolutionError     # Failed to resolve type information
```

## Security Improvements

### Before (Dangerous)
```python
try:
    magic = self._read_uint32(addr)
except:  # BAD: Catches KeyboardInterrupt, SystemExit
    pass
```

**Problems:**
- Catches `KeyboardInterrupt` → Can't emergency-exit when analyzing malware
- Catches `SystemExit` → Prevents cleanup handlers
- Hides bugs by silencing unexpected exceptions
- No debugging information when failures occur

### After (Secure)
```python
try:
    magic = self._read_uint32(addr)
except (MemoryAccessError, struct.error):
    # Expected: scanning memory hits invalid regions
    pass
except Exception as e:
    # Unexpected error - log for debugging
    print(f"[DEBUG] Unexpected error at {addr}: {e}")
    pass
```

**Benefits:**
- Specific exceptions only → Keyboard interrupts work
- Logging of unexpected errors → Easier debugging
- Distinguishes expected vs. unexpected failures
- Enables security incident analysis

## Memory Access Pattern

All memory reads now use defensive error handling:

```python
def _read_uint32(self, addr):
    """Read 32-bit unsigned integer"""
    try:
        byte_data = getBytes(addr, 4)
        return struct.unpack("<I", byte_data.tostring())[0]
    except (AttributeError, TypeError) as e:
        # Ghidra API failure
        raise MemoryAccessError(addr, f"Failed to read 4 bytes: {e}")
    except struct.error as e:
        # Invalid data format
        raise MemoryAccessError(addr, f"Invalid data for uint32: {e}")
```

## Main Entry Point

Top-level exception handling with user-friendly messages:

```python
def main():
    try:
        # Analysis code...
    except StructureNotFoundError as e:
        print(f"[!] Error: {e}")
        print("[!] This may not be a Go binary")
        return
    except (MemoryAccessError, InvalidBinaryError, ParseError) as e:
        print(f"[!] Binary analysis error: {e}")
        print("[!] Binary may be corrupted or use custom packing")
        return
    except KeyboardInterrupt:
        print("[!] Analysis interrupted by user")
        raise  # Re-raise for Ghidra cleanup
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        traceback.print_exc()
        raise  # Don't hide bugs
```

## Enforcement

Ruff linter now **enforces** specific exception handling:

```toml
# ruff.toml
[lint]
ignore = [
    # E501 still ignored for line length
]

# E722 (bare except) is now ENFORCED!
# Security-conscious exception handling is critical
```

## Testing

Verify exception handling:

```bash
# Should pass - no bare except clauses
cd development
ruff check --select=E722 GhidraGo/ghidra_scripts/RecoverGoFunctions.py

# Should pass - all checks
ruff check GhidraGo/ghidra_scripts/RecoverGoFunctions.py
```

## Operational Benefits

### For Security Analysts
- **Emergency Exit Works**: Ctrl+C always works when analyzing malware
- **Better Debugging**: Log messages show *why* analysis failed
- **Incident Response**: Exception types indicate attack vs. corruption

### For Developers
- **Find Bugs Faster**: Unexpected exceptions aren't hidden
- **Better Error Messages**: Specific exceptions provide context
- **Maintainable**: Clear separation of expected vs. unexpected errors

## Version 2.0.0 Changes

- ✅ Created `exceptions.py` with security-focused exception hierarchy
- ✅ Updated all `_read_*` methods with defensive error handling
- ✅ Replaced all bare `except:` with specific exception types
- ✅ Added logging for unexpected errors
- ✅ Implemented graceful degradation (continue on expected errors)
- ✅ Re-raise `KeyboardInterrupt` for user control
- ✅ Enhanced main() with comprehensive error handling
- ✅ Updated ruff.toml to enforce proper exception handling

## Comparison to Industry Standards

| Feature | Before | After | Industry Standard |
|---------|--------|-------|-------------------|
| Bare except | ✗ Used | ✓ Banned | OWASP, Google Style |
| Specific exceptions | ✗ No | ✓ Yes | Required for security tools |
| KeyboardInterrupt handling | ✗ Blocked | ✓ Preserved | Critical for RE tools |
| Error logging | ✗ Silent failures | ✓ Logged | Required for debugging |
| Exception hierarchy | ✗ None | ✓ Comprehensive | Best practice |

## References

- OWASP Secure Coding Practices
- Google Python Style Guide: Exception Handling
- D3FEND Framework: Defensive Security Practices
- Python Exception Hierarchy Best Practices
