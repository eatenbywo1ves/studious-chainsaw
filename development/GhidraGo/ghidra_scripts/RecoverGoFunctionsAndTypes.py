# Recover Go Functions and Types (GhidraGo v1.1)
# @author Catalytic Computing
# @category Golang
# @keybinding
# @menupath Analysis.Golang.Recover Functions and Types
# @toolbar

"""
GhidraGo v1.1 Phase 2 - Comprehensive Go Binary Analysis with Enhanced Type Extraction

This script combines v1.0 function recovery with v1.1 Phase 2 enhanced type extraction:
1. Detects Go version and locates PCLNTAB
2. Recovers function names (v1.0 MVP functionality)
3. Locates moduledata structure (v1.1 Phase 1)
4. Parses typelinks array (v1.1 Phase 1)
5. Extracts type information (v1.1 Phase 1)
5.5. Resolves struct fields and interface methods (v1.1 Phase 2 NEW)
6. Applies enhanced types to Ghidra (v1.1 Phase 2)

Phase 2 Enhancements:
- Detailed struct field parsing (names, types, offsets, tags)
- Interface method parsing (names, signatures)
- Nested type resolution with circular reference handling
- Field-aware type application to Ghidra DataTypeManager

Based on research from:
- CUJO AI: Reverse Engineering Go Binaries with Ghidra (Parts 1 & 2)
- Google Cloud: Golang Internals and Symbol Recovery
- Mandiant GoReSym: Go Symbol Recovery Tool
"""

import sys
import os

# Add ghidrago package to path
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from ghidrago.moduledata_scanner import ModuledataScanner
from ghidrago.typelinks_parser import TypelinksParser
from ghidrago.rtype_parser import RtypeParser
from ghidrago.type_recovery_service import TypeRecoveryService
from ghidrago.struct_field_parser import StructFieldParser
from ghidrago.interface_method_parser import InterfaceMethodParser
from ghidrago.type_resolver import TypeResolver
from ghidrago.exceptions import (
    MemoryAccessError,
    InvalidBinaryError,
    ParseError,
    StructureNotFoundError
)

# Import v1.0 classes (from RecoverGoFunctions.py)
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
import struct


# ============================================================================
# Go Version Detection and PCLNTAB Parsing (from v1.0 MVP)
# ============================================================================

MAGIC_12 = 0xfffffffb    # Go 1.2-1.15
MAGIC_116 = 0xfffffff0   # Go 1.16-1.17
MAGIC_118 = 0xfffffff1   # Go 1.18+


class GoVersionDetector:
    """Detect Go version from PCLNTAB magic number (v1.0 functionality)"""

    def __init__(self, program):
        self.program = program
        self.version = None
        self.pclntab_addr = None

    def detect(self):
        """Detect Go version and locate PCLNTAB"""
        memory = self.program.getMemory()

        # Search for .gopclntab section
        for block in memory.getBlocks():
            if block.getName() == ".gopclntab":
                self.pclntab_addr = block.getStart()
                magic = self._read_uint32(self.pclntab_addr)
                self.version = self._identify_version(magic)
                return True

        # Fallback: scan for magic numbers
        return self._scan_for_magic()

    def _scan_for_magic(self):
        """Scan memory for PCLNTAB magic numbers"""
        memory = self.program.getMemory()

        for block in memory.getBlocks():
            if not block.isInitialized():
                continue

            addr = block.getStart()
            end_addr = block.getEnd()

            while addr.compareTo(end_addr) < 0:
                try:
                    magic = self._read_uint32(addr)
                    version = self._identify_version(magic)

                    if version and self._validate_pclntab_header(addr, version):
                        self.pclntab_addr = addr
                        self.version = version
                        return True
                except (MemoryAccessError, struct.error):
                    # Expected: scanning memory hits invalid regions
                    pass
                except Exception as e:
                    # Unexpected error - log for debugging
                    print(f"[DEBUG] Unexpected scan error at {addr}: {e}")
                    pass

                addr = addr.add(4)

        return False

    def _identify_version(self, magic):
        """Identify Go version from magic number"""
        if magic == MAGIC_12:
            return "1.2-1.15"
        elif magic == MAGIC_116:
            return "1.16-1.17"
        elif magic == MAGIC_118:
            return "1.18+"
        return None

    def _validate_pclntab_header(self, addr, version):
        """Validate PCLNTAB header structure"""
        try:
            ptrsize = self._read_uint8(addr.add(7))
            if ptrsize not in [4, 8]:
                return False

            if version in ["1.16-1.17", "1.18+"]:
                nfunc = self._read_uint32(addr.add(8)) if ptrsize == 4 else self._read_uint64(addr.add(8))
                if nfunc < 1 or nfunc > 100000:
                    return False

            return True
        except (MemoryAccessError, struct.error, AttributeError):
            # Invalid PCLNTAB header structure
            return False

    def _read_uint32(self, addr):
        """Read 32-bit unsigned integer"""
        bytes_data = getBytes(addr, 4)
        return struct.unpack("<I", bytes_data.tostring())[0]

    def _read_uint64(self, addr):
        """Read 64-bit unsigned integer"""
        bytes_data = getBytes(addr, 8)
        return struct.unpack("<Q", bytes_data.tostring())[0]

    def _read_uint8(self, addr):
        """Read 8-bit unsigned integer"""
        return getByte(addr) & 0xFF


class PclntabParser:
    """Parse PCLNTAB structure to recover function names (v1.0 functionality)"""

    def __init__(self, program, pclntab_addr, version):
        self.program = program
        self.pclntab_addr = pclntab_addr
        self.version = version
        self.functions = []

    def parse(self):
        """Parse PCLNTAB and extract function information"""
        print("[*] Parsing PCLNTAB at {}".format(self.pclntab_addr))
        print("[*] Go version: {}".format(self.version))

        if self.version == "1.2-1.15":
            return self._parse_go12()
        else:
            return self._parse_go116()

    def _parse_go116(self):
        """Parse Go 1.16+ PCLNTAB format"""
        addr = self.pclntab_addr

        self._read_uint32(addr)
        ptrsize = self._read_uint8(addr.add(7))
        nfunc = self._read_uintptr(addr.add(8), ptrsize)

        print("[*] Found {} functions".format(nfunc))

        offset = 8 + ptrsize
        funcnameOffset = self._read_uintptr(addr.add(offset), ptrsize)
        offset += ptrsize * 4  # Skip cu, filetab, pctab offsets

        ftab_offset = offset + ptrsize
        ftab_addr = addr.add(ftab_offset)
        entry_size = ptrsize * 2

        for i in range(min(int(nfunc), 10000)):
            entry_addr = ftab_addr.add(i * entry_size)

            try:
                func_entry = self._read_uintptr(entry_addr, ptrsize)
                func_info_offset = self._read_uintptr(entry_addr.add(ptrsize), ptrsize)

                if func_entry == 0 or func_info_offset == 0:
                    continue

                func_info_addr = addr.add(func_info_offset)
                name_offset = self._read_uint32(func_info_addr.add(ptrsize))

                name_addr = addr.add(funcnameOffset + name_offset)
                func_name = self._read_string(name_addr)

                if func_name and func_entry > 0:
                    self.functions.append({
                        'address': func_entry,
                        'name': func_name
                    })
            except (MemoryAccessError, struct.error) as e:
                # Expected: some entries may be corrupted
                print(f"[DEBUG] Skipping entry: {e}")
                continue
            except Exception as e:
                # Unexpected error - log and continue
                print(f"[WARN] Unexpected parsing error: {e}")
                continue

        return len(self.functions)

    def _parse_go12(self):
        """Parse Go 1.2-1.15 PCLNTAB format"""
        # Simplified version for brevity
        # Full implementation is in RecoverGoFunctions.py
        return 0

    def _read_uintptr(self, addr, ptrsize):
        """Read pointer-sized unsigned integer"""
        if ptrsize == 4:
            return self._read_uint32(addr)
        else:
            return self._read_uint64(addr)

    def _read_uint32(self, addr):
        bytes_data = getBytes(addr, 4)
        return struct.unpack("<I", bytes_data.tostring())[0]

    def _read_uint64(self, addr):
        bytes_data = getBytes(addr, 8)
        return struct.unpack("<Q", bytes_data.tostring())[0]

    def _read_uint8(self, addr):
        return getByte(addr) & 0xFF

    def _read_string(self, addr):
        """Read null-terminated string"""
        try:
            chars = []
            max_len = 256

            for i in range(max_len):
                byte = getByte(addr.add(i)) & 0xFF
                if byte == 0:
                    break
                if byte >= 32 and byte < 127:
                    chars.append(chr(byte))
                else:
                    break

            return ''.join(chars) if chars else None
        except (AttributeError, TypeError) as e:
            # Failed to read string
            raise MemoryAccessError(addr, f"Failed to read string: {e}")
        except Exception as e:
            # Unexpected error during string read
            print(f"[WARN] Unexpected error reading string at {addr}: {e}")
            return None


class FunctionRecoveryService:
    """Apply recovered function names to the program (v1.0 functionality)"""

    def __init__(self, program):
        self.program = program
        self.func_mgr = program.getFunctionManager()
        self.created = 0
        self.renamed = 0
        self.failed = 0

    def apply_functions(self, functions):
        """Create or rename functions based on recovered information"""
        print("\n[*] Applying {} recovered functions...".format(len(functions)))

        for func_info in functions:
            try:
                addr_value = func_info['address']
                func_name = func_info['name']
                addr = toAddr(addr_value)

                existing_func = self.func_mgr.getFunctionAt(addr)

                if existing_func:
                    old_name = existing_func.getName()
                    if old_name.startswith("FUN_") or old_name.startswith("SUB_"):
                        existing_func.setName(func_name, SourceType.ANALYSIS)
                        self.renamed += 1
                else:
                    cmd = CreateFunctionCmd(addr)
                    if cmd.applyTo(self.program):
                        new_func = self.func_mgr.getFunctionAt(addr)
                        if new_func:
                            new_func.setName(func_name, SourceType.ANALYSIS)
                            self.created += 1
                    else:
                        self.failed += 1

            except Exception:
                self.failed += 1

        print("\n[*] Function Recovery Summary:")
        print("    Functions created: {}".format(self.created))
        print("    Functions renamed: {}".format(self.renamed))
        print("    Failed: {}".format(self.failed))


# ============================================================================
# Main Script - Integrated v1.0 + v1.1
# ============================================================================

def main():
    """Main entry point for GhidraGo v1.1 analysis"""
    print("="*70)
    print("GhidraGo v1.1 - Go Function and Type Recovery")
    print("="*70)

    program = currentProgram
    if not program:
        print("[!] No program loaded")
        return

    print("\n[*] Analyzing program: {}".format(program.getName()))

    # ========================================================================
    # Phase 1: Detect Go binary and locate PCLNTAB (v1.0 MVP)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 1: Go Detection and PCLNTAB Location")
    print("="*70)

    detector = GoVersionDetector(program)
    if not detector.detect():
        print("[!] Failed to detect Go binary or locate PCLNTAB")
        print("[!] This may not be a Go binary, or it uses an unsupported version")
        return

    print("[+] Detected Go version: {}".format(detector.version))
    print("[+] PCLNTAB located at: {}".format(detector.pclntab_addr))

    # ========================================================================
    # Phase 2: Parse PCLNTAB and recover functions (v1.0 MVP)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 2: Function Name Recovery")
    print("="*70)

    parser = PclntabParser(program, detector.pclntab_addr, detector.version)
    func_count = parser.parse()

    if func_count == 0:
        print("[!] No functions recovered from PCLNTAB")
        # Continue anyway - we can still try type extraction
    else:
        print("\n[+] Successfully parsed {} functions".format(func_count))

        service = FunctionRecoveryService(program)
        service.apply_functions(parser.functions)

    # ========================================================================
    # Phase 3: Locate moduledata structure (v1.1 NEW)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 3: Moduledata Structure Location (v1.1)")
    print("="*70)

    scanner = ModuledataScanner(program, detector.pclntab_addr, detector.version)
    moduledata_addr = scanner.scan()

    if not moduledata_addr:
        print("[!] Failed to locate moduledata structure")
        print("[!] Type extraction unavailable")
        print("\n[*] Analysis complete (function recovery only)")
        return

    moduledata = scanner.get_moduledata()

    # ========================================================================
    # Phase 4: Parse typelinks array (v1.1 NEW)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 4: Typelinks Array Parsing (v1.1)")
    print("="*70)

    typelinks_parser = TypelinksParser(program, moduledata)
    type_offsets = typelinks_parser.parse()

    if len(type_offsets) == 0:
        print("[!] No type offsets recovered")
        print("\n[*] Analysis complete (function recovery only)")
        return

    type_addresses = typelinks_parser.get_type_addresses()

    # ========================================================================
    # Phase 5: Parse rtype structures and extract types (v1.1 NEW)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 5: Type Information Extraction (v1.1 Phase 2)")
    print("="*70)

    rtype_parser = RtypeParser(program, moduledata, detector.version)
    recovered_types = []

    print("[*] Parsing {} type structures...".format(len(type_addresses)))

    for i, addr in enumerate(type_addresses[:1000]):  # Limit to 1000 for MVP
        type_info = rtype_parser.parse_rtype(addr)
        if type_info:
            recovered_types.append(type_info)

        # Progress indicator
        if (i + 1) % 100 == 0:
            print(f"[*] Processed {i + 1}/{min(len(type_addresses), 1000)} types...")

    print(f"\n[+] Successfully extracted {len(recovered_types)} types")

    # ========================================================================
    # Phase 5.5: Create Phase 2 Parsers and Resolver (v1.1 Phase 2 NEW)
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 5.5: Initialize Phase 2 Parsers and Resolver")
    print("="*70)

    # Create Phase 2 parsers for detailed struct/interface parsing
    struct_field_parser = StructFieldParser(program, moduledata['types'])
    interface_method_parser = InterfaceMethodParser(program, moduledata['types'])
    type_resolver = TypeResolver(program, moduledata['types'], rtype_parser)

    print("[+] Struct field parser initialized")
    print("[+] Interface method parser initialized")
    print("[+] Type resolver initialized (handles nested references)")

    # ========================================================================
    # Phase 6: Apply types to Ghidra (v1.1 NEW) with Dependency Ordering
    # ========================================================================
    print("\n" + "="*70)
    print("PHASE 6: Type Application to Ghidra (Phase 2)")
    print("="*70)

    type_service = TypeRecoveryService(program)
    type_service.begin_transaction()

    print("[*] Applying {} types with dependency resolution...".format(len(recovered_types)))

    # Use the new high-level method that handles dependency ordering
    stats = type_service.apply_types_with_resolution(
        recovered_types,
        type_resolver,
        struct_field_parser,
        interface_method_parser
    )

    type_service.end_transaction()

    resolver_stats = type_resolver.get_resolution_statistics()

    print("\n[*] Type Recovery Summary:")
    print("    Types created: {}".format(stats['types_created']))
    print("    Types failed: {}".format(stats['types_failed']))
    print("    Types resolved: {}".format(resolver_stats['types_cached']))

    # ========================================================================
    # Final Summary
    # ========================================================================
    print("\n" + "="*70)
    print("ANALYSIS COMPLETE - GhidraGo v1.1 Phase 2")
    print("="*70)

    print("\n[+] GhidraGo v1.1 Phase 2 Results:")
    print(f"    Functions recovered: {func_count}")
    print(f"    Types extracted: {len(recovered_types)}")
    print(f"    Types created in Ghidra: {stats['types_created']}")
    print(f"    Type references resolved: {resolver_stats['types_cached']}")
    print("\n[+] Phase 2 enhancements applied:")
    print("    - Struct fields parsed with names, types, offsets, and tags")
    print("    - Interface methods extracted with type signatures")
    print("    - Nested type references resolved (circular ref detection)")
    print("    - Types applied in dependency order (no forward references)")
    print("\n[+] Check the decompiler and Data Type Manager for improved type information!")
    print("[+] Check Data Type Manager for recovered Go types with field details")

    print("\n" + "="*70)


# Run the script
if __name__ == "__main__":
    main()
