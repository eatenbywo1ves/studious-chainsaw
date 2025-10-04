# ModuledataScanner - Locate Go runtime moduledata structure
# @author Catalytic Computing
# @category Golang.TypeExtraction

"""
ModuledataScanner locates the Go runtime moduledata structure in binaries.

The moduledata structure contains critical metadata including:
- PCLNTAB pointer (already used in v1.0)
- types/etypes range (type information storage)
- typelinks slice (array of type offsets)
- text/etext range (code section boundaries)

This is the foundation for type extraction in GhidraGo v1.1.
"""

import struct
from typing import Optional, Dict, Any
from .exceptions import MemoryAccessError, InvalidBinaryError


class ModuledataScanner:
    """
    Scan for and parse Go runtime moduledata structure.

    The moduledata structure is the central metadata hub for Go binaries,
    containing pointers to all runtime information including types.
    """

    # Moduledata field offsets vary by Go version
    # These are for Go 1.18+ (64-bit)
    MODULEDATA_OFFSETS_118 = {
        'pclntab': 0x20,        # Pointer to PCLNTAB (we already have this)
        'ftab': 0x28,           # Function table
        'filetab': 0x30,        # File table
        'findfunctab': 0x38,    # Find function table
        'minpc': 0x40,          # Minimum PC
        'maxpc': 0x48,          # Maximum PC
        'text': 0x50,           # Text section start
        'etext': 0x58,          # Text section end
        'noptrdata': 0x60,      # No-pointer data start
        'enoptrdata': 0x68,     # No-pointer data end
        'data': 0x70,           # Data section start
        'edata': 0x78,          # Data section end
        'bss': 0x80,            # BSS section start
        'ebss': 0x88,           # BSS section end
        'noptrbss': 0x90,       # No-pointer BSS start
        'enoptrbss': 0x98,      # No-pointer BSS end
        'types': 0xC0,          # Types section start ⭐ KEY for v1.1
        'etypes': 0xC8,         # Types section end ⭐ KEY for v1.1
        'typelinks_addr': 0xD8, # Typelinks slice address ⭐ KEY for v1.1
        'typelinks_len': 0xE0,  # Typelinks slice length ⭐ KEY for v1.1
        'typelinks_cap': 0xE8,  # Typelinks slice capacity
    }

    def __init__(self, program, pclntab_addr, go_version):
        """
        Initialize moduledata scanner.

        Args:
            program: Ghidra Program object
            pclntab_addr: Address of PCLNTAB (from v1.0 MVP)
            go_version: Detected Go version string (e.g., "1.18+")
        """
        self.program = program
        self.pclntab_addr = pclntab_addr
        self.go_version = go_version
        self.memory = program.getMemory()
        self.moduledata_addr = None
        self.moduledata = {}

    def scan(self) -> Optional[int]:
        """
        Locate moduledata structure in the binary.

        Strategy:
        1. For ELF: Look in .noptrdata or .data sections
        2. Scan for PCLNTAB pointer reference
        3. Validate structure by checking field sanity

        Returns:
            Address of moduledata structure, or None if not found
        """
        print("[*] Scanning for moduledata structure...")

        # Strategy 1: Search sections by name (ELF-specific)
        moduledata_addr = self._scan_named_sections()
        if moduledata_addr:
            return moduledata_addr

        # Strategy 2: Scan for PCLNTAB reference
        moduledata_addr = self._scan_for_pclntab_reference()
        if moduledata_addr:
            return moduledata_addr

        print("[!] Failed to locate moduledata structure")
        return None

    def _scan_named_sections(self) -> Optional[int]:
        """
        Scan platform-specific sections for moduledata.

        - ELF (Linux): .noptrdata, .data
        - PE (Windows): .data, .rdata
        - Mach-O (macOS): __noptrdata, __data

        The moduledata structure is typically in .noptrdata or .data section.
        We identify it by finding our known PCLNTAB pointer.
        """
        # Platform-specific section names
        # ELF (Linux): .noptrdata, .data, .rodata
        # PE (Windows): .data, .rdata
        # Mach-O (macOS): __noptrdata, __data, __rodata
        target_sections = [
            '.noptrdata', '.data', '.rodata',  # ELF
            '__noptrdata', '__data', '__rodata',  # Mach-O
            '.rdata'  # PE
        ]

        for section_name in target_sections:
            block = self._get_memory_block(section_name)
            if not block:
                continue

            print(f"[*] Scanning {section_name} section...")
            addr = self._scan_block_for_pclntab_ref(block)
            if addr:
                print(f"[+] Found moduledata in {section_name} at {addr}")
                self.moduledata_addr = addr
                self._parse_moduledata(addr)
                return addr

        return None

    def _get_memory_block(self, name):
        """Get memory block by name."""
        for block in self.memory.getBlocks():
            if block.getName() == name:
                return block
        return None

    def _scan_block_for_pclntab_ref(self, block):
        """
        Scan a memory block for PCLNTAB pointer reference.

        The moduledata structure contains a pointer to PCLNTAB at a known offset.
        We scan for this pointer value and validate the surrounding structure.
        """
        addr = block.getStart()
        end_addr = block.getEnd()
        pclntab_value = self.pclntab_addr.getOffset()

        while addr.compareTo(end_addr) < 0:
            try:
                # Read 8-byte value (64-bit pointer)
                ptr_value = self._read_uint64(addr)

                # Check if this matches our PCLNTAB address
                if ptr_value == pclntab_value:
                    # Potential moduledata found!
                    # Back up to start of structure (pclntab is at offset 0x20)
                    candidate_addr = addr.subtract(self.MODULEDATA_OFFSETS_118['pclntab'])

                    if self._validate_moduledata(candidate_addr):
                        return candidate_addr

            except (MemoryAccessError, struct.error):
                # Expected: scanning memory hits invalid regions
                pass
            except Exception as e:
                # Unexpected error - log and continue
                print(f"[DEBUG] Unexpected error scanning at {search_addr}: {e}")
                pass

            # Move forward by pointer size
            addr = addr.add(8)

        return None

    def _scan_for_pclntab_reference(self) -> Optional[int]:
        """
        Fallback: scan all initialized memory for PCLNTAB reference.

        Used when named sections aren't available (PE/Mach-O) or as fallback.
        """
        print("[*] Performing memory-wide scan for moduledata...")

        self.pclntab_addr.getOffset()

        for block in self.memory.getBlocks():
            if not block.isInitialized():
                continue

            # Skip code sections (moduledata is in data)
            if block.isExecute():
                continue

            addr = self._scan_block_for_pclntab_ref(block)
            if addr:
                return addr

        return None

    def _validate_moduledata(self, addr) -> bool:
        """
        Validate that address points to a valid moduledata structure.

        Checks:
        1. PCLNTAB pointer matches our known value
        2. types/etypes range is reasonable
        3. text/etext range makes sense
        4. typelinks length is reasonable (1 to 100,000)
        """
        try:
            # Check 1: PCLNTAB pointer
            pclntab_offset = self.MODULEDATA_OFFSETS_118['pclntab']
            pclntab_ptr = self._read_uint64(addr.add(pclntab_offset))
            if pclntab_ptr != self.pclntab_addr.getOffset():
                return False

            # Check 2: types/etypes range
            types_addr = self._read_uint64(addr.add(self.MODULEDATA_OFFSETS_118['types']))
            etypes_addr = self._read_uint64(addr.add(self.MODULEDATA_OFFSETS_118['etypes']))

            if types_addr == 0 or etypes_addr == 0:
                return False

            types_size = etypes_addr - types_addr
            # Types section should be reasonable size (1KB to 100MB)
            if types_size < 1024 or types_size > 100 * 1024 * 1024:
                return False

            # Check 3: typelinks length
            typelinks_len = self._read_uint64(addr.add(self.MODULEDATA_OFFSETS_118['typelinks_len']))
            # Should have at least 1 type, but not more than 100,000
            if typelinks_len < 1 or typelinks_len > 100000:
                return False

            return True

        except (MemoryAccessError, struct.error, AttributeError):
            # Invalid moduledata structure
            return False
        except Exception as e:
            # Unexpected validation error
            print(f"[DEBUG] Unexpected validation error: {e}")
            return False

    def _parse_moduledata(self, addr):
        """
        Parse moduledata structure and extract key fields.

        Stores important addresses in self.moduledata dict for use by
        other components (TypelinksParser, RtypeParser, etc.)
        """
        print(f"[*] Parsing moduledata structure at {addr}")

        offsets = self.MODULEDATA_OFFSETS_118

        self.moduledata = {
            'base_addr': addr,
            'pclntab': toAddr(self._read_uint64(addr.add(offsets['pclntab']))),
            'text': toAddr(self._read_uint64(addr.add(offsets['text']))),
            'etext': toAddr(self._read_uint64(addr.add(offsets['etext']))),
            'types': toAddr(self._read_uint64(addr.add(offsets['types']))),
            'etypes': toAddr(self._read_uint64(addr.add(offsets['etypes']))),
            'typelinks_addr': toAddr(self._read_uint64(addr.add(offsets['typelinks_addr']))),
            'typelinks_len': self._read_uint64(addr.add(offsets['typelinks_len'])),
            'typelinks_cap': self._read_uint64(addr.add(offsets['typelinks_cap'])),
        }

        # Calculate derived values
        types_start = self.moduledata['types'].getOffset()
        types_end = self.moduledata['etypes'].getOffset()
        self.moduledata['types_size'] = types_end - types_start

        print("[+] Moduledata parsed successfully:")
        print(f"    Types section: {self.moduledata['types']} - {self.moduledata['etypes']} ({self.moduledata['types_size']} bytes)")
        print(f"    Typelinks: {self.moduledata['typelinks_len']} entries at {self.moduledata['typelinks_addr']}")

    def get_moduledata(self) -> Dict[str, Any]:
        """
        Get parsed moduledata fields.

        Returns:
            Dictionary containing moduledata fields (types, etypes, typelinks, etc.)
        """
        return self.moduledata

    def _read_uint64(self, addr):
        """Read 64-bit unsigned integer."""
        bytes_data = getBytes(addr, 8)
        return struct.unpack("<Q", bytes_data.tostring())[0]

    def _read_uint32(self, addr):
        """Read 32-bit unsigned integer."""
        bytes_data = getBytes(addr, 4)
        return struct.unpack("<I", bytes_data.tostring())[0]


# Helper function for testing
def test_moduledata_scanner():
    """Test moduledata scanner with current program."""
    print("="*60)
    print("Testing ModuledataScanner")
    print("="*60)

    # This requires PCLNTAB to already be located (from v1.0)
    # For now, this is a placeholder for integration testing

    print("\nTo use ModuledataScanner:")
    print("1. First run RecoverGoFunctions.py to locate PCLNTAB")
    print("2. Then use ModuledataScanner(program, pclntab_addr, go_version)")
    print("3. Call scanner.scan() to locate moduledata")
    print("4. Use scanner.get_moduledata() to get parsed fields")


if __name__ == "__main__":
    test_moduledata_scanner()
