# TypelinksParser - Parse Go typelinks array for type metadata
# @author Catalytic Computing
# @category Golang.TypeExtraction

"""
TypelinksParser extracts type information from the Go typelinks array.

The typelinks array contains 32-bit offsets to type descriptors (rtype structures).
These offsets are relative to the 'types' base address in moduledata.

Each offset points to an rtype structure that describes a Go type (struct, interface, etc.).
"""

import struct
from typing import List


class TypelinksParser:
    """
    Parse typelinks array to extract type metadata offsets.

    The typelinks array is a slice of int32 values, where each value is an offset
    from the types base address to an rtype structure.
    """

    def __init__(self, program, moduledata):
        """
        Initialize typelinks parser.

        Args:
            program: Ghidra Program object
            moduledata: Dictionary from ModuledataScanner.get_moduledata()
        """
        self.program = program
        self.moduledata = moduledata
        self.memory = program.getMemory()
        self.type_offsets = []
        self.types_base = moduledata['types']
        self.typelinks_addr = moduledata['typelinks_addr']
        self.typelinks_len = moduledata['typelinks_len']

    def parse(self) -> List[int]:
        """
        Parse typelinks array and return list of type offsets.

        Returns:
            List of integers representing offsets to rtype structures
        """
        print(f"[*] Parsing typelinks array ({self.typelinks_len} entries)...")

        self.type_offsets = []
        addr = self.typelinks_addr

        for i in range(min(int(self.typelinks_len), 100000)):  # Safety limit
            try:
                # Read 32-bit offset
                offset = self._read_int32(addr)

                # Validate offset is within types section
                if self._validate_offset(offset):
                    self.type_offsets.append(offset)
                else:
                    print(f"[!] Warning: Invalid offset at index {i}: 0x{offset:x}")

                # Move to next entry
                addr = addr.add(4)  # 32-bit = 4 bytes

            except Exception as e:
                print(f"[!] Error reading typelinks at index {i}: {e}")
                break

        print(f"[+] Parsed {len(self.type_offsets)} valid type offsets")
        return self.type_offsets

    def _validate_offset(self, offset) -> bool:
        """
        Validate that offset points within the types section.

        Args:
            offset: 32-bit offset from types base

        Returns:
            True if offset is valid, False otherwise
        """
        # Offset can be negative (before types base) in some cases
        # But should still resolve to a valid address

        types_start = self.types_base.getOffset()
        types_end = self.moduledata['etypes'].getOffset()
        types_end - types_start

        # The offset is signed, so handle negative values
        if offset < 0:
            # Negative offset - points before types base
            # This can happen in some Go versions
            target_addr = types_start + offset
        else:
            # Positive offset - normal case
            target_addr = types_start + offset

        # Check if target address is in a reasonable range
        # Allow some flexibility for edge cases
        min_addr = types_start - (10 * 1024 * 1024)  # 10MB before
        max_addr = types_end + (10 * 1024 * 1024)    # 10MB after

        return min_addr <= target_addr <= max_addr

    def get_type_addresses(self) -> List:
        """
        Convert type offsets to absolute Ghidra addresses.

        Returns:
            List of Ghidra Address objects pointing to rtype structures
        """
        addresses = []
        types_base_offset = self.types_base.getOffset()

        for offset in self.type_offsets:
            # Calculate absolute address
            type_addr = toAddr(types_base_offset + offset)
            addresses.append(type_addr)

        return addresses

    def _read_int32(self, addr):
        """Read signed 32-bit integer."""
        bytes_data = getBytes(addr, 4)
        return struct.unpack("<i", bytes_data.tostring())[0]

    def _read_uint32(self, addr):
        """Read unsigned 32-bit integer."""
        bytes_data = getBytes(addr, 4)
        return struct.unpack("<I", bytes_data.tostring())[0]


# Helper function for testing
def test_typelinks_parser():
    """Test typelinks parser with current program."""
    print("="*60)
    print("Testing TypelinksParser")
    print("="*60)

    print("\nTo use TypelinksParser:")
    print("1. First run ModuledataScanner to get moduledata dict")
    print("2. Create parser: TypelinksParser(program, moduledata)")
    print("3. Call parser.parse() to extract offsets")
    print("4. Use parser.get_type_addresses() for absolute addresses")
    print("\nExample:")
    print("  scanner = ModuledataScanner(program, pclntab_addr, go_version)")
    print("  scanner.scan()")
    print("  moduledata = scanner.get_moduledata()")
    print("  parser = TypelinksParser(program, moduledata)")
    print("  offsets = parser.parse()")
    print("  addresses = parser.get_type_addresses()")


if __name__ == "__main__":
    test_typelinks_parser()
