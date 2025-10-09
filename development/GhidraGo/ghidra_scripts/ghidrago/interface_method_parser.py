# InterfaceMethodParser - Parse Go interface methods
# @author Catalytic Computing
# @category Golang.TypeExtraction

"""
InterfaceMethodParser provides detailed parsing of Go interface methods.

Go interface structure (from runtime/type.go):

type interfaceType struct {
    rtype
    pkgPath name
    methods []imethod
}

type imethod struct {
    name nameOff  // Method name
    typ  typeOff  // Method type (signature)
}

Interfaces in Go define a contract - a set of methods that a type must implement.
"""

import struct
from typing import List, Dict, Optional, Any


class InterfaceMethodParser:
    """
    Parse Go interfaceType and imethod structures.

    Extracts method names and type signatures from interface definitions.
    """

    def __init__(self, program, types_base):
        """
        Initialize interface method parser.

        Args:
            program: Ghidra Program object
            types_base: Base address of types section (from moduledata)
        """
        self.program = program
        self.types_base = types_base
        self.memory = program.getMemory()

    def parse_interface_type(self, rtype_addr, type_info) -> List[Dict[str, Any]]:
        """
        Parse interfaceType and extract all method information.

        Args:
            rtype_addr: Address of rtype structure
            type_info: Dictionary from RtypeParser (contains interface_methods_ptr)

        Returns:
            List of method dictionaries with name and type_offset
        """
        methods = []

        # interfaceType layout (Go 1.18+):
        # - rtype (0x30 bytes)
        # - pkgPath name (~0x08 bytes, variable)
        # - methods []imethod (0x18 bytes slice header)

        try:
            # Get methods pointer and count from type_info
            if "interface_methods_ptr" not in type_info:
                return methods

            methods_ptr = type_info["interface_methods_ptr"]
            methods_count = type_info.get("interface_methods_count", 0)

            if methods_ptr == 0 or methods_count == 0:
                return methods

            # Parse each imethod
            methods_addr = toAddr(methods_ptr)
            imethod_size = 0x08  # imethod is 8 bytes (4+4)

            for i in range(min(int(methods_count), 100)):  # Safety limit
                method_addr = methods_addr.add(i * imethod_size)
                method_info = self._parse_imethod(method_addr)

                if method_info:
                    methods.append(method_info)

            print(f"    [+] Parsed {len(methods)} methods for {type_info.get('name', '<unknown>')}")

        except Exception as e:
            print(f"[!] Error parsing interface methods: {e}")

        return methods

    def _parse_imethod(self, method_addr) -> Optional[Dict[str, Any]]:
        """
        Parse a single imethod structure.

        imethod layout (Go 1.18+, 64-bit):
        +0x00: name nameOff (4 bytes) - offset to method name
        +0x04: typ  typeOff (4 bytes) - offset to method type/signature

        Returns:
            Dictionary with method information or None if invalid
        """
        try:
            # Read imethod fields
            name_offset = self._read_uint32(method_addr)  # +0x00
            type_offset = self._read_uint32(method_addr.add(0x04))  # +0x04

            # Parse method name
            method_name = self._parse_name(name_offset)

            method_info = {
                "name": method_name,
                "type_offset": type_offset,
            }

            return method_info

        except Exception as e:
            print(f"[!] Error parsing imethod at {method_addr}: {e}")
            return None

    def _parse_name(self, name_offset) -> str:
        """
        Parse Go name structure to extract method name.

        Same encoding as struct field names (see struct_field_parser.py).

        Returns:
            Method name string
        """
        if name_offset == 0:
            return "<anonymous>"

        try:
            # Name is at types_base + name_offset
            name_addr = toAddr(self.types_base.getOffset() + name_offset)

            # Read flags byte
            self._read_uint8(name_addr)

            # Read name length (varint - simplified)
            name_len_addr = name_addr.add(1)
            name_len = self._read_varint(name_len_addr)

            if name_len <= 0 or name_len > 200:
                return "<invalid_name>"

            # Read name string
            name_start_addr = name_len_addr.add(1)
            name_str = self._read_utf8_string(name_start_addr, name_len)

            return name_str

        except Exception as e:
            print(f"[!] Error parsing method name: {e}")
            return "<error>"

    def _read_varint(self, addr) -> int:
        """Read varint (simplified - single byte)."""
        first_byte = self._read_uint8(addr)
        if (first_byte & 0x80) == 0:
            return first_byte
        return first_byte & 0x7F

    def _read_utf8_string(self, addr, length) -> str:
        """Read UTF-8 encoded string."""
        try:
            chars = []
            for i in range(min(int(length), 200)):
                byte = self._read_uint8(addr.add(i))

                if 32 <= byte < 127:
                    chars.append(chr(byte))
                elif byte == 0:
                    break
                else:
                    chars.append("_")

            return "".join(chars) if chars else "<empty>"

        except Exception:
            return "<error>"

    def _read_uint32(self, addr):
        """Read 32-bit unsigned integer."""
        bytes_data = getBytes(addr, 4)
        return struct.unpack("<I", bytes_data.tostring())[0]

    def _read_uint8(self, addr):
        """Read 8-bit unsigned integer."""
        return getByte(addr) & 0xFF


# Helper function for testing
def test_interface_method_parser():
    """Test interface method parser with current program."""
    print("=" * 60)
    print("Testing InterfaceMethodParser")
    print("=" * 60)

    print("\nTo use InterfaceMethodParser:")
    print("1. Parse rtype to get interface_methods_ptr and count")
    print("2. Create parser: InterfaceMethodParser(program, types_base)")
    print("3. Call: methods = parser.parse_interface_type(rtype_addr, type_info)")
    print("\nExample:")
    print("  parser = InterfaceMethodParser(program, types_base)")
    print("  methods = parser.parse_interface_type(addr, type_info)")
    print("  for method in methods:")
    print("      print(f'method: {method['name']}')")


if __name__ == "__main__":
    test_interface_method_parser()
