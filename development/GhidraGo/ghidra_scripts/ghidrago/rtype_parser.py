# RtypeParser - Parse Go runtime type (rtype) structures
# @author Catalytic Computing
# @category Golang.TypeExtraction

"""
RtypeParser decodes Go runtime type (rtype) structures.

The rtype structure is the base type descriptor in Go's reflection system.
All type-specific structures (structType, interfaceType, etc.) embed rtype.

rtype contains:
- size: Size of the type in bytes
- kind: Type classification (struct, interface, int, string, etc.)
- align: Alignment requirement
- fieldAlign: Field alignment
- tflag: Type flags
- str: Offset to type name string (nameOff)
- ptrToThis: Offset to pointer-to-this-type (typeOff)
"""

import struct
from typing import Optional, Dict, Any


class RtypeParser:
    """
    Parse Go runtime rtype structures and type-specific extensions.

    Handles version-specific structure layouts for Go 1.16, 1.18, 1.20+.
    """

    # Type kind constants (from Go runtime/type.go)
    KIND_BOOL = 1
    KIND_INT = 2
    KIND_INT8 = 3
    KIND_INT16 = 4
    KIND_INT32 = 5
    KIND_INT64 = 6
    KIND_UINT = 7
    KIND_UINT8 = 8
    KIND_UINT16 = 9
    KIND_UINT32 = 10
    KIND_UINT64 = 11
    KIND_UINTPTR = 12
    KIND_FLOAT32 = 13
    KIND_FLOAT64 = 14
    KIND_COMPLEX64 = 15
    KIND_COMPLEX128 = 16
    KIND_ARRAY = 17
    KIND_CHAN = 18
    KIND_FUNC = 19
    KIND_INTERFACE = 20
    KIND_MAP = 21
    KIND_PTR = 22
    KIND_SLICE = 23
    KIND_STRING = 24
    KIND_STRUCT = 25
    KIND_UNSAFE_POINTER = 26

    KIND_NAMES = {
        1: "bool",
        2: "int",
        3: "int8",
        4: "int16",
        5: "int32",
        6: "int64",
        7: "uint",
        8: "uint8",
        9: "uint16",
        10: "uint32",
        11: "uint64",
        12: "uintptr",
        13: "float32",
        14: "float64",
        15: "complex64",
        16: "complex128",
        17: "array",
        18: "chan",
        19: "func",
        20: "interface",
        21: "map",
        22: "ptr",
        23: "slice",
        24: "string",
        25: "struct",
        26: "unsafe.Pointer",
    }

    def __init__(self, program, moduledata, go_version="1.18+"):
        """
        Initialize rtype parser.

        Args:
            program: Ghidra Program object
            moduledata: Dictionary from ModuledataScanner
            go_version: Go version string for version-specific parsing
        """
        self.program = program
        self.moduledata = moduledata
        self.go_version = go_version
        self.memory = program.getMemory()
        self.types_base = moduledata["types"]

    def parse_rtype(self, type_addr) -> Optional[Dict[str, Any]]:
        """
        Parse rtype structure at given address.

        Args:
            type_addr: Address of rtype structure

        Returns:
            Dictionary containing type information, or None if invalid
        """
        try:
            # Go 1.18+ rtype structure (64-bit):
            # type rtype struct {
            #     size       uintptr  // +0x00 (8 bytes)
            #     ptrdata    uintptr  // +0x08 (8 bytes)
            #     hash       uint32   // +0x10 (4 bytes)
            #     tflag      tflag    // +0x14 (1 byte)
            #     align      uint8    // +0x15 (1 byte)
            #     fieldAlign uint8    // +0x16 (1 byte)
            #     kind       uint8    // +0x17 (1 byte)
            #     equal      func     // +0x18 (8 bytes ptr)
            #     gcdata     *byte    // +0x20 (8 bytes ptr)
            #     str        nameOff  // +0x28 (4 bytes offset)
            #     ptrToThis  typeOff  // +0x2C (4 bytes offset)
            # }

            size = self._read_uint64(type_addr)  # +0x00
            self._read_uint64(type_addr.add(0x08))  # +0x08
            hash_val = self._read_uint32(type_addr.add(0x10))  # +0x10
            tflag = self._read_uint8(type_addr.add(0x14))  # +0x14
            align = self._read_uint8(type_addr.add(0x15))  # +0x15
            field_align = self._read_uint8(type_addr.add(0x16))  # +0x16
            kind = self._read_uint8(type_addr.add(0x17))  # +0x17
            str_offset = self._read_uint32(type_addr.add(0x28))  # +0x28
            self._read_uint32(type_addr.add(0x2C))  # +0x2C

            # Extract kind (lower 5 bits)
            kind_masked = kind & 0x1F

            # Validate kind
            if kind_masked not in self.KIND_NAMES:
                return None

            # Read type name
            type_name = self._read_type_name(str_offset)

            type_info = {
                "address": type_addr,
                "size": size,
                "kind": kind_masked,
                "kind_name": self.KIND_NAMES[kind_masked],
                "name": type_name,
                "align": align,
                "field_align": field_align,
                "tflag": tflag,
                "hash": hash_val,
            }

            # Parse type-specific extensions
            if kind_masked == self.KIND_STRUCT:
                self._parse_struct_type(type_addr, type_info)
            elif kind_masked == self.KIND_INTERFACE:
                self._parse_interface_type(type_addr, type_info)
            elif kind_masked == self.KIND_SLICE:
                self._parse_slice_type(type_addr, type_info)
            elif kind_masked == self.KIND_ARRAY:
                self._parse_array_type(type_addr, type_info)
            elif kind_masked == self.KIND_PTR:
                self._parse_ptr_type(type_addr, type_info)

            return type_info

        except Exception as e:
            print(f"[!] Error parsing rtype at {type_addr}: {e}")
            return None

    def _parse_struct_type(self, rtype_addr, type_info):
        """
        Parse structType which embeds rtype.

        type structType struct {
            rtype
            pkgPath name
            fields  []structField  // Slice of fields
        }

        type structField struct {
            name       name      // Field name
            typ        *rtype    // Field type
            offsetAnon uintptr   // Offset + embedded flag
        }
        """
        # structType starts at rtype + sizeof(rtype)
        # For Go 1.18+, sizeof(rtype) = 0x30
        struct_type_addr = rtype_addr.add(0x30)

        try:
            # Skip pkgPath name (variable size, complex to parse)
            # Jump to fields slice (approximate offset +0x10)
            fields_slice_addr = struct_type_addr.add(0x10)

            # Read slice header: [ptr, len, cap]
            fields_ptr = self._read_uint64(fields_slice_addr)
            fields_len = self._read_uint64(fields_slice_addr.add(0x08))
            self._read_uint64(fields_slice_addr.add(0x10))

            type_info["struct_fields_count"] = fields_len
            type_info["struct_fields_ptr"] = fields_ptr

            # TODO: Parse individual fields in Phase 2
            # For now, just record the count

        except Exception as e:
            print(f"[!] Error parsing structType: {e}")

    def _parse_interface_type(self, rtype_addr, type_info):
        """
        Parse interfaceType which embeds rtype.

        type interfaceType struct {
            rtype
            pkgPath name
            methods []imethod  // Slice of interface methods
        }
        """
        # Similar structure to structType
        interface_type_addr = rtype_addr.add(0x30)

        try:
            methods_slice_addr = interface_type_addr.add(0x10)

            methods_ptr = self._read_uint64(methods_slice_addr)
            methods_len = self._read_uint64(methods_slice_addr.add(0x08))

            type_info["interface_methods_count"] = methods_len
            type_info["interface_methods_ptr"] = methods_ptr

        except Exception as e:
            print(f"[!] Error parsing interfaceType: {e}")

    def _parse_slice_type(self, rtype_addr, type_info):
        """
        Parse sliceType which embeds rtype.

        type sliceType struct {
            rtype
            elem *rtype  // Slice element type
        }
        """
        slice_type_addr = rtype_addr.add(0x30)

        try:
            elem_type_offset = self._read_uint32(slice_type_addr)
            type_info["slice_elem_type_offset"] = elem_type_offset

        except Exception as e:
            print(f"[!] Error parsing sliceType: {e}")

    def _parse_array_type(self, rtype_addr, type_info):
        """
        Parse arrayType which embeds rtype.

        type arrayType struct {
            rtype
            elem  *rtype  // Array element type
            slice *rtype  // Slice type for this array
            len   uintptr // Array length
        }
        """
        array_type_addr = rtype_addr.add(0x30)

        try:
            elem_type_offset = self._read_uint32(array_type_addr)
            # Skip slice pointer (8 bytes)
            array_len = self._read_uint64(array_type_addr.add(0x10))

            type_info["array_elem_type_offset"] = elem_type_offset
            type_info["array_length"] = array_len

        except Exception as e:
            print(f"[!] Error parsing arrayType: {e}")

    def _parse_ptr_type(self, rtype_addr, type_info):
        """
        Parse ptrType which embeds rtype.

        type ptrType struct {
            rtype
            elem *rtype  // Pointer element type
        }
        """
        ptr_type_addr = rtype_addr.add(0x30)

        try:
            elem_type_offset = self._read_uint32(ptr_type_addr)
            type_info["ptr_elem_type_offset"] = elem_type_offset

        except Exception as e:
            print(f"[!] Error parsing ptrType: {e}")

    def _read_type_name(self, name_offset) -> str:
        """
        Read type name string from name offset.

        Name encoding in Go 1.18+:
        - First 2 bytes: name length (varint encoded)
        - Following bytes: UTF-8 name string

        This is a simplified version. Full implementation would handle:
        - Varint decoding
        - Tag strings (for struct fields)
        - Exported/unexported flags
        """
        if name_offset == 0:
            return "<anonymous>"

        try:
            # Name is at types_base + name_offset
            name_addr = toAddr(self.types_base.getOffset() + name_offset)

            # Read first byte (simplified - assumes length < 128)
            length = self._read_uint8(name_addr)

            if length == 0 or length > 200:  # Sanity check
                return "<invalid_name>"

            # Read name bytes
            name_addr = name_addr.add(1)
            name_bytes = []

            for i in range(min(length, 200)):
                b = self._read_uint8(name_addr.add(i))
                if 32 <= b < 127:  # Printable ASCII
                    name_bytes.append(chr(b))
                elif b == 0:
                    break

            return "".join(name_bytes) if name_bytes else "<unknown>"

        except Exception as e:
            print(f"[!] Error reading type name: {e}")
            return "<error_reading_name>"

    def _read_uint64(self, addr):
        """Read 64-bit unsigned integer."""
        bytes_data = getBytes(addr, 8)
        return struct.unpack("<Q", bytes_data.tostring())[0]

    def _read_uint32(self, addr):
        """Read 32-bit unsigned integer."""
        bytes_data = getBytes(addr, 4)
        return struct.unpack("<I", bytes_data.tostring())[0]

    def _read_uint8(self, addr):
        """Read 8-bit unsigned integer."""
        return getByte(addr) & 0xFF


# Helper function for testing
def test_rtype_parser():
    """Test rtype parser with current program."""
    print("=" * 60)
    print("Testing RtypeParser")
    print("=" * 60)

    print("\nTo use RtypeParser:")
    print("1. Get type addresses from TypelinksParser")
    print("2. Create parser: RtypeParser(program, moduledata)")
    print("3. For each address: type_info = parser.parse_rtype(addr)")
    print("\nExample:")
    print("  parser = RtypeParser(program, moduledata)")
    print("  for addr in type_addresses:")
    print("      info = parser.parse_rtype(addr)")
    print("      print(f'{info['name']}: {info['kind_name']} ({info['size']} bytes)')")


if __name__ == "__main__":
    test_rtype_parser()
