# StructFieldParser - Parse Go structField and structType in detail
# @author Catalytic Computing
# @category Golang.TypeExtraction

"""
StructFieldParser provides detailed parsing of Go struct fields.

Go struct field structure (from runtime/type.go):

type structType struct {
    rtype
    pkgPath name
    fields  []structField
}

type structField struct {
    name       name      // Field name + tag
    typ        *rtype    // Field type pointer
    offsetAnon uintptr   // Offset in bytes + embedded flag
}

type name struct {
    bytes *byte
}

The name structure encoding (Go 1.18+):
- Byte 0: flags (1=exported, 2=has tag, 4=embedded, etc.)
- Bytes 1-2: name length (varint)
- Following bytes: UTF-8 name string
- If has tag: tag length (varint) + tag string
"""

import struct
from typing import List, Dict, Optional, Any


class StructFieldParser:
    """
    Parse Go structType and structField structures in detail.

    Extracts complete field information: names, types, offsets, tags, embedded flags.
    """

    def __init__(self, program, types_base):
        """
        Initialize struct field parser.

        Args:
            program: Ghidra Program object
            types_base: Base address of types section (from moduledata)
        """
        self.program = program
        self.types_base = types_base
        self.memory = program.getMemory()

    def parse_struct_type(self, rtype_addr, type_info) -> List[Dict[str, Any]]:
        """
        Parse structType and extract all field information.

        Args:
            rtype_addr: Address of rtype structure
            type_info: Dictionary from RtypeParser (contains struct_fields_ptr)

        Returns:
            List of field dictionaries with name, type_offset, offset, embedded, tag
        """
        fields = []

        # structType layout (Go 1.18+):
        # - rtype (0x30 bytes)
        # - pkgPath name (~0x08 bytes, variable)
        # - fields []structField (0x18 bytes slice header)

        try:
            # Get fields pointer and count from type_info (parsed in Phase 1)
            if 'struct_fields_ptr' not in type_info:
                return fields

            fields_ptr = type_info['struct_fields_ptr']
            fields_count = type_info.get('struct_fields_count', 0)

            if fields_ptr == 0 or fields_count == 0:
                return fields

            # Parse each structField
            fields_addr = toAddr(fields_ptr)
            struct_field_size = 0x18  # structField is 24 bytes (8+8+8)

            for i in range(min(int(fields_count), 1000)):  # Safety limit
                field_addr = fields_addr.add(i * struct_field_size)
                field_info = self._parse_struct_field(field_addr)

                if field_info:
                    fields.append(field_info)

            print(f"    [+] Parsed {len(fields)} fields for {type_info.get('name', '<unknown>')}")

        except Exception as e:
            print(f"[!] Error parsing struct fields: {e}")

        return fields

    def _parse_struct_field(self, field_addr) -> Optional[Dict[str, Any]]:
        """
        Parse a single structField structure.

        structField layout (Go 1.18+, 64-bit):
        +0x00: name       nameOff (4 bytes) - offset to name structure
        +0x08: typ        typeOff (4 bytes) - offset to field type
        +0x10: offsetAnon uintptr (8 bytes) - offset + embedded flag

        Returns:
            Dictionary with field information or None if invalid
        """
        try:
            # Read structField fields
            name_offset = self._read_uint32(field_addr)          # +0x00
            type_offset = self._read_uint32(field_addr.add(0x08)) # +0x08
            offset_anon = self._read_uint64(field_addr.add(0x10)) # +0x10

            # Extract offset and embedded flag
            # Lower bits = offset, highest bit = embedded flag
            offset = offset_anon >> 1  # Shift right 1 to get offset
            embedded = (offset_anon & 0x1) == 1  # Lowest bit = embedded flag

            # Parse field name
            field_name, field_tag = self._parse_name(name_offset)

            field_info = {
                'name': field_name,
                'type_offset': type_offset,
                'offset': offset,
                'embedded': embedded,
                'tag': field_tag,
            }

            return field_info

        except Exception as e:
            print(f"[!] Error parsing structField at {field_addr}: {e}")
            return None

    def _parse_name(self, name_offset) -> tuple:
        """
        Parse Go name structure to extract name and optional tag.

        Go name encoding (Go 1.18+):
        - Byte 0: flags
            bit 0: exported (if set, name is exported)
            bit 1: has tag (if set, tag follows name)
            bit 2: embedded (handled in structField.offsetAnon)
        - Bytes 1-N: name length (varint, typically 1-2 bytes)
        - Following bytes: UTF-8 name string
        - If has tag:
            - Tag length (varint)
            - UTF-8 tag string

        Returns:
            Tuple (name_string, tag_string) or (name, None) if no tag
        """
        if name_offset == 0:
            return ("<anonymous>", None)

        try:
            # Name is at types_base + name_offset
            name_addr = toAddr(self.types_base.getOffset() + name_offset)

            # Read flags byte
            flags = self._read_uint8(name_addr)
            (flags & 0x01) != 0
            has_tag = (flags & 0x02) != 0

            # Read name length (varint - simplified for lengths < 128)
            name_len_addr = name_addr.add(1)
            name_len = self._read_varint(name_len_addr)

            if name_len <= 0 or name_len > 200:  # Sanity check
                return ("<invalid_name>", None)

            # Read name string (skip varint bytes - assume 1 byte for simplicity)
            name_start_addr = name_len_addr.add(1)
            name_str = self._read_utf8_string(name_start_addr, name_len)

            # Read tag if present
            tag_str = None
            if has_tag:
                # Tag starts after name
                tag_len_addr = name_start_addr.add(name_len)
                tag_len = self._read_varint(tag_len_addr)

                if tag_len > 0 and tag_len <= 500:
                    tag_start_addr = tag_len_addr.add(1)
                    tag_str = self._read_utf8_string(tag_start_addr, tag_len)

            return (name_str, tag_str)

        except Exception as e:
            print(f"[!] Error parsing name at offset 0x{name_offset:x}: {e}")
            return ("<error>", None)

    def _read_varint(self, addr) -> int:
        """
        Read a varint (variable-length integer).

        Simplified implementation: assumes length < 128 (single byte).
        Full implementation would handle multi-byte varints.

        Returns:
            Integer value
        """
        first_byte = self._read_uint8(addr)

        # If highest bit is 0, it's a single-byte varint
        if (first_byte & 0x80) == 0:
            return first_byte

        # Multi-byte varint (not implemented in Phase 2 MVP)
        # For now, mask off high bit and treat as approximate
        return first_byte & 0x7F

    def _read_utf8_string(self, addr, length) -> str:
        """
        Read UTF-8 encoded string.

        Args:
            addr: Start address
            length: Number of bytes to read

        Returns:
            Decoded string
        """
        try:
            chars = []
            for i in range(min(int(length), 200)):  # Safety limit
                byte = self._read_uint8(addr.add(i))

                # Simple ASCII check
                if 32 <= byte < 127:
                    chars.append(chr(byte))
                elif byte == 0:
                    break
                else:
                    # Non-ASCII - could be UTF-8 multi-byte
                    # For Phase 2, replace with underscore
                    chars.append('_')

            return ''.join(chars) if chars else "<empty>"

        except Exception as e:
            print(f"[!] Error reading UTF-8 string: {e}")
            return "<error>"

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
def test_struct_field_parser():
    """Test struct field parser with current program."""
    print("="*60)
    print("Testing StructFieldParser")
    print("="*60)

    print("\nTo use StructFieldParser:")
    print("1. Parse rtype to get struct_fields_ptr and count")
    print("2. Create parser: StructFieldParser(program, types_base)")
    print("3. Call: fields = parser.parse_struct_type(rtype_addr, type_info)")
    print("\nExample:")
    print("  parser = StructFieldParser(program, types_base)")
    print("  fields = parser.parse_struct_type(addr, type_info)")
    print("  for field in fields:")
    print("      print(f'{field['name']}: offset={field['offset']}')")


if __name__ == "__main__":
    test_struct_field_parser()
