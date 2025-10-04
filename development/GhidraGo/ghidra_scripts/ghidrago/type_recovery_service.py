# TypeRecoveryService - Apply recovered types to Ghidra program
# @author Catalytic Computing
# @category Golang.TypeExtraction

"""
TypeRecoveryService applies recovered Go types to the Ghidra program.

This service creates Ghidra DataType objects from parsed rtype information
and applies them to variables, function parameters, and struct fields.
"""

from ghidra.program.model.data import *


class TypeRecoveryService:
    """
    Apply recovered Go types to Ghidra's DataTypeManager.

    Creates Structures, Typedefs, and other DataType objects that represent
    Go types (structs, interfaces, slices, etc.) and makes them available
    in the decompiler.
    """

    def __init__(self, program):
        """
        Initialize type recovery service.

        Args:
            program: Ghidra Program object
        """
        self.program = program
        self.dtm = program.getDataTypeManager()
        self.transaction_id = None
        self.types_created = 0
        self.types_failed = 0

        # Cache of created types to avoid duplicates
        self.type_cache = {}

    def begin_transaction(self):
        """Start a transaction for modifying program data types."""
        self.transaction_id = self.program.startTransaction("GhidraGo Type Recovery")

    def apply_types_with_resolution(self, type_list, type_resolver, struct_field_parser, interface_method_parser):
        """
        Apply multiple types with full Phase 2 field/method resolution.

        This method uses TypeResolver to resolve all type references and applies
        types in dependency order to ensure referenced types exist.

        Args:
            type_list: List of type_info dicts from RtypeParser
            type_resolver: TypeResolver instance for resolving type references
            struct_field_parser: StructFieldParser instance
            interface_method_parser: InterfaceMethodParser instance

        Returns:
            Statistics dictionary with types_created, types_failed counts
        """
        print("\n[*] Phase 2: Applying types with detailed field/method resolution...")

        # Build dependency graph and get resolution order
        dep_graph = type_resolver.build_dependency_graph(type_list)
        resolution_order = type_resolver.get_resolution_order(type_list)

        print(f"[*] Dependency graph built: {len(dep_graph)} types")
        print(f"[*] Resolution order determined: {len(resolution_order)} types")

        # Create type_info lookup by name
        type_by_name = {t.get('name'): t for t in type_list if t.get('name')}

        # Apply types in dependency order
        for type_name in resolution_order:
            type_info = type_by_name.get(type_name)
            if not type_info:
                continue

            kind = type_info.get('kind_name')

            # Resolve fields/methods based on type kind
            if kind == 'struct':
                # Resolve struct fields with type information
                resolved_fields = type_resolver.resolve_struct_fields(
                    type_info, struct_field_parser
                )
                self.apply_type(type_info, resolved_fields=resolved_fields)

            elif kind == 'interface':
                # Resolve interface methods with type information
                resolved_methods = type_resolver.resolve_interface_methods(
                    type_info, interface_method_parser
                )
                self.apply_type(type_info, resolved_methods=resolved_methods)

            else:
                # Other types don't need field/method resolution
                self.apply_type(type_info)

        # Get resolution statistics
        resolver_stats = type_resolver.get_resolution_statistics()

        print("\n[+] Type resolution complete!")
        print(f"    Types cached: {resolver_stats.get('types_cached', 0)}")
        print(f"    Types created in Ghidra: {self.types_created}")
        print(f"    Types failed: {self.types_failed}")

        return self.get_statistics()

    def end_transaction(self, commit=True):
        """End the transaction."""
        if self.transaction_id is not None:
            self.program.endTransaction(self.transaction_id, commit)
            self.transaction_id = None

    def apply_type(self, type_info, resolved_fields=None, resolved_methods=None) -> bool:
        """
        Apply a single type to the Ghidra program.

        Args:
            type_info: Dictionary from RtypeParser.parse_rtype()
            resolved_fields: Optional list of resolved field dicts (for structs) from TypeResolver
            resolved_methods: Optional list of resolved method dicts (for interfaces) from TypeResolver

        Returns:
            True if successful, False otherwise
        """
        try:
            kind = type_info['kind_name']
            name = type_info['name']

            # Skip anonymous or invalid types
            if not name or name.startswith('<'):
                return False

            # Check cache
            if name in self.type_cache:
                return True  # Already created

            # Dispatch to kind-specific handler
            if kind == 'struct':
                return self._create_struct_type(type_info, resolved_fields)
            elif kind == 'interface':
                return self._create_interface_type(type_info, resolved_methods)
            elif kind == 'slice':
                return self._create_slice_type(type_info)
            elif kind == 'array':
                return self._create_array_type(type_info)
            elif kind == 'ptr':
                return self._create_pointer_type(type_info)
            else:
                # Primitive types (int, string, etc.) - create typedef
                return self._create_primitive_typedef(type_info)

        except Exception as e:
            print(f"[!] Error applying type '{type_info.get('name', '<unknown>')}': {e}")
            self.types_failed += 1
            return False

    def _create_struct_type(self, type_info, resolved_fields=None) -> bool:
        """
        Create a Ghidra Structure from Go struct type.

        Args:
            type_info: Dictionary with struct information
            resolved_fields: Optional list of resolved field dictionaries from TypeResolver

        Returns:
            True if successful
        """
        name = type_info['name']
        size = type_info['size']

        # Create structure
        struct = StructureDataType(name, 0)

        # Set size (even if we don't have all fields yet)
        # This ensures the struct has the correct total size
        struct.setPackingEnabled(True)

        # Add fields if we have detailed field information (Phase 2)
        if resolved_fields and len(resolved_fields) > 0:
            print(f"  [+] Creating struct: {name} with {len(resolved_fields)} fields")

            # Sort fields by offset
            sorted_fields = sorted(resolved_fields, key=lambda f: f.get('offset', 0))

            for field in sorted_fields:
                field_name = field.get('name', 'field')
                field_offset = int(field.get('offset', 0))
                field.get('type_name', '<unknown>')
                field_tag = field.get('tag', None)
                embedded = field.get('embedded', False)

                # Get Ghidra DataType for field
                field_dt = self._get_field_datatype(field)

                if field_dt:
                    # Build field comment
                    comment_parts = []
                    if field_tag:
                        comment_parts.append(f"tag: {field_tag}")
                    if embedded:
                        comment_parts.append("embedded")
                    comment = ", ".join(comment_parts) if comment_parts else None

                    try:
                        # Add field at specific offset
                        struct.replaceAtOffset(field_offset, field_dt, field_dt.getLength(),
                                              field_name, comment)
                    except Exception:
                        # If offset placement fails, add field normally
                        struct.add(field_dt, field_name, comment)

            # Ensure struct has correct total size
            if struct.getLength() < size:
                # Pad to correct size
                padding_size = int(size) - struct.getLength()
                if padding_size > 0:
                    struct.add(Undefined.getUndefinedDataType(padding_size),
                              padding_size, "_padding", None)

        else:
            # No field information - create as undefined (Phase 1 behavior)
            if size > 0:
                struct.add(Undefined.getUndefinedDataType(int(size)), int(size), "data", None)

        # Add to program
        result = self.dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)

        self.type_cache[name] = result
        self.types_created += 1

        if resolved_fields:
            print(f"  [+] Created struct: {name} ({size} bytes, {len(resolved_fields)} fields)")
        else:
            print(f"  [+] Created struct: {name} ({size} bytes)")
        return True

    def _create_interface_type(self, type_info, resolved_methods=None) -> bool:
        """
        Create a Ghidra representation of a Go interface.

        Go interfaces are represented as structs containing method pointers.

        Args:
            type_info: Dictionary with interface information
            resolved_methods: Optional list of resolved method dictionaries from TypeResolver
        """
        name = type_info['name']
        type_info['size']

        # Interfaces in Go are represented as:
        # struct {
        #     tab  *itab      // Interface table (8 bytes)
        #     data unsafe.Pointer  // Data pointer (8 bytes)
        # }

        struct = StructureDataType(name, 0)
        struct.add(PointerDataType.dataType, 8, "tab", "Interface table pointer")
        struct.add(PointerDataType.dataType, 8, "data", "Data pointer")

        # Add method information as comments (Phase 2)
        if resolved_methods and len(resolved_methods) > 0:
            method_list = []
            for method in resolved_methods:
                method_name = method.get('name', '<unknown>')
                signature = method.get('signature', '<unknown>')
                method_list.append(f"{method_name}: {signature}")

            # Set struct comment with method list
            method_comment = "Methods:\\n" + "\\n".join(method_list)
            struct.setDescription(method_comment)

            print(f"  [+] Created interface: {name} with {len(resolved_methods)} methods")
        else:
            print(f"  [+] Created interface: {name}")

        result = self.dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)

        self.type_cache[name] = result
        self.types_created += 1

        return True

    def _create_slice_type(self, type_info) -> bool:
        """
        Create a Ghidra representation of a Go slice.

        Go slices are represented as:
        struct {
            array unsafe.Pointer  // Pointer to array (8 bytes)
            len   int             // Length (8 bytes)
            cap   int             // Capacity (8 bytes)
        }
        """
        name = type_info['name']

        struct = StructureDataType(name, 0)
        struct.add(PointerDataType.dataType, 8, "array", "Pointer to underlying array")
        struct.add(LongLongDataType.dataType, 8, "len", "Slice length")
        struct.add(LongLongDataType.dataType, 8, "cap", "Slice capacity")

        result = self.dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER)

        self.type_cache[name] = result
        self.types_created += 1

        print(f"  [+] Created slice: {name}")
        return True

    def _create_array_type(self, type_info) -> bool:
        """
        Create a Ghidra array type from Go array.

        Args:
            type_info: Dictionary with array information

        Returns:
            True if successful
        """
        name = type_info['name']
        size = type_info['size']

        # For now, create as a typedef to an array of bytes
        # Full element type resolution is TODO for Phase 2
        array_length = type_info.get('array_length', size)

        if array_length > 0:
            array_dt = ArrayDataType(ByteDataType.dataType, int(array_length), 1)
            typedef = TypedefDataType(name, array_dt)

            result = self.dtm.addDataType(typedef, DataTypeConflictHandler.DEFAULT_HANDLER)

            self.type_cache[name] = result
            self.types_created += 1

            print(f"  [+] Created array: {name} [{array_length}]")
            return True

        return False

    def _create_pointer_type(self, type_info) -> bool:
        """
        Create a Ghidra pointer type from Go pointer.

        Args:
            type_info: Dictionary with pointer information

        Returns:
            True if successful
        """
        name = type_info['name']

        # Create as typedef to generic pointer
        # Full element type resolution is TODO for Phase 2
        typedef = TypedefDataType(name, PointerDataType.dataType)

        result = self.dtm.addDataType(typedef, DataTypeConflictHandler.DEFAULT_HANDLER)

        self.type_cache[name] = result
        self.types_created += 1

        print(f"  [+] Created pointer: {name}")
        return True

    def _create_primitive_typedef(self, type_info) -> bool:
        """
        Create typedef for Go primitive types.

        Args:
            type_info: Dictionary with type information

        Returns:
            True if successful
        """
        name = type_info['name']
        kind = type_info['kind_name']
        size = type_info['size']

        # Map Go kinds to Ghidra primitives
        ghidra_type = self._get_ghidra_primitive(kind, size)

        if ghidra_type:
            typedef = TypedefDataType(name, ghidra_type)
            result = self.dtm.addDataType(typedef, DataTypeConflictHandler.DEFAULT_HANDLER)

            self.type_cache[name] = result
            self.types_created += 1

            print(f"  [+] Created primitive: {name} ({kind})")
            return True

        return False

    def _get_ghidra_primitive(self, kind, size):
        """
        Map Go primitive kind to Ghidra DataType.

        Args:
            kind: Go kind string (from KIND_NAMES)
            size: Size in bytes

        Returns:
            Ghidra DataType or None
        """
        mapping = {
            'bool': BooleanDataType.dataType,
            'int': SignedIntegerDataType.dataType if size == 4 else LongLongDataType.dataType,
            'int8': CharDataType.dataType,
            'int16': ShortDataType.dataType,
            'int32': IntegerDataType.dataType,
            'int64': LongLongDataType.dataType,
            'uint': UnsignedIntegerDataType.dataType if size == 4 else UnsignedLongLongDataType.dataType,
            'uint8': UnsignedCharDataType.dataType,
            'uint16': UnsignedShortDataType.dataType,
            'uint32': UnsignedIntegerDataType.dataType,
            'uint64': UnsignedLongLongDataType.dataType,
            'float32': FloatDataType.dataType,
            'float64': DoubleDataType.dataType,
            'string': PointerDataType.dataType,  # Simplified - Go strings are actually structs
            'uintptr': PointerDataType.dataType,
        }

        return mapping.get(kind)

    def _get_field_datatype(self, field) -> Optional:
        """
        Get appropriate Ghidra DataType for a struct field.

        Args:
            field: Field dictionary with type_info

        Returns:
            Ghidra DataType or None
        """
        # Check if we have resolved type information
        type_info = field.get('type_info')

        if type_info:
            type_kind = type_info.get('kind_name', '')
            type_name = type_info.get('name', '')
            type_size = type_info.get('size', 0)

            # Check if type already exists in cache
            if type_name in self.type_cache:
                return self.type_cache[type_name]

            # Try to get primitive type
            primitive = self._get_ghidra_primitive(type_kind, type_size)
            if primitive:
                return primitive

            # For complex types, return pointer or undefined
            if type_kind in ['struct', 'interface', 'slice']:
                return PointerDataType.dataType
            elif type_kind == 'array':
                # Create small array or use pointer
                type_info.get('array_elem_size', 1)
                array_len = type_info.get('array_length', 0)
                if array_len > 0 and array_len < 1000:
                    return ArrayDataType(ByteDataType.dataType, int(array_len), 1)
                return PointerDataType.dataType
            elif type_kind == 'ptr':
                return PointerDataType.dataType

        # Fallback: use field offset to determine size
        # This is imperfect but better than nothing
        return LongLongDataType.dataType  # 8 bytes (common for pointers/ints)

    def get_statistics(self) -> dict:
        """
        Get statistics about type recovery.

        Returns:
            Dictionary with types_created and types_failed counts
        """
        return {
            'types_created': self.types_created,
            'types_failed': self.types_failed,
            'total_processed': self.types_created + self.types_failed,
        }


# Helper function for testing
def test_type_recovery_service():
    """Test type recovery service with current program."""
    print("="*60)
    print("Testing TypeRecoveryService")
    print("="*60)

    print("\nTo use TypeRecoveryService:")
    print("1. Create service: service = TypeRecoveryService(program)")
    print("2. Start transaction: service.begin_transaction()")
    print("3. Apply types: service.apply_type(type_info)")
    print("4. End transaction: service.end_transaction()")
    print("\nExample:")
    print("  service = TypeRecoveryService(program)")
    print("  service.begin_transaction()")
    print("  for type_info in recovered_types:")
    print("      service.apply_type(type_info)")
    print("  service.end_transaction()")
    print("  stats = service.get_statistics()")
    print("  print(f'Created {stats['types_created']} types')")


if __name__ == "__main__":
    test_type_recovery_service()
