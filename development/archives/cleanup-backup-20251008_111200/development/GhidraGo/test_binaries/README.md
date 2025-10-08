# GhidraGo Phase 2 Test Binaries

This directory contains test programs designed to validate GhidraGo v1.1 Phase 2 enhanced type extraction capabilities.

## Test Programs

### 1. test_structs_simple.go
**Purpose**: Test basic struct type extraction
**Features tested**:
- Simple structs with primitive fields (int, int32, bool, float64)
- Structs with string fields
- Structs with pointer fields (*int, *string, *struct)
- Structs with slice fields ([]int, []string, []struct)
- Structs with array fields ([10]int, [5]string)

**Expected results**:
- All struct types appear in Ghidra Data Type Manager
- Fields have correct names and types
- Field offsets are correct
- Pointer/slice/array types are properly represented

---

### 2. test_structs_tags.go
**Purpose**: Test struct tag extraction
**Features tested**:
- JSON tags (`json:"name"`, `json:"field,omitempty"`)
- Multiple tag types (`json:"x" xml:"y" db:"z"`)
- Validation tags (`validate:"required,email"`)
- Tag modifiers (omitempty, attr, -)
- Nested structs with tags

**Expected results**:
- Tags appear in field comments
- Full tag string preserved (e.g., `json:"email,omitempty"`)
- Multiple tags shown together
- Nested struct tags are extracted

---

### 3. test_embedded_fields.go
**Purpose**: Test embedded field detection
**Features tested**:
- Simple embedded fields (anonymous struct fields)
- Multiple embedded fields in same struct
- Embedded pointer fields (*Logger)
- Nested embedded fields (Level3 embeds Level2 embeds Level1)
- Mix of embedded and regular fields

**Expected results**:
- Embedded fields marked with "embedded" comment
- Embedded field names match type names
- Nested embedding properly detected
- Pointer vs value embedding distinguished

---

### 4. test_interfaces.go
**Purpose**: Test interface method extraction
**Features tested**:
- Simple interfaces (Reader with Read method)
- Multi-method interfaces (Writer with Write/Flush/Close)
- Embedded interfaces (ReadWriter embeds Reader and Writer)
- Interfaces with complex parameters (struct, interface{}, slices)
- Concrete implementations of interfaces

**Expected results**:
- Interface types appear in Data Type Manager
- Method names extracted and shown
- Method signatures shown (when possible)
- Embedded interfaces resolved

---

### 5. test_circular_refs.go
**Purpose**: Test circular reference detection
**Features tested**:
- Linked list (Node -> *Node)
- Doubly linked list (DNode -> *DNode, *DNode)
- Binary tree (TreeNode -> *TreeNode, *TreeNode)
- Mutual references (TypeA -> TypeB -> TypeA)
- Circular through slices ([]*Graph)
- Parent-child relationships

**Expected results**:
- No infinite loops during type resolution
- Circular reference placeholders inserted
- All types successfully created despite cycles
- Type dependency graph handles cycles gracefully

---

### 6. test_comprehensive.go
**Purpose**: Combined test of all Phase 2 features
**Features tested**:
- All of the above in complex nested structures
- Real-world patterns (User, Address, ContactInfo)
- Embedded fields with tags
- Circular references in complex structs
- Interfaces with struct parameters
- Maps, slices, arrays in combination
- Multiple levels of nesting

**Expected results**:
- All types extracted successfully
- Complex dependencies resolved correctly
- Tags preserved on embedded fields
- Comprehensive struct definitions in Ghidra

---

## Building Test Binaries

### Windows (with Go installed):
```bash
cd C:\Users\Corbin\development\GhidraGo\test_binaries
build_tests.bat
```

### Manual compilation:
```bash
# Windows AMD64
set GOOS=windows
set GOARCH=amd64
go build -o test_structs_simple.exe test_structs_simple.go

# Linux AMD64
set GOOS=linux
set GOARCH=amd64
go build -o test_structs_simple test_structs_simple.go
```

## Output Structure

```
test_binaries/
├── test_structs_simple.go
├── test_structs_tags.go
├── test_embedded_fields.go
├── test_interfaces.go
├── test_circular_refs.go
├── test_comprehensive.go
├── build_tests.bat
├── README.md
├── windows_amd64/
│   ├── test_structs_simple.exe
│   ├── test_structs_tags.exe
│   ├── test_embedded_fields.exe
│   ├── test_interfaces.exe
│   ├── test_circular_refs.exe
│   └── test_comprehensive.exe
└── linux_amd64/
    ├── test_structs_simple
    ├── test_structs_tags
    ├── test_embedded_fields
    ├── test_interfaces
    ├── test_circular_refs
    └── test_comprehensive
```

## Testing with GhidraGo

### Step 1: Load binary into Ghidra
1. Open Ghidra
2. Create/open project
3. Import test binary (e.g., `test_comprehensive.exe`)
4. Analyze with default settings

### Step 2: Run GhidraGo Phase 2 script
1. Open Script Manager (Window -> Script Manager)
2. Navigate to `RecoverGoFunctionsAndTypes.py`
3. Run script
4. Wait for 6-phase analysis to complete

### Step 3: Verify results

**Check Data Type Manager**:
- Open Data Type Manager (Window -> Data Type Manager)
- Look for recovered Go types (main.User, main.Address, etc.)
- Expand struct types to see fields

**Expected struct output**:
```
main.User
├── int ID                      (offset: 0x00, size: 8)
├── *string Name                (offset: 0x08, size: 8, tag: json:"name")
├── *main.Address Address       (offset: 0x10, size: 8, tag: json:"address")
└── []string Roles              (offset: 0x18, size: 24)
```

**Check field details**:
- Field names match source code
- Field offsets are correct
- Field types are resolved (not generic pointers)
- Tags appear in comments
- Embedded fields marked

**Check interface types**:
- Interfaces represented as structs with tab/data pointers
- Method lists in struct description/comment

**Check decompiler**:
- Functions using structs show field access with names
- Better type propagation through code

## Validation Checklist

For each test binary:

- [ ] Binary loads successfully in Ghidra
- [ ] GhidraGo Phase 2 completes without errors
- [ ] All expected struct types created
- [ ] Struct fields have correct names
- [ ] Struct fields have correct offsets
- [ ] Struct fields have resolved types (not undefined)
- [ ] Tags appear in field comments (test_structs_tags)
- [ ] Embedded fields marked (test_embedded_fields)
- [ ] Interface methods listed (test_interfaces)
- [ ] Circular refs handled without infinite loops (test_circular_refs)
- [ ] Complex nested types resolved (test_comprehensive)

## Known Limitations

1. **Varint names**: Only single-byte varint supported (names < 128 chars)
2. **Function signatures**: Method signatures shown as type names, not full signatures
3. **Map types**: Shown as generic map representation
4. **Channel types**: Shown as generic channel representation

These limitations are documented for future Phase 3+ enhancements.

## Troubleshooting

**Issue**: Script fails at Phase 3 (moduledata not found)
- **Solution**: Ensure binary is actually a Go binary, try different Go version

**Issue**: No types extracted (Phase 5 returns 0 types)
- **Solution**: Check if types section exists, verify Go version compatibility

**Issue**: Struct fields all show as "undefined"
- **Solution**: Ensure Phase 2 parsers initialized, check for errors in Phase 5.5

**Issue**: Circular reference causes infinite loop
- **Solution**: Check TypeResolver circular reference detection logic

**Issue**: Tags not appearing
- **Solution**: Verify StructFieldParser._parse_name() extracts tags correctly

## Performance Benchmarks

Expected performance on test binaries:

| Test Binary | Size | Types | Time |
|-------------|------|-------|------|
| test_structs_simple | ~2MB | ~20 types | ~5-10s |
| test_structs_tags | ~2MB | ~15 types | ~5-10s |
| test_embedded_fields | ~2MB | ~25 types | ~10-15s |
| test_interfaces | ~2MB | ~20 types | ~10-15s |
| test_circular_refs | ~2MB | ~30 types | ~10-15s |
| test_comprehensive | ~3MB | ~50 types | ~15-30s |

Note: Times include function recovery (Phase 1-2) + type extraction (Phase 3-6)

## Next Steps

After validating all test binaries:

1. **Phase 2 validation complete** ✅
2. **Test on real-world Go binaries** (Docker, Kubernetes, etc.)
3. **Begin Phase 3 planning** (function signature recovery)
4. **Performance optimization** (if needed)
5. **User documentation** and examples

## Contact

For issues with test binaries or unexpected results, document:
- Test binary used
- GhidraGo version
- Ghidra version
- Error messages from console
- Screenshots of unexpected output
