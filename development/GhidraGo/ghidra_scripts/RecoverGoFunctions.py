# Recover Go function names from PCLNTAB
# @author Catalytic Computing
# @category Golang
# @keybinding
# @menupath Analysis.Golang.Recover Functions
# @toolbar

"""
GhidraGo - Go Function Recovery Script

This script recovers function names from Go binaries by parsing the PCLNTAB
(Program Counter Line Table) structure. It supports Go versions 1.16 through 1.23.

Based on research from:
- CUJO AI: Reverse Engineering Go Binaries with Ghidra
- Google Cloud: Golang Internals and Symbol Recovery
"""

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
import struct
import sys
import os

# Add ghidrago module to path for exception handling
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)

from ghidrago.exceptions import (
    MemoryAccessError,
    InvalidBinaryError,
    ParseError,
    StructureNotFoundError
)

# Ghidra runtime functions (injected by Ghidra at runtime)
# pylint: disable=undefined-variable
try:
    getBytes  # noqa: F821
    getByte  # noqa: F821
    toAddr  # noqa: F821
    currentProgram  # noqa: F821
except NameError:
    pass  # Only defined when run in Ghidra

# Go PCLNTAB magic numbers by version
MAGIC_12 = 0xfffffffb    # Go 1.2-1.15
MAGIC_116 = 0xfffffff0   # Go 1.16-1.17
MAGIC_118 = 0xfffffff1   # Go 1.18+

class GoVersionDetector:
    """Detect Go version from PCLNTAB magic number"""

    def __init__(self, program):
        self.program = program
        self.version = None
        self.pclntab_addr = None

    def detect(self):
        """Detect Go version and locate PCLNTAB"""
        # Try finding .gopclntab section (ELF binaries)
        memory = self.program.getMemory()

        # Search for .gopclntab section
        for block in memory.getBlocks():
            if block.getName() == ".gopclntab":
                self.pclntab_addr = block.getStart()
                magic = self._read_uint32(self.pclntab_addr)
                self.version = self._identify_version(magic)
                return True

        # If not found, search for magic numbers in memory
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

                    if version:
                        # Verify this is actually PCLNTAB by checking header
                        if self._validate_pclntab_header(addr, version):
                            self.pclntab_addr = addr
                            self.version = version
                            return True
                except (MemoryAccessError, struct.error):
                    # Expected: scanning through memory will hit invalid regions
                    pass
                except Exception as e:
                    # Unexpected error - log but continue scanning
                    print(f"[DEBUG] Unexpected error at {addr}: {e}")
                    pass

                addr = addr.add(4)  # Move forward

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
            # Read ptrsize (should be 4 or 8)
            ptrsize = self._read_uint8(addr.add(7))
            if ptrsize not in [4, 8]:
                return False

            # For Go 1.16+, check nfunc is reasonable
            if version in ["1.16-1.17", "1.18+"]:
                if ptrsize == 4:
                    nfunc = self._read_uint32(addr.add(8))
                else:
                    nfunc = self._read_uint64(addr.add(8))
                # Reasonable function count: 1 to 100,000
                if nfunc < 1 or nfunc > 100000:
                    return False

            return True
        except (MemoryAccessError, struct.error, AttributeError):
            # Invalid PCLNTAB header structure
            return False

    def _read_uint32(self, addr):
        """Read 32-bit unsigned integer"""
        try:
            byte_data = getBytes(addr, 4)  # noqa: F821
            return struct.unpack("<I", byte_data.tostring())[0]
        except (AttributeError, TypeError) as e:
            raise MemoryAccessError(
                addr, f"Failed to read 4 bytes: {e}"
            )
        except struct.error as e:
            raise MemoryAccessError(
                addr, f"Invalid data for uint32: {e}"
            )

    def _read_uint64(self, addr):
        """Read 64-bit unsigned integer"""
        try:
            byte_data = getBytes(addr, 8)  # noqa: F821
            return struct.unpack("<Q", byte_data.tostring())[0]
        except (AttributeError, TypeError) as e:
            raise MemoryAccessError(
                addr, f"Failed to read 8 bytes: {e}"
            )
        except struct.error as e:
            raise MemoryAccessError(
                addr, f"Invalid data for uint64: {e}"
            )

    def _read_uint8(self, addr):
        """Read 8-bit unsigned integer"""
        try:
            return getByte(addr) & 0xFF  # noqa: F821
        except (AttributeError, TypeError) as e:
            raise MemoryAccessError(
                addr, f"Failed to read byte: {e}"
            )  # noqa: F821


class PclntabParser:
    """Parse PCLNTAB structure to recover function names"""

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

    def _parse_go12(self):
        """Parse Go 1.2-1.15 PCLNTAB format"""
        # Header: magic(4) + pad1(1) + pad2(1) + minLC(1) + ptrsize(1)
        ptrsize = self._read_uint8(self.pclntab_addr.add(7))

        # Function table starts after 8-byte header
        ftab_addr = self.pclntab_addr.add(8)

        # Read function count (first entry in ftab)
        nfunc = self._read_uintptr(ftab_addr, ptrsize)

        print("[*] Found {} functions (estimated)".format(nfunc))

        # Parse function table entries
        entry_size = ptrsize * 2  # Each entry: [entry_offset, func_offset]

        for i in range(min(int(nfunc), 10000)):  # Limit to prevent hang
            entry_addr = ftab_addr.add(i * entry_size)

            try:
                # Read function entry offset
                func_offset = self._read_uintptr(entry_addr.add(ptrsize), ptrsize)

                if func_offset == 0:
                    continue

                # Function info is at pclntab_addr + func_offset
                func_info_addr = self.pclntab_addr.add(func_offset)

                # Read function entry point and name offset
                func_entry = self._read_uintptr(func_info_addr, ptrsize)
                name_offset = self._read_uintptr(func_info_addr.add(ptrsize), ptrsize)

                # Read function name
                name_addr = self.pclntab_addr.add(name_offset)
                func_name = self._read_string(name_addr)

                if func_name and func_entry > 0:
                    self.functions.append({
                        'address': func_entry,
                        'name': func_name
                    })
            except (MemoryAccessError, struct.error) as e:
                # Expected: some entries may be corrupted or invalid
                print(f"[DEBUG] Skipping entry: {e}")
                continue
            except Exception as e:
                # Unexpected error - log and continue
                print(f"[WARN] Unexpected error: {e}")
                continue

        return len(self.functions)

    def _parse_go116(self):
        """Parse Go 1.16+ PCLNTAB format"""
        addr = self.pclntab_addr

        # Read header
        self._read_uint32(addr)
        ptrsize = self._read_uint8(addr.add(7))
        nfunc = self._read_uintptr(addr.add(8), ptrsize)

        print("[*] Found {} functions".format(nfunc))

        # Read offset table pointers
        offset = 8 + ptrsize
        funcnameOffset = self._read_uintptr(addr.add(offset), ptrsize)
        offset += ptrsize
        self._read_uintptr(addr.add(offset), ptrsize)
        offset += ptrsize
        self._read_uintptr(addr.add(offset), ptrsize)
        offset += ptrsize
        self._read_uintptr(addr.add(offset), ptrsize)
        offset += ptrsize
        self._read_uintptr(addr.add(offset), ptrsize)

        # Function table starts after header + offset table
        ftab_offset = offset + ptrsize
        ftab_addr = addr.add(ftab_offset)

        # Each function table entry: [entry, funcoff]
        entry_size = ptrsize * 2

        for i in range(min(int(nfunc), 10000)):
            entry_addr = ftab_addr.add(i * entry_size)

            try:
                # Read function entry point
                func_entry = self._read_uintptr(entry_addr, ptrsize)
                func_info_offset = self._read_uintptr(entry_addr.add(ptrsize), ptrsize)

                if func_entry == 0 or func_info_offset == 0:
                    continue

                # Read function info structure
                func_info_addr = addr.add(func_info_offset)

                # Function info format (simplified):
                # entry(ptrsize) + name_offset(4) + ...
                name_offset = self._read_uint32(func_info_addr.add(ptrsize))

                # Name is at pclntab + funcnameOffset + name_offset
                name_addr = addr.add(funcnameOffset + name_offset)
                func_name = self._read_string(name_addr)

                if func_name and func_entry > 0:
                    self.functions.append({
                        'address': func_entry,
                        'name': func_name
                    })
            except (MemoryAccessError, struct.error) as e:
                # Expected: some entries may be corrupted or invalid
                print(f"[DEBUG] Skipping entry: {e}")
                continue
            except Exception as e:
                # Unexpected error - log and continue
                print(f"[WARN] Unexpected error: {e}")
                continue

        return len(self.functions)

    def _read_uintptr(self, addr, ptrsize):
        """Read pointer-sized unsigned integer"""
        if ptrsize == 4:
            return self._read_uint32(addr)
        else:
            return self._read_uint64(addr)

    def _read_uint32(self, addr):
        """Read 32-bit unsigned integer"""
        try:
            byte_data = getBytes(addr, 4)  # noqa: F821
            return struct.unpack("<I", byte_data.tostring())[0]
        except (AttributeError, TypeError) as e:
            raise MemoryAccessError(
                addr, f"Failed to read 4 bytes: {e}"
            )
        except struct.error as e:
            raise MemoryAccessError(
                addr, f"Invalid data for uint32: {e}"
            )

    def _read_uint64(self, addr):
        """Read 64-bit unsigned integer"""
        try:
            byte_data = getBytes(addr, 8)  # noqa: F821
            return struct.unpack("<Q", byte_data.tostring())[0]
        except (AttributeError, TypeError) as e:
            raise MemoryAccessError(
                addr, f"Failed to read 8 bytes: {e}"
            )
        except struct.error as e:
            raise MemoryAccessError(
                addr, f"Invalid data for uint64: {e}"
            )

    def _read_uint8(self, addr):
        """Read 8-bit unsigned integer"""
        try:
            return getByte(addr) & 0xFF  # noqa: F821
        except (AttributeError, TypeError) as e:
            raise MemoryAccessError(
                addr, f"Failed to read byte: {e}"
            )

    def _read_string(self, addr):
        """Read null-terminated string"""
        try:
            chars = []
            max_len = 256

            for i in range(max_len):
                byte = getByte(addr.add(i)) & 0xFF  # noqa: F821
                if byte == 0:
                    break
                if byte >= 32 and byte < 127:  # Printable ASCII
                    chars.append(chr(byte))
                else:
                    break  # Non-ASCII, probably not a string

            return ''.join(chars) if chars else None
        except (AttributeError, TypeError) as e:
            # Failed to read - likely invalid address
            raise MemoryAccessError(
                addr, f"Failed to read string: {e}"
            )
        except Exception as e:
            # Unexpected error during string read
            print(f"[WARN] Unexpected error reading string at {addr}: {e}")
            return None


class FunctionRecoveryService:
    """Apply recovered function names to the program"""

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

                # Create address
                addr = toAddr(addr_value)  # noqa: F821

                # Check if function already exists
                existing_func = self.func_mgr.getFunctionAt(addr)

                if existing_func:
                    # Rename existing function
                    old_name = existing_func.getName()
                    is_default_name = (
                        old_name.startswith("FUN_") or
                        old_name.startswith("SUB_")
                    )
                    if is_default_name:
                        existing_func.setName(func_name, SourceType.ANALYSIS)
                        self.renamed += 1
                        rename_msg = "  [+] Renamed: {} -> {}".format(
                            old_name, func_name
                        )
                        print(rename_msg)
                else:
                    # Create new function
                    cmd = CreateFunctionCmd(addr)
                    if cmd.applyTo(self.program):
                        new_func = self.func_mgr.getFunctionAt(addr)
                        if new_func:
                            new_func.setName(func_name, SourceType.ANALYSIS)
                            self.created += 1
                            create_msg = "  [+] Created: {} at {}".format(
                                func_name, addr
                            )
                            print(create_msg)
                    else:
                        self.failed += 1

            except Exception as e:
                self.failed += 1
                err_msg = "  [-] Error processing {}: {}".format(
                    func_name, str(e)
                )
                print(err_msg)

        print("\n[*] Summary:")
        print("    Functions created: {}".format(self.created))
        print("    Functions renamed: {}".format(self.renamed))
        print("    Failed: {}".format(self.failed))


# Main script execution
def main():
    print("="*60)
    print("GhidraGo - Go Function Recovery")
    print("="*60)

    try:
        # Get current program
        program = currentProgram  # noqa: F821
        if not program:
            print("[!] No program loaded")
            return

        print("\n[*] Analyzing program: {}".format(program.getName()))

        # Detect Go version and locate PCLNTAB
        detector = GoVersionDetector(program)
        if not detector.detect():
            raise StructureNotFoundError("PCLNTAB")

        print("[+] Detected Go version: {}".format(detector.version))
        print("[+] PCLNTAB located at: {}".format(detector.pclntab_addr))

        # Parse PCLNTAB
        parser = PclntabParser(
            program, detector.pclntab_addr, detector.version
        )
        func_count = parser.parse()

        if func_count == 0:
            print("[!] No functions recovered from PCLNTAB")
            print("[!] Binary may be stripped or corrupted")
            return

        print("\n[+] Successfully parsed {} functions".format(func_count))

        # Apply recovered functions to program
        service = FunctionRecoveryService(program)
        service.apply_functions(parser.functions)

        print("\n[*] Function recovery complete!")
        print("="*60)

    except StructureNotFoundError as e:
        print(f"\n[!] Error: {e}")
        print("[!] This may not be a Go binary, or uses unsupported version")
        print("="*60)
        return

    except (MemoryAccessError, InvalidBinaryError, ParseError) as e:
        print(f"\n[!] Binary analysis error: {e}")
        print("[!] The binary may be corrupted or use custom packing")
        print("="*60)
        return

    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user")
        print("="*60)
        raise  # Re-raise to allow Ghidra to handle cleanup

    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        print("[!] Please report this issue with binary details")
        print("="*60)
        import traceback
        traceback.print_exc()
        raise


# Run the script
if __name__ == "__main__":
    main()
