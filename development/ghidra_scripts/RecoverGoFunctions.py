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

# Go PCLNTAB magic numbers by version
MAGIC_12 = 0xFFFFFFFB  # Go 1.2-1.15
MAGIC_116 = 0xFFFFFFF0  # Go 1.16-1.17
MAGIC_118 = 0xFFFFFFF1  # Go 1.18+


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
                except:
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
                nfunc = (
                    self._read_uint32(addr.add(8))
                    if ptrsize == 4
                    else self._read_uint64(addr.add(8))
                )
                # Reasonable function count: 1 to 100,000
                if nfunc < 1 or nfunc > 100000:
                    return False

            return True
        except:
            return False

    def _read_uint32(self, addr):
        """Read 32-bit unsigned integer"""
        bytes = getBytes(addr, 4)
        return struct.unpack("<I", bytes.tostring())[0]

    def _read_uint64(self, addr):
        """Read 64-bit unsigned integer"""
        bytes = getBytes(addr, 8)
        return struct.unpack("<Q", bytes.tostring())[0]

    def _read_uint8(self, addr):
        """Read 8-bit unsigned integer"""
        return getByte(addr) & 0xFF


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
                    self.functions.append({"address": func_entry, "name": func_name})
            except:
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
                    self.functions.append({"address": func_entry, "name": func_name})
            except:
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
        bytes = getBytes(addr, 4)
        return struct.unpack("<I", bytes.tostring())[0]

    def _read_uint64(self, addr):
        """Read 64-bit unsigned integer"""
        bytes = getBytes(addr, 8)
        return struct.unpack("<Q", bytes.tostring())[0]

    def _read_uint8(self, addr):
        """Read 8-bit unsigned integer"""
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
                if byte >= 32 and byte < 127:  # Printable ASCII
                    chars.append(chr(byte))
                else:
                    break  # Non-ASCII, probably not a string

            return "".join(chars) if chars else None
        except:
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
                addr_value = func_info["address"]
                func_name = func_info["name"]

                # Create address
                addr = toAddr(addr_value)

                # Check if function already exists
                existing_func = self.func_mgr.getFunctionAt(addr)

                if existing_func:
                    # Rename existing function
                    old_name = existing_func.getName()
                    if old_name.startswith("FUN_") or old_name.startswith("SUB_"):
                        existing_func.setName(func_name, SourceType.ANALYSIS)
                        self.renamed += 1
                        print("  [+] Renamed: {} -> {}".format(old_name, func_name))
                else:
                    # Create new function
                    cmd = CreateFunctionCmd(addr)
                    if cmd.applyTo(self.program):
                        new_func = self.func_mgr.getFunctionAt(addr)
                        if new_func:
                            new_func.setName(func_name, SourceType.ANALYSIS)
                            self.created += 1
                            print("  [+] Created: {} at {}".format(func_name, addr))
                    else:
                        self.failed += 1

            except Exception as e:
                self.failed += 1
                print("  [-] Error processing {}: {}".format(func_name, str(e)))

        print("\n[*] Summary:")
        print("    Functions created: {}".format(self.created))
        print("    Functions renamed: {}".format(self.renamed))
        print("    Failed: {}".format(self.failed))


# Main script execution
def main():
    print("=" * 60)
    print("GhidraGo - Go Function Recovery")
    print("=" * 60)

    # Get current program
    program = currentProgram
    if not program:
        print("[!] No program loaded")
        return

    print("\n[*] Analyzing program: {}".format(program.getName()))

    # Detect Go version and locate PCLNTAB
    detector = GoVersionDetector(program)
    if not detector.detect():
        print("[!] Failed to detect Go binary or locate PCLNTAB")
        print("[!] This may not be a Go binary, or it uses an unsupported version")
        return

    print("[+] Detected Go version: {}".format(detector.version))
    print("[+] PCLNTAB located at: {}".format(detector.pclntab_addr))

    # Parse PCLNTAB
    parser = PclntabParser(program, detector.pclntab_addr, detector.version)
    func_count = parser.parse()

    if func_count == 0:
        print("[!] No functions recovered from PCLNTAB")
        return

    print("\n[+] Successfully parsed {} functions".format(func_count))

    # Apply recovered functions to program
    service = FunctionRecoveryService(program)
    service.apply_functions(parser.functions)

    print("\n[*] Function recovery complete!")
    print("=" * 60)


# Run the script
if __name__ == "__main__":
    main()
