#!/usr/bin/env python3
"""
x86/x86-64 ROP Gadget Byte Scanner

Fast standalone ROP gadget scanner that works by scanning for
RET instructions and disassembling backwards.

Does NOT require Ghidra - uses capstone for disassembly.

Usage:
    python x86_rop_scanner.py <binary_path> [--arch x86|x64] [--depth 10]

Requirements:
    pip install capstone

Author: Claude Code / Corbin
"""

import argparse
import json
import os
import struct
import sys
from collections import defaultdict
from datetime import datetime

try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    print("[!] capstone not installed. Install with: pip install capstone")


class X86RopScanner:
    """Fast x86/x64 ROP gadget scanner using byte-level analysis."""

    # x86 RET opcodes
    RET_OPCODES = {
        b'\xc3': 'ret',           # ret
        b'\xc2': 'ret imm16',     # ret imm16 (2 bytes follow)
        b'\xcb': 'retf',          # far ret
        b'\xca': 'retf imm16',    # far ret imm16
    }

    # Syscall/interrupt opcodes
    SYSCALL_OPCODES = {
        b'\x0f\x05': 'syscall',       # syscall (x64)
        b'\x0f\x34': 'sysenter',      # sysenter
        b'\xcd\x80': 'int 0x80',      # int 0x80 (x86 Linux)
    }

    def __init__(self, binary_path, arch='x64'):
        self.binary_path = binary_path
        self.arch = arch
        self.gadgets = []
        self.statistics = defaultdict(int)

        # Load binary
        with open(binary_path, 'rb') as f:
            self.data = f.read()

        # Detect if PE or ELF
        self.is_pe = self.data[:2] == b'MZ'
        self.is_elf = self.data[:4] == b'\x7fELF'

        # Parse headers for code sections
        self.code_sections = self._find_code_sections()

        # Initialize capstone
        if CAPSTONE_AVAILABLE:
            if arch == 'x64':
                self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.cs.detail = True

    def _find_code_sections(self):
        """Find executable code sections in the binary."""
        sections = []

        if self.is_elf:
            sections = self._parse_elf_sections()
        elif self.is_pe:
            sections = self._parse_pe_sections()
        else:
            # Raw binary - treat entire file as code
            sections = [(0, len(self.data), 0)]

        return sections

    def _parse_elf_sections(self):
        """Parse ELF headers to find executable sections."""
        sections = []

        # ELF header
        bits = self.data[4]  # 1 = 32-bit, 2 = 64-bit

        if bits == 2:  # 64-bit
            e_phoff = struct.unpack('<Q', self.data[32:40])[0]
            e_phentsize = struct.unpack('<H', self.data[54:56])[0]
            e_phnum = struct.unpack('<H', self.data[56:58])[0]

            for i in range(e_phnum):
                ph_offset = e_phoff + (i * e_phentsize)
                p_type = struct.unpack('<I', self.data[ph_offset:ph_offset+4])[0]
                p_flags = struct.unpack('<I', self.data[ph_offset+4:ph_offset+8])[0]
                p_offset = struct.unpack('<Q', self.data[ph_offset+8:ph_offset+16])[0]
                p_vaddr = struct.unpack('<Q', self.data[ph_offset+16:ph_offset+24])[0]
                p_filesz = struct.unpack('<Q', self.data[ph_offset+32:ph_offset+40])[0]

                # PT_LOAD = 1, PF_X = 1 (executable)
                if p_type == 1 and (p_flags & 1):
                    sections.append((p_offset, p_filesz, p_vaddr))

        else:  # 32-bit
            e_phoff = struct.unpack('<I', self.data[28:32])[0]
            e_phentsize = struct.unpack('<H', self.data[42:44])[0]
            e_phnum = struct.unpack('<H', self.data[44:46])[0]

            for i in range(e_phnum):
                ph_offset = e_phoff + (i * e_phentsize)
                p_type = struct.unpack('<I', self.data[ph_offset:ph_offset+4])[0]
                p_offset = struct.unpack('<I', self.data[ph_offset+4:ph_offset+8])[0]
                p_vaddr = struct.unpack('<I', self.data[ph_offset+8:ph_offset+12])[0]
                p_filesz = struct.unpack('<I', self.data[ph_offset+16:ph_offset+20])[0]
                p_flags = struct.unpack('<I', self.data[ph_offset+24:ph_offset+28])[0]

                if p_type == 1 and (p_flags & 1):
                    sections.append((p_offset, p_filesz, p_vaddr))

        return sections if sections else [(0, len(self.data), 0)]

    def _parse_pe_sections(self):
        """Parse PE headers to find executable sections."""
        sections = []

        try:
            pe_offset = struct.unpack('<I', self.data[0x3c:0x40])[0]

            # Number of sections
            num_sections = struct.unpack('<H', self.data[pe_offset+6:pe_offset+8])[0]

            # Optional header size
            opt_header_size = struct.unpack('<H', self.data[pe_offset+20:pe_offset+22])[0]

            # Section headers start after optional header
            section_offset = pe_offset + 24 + opt_header_size

            # Image base
            magic = struct.unpack('<H', self.data[pe_offset+24:pe_offset+26])[0]
            if magic == 0x20b:  # PE32+
                image_base = struct.unpack('<Q', self.data[pe_offset+24+24:pe_offset+24+32])[0]
            else:  # PE32
                image_base = struct.unpack('<I', self.data[pe_offset+24+28:pe_offset+24+32])[0]

            for i in range(num_sections):
                sec_off = section_offset + (i * 40)
                characteristics = struct.unpack('<I', self.data[sec_off+36:sec_off+40])[0]
                virtual_addr = struct.unpack('<I', self.data[sec_off+12:sec_off+16])[0]
                raw_size = struct.unpack('<I', self.data[sec_off+16:sec_off+20])[0]
                raw_offset = struct.unpack('<I', self.data[sec_off+20:sec_off+24])[0]

                # IMAGE_SCN_MEM_EXECUTE = 0x20000000
                if characteristics & 0x20000000:
                    sections.append((raw_offset, raw_size, image_base + virtual_addr))

        except Exception as e:
            print(f"[!] PE parsing error: {e}")

        return sections if sections else [(0, len(self.data), 0)]

    def find_gadgets(self, max_depth=10, max_gadgets=10000):
        """Find ROP gadgets by scanning for RET and working backwards."""
        if not CAPSTONE_AVAILABLE:
            print("[!] Capstone required for disassembly")
            return []

        print(f"[*] Scanning for ROP gadgets (depth={max_depth})...")
        print(f"[*] Found {len(self.code_sections)} code section(s)")

        gadget_set = set()  # For deduplication

        for section_offset, section_size, vaddr in self.code_sections:
            section_data = self.data[section_offset:section_offset + section_size]
            print(f"[*] Scanning section at offset 0x{section_offset:x}, size 0x{section_size:x}")

            # Find all RET instructions
            for opcode, name in self.RET_OPCODES.items():
                pos = 0
                while True:
                    idx = section_data.find(opcode, pos)
                    if idx == -1:
                        break

                    ret_addr = vaddr + idx

                    # Scan backwards from RET
                    for depth in range(1, max_depth + 1):
                        start_idx = idx - depth
                        if start_idx < 0:
                            break

                        gadget_bytes = section_data[start_idx:idx + len(opcode)]
                        gadget_addr = vaddr + start_idx

                        # Disassemble
                        gadget = self._disassemble_gadget(gadget_bytes, gadget_addr)
                        if gadget and gadget not in gadget_set:
                            gadget_set.add(gadget)
                            self.gadgets.append({
                                'address': gadget_addr,
                                'instructions': gadget,
                                'bytes': gadget_bytes.hex(),
                                'type': self._classify_gadget(gadget)
                            })

                            if len(self.gadgets) >= max_gadgets:
                                print(f"[*] Reached max gadget limit ({max_gadgets})")
                                return self.gadgets

                    pos = idx + 1

            # Also scan for syscall gadgets
            for opcode, name in self.SYSCALL_OPCODES.items():
                pos = 0
                while True:
                    idx = section_data.find(opcode, pos)
                    if idx == -1:
                        break

                    syscall_addr = vaddr + idx

                    for depth in range(0, max_depth + 1):
                        start_idx = idx - depth
                        if start_idx < 0:
                            break

                        gadget_bytes = section_data[start_idx:idx + len(opcode)]
                        gadget_addr = vaddr + start_idx

                        gadget = self._disassemble_gadget(gadget_bytes, gadget_addr)
                        if gadget and gadget not in gadget_set:
                            gadget_set.add(gadget)
                            self.gadgets.append({
                                'address': gadget_addr,
                                'instructions': gadget,
                                'bytes': gadget_bytes.hex(),
                                'type': 'syscall'
                            })
                            self.statistics['syscall'] += 1

                    pos = idx + 1

        print(f"[+] Found {len(self.gadgets)} unique gadgets")
        return self.gadgets

    def _disassemble_gadget(self, gadget_bytes, address):
        """Disassemble bytes and validate as a proper gadget."""
        try:
            instructions = list(self.cs.disasm(gadget_bytes, address))

            if not instructions:
                return None

            # Check if disassembly covers the entire buffer
            total_size = sum(i.size for i in instructions)
            if total_size != len(gadget_bytes):
                return None

            # Check for bad instructions
            for insn in instructions:
                mnem = insn.mnemonic.lower()
                # Skip gadgets with certain instructions
                if mnem in ['call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb',
                           'jl', 'jg', 'jle', 'jge', 'jo', 'js', 'loop']:
                    # Allow call at end for call-preceded gadgets
                    if mnem == 'call' and insn != instructions[-1]:
                        return None
                    if mnem == 'jmp' and insn != instructions[-1]:
                        return None
                    if mnem not in ['call', 'jmp'] and mnem.startswith('j'):
                        return None

            # Format as string
            gadget_str = ' ; '.join(f"{i.mnemonic} {i.op_str}".strip()
                                    for i in instructions)
            return gadget_str

        except Exception:
            return None

    def _classify_gadget(self, gadget_str):
        """Classify gadget by type."""
        gadget_lower = gadget_str.lower()

        if 'syscall' in gadget_lower or 'int 0x80' in gadget_lower or 'sysenter' in gadget_lower:
            self.statistics['syscall'] += 1
            return 'syscall'
        elif any(x in gadget_lower for x in ['mov esp', 'mov rsp', 'xchg esp', 'xchg rsp', 'leave']):
            self.statistics['stack_pivot'] += 1
            return 'stack_pivot'
        elif 'pop' in gadget_lower:
            self.statistics['register_pop'] += 1
            return 'register_pop'
        elif 'mov' in gadget_lower:
            self.statistics['register_move'] += 1
            return 'register_move'
        elif any(x in gadget_lower for x in ['add', 'sub', 'xor', 'or', 'and', 'inc', 'dec']):
            self.statistics['arithmetic'] += 1
            return 'arithmetic'
        elif any(x in gadget_lower for x in ['mov [', 'mov dword ptr', 'mov qword ptr']):
            self.statistics['memory_write'] += 1
            return 'memory_write'
        else:
            self.statistics['other'] += 1
            return 'other'

    def get_gadgets_by_type(self, gadget_type):
        """Get gadgets filtered by type."""
        return [g for g in self.gadgets if g['type'] == gadget_type]

    def generate_report(self, output_path=None):
        """Generate markdown report."""
        binary_name = os.path.basename(self.binary_path)

        report = []
        report.append(f"# ROP Gadget Analysis: {binary_name}")
        report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"\n## Architecture: {self.arch}")
        report.append(f"## Binary Type: {'PE' if self.is_pe else 'ELF' if self.is_elf else 'Raw'}")

        report.append("\n## Gadget Statistics")
        report.append(f"- **Total gadgets:** {len(self.gadgets)}")
        for gtype, count in sorted(self.statistics.items()):
            report.append(f"- **{gtype.replace('_', ' ').title()}:** {count}")

        # Sort by usefulness
        type_order = ['syscall', 'stack_pivot', 'memory_write', 'register_pop',
                      'register_move', 'arithmetic', 'other']

        for gtype in type_order:
            gadgets = self.get_gadgets_by_type(gtype)
            if gadgets:
                report.append(f"\n## {gtype.replace('_', ' ').title()} Gadgets ({len(gadgets)})")
                for g in gadgets[:30]:  # Top 30 per type
                    report.append(f"- `0x{g['address']:x}: {g['instructions']}`")
                if len(gadgets) > 30:
                    report.append(f"- ... and {len(gadgets) - 30} more")

        report_text = '\n'.join(report)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(report_text)
            print(f"[+] Report saved: {output_path}")

        return report_text

    def export_json(self, output_path):
        """Export to JSON."""
        data = {
            'binary': os.path.basename(self.binary_path),
            'architecture': self.arch,
            'timestamp': datetime.now().isoformat(),
            'statistics': dict(self.statistics),
            'total_gadgets': len(self.gadgets),
            'gadgets': self.gadgets
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[+] JSON saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Fast x86/x64 ROP gadget scanner using byte-level analysis'
    )
    parser.add_argument('binary', help='Path to binary')
    parser.add_argument('--arch', '-a', choices=['x86', 'x64'], default='x64',
                        help='Architecture (default: x64)')
    parser.add_argument('--depth', '-d', type=int, default=10,
                        help='Max gadget depth in bytes (default: 10)')
    parser.add_argument('--output', '-o', default='.',
                        help='Output directory (default: current)')
    parser.add_argument('--max-gadgets', '-m', type=int, default=10000,
                        help='Max gadgets to find (default: 10000)')

    args = parser.parse_args()

    if not os.path.exists(args.binary):
        print(f"[!] Binary not found: {args.binary}")
        sys.exit(1)

    if not CAPSTONE_AVAILABLE:
        print("[!] Please install capstone: pip install capstone")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    scanner = X86RopScanner(args.binary, args.arch)
    scanner.find_gadgets(max_depth=args.depth, max_gadgets=args.max_gadgets)

    # Generate outputs
    binary_name = os.path.basename(args.binary).replace('.', '_')
    scanner.generate_report(os.path.join(args.output, f'{binary_name}_rop_report.md'))
    scanner.export_json(os.path.join(args.output, f'{binary_name}_rop_gadgets.json'))

    # Print summary
    print("\n" + "=" * 60)
    print("Summary:")
    print("=" * 60)
    for gtype, count in sorted(scanner.statistics.items()):
        print(f"  {gtype}: {count}")
    print(f"\nTotal: {len(scanner.gadgets)} gadgets")


if __name__ == '__main__':
    main()
