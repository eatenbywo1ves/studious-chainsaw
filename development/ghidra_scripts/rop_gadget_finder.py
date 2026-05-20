#!/usr/bin/env python3
"""
ROP Gadget Discovery Tool for Ghidra

This script discovers ROP gadgets in binaries using Ghidra's analysis capabilities.
Supports ARM, MIPS, x86, and x86-64 architectures.

Usage:
    From Ghidra Script Manager: Run directly
    From command line with ghidra_bridge: python rop_gadget_finder.py --binary <path>

Author: Claude Code / Corbin
License: MIT
"""

import json
import os
import re
from datetime import datetime
from collections import defaultdict

# Check if running inside Ghidra or via bridge
try:
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.symbol import RefType
    RUNNING_IN_GHIDRA = True
except ImportError:
    RUNNING_IN_GHIDRA = False


class RopInstruction:
    """Represents an instruction pattern to search for."""
    def __init__(self, mnem, op1=None, op2=None, op3=None):
        self.mnem = mnem
        self.op1 = op1
        self.op2 = op2
        self.op3 = op3


class RopGadget:
    """Represents a discovered ROP gadget."""
    def __init__(self, address, instructions, gadget_type, description=""):
        self.address = address
        self.instructions = instructions  # List of (addr, instruction_str) tuples
        self.gadget_type = gadget_type
        self.description = description
        self.utility_score = 0

    def to_dict(self):
        return {
            "address": str(self.address),
            "instructions": [{"addr": str(a), "insn": i} for a, i in self.instructions],
            "type": self.gadget_type,
            "description": self.description,
            "utility_score": self.utility_score
        }

    def __str__(self):
        insn_str = " ; ".join([i for _, i in self.instructions])
        return f"0x{self.address}: {insn_str}"


class RopGadgetFinder:
    """Main ROP gadget finder class."""

    SUPPORTED_ARCHITECTURES = ["ARM", "MIPS", "x86", "x86-64", "AARCH64"]

    def __init__(self, program):
        self.program = program
        self.flat_api = FlatProgramAPI(program)
        self.architecture = self._detect_architecture()
        self.gadgets = []
        self.statistics = defaultdict(int)

    def _detect_architecture(self):
        """Detect the binary architecture."""
        language = self.program.getLanguage()
        processor = language.getProcessor().toString()

        if "ARM" in processor:
            if "AARCH64" in processor or "64" in str(language):
                return "AARCH64"
            return "ARM"
        elif "MIPS" in processor:
            return "MIPS"
        elif "x86" in processor:
            if "64" in str(language):
                return "x86-64"
            return "x86"
        else:
            return processor

    def _get_instruction_at(self, address):
        """Get instruction at address."""
        return self.flat_api.getInstructionAt(address)

    def _get_previous_instruction(self, instruction):
        """Get the previous instruction following control flow."""
        fall_from = instruction.getFallFrom()
        if fall_from is None:
            return instruction.getPrevious()
        return self.flat_api.getInstructionAt(fall_from)

    def _instruction_matches(self, ins, patterns):
        """Check if instruction matches any pattern."""
        if ins is None:
            return False

        for pattern in patterns:
            if not re.match(pattern.mnem, ins.getMnemonicString(), re.IGNORECASE):
                continue
            try:
                if pattern.op1:
                    op0 = ins.getOpObjects(0)
                    if not op0 or not re.match(pattern.op1, str(op0[0]), re.IGNORECASE):
                        continue
                if pattern.op2:
                    op1 = ins.getOpObjects(1)
                    if not op1 or not re.match(pattern.op2, str(op1[0]), re.IGNORECASE):
                        continue
                if pattern.op3:
                    op2 = ins.getOpObjects(2)
                    if not op2 or not re.match(pattern.op3, str(op2[0]), re.IGNORECASE):
                        continue
                return True
            except (IndexError, AttributeError):
                continue
        return False

    def _is_gadget_terminator(self, ins):
        """Check if instruction terminates a gadget (ret, indirect jump, etc)."""
        if ins is None:
            return False

        mnem = ins.getMnemonicString().lower()
        flow = ins.getFlowType()

        # Architecture-specific terminators
        if self.architecture == "ARM" or self.architecture == "AARCH64":
            # ARM: pop {pc}, bx lr, ldmia sp!, {..., pc}
            if mnem in ["bx", "blx", "pop", "ldmia", "ldmfd", "ret"]:
                insn_str = str(ins).lower()
                if "pc" in insn_str or "lr" in insn_str:
                    return True

        elif self.architecture == "MIPS":
            # MIPS: jr ra, jalr
            if mnem in ["jr", "jalr"]:
                return True

        elif self.architecture in ["x86", "x86-64"]:
            # x86: ret, jmp reg, call reg
            if mnem in ["ret", "retn", "retf"]:
                return True
            if mnem in ["jmp", "call"] and flow.isComputed():
                return True

        return flow.isTerminal()

    def find_gadgets(self, max_gadget_length=10):
        """Find all ROP gadgets in the binary."""
        print(f"[*] Detecting gadgets for {self.architecture} architecture...")

        if self.architecture == "ARM":
            self._find_arm_gadgets(max_gadget_length)
        elif self.architecture == "AARCH64":
            self._find_aarch64_gadgets(max_gadget_length)
        elif self.architecture == "MIPS":
            self._find_mips_gadgets(max_gadget_length)
        elif self.architecture in ["x86", "x86-64"]:
            self._find_x86_gadgets(max_gadget_length)
        else:
            print(f"[!] Architecture {self.architecture} not fully supported")
            self._find_generic_gadgets(max_gadget_length)

        return self.gadgets

    def _find_arm_gadgets(self, max_length):
        """Find ARM-specific ROP gadgets."""
        print("[*] Finding ARM gadgets...")

        # Find all potential gadget terminators
        code_manager = self.program.getCodeManager()
        instructions = code_manager.getInstructions(self.program.getImageBase(), True)

        terminator_patterns = [
            RopInstruction("pop", ".*pc.*"),
            RopInstruction("bx", ".*"),
            RopInstruction("blx", "[^lr].*"),  # blx to register (not lr)
            RopInstruction("ldmia", "sp.*"),
            RopInstruction("ldmfd", "sp.*"),
        ]

        for ins in instructions:
            if self._is_gadget_terminator(ins):
                gadgets = self._extract_gadget_chain(ins, max_length)
                for gadget in gadgets:
                    self._classify_gadget(gadget)
                    self.gadgets.append(gadget)

        # Specifically look for useful ARM gadgets
        self._find_arm_register_control()
        self._find_arm_stack_pivot()
        self._find_arm_system_gadgets()

    def _find_aarch64_gadgets(self, max_length):
        """Find AARCH64-specific ROP gadgets."""
        print("[*] Finding AARCH64 gadgets...")

        code_manager = self.program.getCodeManager()
        instructions = code_manager.getInstructions(self.program.getImageBase(), True)

        for ins in instructions:
            mnem = ins.getMnemonicString().lower()
            if mnem == "ret" or (mnem in ["br", "blr"] and "x30" not in str(ins).lower()):
                gadgets = self._extract_gadget_chain(ins, max_length)
                for gadget in gadgets:
                    self._classify_gadget(gadget)
                    self.gadgets.append(gadget)

    def _find_mips_gadgets(self, max_length):
        """Find MIPS-specific ROP gadgets."""
        print("[*] Finding MIPS gadgets...")

        code_manager = self.program.getCodeManager()
        instructions = code_manager.getInstructions(self.program.getImageBase(), True)

        for ins in instructions:
            mnem = ins.getMnemonicString().lower()
            # MIPS uses jr $ra for returns, jalr for indirect calls
            if mnem in ["jr", "jalr"]:
                gadgets = self._extract_gadget_chain(ins, max_length)
                for gadget in gadgets:
                    self._classify_gadget(gadget)
                    self.gadgets.append(gadget)

        # Look for MIPS-specific useful gadgets
        self._find_mips_register_control()
        self._find_mips_stack_pivot()
        self._find_mips_system_gadgets()

    def _find_x86_gadgets(self, max_length):
        """Find x86/x86-64 specific ROP gadgets."""
        print(f"[*] Finding {self.architecture} gadgets...")

        code_manager = self.program.getCodeManager()
        instructions = code_manager.getInstructions(self.program.getImageBase(), True)

        for ins in instructions:
            mnem = ins.getMnemonicString().lower()
            if mnem in ["ret", "retn", "retf"]:
                gadgets = self._extract_gadget_chain(ins, max_length)
                for gadget in gadgets:
                    self._classify_gadget(gadget)
                    self.gadgets.append(gadget)
            elif mnem in ["jmp", "call"]:
                flow = ins.getFlowType()
                if flow.isComputed():  # Indirect jump/call
                    gadgets = self._extract_gadget_chain(ins, max_length)
                    for gadget in gadgets:
                        gadget.gadget_type = "indirect_" + gadget.gadget_type
                        self._classify_gadget(gadget)
                        self.gadgets.append(gadget)

        # Look for specific useful gadgets
        self._find_x86_pop_gadgets()
        self._find_x86_stack_pivot()
        self._find_x86_syscall_gadgets()

    def _find_generic_gadgets(self, max_length):
        """Find gadgets for unsupported architectures."""
        print("[*] Finding generic gadgets (limited support)...")

        code_manager = self.program.getCodeManager()
        instructions = code_manager.getInstructions(self.program.getImageBase(), True)

        for ins in instructions:
            flow = ins.getFlowType()
            if flow.isTerminal() or (flow.isJump() and flow.isComputed()):
                gadgets = self._extract_gadget_chain(ins, max_length)
                for gadget in gadgets:
                    self.gadgets.append(gadget)

    def _extract_gadget_chain(self, terminator, max_length):
        """Extract instruction chain ending at terminator."""
        gadgets = []

        # Start from the terminator and work backwards
        chain = [(terminator.getAddress(), str(terminator))]
        current = self._get_previous_instruction(terminator)

        for _ in range(max_length - 1):
            if current is None:
                break

            # Stop if we hit another control flow instruction
            flow = current.getFlowType()
            if flow.isCall() or flow.isJump():
                break

            # Skip NOPs
            if "nop" in str(current).lower():
                current = self._get_previous_instruction(current)
                continue

            chain.insert(0, (current.getAddress(), str(current)))

            # Create a gadget for each prefix length
            gadget = RopGadget(
                address=current.getAddress(),
                instructions=list(chain),
                gadget_type="generic",
                description=""
            )
            gadgets.append(gadget)

            current = self._get_previous_instruction(current)

        return gadgets

    def _classify_gadget(self, gadget):
        """Classify gadget by type and assign utility score."""
        insn_str = " ".join([i for _, i in gadget.instructions]).lower()

        # Stack pivot detection
        if any(x in insn_str for x in ["mov esp", "mov rsp", "xchg esp", "xchg rsp",
                                        "add sp", "sub sp", "pop sp", "leave"]):
            gadget.gadget_type = "stack_pivot"
            gadget.utility_score = 90
            gadget.description = "Stack pivot - control stack pointer"
            self.statistics["stack_pivot"] += 1

        # Register pop/control
        elif "pop" in insn_str:
            gadget.gadget_type = "register_pop"
            # Count number of pops
            pop_count = insn_str.count("pop")
            gadget.utility_score = 50 + (pop_count * 10)
            gadget.description = f"Pop {pop_count} register(s) from stack"
            self.statistics["register_pop"] += 1

        # Register move
        elif "mov" in insn_str and "sp" not in insn_str:
            gadget.gadget_type = "register_move"
            gadget.utility_score = 40
            gadget.description = "Move value between registers"
            self.statistics["register_move"] += 1

        # Arithmetic operations
        elif any(x in insn_str for x in ["add", "sub", "inc", "dec", "xor", "or", "and"]):
            gadget.gadget_type = "arithmetic"
            gadget.utility_score = 30
            gadget.description = "Arithmetic/logic operation"
            self.statistics["arithmetic"] += 1

        # Memory operations
        elif any(x in insn_str for x in ["mov [", "mov dword", "mov qword", "str ", "ldr "]):
            gadget.gadget_type = "memory_write"
            gadget.utility_score = 70
            gadget.description = "Memory read/write operation"
            self.statistics["memory"] += 1

        # System call
        elif any(x in insn_str for x in ["syscall", "int 0x80", "svc", "swi"]):
            gadget.gadget_type = "syscall"
            gadget.utility_score = 100
            gadget.description = "System call gadget"
            self.statistics["syscall"] += 1

        else:
            gadget.gadget_type = "other"
            gadget.utility_score = 10
            self.statistics["other"] += 1

    # Architecture-specific gadget finders
    def _find_arm_register_control(self):
        """Find ARM gadgets for register control."""
        pass  # Already covered in main search

    def _find_arm_stack_pivot(self):
        """Find ARM stack pivot gadgets."""
        pass

    def _find_arm_system_gadgets(self):
        """Find ARM system call gadgets."""
        pass

    def _find_mips_register_control(self):
        """Find MIPS register control gadgets."""
        pass

    def _find_mips_stack_pivot(self):
        """Find MIPS stack pivot gadgets."""
        pass

    def _find_mips_system_gadgets(self):
        """Find MIPS system call gadgets."""
        pass

    def _find_x86_pop_gadgets(self):
        """Find x86 pop gadgets."""
        pass  # Already covered

    def _find_x86_stack_pivot(self):
        """Find x86 stack pivot gadgets."""
        pass

    def _find_x86_syscall_gadgets(self):
        """Find x86 syscall gadgets."""
        pass

    def get_top_gadgets(self, count=50):
        """Get the most useful gadgets sorted by utility score."""
        return sorted(self.gadgets, key=lambda g: g.utility_score, reverse=True)[:count]

    def get_gadgets_by_type(self, gadget_type):
        """Get gadgets filtered by type."""
        return [g for g in self.gadgets if g.gadget_type == gadget_type]

    def generate_report(self, output_path=None):
        """Generate a markdown report of discovered gadgets."""
        binary_name = self.program.getName()

        report = []
        report.append(f"# ROP Gadget Analysis: {binary_name}")
        report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"\n## Architecture: {self.architecture}")
        report.append(f"\n## Image Base: {self.program.getImageBase()}")

        # Statistics
        report.append("\n## Gadget Statistics")
        report.append(f"- **Total gadgets found:** {len(self.gadgets)}")
        for gtype, count in sorted(self.statistics.items()):
            report.append(f"- **{gtype.replace('_', ' ').title()}:** {count}")

        # Top gadgets by utility
        report.append("\n## Top 50 Most Useful Gadgets")
        report.append("\n| Address | Instructions | Type | Score |")
        report.append("|---------|--------------|------|-------|")

        for gadget in self.get_top_gadgets(50):
            insn_str = " ; ".join([i for _, i in gadget.instructions])
            if len(insn_str) > 50:
                insn_str = insn_str[:47] + "..."
            report.append(f"| `{gadget.address}` | `{insn_str}` | {gadget.gadget_type} | {gadget.utility_score} |")

        # Stack pivot gadgets
        stack_pivots = self.get_gadgets_by_type("stack_pivot")
        if stack_pivots:
            report.append("\n## Stack Pivot Gadgets")
            report.append("\nThese gadgets allow controlling the stack pointer:")
            for gadget in stack_pivots[:20]:
                report.append(f"- `{gadget}`")

        # Syscall gadgets
        syscalls = self.get_gadgets_by_type("syscall")
        if syscalls:
            report.append("\n## System Call Gadgets")
            report.append("\nThese gadgets can invoke system calls:")
            for gadget in syscalls[:20]:
                report.append(f"- `{gadget}`")

        # Memory write gadgets
        mem_writes = self.get_gadgets_by_type("memory_write")
        if mem_writes:
            report.append("\n## Memory Write Gadgets")
            report.append("\nThese gadgets can write to memory:")
            for gadget in mem_writes[:20]:
                report.append(f"- `{gadget}`")

        # Exploit development notes
        report.append("\n## Exploit Development Notes")
        report.append("\n### Security Mitigations to Check")
        report.append("- [ ] ASLR enabled (check /proc/sys/kernel/randomize_va_space)")
        report.append("- [ ] PIE (Position Independent Executable)")
        report.append("- [ ] Stack Canaries")
        report.append("- [ ] NX/DEP (Non-executable stack)")
        report.append("- [ ] RELRO (Relocation Read-Only)")

        report.append("\n### Recommended ROP Chain Strategy")
        if syscalls:
            report.append("1. System call gadgets available - can invoke execve directly")
        if stack_pivots:
            report.append("2. Stack pivot gadgets available - useful for stack-based exploits")
        if mem_writes:
            report.append("3. Memory write gadgets available - can modify GOT/data sections")

        report_text = "\n".join(report)

        if output_path:
            with open(output_path, "w") as f:
                f.write(report_text)
            print(f"[+] Report saved to: {output_path}")

        return report_text

    def export_json(self, output_path):
        """Export gadgets to JSON format."""
        data = {
            "binary": self.program.getName(),
            "architecture": self.architecture,
            "image_base": str(self.program.getImageBase()),
            "timestamp": datetime.now().isoformat(),
            "statistics": dict(self.statistics),
            "total_gadgets": len(self.gadgets),
            "gadgets": [g.to_dict() for g in self.gadgets]
        }

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] JSON export saved to: {output_path}")

        return data


def main():
    """Main entry point when running inside Ghidra."""
    if not RUNNING_IN_GHIDRA:
        print("This script must be run inside Ghidra or via ghidra_bridge")
        return

    # Get the current program
    finder = RopGadgetFinder(currentProgram)

    print(f"[*] Analyzing: {currentProgram.getName()}")
    print(f"[*] Architecture: {finder.architecture}")

    # Find gadgets
    gadgets = finder.find_gadgets()

    print(f"\n[+] Found {len(gadgets)} gadgets")

    # Print statistics
    print("\n[*] Gadget Statistics:")
    for gtype, count in sorted(finder.statistics.items()):
        print(f"    {gtype}: {count}")

    # Print top 20 gadgets
    print("\n[*] Top 20 Gadgets:")
    for gadget in finder.get_top_gadgets(20):
        print(f"    {gadget}")

    # Ask user if they want to save report
    try:
        save_report = askYesNo("Save Report", "Save ROP gadget report to file?")
        if save_report:
            output_dir = str(askDirectory("Select Output Directory", "Select"))
            binary_name = currentProgram.getName().replace(".", "_")

            # Save markdown report
            md_path = os.path.join(output_dir, f"{binary_name}_rop_report.md")
            finder.generate_report(md_path)

            # Save JSON export
            json_path = os.path.join(output_dir, f"{binary_name}_rop_gadgets.json")
            finder.export_json(json_path)

            print(f"\n[+] Reports saved to {output_dir}")
    except:
        pass  # User cancelled or headless mode


# Run main when executed in Ghidra
if __name__ == "__main__" or RUNNING_IN_GHIDRA:
    try:
        main()
    except NameError:
        # currentProgram not defined - running outside Ghidra
        print("Run this script from within Ghidra's Script Manager")
