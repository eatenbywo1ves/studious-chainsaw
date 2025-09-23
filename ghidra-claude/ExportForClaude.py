# Export analysis data for Claude AI
# @author Ghidra-Claude Bridge
# @category Analysis
# @keybinding Ctrl+Shift+C
# @menupath Analysis.Export for Claude
# @toolbar

"""
Ghidra script to export comprehensive analysis data for Claude AI.
Place this file in Ghidra's scripts directory or add the directory to script paths.
"""

import json
import os
from java.io import File
from ghidra.app.decompiler import DecompInterface
from ghidra.app.util.bin.format.pe import PortableExecutable
from ghidra.program.model.symbol import SourceType, SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.task import ConsoleTaskMonitor
from java.util import ArrayList
from javax.swing import JFileChooser, JOptionPane

class ClaudeExporter:
    def __init__(self, program, monitor):
        self.program = program
        self.monitor = monitor
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(program)
        self.export_data = {}

    def export_binary_info(self):
        """Export general binary information"""
        info = {
            "name": self.program.getName(),
            "path": self.program.getExecutablePath(),
            "format": self.program.getExecutableFormat(),
            "architecture": str(self.program.getLanguageID()),
            "compiler": str(self.program.getCompilerSpec().getCompilerSpecID()),
            "endianness": "big" if self.program.getMemory().isBigEndian() else "little",
            "address_size": self.program.getAddressFactory().getDefaultAddressSpace().getSize(),
            "image_base": str(self.program.getImageBase()),
            "min_address": str(self.program.getMinAddress()),
            "max_address": str(self.program.getMaxAddress())
        }

        # Get creation/modification info
        metadata = self.program.getMetadata()
        if metadata:
            info["created"] = str(metadata.get("Date Created", "Unknown"))
            info["analyzed"] = str(metadata.get("Date Analyzed", "Unknown"))

        return info

    def export_memory_map(self):
        """Export memory sections/segments"""
        memory = self.program.getMemory()
        sections = []

        for block in memory.getBlocks():
            section = {
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "type": block.getType().toString(),
                "permissions": {
                    "read": block.isRead(),
                    "write": block.isWrite(),
                    "execute": block.isExecute()
                },
                "initialized": block.isInitialized(),
                "mapped": block.isMapped(),
                "overlay": block.isOverlay()
            }
            sections.append(section)

        return sections

    def export_functions(self, max_functions=100):
        """Export function information with decompilation"""
        function_manager = self.program.getFunctionManager()
        functions = []
        count = 0

        for func in function_manager.getFunctions(True):
            if count >= max_functions:
                break

            # Skip external and thunk functions unless specifically interesting
            if func.isExternal():
                continue

            func_info = {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "signature": func.getPrototypeString(False, False),
                "calling_convention": func.getCallingConventionName(),
                "is_thunk": func.isThunk(),
                "is_library": func.isLibrary(),
                "has_varargs": func.hasVarArgs(),
                "stack_frame_size": func.getStackFrame().getFrameSize() if func.getStackFrame() else 0
            }

            # Get function comments
            comment = func.getComment()
            if comment:
                func_info["comment"] = comment

            # Get parameters
            params = []
            for param in func.getParameters():
                params.append({
                    "name": param.getName(),
                    "type": str(param.getDataType()),
                    "ordinal": param.getOrdinal(),
                    "storage": str(param.getVariableStorage())
                })
            func_info["parameters"] = params

            # Get local variables
            locals = []
            for var in func.getLocalVariables():
                locals.append({
                    "name": var.getName(),
                    "type": str(var.getDataType()),
                    "stack_offset": var.getStackOffset()
                })
            func_info["local_variables"] = locals

            # Get decompiled code
            decompiled = self.get_decompiled_function(func)
            if decompiled:
                func_info["decompiled_code"] = decompiled

            # Get calls from this function
            called_functions = []
            for called_func in func.getCalledFunctions(self.monitor):
                called_functions.append({
                    "name": called_func.getName(),
                    "address": str(called_func.getEntryPoint())
                })
            func_info["calls"] = called_functions

            # Get references to this function
            ref_manager = self.program.getReferenceManager()
            callers = []
            for ref in ref_manager.getReferencesTo(func.getEntryPoint()):
                from_func = self.program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
                if from_func:
                    callers.append({
                        "function": from_func.getName(),
                        "address": str(ref.getFromAddress())
                    })
            func_info["called_by"] = callers

            functions.append(func_info)
            count += 1

        return functions

    def get_decompiled_function(self, func):
        """Get decompiled C code for a function"""
        try:
            results = self.decompiler.decompileFunction(func, 30, self.monitor)
            if results.decompileCompleted():
                return results.getDecompiledFunction().getC()
        except Exception as e:
            print(f"Failed to decompile {func.getName()}: {e}")
        return None

    def export_strings(self, min_length=4, max_strings=500):
        """Export defined strings from the binary"""
        strings = []
        count = 0
        listing = self.program.getListing()

        for data in listing.getDefinedData(True):
            if count >= max_strings:
                break

            if data.hasStringValue():
                value = data.getDefaultValueRepresentation()
                if len(value) >= min_length:
                    strings.append({
                        "address": str(data.getAddress()),
                        "value": value,
                        "type": str(data.getDataType().getName()),
                        "length": len(value),
                        "references": self.get_references_to_address(data.getAddress())
                    })
                    count += 1

        return strings

    def get_references_to_address(self, address):
        """Get all references to a specific address"""
        refs = []
        ref_manager = self.program.getReferenceManager()
        for ref in ref_manager.getReferencesTo(address):
            func = self.program.getFunctionManager().getFunctionContaining(ref.getFromAddress())
            refs.append({
                "from_address": str(ref.getFromAddress()),
                "function": func.getName() if func else None,
                "type": ref.getReferenceType().getName()
            })
        return refs

    def export_imports_exports(self):
        """Export imported and exported symbols"""
        symbol_table = self.program.getSymbolTable()
        imports = []
        exports = []

        for symbol in symbol_table.getAllSymbols(True):
            sym_info = {
                "name": symbol.getName(),
                "address": str(symbol.getAddress()),
                "type": symbol.getSymbolType().toString()
            }

            if symbol.isExternal():
                # Import
                external_loc = symbol.getProgram().getExternalManager().getExternalLocation(symbol)
                if external_loc:
                    sym_info["library"] = external_loc.getLibraryName()
                imports.append(sym_info)
            elif symbol.getSource() == SourceType.EXPORTED:
                # Export
                exports.append(sym_info)

        return {"imports": imports, "exports": exports}

    def export_interesting_patterns(self):
        """Identify interesting code patterns for security analysis"""
        patterns = {
            "crypto_functions": [],
            "network_functions": [],
            "file_operations": [],
            "memory_operations": [],
            "string_operations": [],
            "suspicious_functions": []
        }

        # Define pattern keywords
        crypto_keywords = ["crypt", "aes", "des", "rsa", "sha", "md5", "hash", "cipher", "encrypt", "decrypt"]
        network_keywords = ["socket", "send", "recv", "connect", "bind", "listen", "accept", "http", "ftp"]
        file_keywords = ["open", "read", "write", "create", "delete", "file", "directory"]
        memory_keywords = ["alloc", "malloc", "calloc", "realloc", "free", "heap", "virtualalloc"]
        string_keywords = ["strcpy", "strcat", "sprintf", "gets", "scanf", "strncpy"]
        suspicious_keywords = ["hook", "inject", "hide", "rootkit", "backdoor", "shellcode", "payload"]

        function_manager = self.program.getFunctionManager()
        for func in function_manager.getFunctions(True):
            func_name_lower = func.getName().lower()

            func_data = {
                "name": func.getName(),
                "address": str(func.getEntryPoint())
            }

            # Categorize based on function name
            if any(keyword in func_name_lower for keyword in crypto_keywords):
                patterns["crypto_functions"].append(func_data)
            if any(keyword in func_name_lower for keyword in network_keywords):
                patterns["network_functions"].append(func_data)
            if any(keyword in func_name_lower for keyword in file_keywords):
                patterns["file_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in memory_keywords):
                patterns["memory_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in string_keywords):
                patterns["string_operations"].append(func_data)
            if any(keyword in func_name_lower for keyword in suspicious_keywords):
                patterns["suspicious_functions"].append(func_data)

        return patterns

    def export_control_flow_info(self):
        """Export control flow and basic block information for key functions"""
        control_flow = []
        function_manager = self.program.getFunctionManager()
        count = 0

        for func in function_manager.getFunctions(True):
            if count >= 20:  # Limit to 20 functions
                break
            if func.isExternal() or func.isThunk():
                continue

            func_cf = {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "basic_blocks": [],
                "cyclomatic_complexity": self.calculate_cyclomatic_complexity(func)
            }

            # Get basic blocks
            basic_block_model = self.program.getBasicBlockModel()
            blocks = basic_block_model.getCodeBlocksContaining(func.getBody(), self.monitor)
            while blocks.hasNext():
                block = blocks.next()
                block_info = {
                    "start": str(block.getMinAddress()),
                    "end": str(block.getMaxAddress()),
                    "size": block.getNumAddresses()
                }
                func_cf["basic_blocks"].append(block_info)

            control_flow.append(func_cf)
            count += 1

        return control_flow

    def calculate_cyclomatic_complexity(self, func):
        """Calculate cyclomatic complexity of a function"""
        # Simplified calculation: count decision points
        complexity = 1
        listing = self.program.getListing()
        instructions = listing.getInstructions(func.getBody(), True)

        branch_mnemonics = ["JMP", "JE", "JNE", "JZ", "JNZ", "JG", "JGE", "JL", "JLE",
                           "JA", "JAE", "JB", "JBE", "CALL", "RET"]

        for instr in instructions:
            if any(instr.getMnemonicString().upper().startswith(mnem) for mnem in branch_mnemonics):
                complexity += 1

        return complexity

    def export_all(self):
        """Export all analysis data"""
        print("Exporting binary information...")
        self.export_data["binary_info"] = self.export_binary_info()

        print("Exporting memory map...")
        self.export_data["memory_map"] = self.export_memory_map()

        print("Exporting functions...")
        self.export_data["functions"] = self.export_functions()

        print("Exporting strings...")
        self.export_data["strings"] = self.export_strings()

        print("Exporting imports/exports...")
        ie_data = self.export_imports_exports()
        self.export_data["imports"] = ie_data["imports"]
        self.export_data["exports"] = ie_data["exports"]

        print("Identifying interesting patterns...")
        self.export_data["patterns"] = self.export_interesting_patterns()

        print("Exporting control flow information...")
        self.export_data["control_flow"] = self.export_control_flow_info()

        return self.export_data

    def save_to_file(self, filepath):
        """Save exported data to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.export_data, f, indent=2)
        print(f"Export complete: {filepath}")

def main():
    """Main execution function"""
    monitor = ConsoleTaskMonitor()
    exporter = ClaudeExporter(currentProgram, monitor)

    # Ask user where to save the export
    chooser = JFileChooser()
    chooser.setDialogTitle("Save Claude Export")
    chooser.setSelectedFile(File(currentProgram.getName() + "_claude_export.json"))

    if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
        output_file = chooser.getSelectedFile().getAbsolutePath()

        print("Starting export for Claude AI analysis...")
        exporter.export_all()
        exporter.save_to_file(output_file)

        JOptionPane.showMessageDialog(None,
            f"Export complete!\nFile saved to: {output_file}\n\nYou can now use this file with the Claude AI integration.",
            "Export Successful",
            JOptionPane.INFORMATION_MESSAGE)
    else:
        print("Export cancelled by user")

if __name__ == "__main__":
    main()