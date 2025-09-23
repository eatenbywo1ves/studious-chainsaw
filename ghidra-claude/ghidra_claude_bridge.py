#!/usr/bin/env python3
"""
Ghidra-Claude Bridge: Integration framework for reverse engineering with Claude AI
This module provides a bidirectional communication interface between Ghidra and Claude.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import base64


class AnalysisType(Enum):
    """Types of analysis that can be requested from Claude"""
    FUNCTION_PURPOSE = "function_purpose"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CODE_PATTERNS = "code_patterns"
    CRYPTO_IDENTIFICATION = "crypto_identification"
    PROTOCOL_ANALYSIS = "protocol_analysis"
    MALWARE_INDICATORS = "malware_indicators"
    CONTROL_FLOW = "control_flow"
    DATA_STRUCTURES = "data_structures"


@dataclass
class FunctionInfo:
    """Represents a function extracted from Ghidra"""
    name: str
    address: str
    size: int
    decompiled_code: Optional[str]
    assembly_code: Optional[str]
    xrefs_to: List[str]
    xrefs_from: List[str]
    strings: List[str]
    imports: List[str]

    def to_dict(self):
        return asdict(self)


@dataclass
class BinaryInfo:
    """Represents overall binary information"""
    name: str
    path: str
    architecture: str
    endianness: str
    compiler: Optional[str]
    entry_point: str
    sections: List[Dict[str, Any]]
    imports: List[str]
    exports: List[str]
    strings: List[str]

    def to_dict(self):
        return asdict(self)


class GhidraClaudeBridge:
    """Main bridge class for Ghidra-Claude communication"""

    def __init__(self, ghidra_path: str, project_path: Optional[str] = None):
        self.ghidra_path = Path(ghidra_path)
        self.project_path = Path(project_path) if project_path else None
        self.headless_script_path = self.ghidra_path / "support" / "analyzeHeadless.bat"
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ghidra_claude_"))

    def analyze_binary(self, binary_path: str, analysis_type: AnalysisType) -> Dict:
        """Analyze a binary file using Ghidra and prepare data for Claude"""
        binary_path = Path(binary_path)

        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Extract data using Ghidra
        ghidra_data = self._extract_ghidra_data(binary_path)

        # Prepare context for Claude based on analysis type
        claude_context = self._prepare_claude_context(ghidra_data, analysis_type)

        return {
            "binary_info": ghidra_data.get("binary_info"),
            "analysis_type": analysis_type.value,
            "context": claude_context,
            "prompt": self._generate_analysis_prompt(analysis_type)
        }

    def _extract_ghidra_data(self, binary_path: Path) -> Dict:
        """Extract analysis data from Ghidra using headless analyzer"""
        # Create temporary Ghidra project
        project_name = f"temp_analysis_{binary_path.stem}"
        project_location = self.temp_dir / project_name

        # Create export script
        export_script = self._create_export_script()
        script_path = self.temp_dir / "export_analysis.py"
        script_path.write_text(export_script)

        # Run Ghidra headless analyzer
        cmd = [
            str(self.headless_script_path),
            str(project_location),
            project_name,
            "-import", str(binary_path),
            "-scriptPath", str(self.temp_dir),
            "-postScript", "export_analysis.py",
            "-deleteProject"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            # Parse exported JSON data
            export_file = self.temp_dir / "ghidra_export.json"
            if export_file.exists():
                with open(export_file, 'r') as f:
                    return json.load(f)
            else:
                return {"error": "Failed to export data from Ghidra", "stderr": result.stderr}

        except subprocess.TimeoutExpired:
            return {"error": "Ghidra analysis timeout"}
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}

    def _create_export_script(self) -> str:
        """Create Ghidra script to export analysis data"""
        return '''
# Ghidra Python script to export analysis data for Claude
# @category Analysis
# @keybinding
# @menupath
# @toolbar

import json
import os
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface

def get_function_info(func):
    """Extract detailed function information"""
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    result = {
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
        "xrefs_to": [],
        "xrefs_from": [],
        "strings": [],
        "decompiled_code": None,
        "assembly_code": []
    }

    # Get decompiled code
    try:
        decompile_result = decompiler.decompileFunction(func, 30, monitor)
        if decompile_result.decompileCompleted():
            result["decompiled_code"] = decompile_result.getDecompiledFunction().getC()
    except:
        pass

    # Get assembly code
    listing = currentProgram.getListing()
    func_body = func.getBody()
    code_units = listing.getCodeUnits(func_body, True)

    for code_unit in code_units:
        result["assembly_code"].append({
            "address": str(code_unit.getAddress()),
            "mnemonic": code_unit.getMnemonicString(),
            "operands": code_unit.getDefaultOperandRepresentation(),
            "bytes": code_unit.getBytes().hex() if hasattr(code_unit.getBytes(), 'hex') else ""
        })

    # Get references
    ref_manager = currentProgram.getReferenceManager()
    for ref in ref_manager.getReferencesTo(func.getEntryPoint()):
        result["xrefs_to"].append(str(ref.getFromAddress()))

    for ref in ref_manager.getReferencesFrom(func.getEntryPoint()):
        result["xrefs_from"].append(str(ref.getToAddress()))

    return result

def get_binary_info():
    """Extract overall binary information"""
    info = {
        "name": currentProgram.getName(),
        "path": currentProgram.getExecutablePath(),
        "architecture": currentProgram.getLanguageID().toString(),
        "endianness": "big" if currentProgram.getMemory().isBigEndian() else "little",
        "compiler": currentProgram.getCompiler() if hasattr(currentProgram, 'getCompiler') else None,
        "entry_point": str(currentProgram.getImageBase()),
        "sections": [],
        "imports": [],
        "exports": [],
        "strings": []
    }

    # Get memory blocks (sections)
    memory = currentProgram.getMemory()
    for block in memory.getBlocks():
        info["sections"].append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "permissions": {
                "read": block.isRead(),
                "write": block.isWrite(),
                "execute": block.isExecute()
            }
        })

    # Get imports/exports
    symbol_table = currentProgram.getSymbolTable()
    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternal():
            info["imports"].append(symbol.getName())
        elif symbol.getSource() == SourceType.EXPORTED:
            info["exports"].append(symbol.getName())

    # Get defined strings
    listing = currentProgram.getListing()
    data_iterator = listing.getDefinedData(True)
    for data in data_iterator:
        if data.hasStringValue():
            info["strings"].append({
                "address": str(data.getAddress()),
                "value": data.getDefaultValueRepresentation()
            })

    return info

# Main export logic
export_data = {
    "binary_info": get_binary_info(),
    "functions": []
}

# Export top 50 most interesting functions
function_manager = currentProgram.getFunctionManager()
functions = function_manager.getFunctions(True)
func_count = 0

for func in functions:
    if func_count >= 50:
        break
    if not func.isThunk() and not func.isExternal():
        export_data["functions"].append(get_function_info(func))
        func_count += 1

# Write to JSON file
output_path = os.path.join(os.environ.get("TEMP", "/tmp"), "ghidra_export.json")
with open(output_path, 'w') as f:
    json.dump(export_data, f, indent=2)

print(f"Analysis exported to {output_path}")
'''

    def _prepare_claude_context(self, ghidra_data: Dict, analysis_type: AnalysisType) -> Dict:
        """Prepare context data for Claude based on analysis type"""
        context = {
            "binary_overview": ghidra_data.get("binary_info", {}),
            "relevant_functions": []
        }

        functions = ghidra_data.get("functions", [])

        if analysis_type == AnalysisType.VULNERABILITY_SCAN:
            # Focus on functions with dangerous patterns
            dangerous_funcs = ["strcpy", "sprintf", "gets", "scanf", "strcat"]
            for func in functions:
                if any(df in func.get("name", "").lower() for df in dangerous_funcs):
                    context["relevant_functions"].append(func)

        elif analysis_type == AnalysisType.CRYPTO_IDENTIFICATION:
            # Look for crypto-related patterns
            crypto_indicators = ["aes", "rsa", "sha", "md5", "crypt", "cipher", "key"]
            for func in functions:
                if any(ci in func.get("name", "").lower() for ci in crypto_indicators):
                    context["relevant_functions"].append(func)

        elif analysis_type == AnalysisType.MALWARE_INDICATORS:
            # Focus on suspicious behavior patterns
            suspicious = ["inject", "hook", "hide", "rootkit", "backdoor", "payload"]
            for func in functions[:20]:  # Analyze first 20 functions
                context["relevant_functions"].append(func)

        else:
            # Default: include first 10 non-trivial functions
            context["relevant_functions"] = [f for f in functions[:10] if f.get("size", 0) > 10]

        return context

    def _generate_analysis_prompt(self, analysis_type: AnalysisType) -> str:
        """Generate appropriate prompt for Claude based on analysis type"""
        prompts = {
            AnalysisType.FUNCTION_PURPOSE:
                "Analyze these functions and explain their purpose, behavior, and relationships.",

            AnalysisType.VULNERABILITY_SCAN:
                "Identify potential security vulnerabilities in this code, including buffer overflows, "
                "format string bugs, integer overflows, and other memory safety issues.",

            AnalysisType.CODE_PATTERNS:
                "Identify common design patterns, algorithms, and architectural choices in this binary.",

            AnalysisType.CRYPTO_IDENTIFICATION:
                "Identify cryptographic algorithms, key management, and security implementations.",

            AnalysisType.PROTOCOL_ANALYSIS:
                "Analyze network protocols, data formats, and communication patterns in this binary.",

            AnalysisType.MALWARE_INDICATORS:
                "Identify potential malicious behaviors, anti-analysis techniques, and indicators of compromise.",

            AnalysisType.CONTROL_FLOW:
                "Analyze the control flow, execution paths, and program logic.",

            AnalysisType.DATA_STRUCTURES:
                "Identify and explain data structures, object layouts, and memory organization."
        }

        return prompts.get(analysis_type, "Analyze this binary and provide insights.")

    def export_for_claude(self, analysis_result: Dict, output_path: str):
        """Export analysis results in a format optimized for Claude"""
        output_path = Path(output_path)

        # Create markdown report for Claude
        report = self._generate_markdown_report(analysis_result)

        with open(output_path, 'w') as f:
            f.write(report)

        return output_path

    def _generate_markdown_report(self, analysis_result: Dict) -> str:
        """Generate a markdown report for Claude analysis"""
        report = []
        report.append("# Binary Analysis Report for Claude\n")

        # Binary information
        binary_info = analysis_result.get("binary_info", {})
        report.append("## Binary Information\n")
        report.append(f"- **Name**: {binary_info.get('name', 'Unknown')}")
        report.append(f"- **Architecture**: {binary_info.get('architecture', 'Unknown')}")
        report.append(f"- **Entry Point**: {binary_info.get('entry_point', 'Unknown')}")
        report.append(f"- **Endianness**: {binary_info.get('endianness', 'Unknown')}\n")

        # Analysis request
        report.append(f"## Analysis Type: {analysis_result.get('analysis_type', 'general')}\n")
        report.append(f"**Prompt**: {analysis_result.get('prompt', '')}\n")

        # Functions to analyze
        context = analysis_result.get("context", {})
        functions = context.get("relevant_functions", [])

        report.append("## Functions for Analysis\n")
        for func in functions[:10]:  # Limit to 10 functions for readability
            report.append(f"\n### Function: {func.get('name', 'Unknown')}")
            report.append(f"- **Address**: {func.get('address', 'Unknown')}")
            report.append(f"- **Size**: {func.get('size', 0)} bytes")

            if func.get("decompiled_code"):
                report.append("\n**Decompiled Code:**")
                report.append("```c")
                report.append(func["decompiled_code"])
                report.append("```")

            if func.get("assembly_code"):
                report.append("\n**Assembly (first 20 instructions):**")
                report.append("```asm")
                for inst in func["assembly_code"][:20]:
                    report.append(f"{inst['address']}: {inst['mnemonic']} {inst['operands']}")
                report.append("```")

        return "\n".join(report)


def create_claude_prompt(analysis_data: Dict) -> str:
    """Create an optimized prompt for Claude based on Ghidra analysis"""
    prompt_parts = []

    prompt_parts.append("You are analyzing a binary that has been processed by Ghidra.")
    prompt_parts.append(f"Analysis requested: {analysis_data.get('analysis_type', 'general')}\n")

    # Add binary context
    binary_info = analysis_data.get("binary_info", {})
    prompt_parts.append(f"Binary: {binary_info.get('name', 'unknown')}")
    prompt_parts.append(f"Architecture: {binary_info.get('architecture', 'unknown')}")

    # Add specific analysis request
    prompt_parts.append(f"\n{analysis_data.get('prompt', 'Please analyze this binary.')}\n")

    # Add function data
    context = analysis_data.get("context", {})
    functions = context.get("relevant_functions", [])

    if functions:
        prompt_parts.append("\nKey functions to analyze:")
        for func in functions[:5]:  # Limit for token efficiency
            prompt_parts.append(f"\nFunction {func.get('name', 'unknown')} at {func.get('address', '0x0')}:")
            if func.get("decompiled_code"):
                prompt_parts.append("```c")
                prompt_parts.append(func["decompiled_code"][:1000])  # Truncate if too long
                prompt_parts.append("```")

    return "\n".join(prompt_parts)


if __name__ == "__main__":
    # Example usage
    ghidra_path = r"C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV"
    bridge = GhidraClaudeBridge(ghidra_path)

    print("Ghidra-Claude Bridge initialized")
    print(f"Ghidra path: {ghidra_path}")
    print(f"Temp directory: {bridge.temp_dir}")