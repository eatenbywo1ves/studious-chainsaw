# Ghidra-Claude Integration Framework

A powerful integration framework that combines Ghidra's reverse engineering capabilities with Claude AI's analysis abilities to accelerate and enhance binary analysis workflows.

## Overview

This framework provides seamless integration between your local Ghidra installation and Claude AI, enabling:

- **Automated Binary Analysis**: Extract comprehensive data from binaries using Ghidra
- **AI-Assisted Reverse Engineering**: Leverage Claude's understanding for code analysis
- **Interactive Analysis Sessions**: Real-time Q&A about binary functionality
- **Specialized Workflows**: Pre-built analysis patterns for common RE tasks

## Components

### 1. **ghidra_claude_bridge.py**
Core Python module that handles communication between Ghidra and Claude.

**Key Features:**
- Headless Ghidra analysis automation
- Data extraction and formatting for Claude
- Multiple analysis types (vulnerability, malware, crypto, etc.)
- Optimized prompt generation

### 2. **ExportForClaude.py**
Ghidra script for exporting analysis data from the Ghidra GUI.

**Installation:**
```bash
# Copy to Ghidra scripts directory
cp ExportForClaude.py "C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV\Ghidra\Features\Base\ghidra_scripts"
```

**Usage in Ghidra:**
1. Open your binary in Ghidra
2. Run analysis (Auto Analyze)
3. Script Manager → Search "ExportForClaude"
4. Run the script
5. Save the JSON export

### 3. **ghidra_claude_cli.py**
Interactive command-line interface for analysis sessions.

**Features:**
- Load binaries or Ghidra exports
- Interactive Q&A sessions
- Multiple analysis modes
- Session history and reporting

### 4. **example_workflows.py**
Pre-built analysis workflows for common tasks.

**Available Workflows:**
- Malware analysis
- Vulnerability assessment
- Cryptographic implementation review
- Protocol reverse engineering

## Installation

### Prerequisites

1. **Ghidra Installation**
   - Download from: https://ghidra-sre.org/
   - Ensure Java 17+ is installed
   - Your current path: `C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV`

2. **Python Dependencies**
```bash
pip install rich
```

3. **Claude Access**
   - Ensure you have Claude API access or use the Claude interface
   - The framework generates prompts optimized for Claude

### Setup

1. **Clone or copy the framework files:**
```bash
mkdir C:\Users\Corbin\ghidra-claude
cd C:\Users\Corbin\ghidra-claude
# Copy all provided files here
```

2. **Install the Ghidra script:**
```bash
copy ExportForClaude.py "C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV\Ghidra\Features\Base\ghidra_scripts"
```

3. **Verify Ghidra path in scripts:**
Update the `ghidra_path` variable if your installation differs.

## Usage Examples

### Quick Start: Analyze a Binary

```bash
# Using the CLI tool
python ghidra_claude_cli.py --binary path\to\sample.exe

# Using workflow automation
python example_workflows.py path\to\sample.exe --workflow malware
```

### Method 1: Ghidra GUI Export

1. **In Ghidra:**
```python
# Open your binary in Ghidra
# Run the ExportForClaude.py script
# Save as: sample_claude_export.json
```

2. **Load in CLI:**
```bash
python ghidra_claude_cli.py --export sample_claude_export.json
```

3. **Interactive Analysis:**
```
> functions          # List all functions
> function main      # Analyze specific function
> Show me potential buffer overflows
> What cryptographic algorithms are used?
```

### Method 2: Automated Headless Analysis

```python
from ghidra_claude_bridge import GhidraClaudeBridge, AnalysisType

# Initialize bridge
bridge = GhidraClaudeBridge(r"C:\Users\Corbin\Downloads\ghidra-master\build\ghidra_12.0_DEV")

# Analyze binary
result = bridge.analyze_binary("malware.exe", AnalysisType.MALWARE_INDICATORS)

# Generate Claude prompt
prompt = create_claude_prompt(result)
print(prompt)

# Export for Claude
bridge.export_for_claude(result, "malware_analysis.md")
```

### Method 3: Workflow Execution

```bash
# Vulnerability assessment
python example_workflows.py target.exe --workflow vulnerability

# Crypto review
python example_workflows.py crypto_app.exe --workflow crypto

# Protocol analysis
python example_workflows.py network_app.exe --workflow protocol
```

## Analysis Types

### Vulnerability Scanning
Identifies potential security vulnerabilities:
- Buffer overflows
- Format string bugs
- Use of unsafe functions
- Integer overflows
- Race conditions

### Malware Analysis
Detects malicious behaviors:
- Anti-analysis techniques
- C2 communication patterns
- Persistence mechanisms
- Code injection methods
- Evasion techniques

### Cryptographic Review
Analyzes crypto implementations:
- Algorithm identification
- Key management assessment
- Hardcoded secrets detection
- RNG quality evaluation
- Protocol security review

### Protocol Analysis
Reverse engineers network protocols:
- Message format extraction
- State machine mapping
- Handler identification
- Data structure reconstruction

## Interactive CLI Commands

| Command | Description |
|---------|-------------|
| `functions` | List all analyzed functions |
| `strings` | Display extracted strings |
| `imports` | Show imported functions |
| `exports` | Show exported functions |
| `function <name>` | Analyze specific function |
| `help` | Show command help |
| `exit` | Return to main menu |

## Claude Integration Tips

### Optimal Prompt Structure

The framework generates prompts with:
1. Binary context (architecture, format)
2. Specific analysis request
3. Relevant code/data excerpts
4. Focused questions

### Example Claude Queries

```text
"What is the purpose of the function at 0x401234?"

"Identify all potential SQL injection vulnerabilities in the decompiled code."

"Explain the encryption algorithm used in the crypto_init function."

"Map out the network protocol state machine based on these handler functions."
```

### Token Optimization

The framework automatically:
- Truncates long code segments
- Prioritizes relevant functions
- Formats data efficiently
- Limits context to essentials

## Advanced Usage

### Custom Analysis Types

```python
from ghidra_claude_bridge import GhidraClaudeBridge

class CustomAnalyzer(GhidraClaudeBridge):
    def analyze_custom_pattern(self, binary_path):
        # Extract specific data
        data = self._extract_ghidra_data(binary_path)

        # Custom processing
        patterns = self.find_my_patterns(data)

        # Generate Claude prompt
        prompt = f"Analyze these patterns: {patterns}"

        return prompt
```

### Batch Processing

```python
import glob
from pathlib import Path

def batch_analyze(directory):
    bridge = GhidraClaudeBridge(ghidra_path)

    for binary in Path(directory).glob("*.exe"):
        result = bridge.analyze_binary(str(binary), AnalysisType.VULNERABILITY_SCAN)
        bridge.export_for_claude(result, f"{binary.stem}_analysis.md")
        print(f"Analyzed: {binary.name}")
```

### Integration with Claude API

```python
# Example integration (requires anthropic package)
import anthropic

client = anthropic.Client(api_key="your-api-key")

# Get analysis from Ghidra
result = bridge.analyze_binary("sample.exe", AnalysisType.MALWARE_INDICATORS)
prompt = create_claude_prompt(result)

# Send to Claude
response = client.messages.create(
    model="claude-3-opus-20240229",
    messages=[{"role": "user", "content": prompt}]
)

print(response.content)
```

## Troubleshooting

### Common Issues

1. **Ghidra not found:**
   - Update `ghidra_path` in scripts
   - Ensure Ghidra is properly installed

2. **Java errors:**
   - Verify Java 17+ is installed
   - Check JAVA_HOME environment variable

3. **Script not appearing in Ghidra:**
   - Refresh Script Manager
   - Check script is in correct directory
   - Verify Python support in Ghidra

4. **Analysis timeout:**
   - Increase timeout in `ghidra_claude_bridge.py`
   - Consider analyzing smaller portions

### Debug Mode

```python
# Enable verbose output
import logging
logging.basicConfig(level=logging.DEBUG)

# Run with debug
bridge = GhidraClaudeBridge(ghidra_path)
bridge.debug = True
```

## Security Considerations

- **Binary Safety**: Always analyze untrusted binaries in isolated environments
- **Data Sensitivity**: Review exported data before sharing with Claude
- **API Keys**: Never commit API keys to version control
- **Network Isolation**: Consider air-gapped analysis for sensitive targets

## Contributing

Contributions are welcome! Areas for improvement:
- Additional analysis workflows
- Enhanced pattern detection
- Ghidra plugin development
- Claude prompt optimization
- Support for more file formats

## Resources

- **Ghidra Documentation**: https://ghidra.re/docs/
- **Claude Best Practices**: https://docs.anthropic.com/
- **Reverse Engineering**: https://github.com/tylerha97/awesome-reversing

## License

This framework is provided as-is for educational and legitimate security research purposes only.

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review Ghidra logs in `~/.ghidra/`
3. Verify all paths and dependencies

---

*Built with ♥ for the reverse engineering community*