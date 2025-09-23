# Code Analysis Agent

A **100% offline, zero-traffic** Python code quality analyzer that runs entirely on your local machine.

## 🎯 Features

### Core Capabilities
- **Static Code Analysis** - Analyzes Python code without executing it
- **Complexity Metrics** - Calculates cyclomatic complexity scores
- **Documentation Coverage** - Measures docstring coverage for functions and classes
- **Code Quality Metrics** - Lines of code, comments, blank lines, etc.
- **TODO Tracking** - Finds and counts TODO, FIXME, XXX, and other markers
- **Issue Detection** - Identifies potential code quality issues
- **Automated Reporting** - Generates markdown reports with recommendations

### Why This Agent is Traffic-Free
- Uses Python's built-in `ast` module for analysis
- No external API calls or package downloads
- Reads only local files from your filesystem
- Stores reports locally in your development directory
- No telemetry or analytics collection

## 📊 Metrics Collected

### File-Level Metrics
- **Lines of Code** - Total lines in the file
- **Comment Lines** - Number of comment lines (excluding docstrings)
- **Docstring Lines** - Lines within docstrings
- **Blank Lines** - Empty lines for readability
- **Functions** - Number of standalone functions
- **Classes** - Number of class definitions
- **Methods** - Number of methods within classes
- **Complexity Score** - Cyclomatic complexity measurement
- **Documentation Coverage** - Percentage of documented functions/classes
- **Test Coverage Estimate** - Rough estimate based on test function presence
- **TODO Count** - Number of TODO/FIXME comments
- **Import Count** - Number of import statements
- **Global Variables** - Count of module-level variables

### Issue Detection
The agent automatically detects:
- High complexity functions (score > 20)
- Low documentation coverage (< 50%)
- Excessive TODO comments (> 5 per file)
- Too many global variables (> 10)

## 🚀 Usage

### Running the Agent

```python
# Direct execution
python agent.py

# Or import and use programmatically
from agent import CodeAnalysisAgent
import asyncio

async def run():
    agent = CodeAnalysisAgent()
    results = await agent.analyze_directory(Path("your/code/directory"))
    print(f"Analyzed {results['files_analyzed']} files")
    print(f"Average complexity: {results['total_metrics']['average_complexity']:.1f}")

asyncio.run(run())
```

### Configuration

Edit `config.json` to customize:

```json
{
  "scan_interval": 300,  // Seconds between scans
  "directories": [        // Directories to analyze
    "C:\\Users\\Corbin\\development"
  ],
  "exclude_patterns": [   // Patterns to skip
    "__pycache__",
    "node_modules",
    ".git"
  ],
  "thresholds": {        // Issue detection thresholds
    "complexity_warning": 20,
    "documentation_warning": 50
  }
}
```

## 📈 Example Output

```
CODE ANALYSIS REPORT
====================
Generated: 2025-01-10T15:30:00
Directory: C:\Users\Corbin\development
Files Analyzed: 42

Summary Metrics:
- Total Lines of Code: 8,543
- Total Functions: 156
- Total Classes: 23
- Average Complexity: 12.4
- Average Documentation: 67.8%
- Total TODOs: 18

Issues Found:
- High complexity in validation_demo.py (score: 28)
- Low documentation in test_implementations.py (45.2%)

Recommendations:
- Consider refactoring complex functions
- Add docstrings to improve documentation coverage
```

## 🏗️ Architecture

```
CodeAnalysisAgent
├── CodeAnalyzer           # Core analysis engine
│   ├── analyze_file()     # Analyze single file
│   ├── calculate_metrics() # Compute code metrics
│   └── detect_issues()    # Find quality issues
├── analyze_directory()    # Batch analysis
├── generate_report()      # Create markdown reports
└── run()                  # Main agent loop
```

## 🔧 Technical Details

### How It Works
1. **AST Parsing** - Uses Python's Abstract Syntax Tree to parse code structure
2. **Static Analysis** - Analyzes code without execution (completely safe)
3. **Pattern Matching** - Uses regex for TODO/FIXME detection
4. **Metric Calculation** - Computes various quality metrics
5. **Report Generation** - Creates actionable reports with recommendations

### Performance
- Analyzes ~1000 lines/second
- Low memory footprint (~50MB)
- No network latency (100% local)
- Configurable scan intervals

## 📝 Reports

Reports are automatically saved to:
```
C:\Users\Corbin\development\logs\code-analysis\
├── analysis_20250110_153000.md
├── analysis_20250110_160000.md
└── ...
```

Each report includes:
- Summary metrics
- Issue list with severity
- Recommendations for improvement
- Top complex files
- Documentation coverage statistics

## 🛡️ Privacy & Security

- **No Network Access** - Runs entirely offline
- **No Data Collection** - Your code never leaves your machine
- **No Dependencies** - Uses only Python standard library
- **Read-Only** - Never modifies your code files
- **Local Storage** - Reports stored locally only

## 🚦 Agent Status

The agent registers with the local agent registry and reports:
- Running/stopped status
- Last analysis timestamp
- Directories being monitored
- Total files analyzed

## 💡 Use Cases

- **Continuous Quality Monitoring** - Run in background to track code quality over time
- **Pre-Commit Checks** - Analyze code before committing
- **Technical Debt Tracking** - Monitor complexity and TODO accumulation
- **Documentation Audits** - Ensure adequate documentation coverage
- **Code Review Assistance** - Identify issues before peer review

## 🎯 Future Enhancements

Potential additions (all still offline):
- Support for more languages (JavaScript, TypeScript)
- Duplicate code detection
- Security vulnerability scanning (using local rules)
- Custom linting rules
- Integration with git hooks
- Trend analysis over time

## 📜 License

This agent is part of your local development environment and operates under your project's license.

---

**Status**: ✅ Fully Operational | **Network Traffic**: 🚫 Zero | **Privacy**: 🔒 100% Local