# Development Workspace Organization Guide

This repository contains various development projects, scripts, and tools organized for efficient workflow and maintainability.

## 📁 Directory Structure

```
C:\Users\Corbin\
├── development/          # Main development directory (MCP accessible)
│   ├── shared/          # Shared libraries and components
│   ├── agents/          # MCP agents and automation
│   ├── monitoring/      # System monitoring tools
│   ├── docker/          # Docker configurations
│   ├── k8s/            # Kubernetes manifests
│   └── scripts/        # Development automation scripts
│
├── scripts/            # Organized utility scripts
│   ├── pdf_tools/      # PDF processing and manipulation
│   │   ├── requirements.txt
│   │   └── *.py        # PDF conversion, extraction tools
│   ├── monitoring/     # System and network monitoring
│   │   ├── requirements.txt
│   │   └── *.py        # Wireshark, genetic monitors
│   ├── utilities/      # Shared utility modules
│   │   ├── requirements.txt
│   │   ├── utillogging.py
│   │   └── utils.py
│   └── testing/        # Test scripts and examples
│       └── *.py        # Test implementations
│
├── projects/           # Individual project directories
│   ├── pdf-processor/  # PDF processing project
│   ├── wireshark-monitor/ # Network monitoring project
│   └── genetic-simulation/ # Genetic algorithm simulations
│
├── config/            # Configuration files
│   └── templates/     # Configuration templates
│
├── styles/            # Styling and templates
│   ├── css/          # CSS stylesheets
│   └── templates/    # HTML templates
│
├── docs/             # Documentation
│   └── guides/       # How-to guides and references
│
└── tests/           # Test suites
```

## 🚀 Quick Start

### Setting Up Python Environment

1. **Create a virtual environment** (recommended for each project):
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   source venv/bin/activate  # On Linux/Mac
   ```

2. **Install dependencies** for specific tools:
   ```bash
   # For PDF tools
   pip install -r scripts/pdf_tools/requirements.txt
   
   # For monitoring tools
   pip install -r scripts/monitoring/requirements.txt
   
   # For utilities
   pip install -r scripts/utilities/requirements.txt
   ```

### Using the Scripts

#### PDF Processing Tools
Located in `scripts/pdf_tools/`:
- `html_to_pdf.py` - Convert HTML files to PDF
- `extract_pdf_images.py` - Extract images from PDF files
- `document_pipeline.py` - Complete document processing pipeline
- `rename_images.py` - Batch rename image files

Example usage:
```bash
python scripts/pdf_tools/html_to_pdf.py input.html output.pdf
```

#### Monitoring Tools
Located in `scripts/monitoring/`:
- `wireshark_genetic_monitor.py` - Network monitoring with genetic algorithms

#### Shared Utilities
Located in `scripts/utilities/`:
- `utillogging.py` - Centralized logging utilities
- `utils.py` - Common helper functions

## 🔧 Development Workflow

### MCP (Model Context Protocol) Setup
The `development/` directory is configured for MCP access, enabling:
- Automated file operations
- Agent-based development
- Integrated testing and monitoring

MCP configuration is stored in `.mcp.json` (excluded from version control backups).

### Git Configuration
A comprehensive `.gitignore` file is configured to:
- Exclude system files (Windows, macOS, Linux)
- Ignore credentials and sensitive data
- Skip cache and temporary files
- Exclude large binaries and archives
- Keep essential configuration files

### Best Practices

1. **Virtual Environments**: Always use virtual environments for Python projects
2. **Dependencies**: Keep requirements.txt files updated for each project
3. **Testing**: Write tests in the `tests/` directory
4. **Documentation**: Update docs when adding new features
5. **Version Control**: Commit logical units of work with clear messages

## 📋 Project Status

### Active Projects
- **PDF Processor**: Tools for PDF generation and manipulation
- **Wireshark Monitor**: Network traffic analysis with genetic algorithms
- **Development Environment**: MCP-enabled development tools

### Maintenance Notes
- Regular cleanup of cache directories
- Update dependencies quarterly
- Review and archive old projects

## 🛡️ Security Considerations

- Never commit credentials or API keys
- Use environment variables for sensitive configuration
- Keep `.ssh/` and authentication directories in .gitignore
- Review commits for accidental sensitive data exposure

## 📚 Additional Resources

- [MCP Documentation](development/MCP_AGENT_ARCHITECTURE_PLAN.md)
- [Security Implementation](development/CLAUDE_SECURITY_IMPLEMENTATION.md)
- [Workflow Architecture](development/WORKFLOW_ARCHITECTURE.md)
- [Director Agent Documentation](docs/director-agent-readme.md)

## 🤝 Contributing

When adding new scripts or projects:
1. Place them in the appropriate directory
2. Create a requirements.txt if needed
3. Update this README
4. Follow existing code style and conventions
5. Add appropriate tests

---

*Last Updated: September 2024*
*Organization Structure Version: 1.0*
