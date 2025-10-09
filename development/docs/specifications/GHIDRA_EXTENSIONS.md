# Ghidra Extensions Repository Index

This repository contains a comprehensive collection of Ghidra extensions organized by functionality.
Each extension enhances Ghidra's capabilities for reverse engineering, malware analysis, and binary research.

## 📊 Extension Categories

### 🤖 AI & Analysis Tools

#### GhidrAssist
- **Purpose**: AI-powered analysis assistant for code understanding
- **Features**:
  - Integrates LLM APIs (OpenAI, Anthropic, Ollama, etc.)
  - Context-aware code explanations
  - MCP (Model Context Protocol) support
  - RAG (Retrieval-Augmented Generation) capabilities
- **Location**: `development/GhidrAssist/`
- **Language**: Java
- **Documentation**: README.md, screenshots available

#### ghidra-scripts-bitsofbinary
- **Purpose**: Stack string and dynamic API analysis
- **Features**:
  - Stack string decoding and recovery
  - Dynamic API resolution
  - Advanced static analysis techniques
- **Location**: `development/ghidra-scripts-bitsofbinary/`
- **Language**: Python
- **Example**: Animated GIF demonstration available

#### capa-explorer
- **Purpose**: FLARE-capa integration for capability detection
- **Features**:
  - Rule-based behavior identification
  - Malware capability analysis
  - Integration with Mandiant's capa framework
- **Location**: `development/capa-explorer/`
- **Status**: Integration pending

### 🎨 UI & Navigation Enhancements

#### GhidraCtrlP
- **Purpose**: Command palette for quick navigation (Ctrl+P style)
- **Features**:
  - Fast fuzzy search for functions, labels, and symbols
  - Keyboard-driven workflow
  - IDE-like navigation experience
- **Location**: `development/GhidraCtrlP/`
- **Language**: Python/Java
- **Documentation**: Screenshots in docs/

#### GhidraLookup
- **Purpose**: Windows API documentation lookup
- **Features**:
  - Instant API documentation access
  - Parameter and return value information
  - Context-aware help system
- **Location**: `development/GhidraLookup/`
- **Language**: Java
- **Build**: Gradle

### 🐍 Scripting & Automation Platforms

#### Ghidrathon
- **Purpose**: Full Python 3 scripting support in Ghidra
- **Features**:
  - Native Python 3 interpreter via Jep
  - Full Ghidra API access from Python
  - Virtual environment support
  - Package management capabilities
- **Location**: `development/Ghidrathon/`
- **Language**: Java/Python
- **CI/CD**: GitHub Actions workflows included

#### Ghidraaas
- **Purpose**: REST API service for Ghidra automation
- **Features**:
  - RESTful API wrapper
  - Remote analysis capabilities
  - JSON request/response format
  - Docker support
- **Location**: `development/Ghidraaas/`
- **Language**: Python (Flask)
- **Docker**: Dockerfile included

### 🔧 Specialized Analysis Tools

#### ghidra_scripts
- **Purpose**: Collection of utility and analysis scripts
- **Features**:
  - ARM/MIPS ROP gadget finders
  - Function profiling
  - Code/Data fixup utilities
  - Rizzo function matching
- **Location**: `development/ghidra_scripts/`
- **Language**: Python
- **Documentation**: Extensive readmes with screenshots

#### golang_loader_assist
- **Purpose**: Go binary analysis support
- **Features**:
  - Enhanced Go binary parsing
  - Type recovery
  - Struct reconstruction
  - Go-specific calling conventions
- **Location**: `development/golang_loader_assist/`
- **Language**: Python
- **Test Files**: Sample Go binaries included

#### esp32_flash_loader
- **Purpose**: ESP32 firmware analysis
- **Features**:
  - Flash dump loading and parsing
  - Partition table analysis
  - Firmware extraction
  - ESP32/ESP8266 support
- **Location**: `development/esp32_flash_loader/`
- **Language**: Java
- **Build**: Gradle with CI/CD

#### HyperDbg-Scripts
- **Purpose**: Hypervisor debugging integration
- **Features**:
  - HyperDbg debugger integration
  - Kernel-level debugging
  - VMX/SVM support
- **Location**: `development/HyperDbg-Scripts/`
- **Status**: Scripts collection

## 🚀 Quick Start Guide

### Installation Priority
1. **Essential**: Ghidrathon (Python support)
2. **Productivity**: GhidraCtrlP, GhidraLookup
3. **Analysis**: GhidrAssist, ghidra_scripts
4. **Specialized**: golang_loader_assist, esp32_flash_loader

### Building Extensions
Most extensions use Gradle and can be built with:
```bash
cd development/[extension-name]/
gradle build
```

### Python Script Installation
Copy Python scripts to Ghidra's script directories:
```bash
cp development/ghidra_scripts/*.py $GHIDRA_HOME/ghidra_scripts/
```

## 📖 Documentation Status

| Extension | README | HTML Docs | Examples | Tests |
|-----------|--------|-----------|----------|-------|
| GhidrAssist | ✅ | ⚪ | ✅ | ⚪ |
| GhidraCtrlP | ✅ | ⚪ | ✅ | ⚪ |
| GhidraLookup | ✅ | ⚪ | ⚪ | ✅ |
| Ghidrathon | ✅ | ⚪ | ✅ | ✅ |
| Ghidraaas | ✅ | ⚪ | ✅ | ✅ |
| ghidra_scripts | ✅ | ⚪ | ✅ | ⚪ |
| golang_loader_assist | ✅ | ⚪ | ✅ | ⚪ |
| esp32_flash_loader | ✅ | ⚪ | ⚪ | ⚪ |

## 🔄 Recent Updates

- **2025-09-28**: Organized and committed all Ghidra extensions
- **Phase 1**: AI and analysis tools added
- **Phase 2**: UI enhancements integrated
- **Phase 3**: Scripting platforms configured
- **Phase 4**: Specialized loaders committed

## 🤝 Contributing

Each extension may have its own contribution guidelines. Check individual README files for specific requirements.

## 📝 License

Extensions have various licenses. Check individual LICENSE files in each extension directory.

## 🔗 External Resources

- [Ghidra Official Documentation](https://ghidra-sre.org/)
- [NSA Ghidra GitHub](https://github.com/NationalSecurityAgency/ghidra)
- [Ghidra Scripts Collection](https://github.com/AllsafeCyberSecurity/awesome-ghidra)

---

*This index is maintained as part of the development environment organization effort.*