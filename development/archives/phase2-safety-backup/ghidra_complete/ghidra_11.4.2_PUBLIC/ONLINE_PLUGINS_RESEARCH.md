# Ghidra Online Plugins Research 2025

## 🔍 **Top GitHub Repositories by Stars**

### **Tier 1: High-Impact Plugins (100+ stars)**

#### 1. **grayhatacademy/ghidra_scripts** (492⭐)
- **Description**: Port of devttyS0's IDA plugins to Ghidra framework
- **Features**: ARM/MIPS ROP gadgets, exploit development, binary analysis tools
- **Status**: ✅ **Already deployed** in our installation

#### 2. **Cisco-Talos/Ghidraaas** (226⭐)  
- **Description**: Ghidra as a Service platform
- **Features**: Web-based Ghidra access, API endpoints
- **Deployment**: Server-side solution (not plugin)

#### 3. **kotcrab/ghidra-allegrex** (110⭐)
- **Description**: Processor module for Sony PSP's Allegrex CPU
- **Features**: MIPS-based processor support, PSP homebrew analysis
- **Deployment**: Specialized processor module

### **Tier 2: Active Community Plugins (20-100 stars)**

#### 4. **diommsantos/Gx64Sync** (87⭐)
- **Description**: Ghidra ↔ x64Dbg synchronization plugin
- **Features**: Real-time debugging sync, breakpoint sharing
- **Use Case**: Dynamic analysis integration

#### 5. **goatshriek/ruby-dragon** (47⭐) 
- **Description**: Multi-language scripting support
- **Features**: Ruby, Kotlin, Groovy, Clojure, JShell interpreters
- **Deployment**: Enhanced scripting capabilities

#### 6. **msm-code/GhidraCtrlP** (36⭐)
- **Description**: VS Code-style quick search and command palette
- **Features**: Instant symbol/function search, keyboard shortcuts
- **Status**: ✅ **Already deployed** as scripts

## 🤖 **AI-Powered Extensions (2025 Trending)**

### **GhidrAssist** - LLM Integration
- **Repository**: jtang613/GhidrAssist
- **Description**: AI assistant for reverse engineering tasks
- **Features**:
  - Function explanation (assembly & pseudo-C)  
  - Instruction analysis
  - General LLM queries from Ghidra UI
  - RAG (Retrieval Augmented Generation)
  - MCP client for agentic workflows
- **Supported Models**: Llama3.1:8b, DeepSeek, GPT-4o-mini, Claude Sonnet
- **API Support**: OpenAI v1-compatible APIs, Ollama, LM-Studio

### **Ghidrathon** - Python 3 Integration
- **Repository**: mandiant/Ghidrathon (FLARE team)
- **Description**: Modern Python 3 scripting for Ghidra
- **Features**:
  - CPython 3.8+ support (replaces Jython 2.7)
  - Integration with capa, Unicorn Engine, angr
  - Virtual environment support
  - Interactive interpreter window
- **Requirements**: Python ≥3.8, Jep 4.2.0, Ghidra ≥10.3.2

### **Other AI Extensions**
- **Decyx**: Claude-powered function naming and commenting
- **GhidrOllama**: Local LLM code explanation via Ollama

## 🛡️ **Malware Analysis Specialists**

### **Crypto Detection**
- **py-findcrypt-ghidra**: Python implementation of IDA's FindCrypt
- **FindCrypt-Ghidra**: Updated crypto constants database

### **Behavioral Analysis**
- **CapaExplorer**: CAPA malware capability importer
- **tiny_tracer_tag_annotate**: Dynamic tracing annotation

### **Platform-Specific**
- **JNI Helper**: Android APK analysis for native functions
- **gotools**: Golang binary reverse engineering
- **Ghidra-evm**: Ethereum smart contract analysis

## 🔧 **Development & Integration Tools**

### **Debugging Synchronization**
- **ret-sync**: Multi-debugger synchronization (faster than original)
- **Gx64Sync**: x64Dbg ↔ Ghidra real-time sync

### **Jupyter Integration**
- **ghidra_bridge**: Python 3 bridge for external scripting
- **ipyghidra**: Enhanced IPython console
- **ghidra-jython-kernel**: Jupyter kernel integration

### **Analysis Enhancement**
- **OOAnalyzer**: Object-oriented construct recovery
- **Ghidra Patch Diff Correlator**: Advanced version tracking
- **pcode-emulator**: P-code instruction emulation

## 📦 **Package Repositories**

### **Nix Package Set: ghidra-extensions**
Contains 12+ pre-packaged extensions:
- findcrypt, firmware-utils, golang analyzer
- machine learning extensions, processor modules

### **Community Curations**
- **AllsafeCyberSecurity/awesome-ghidra**: Comprehensive plugin directory
- **GitHub Topics**: `ghidra-plugins`, `ghidra-extension`, `ghidra-plugin`

## 🎯 **Deployment Priority Recommendations**

### **High Priority (Production Ready)**
1. **Ghidrathon** - Essential Python 3 upgrade
2. **GhidrAssist** - AI-powered analysis (if local LLM available)
3. **ret-sync** - Multi-debugger integration
4. **CapaExplorer** - Malware capability analysis

### **Medium Priority (Specialized Use Cases)**
5. **gotools** - For Golang binary analysis
6. **ruby-dragon** - Multi-language scripting
7. **JNI Helper** - Android/Java analysis
8. **Ghidra-evm** - Blockchain smart contracts

### **Development/Advanced**
9. **OOAnalyzer** - Advanced object-oriented analysis
10. **ghidra_bridge** - External Python integration

## 🔗 **Installation Methods**

### **Extension Archives (.zip)**
- Download from GitHub releases
- Install via Ghidra: File → Install Extensions

### **Scripts Collection**  
- Clone repositories to `ghidra_scripts/` directory
- Refresh Script Manager to detect new scripts

### **Processor Modules**
- Extract to Ghidra processor directories
- Requires Ghidra restart for language detection

## ⚡ **Current Status**
- ✅ **34 Built-in features** + **7 extensions** deployed
- ✅ **40+ community scripts** installed (GrayHat Academy collection)
- 🎯 **10+ high-value plugins** identified for potential deployment
- 🚀 **System ready** for advanced plugin integration

## 📈 **2025 Trends**
- **AI Integration**: LLM-powered analysis becoming standard
- **Python 3 Migration**: Moving away from legacy Jython 2.7  
- **Cross-Tool Synchronization**: Real-time debugging workflows
- **Specialized Analysis**: Platform-specific tools (Android, blockchain, IoT)