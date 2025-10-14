# ML-SecTest: Machine Learning Security Testing Framework

<div align="center">

```
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ███╗   ███╗██╗         ███████╗███████╗ ██████╗████████╗███████╗  ║
║   ████╗ ████║██║         ██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔════╝  ║
║   ██╔████╔██║██║         ███████╗█████╗  ██║        ██║   █████╗    ║
║   ██║╚██╔╝██║██║         ╚════██║██╔══╝  ██║        ██║   ██╔══╝    ║
║   ██║ ╚═╝ ██║███████╗    ███████║███████╗╚██████╗   ██║   ███████╗  ║
║   ╚═╝     ╚═╝╚══════╝    ╚══════╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝  ║
║                                                                       ║
║         Machine Learning Security Testing Framework                  ║
║              Automated AI/ML Vulnerability Assessment                ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
```

**Automated Multi-Agent Framework for ML/AI Security Vulnerability Detection**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

## 🎯 Overview

ML-SecTest is a comprehensive, multi-agent security testing framework designed specifically for identifying vulnerabilities in Machine Learning and AI applications. Inspired by the [Machine Learning CTF Challenges](https://github.com/alexdevassy/Machine_Learning_CTF_Challenges) repository, this framework provides automated testing for the full spectrum of ML/AI security threats defined by OWASP and MITRE.

### Key Features

- **🤖 Multi-Agent Architecture**: Specialized agents for each vulnerability type
- **🎯 Game-Theoretic Coordination**: Von Neumann Nash equilibrium optimization for agent sequencing
- **💥 Fusion Attack Chains**: Edward Teller Agent executes multi-stage coordinated attacks
- **🔍 Comprehensive Coverage**: Tests for 7+ ML/AI attack vectors
- **📊 Professional Reporting**: HTML and JSON reports with detailed findings
- **⚡ Parallel Execution**: Optional parallel agent execution for faster assessments
- **🧠 Bayesian Learning**: Adaptive strategy optimization based on historical performance
- **🎓 CTF-Ready**: Pre-configured for popular ML CTF challenges
- **🛡️ Defensive Focus**: Built for security testing and vulnerability research

## 🏗️ Architecture

```
ml-sectest-framework/
├── core/                      # Core framework components
│   ├── base_agent.py         # Base agent class and data structures
│   ├── orchestrator.py       # Agent orchestration system
│   └── agent_coordinator.py  # Game-theoretic agent coordination
├── agents/                    # Specialized security agents
│   ├── prompt_injection_agent.py
│   ├── model_inversion_agent.py
│   ├── data_poisoning_agent.py
│   ├── model_extraction_agent.py
│   ├── model_serialization_agent.py
│   ├── adversarial_attack_agent.py
│   └── edward_teller_agent.py    # Fusion chain attack coordinator
├── utils/                     # Utility modules
│   └── report_generator.py   # Report generation system
├── api/                       # REST API
│   └── main.py               # FastAPI application
├── ml_sectest.py             # Main CLI application
└── requirements.txt          # Dependencies
```

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
cd ml-sectest-framework

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# List available CTF challenges
python ml_sectest.py list-challenges

# Test a specific challenge
python ml_sectest.py test-challenge vault

# Scan a custom target
python ml_sectest.py scan http://localhost:8000

# Parallel execution with JSON output
python ml_sectest.py scan http://target.com --parallel --format json
```

## 🎓 Supported CTF Challenges

Based on [alexdevassy/Machine_Learning_CTF_Challenges](https://github.com/alexdevassy/Machine_Learning_CTF_Challenges):

| Challenge | Difficulty | Attack Type | OWASP/MITRE |
|-----------|-----------|-------------|-------------|
| **Mirage** | Medium | MCP Signature Cloaking | OWASP LLM03:2025 |
| **Vault** | Hard | Model Inversion | OWASP ML03 |
| **Dolos** | Easy | Prompt Injection → RCE | OWASP LLM01, AML.T0051 |
| **Dolos II** | Easy | Prompt Injection → SQLi | OWASP LLM01, AML.T0051 |
| **Heist** | Medium | Data Poisoning | OWASP LLM03, ML02, AML.T0020 |
| **Persuade** | Medium | Model Serialization | OWASP LLM05, ML06, AML.T0010 |
| **Fourtune** | Hard | Model Extraction | OWASP LLM10, AML.T0044 |

## 🔬 Security Agents

### 1. Prompt Injection Agent
**Target**: LLM-based applications  
**Techniques**:
- Direct instruction override
- Indirect injection via data
- Delimiter escape
- Role reversal
- Nested instructions

**Example**:
```python
from agents import PromptInjectionAgent
from core.base_agent import AgentContext

agent = PromptInjectionAgent()
context = AgentContext(
    target_url="http://localhost:8000",
    challenge_name="Dolos",
    difficulty_level="Easy",
    owasp_reference="OWASP LLM01"
)
results = agent.execute(context)
```

### 2. Model Inversion Agent
**Target**: ML models with query access  
**Techniques**:
- Membership inference
- Attribute inference
- Training data extraction
- Gradient-based reconstruction

### 3. Data Poisoning Agent
**Target**: ML training pipelines  
**Techniques**:
- Label flipping
- Backdoor insertion
- Feature manipulation
- Availability attacks

### 4. Model Extraction Agent
**Target**: ML model APIs  
**Techniques**:
- Query-based extraction
- Decision boundary probing
- Architecture inference
- Knowledge distillation

### 5. Model Serialization Agent
**Target**: Model upload/loading systems  
**Techniques**:
- Pickle exploitation
- Malicious model upload
- Format confusion
- Deserialization attacks

### 6. Adversarial Attack Agent
**Target**: ML classifiers
**Techniques**:
- Input perturbation (FGSM-style)
- Boundary attacks
- Transfer attacks
- Evasion techniques

### 7. Edward Teller Agent (Fusion Chain Coordinator)
**Target**: Complex ML/AI systems requiring multi-stage attacks
**Vulnerability Type**: Fusion Attack

**Pre-configured Fusion Chains**:
- **Trinity**: Prompt Injection → Data Poisoning → Model Extraction
- **Ivy Mike**: Model Inversion → Serialization Exploit → Data Exfiltration
- **Castle Bravo**: Adversarial Input → Model Confusion → Backdoor Insertion
- **Tsar Bomba**: Full-spectrum coordinated attack (all agents)
- **Little Boy**: Rapid two-stage exploitation

**Cascade Amplification**: Each stage amplifies the next attack's effectiveness (1.5x-3.0x multiplier)

**Example**:
```python
from agents import EdwardTellerAgent
from core.base_agent import AgentContext

agent = EdwardTellerAgent()
context = AgentContext(
    target_url="http://localhost:8000",
    challenge_name="Advanced Defense System",
    difficulty_level="Hard"
)

# Agent automatically selects optimal fusion chain based on target
results = agent.execute(context)

# View blast radius analysis
print(f"Cascade Amplification: {results.metadata['cascade_amplification']}x")
print(f"Affected Systems: {results.metadata['blast_radius']['affected_systems']}")
```

## 🎮 Agent Coordinator (Game-Theoretic Optimization)

The Agent Coordinator uses **Von Neumann game theory** to optimize agent execution strategies.

### Coordination Strategies

1. **Nash Equilibrium Optimization**: Finds optimal agent sequences using game-theoretic Nash equilibrium
2. **Sequential Execution**: Traditional waterfall approach with dependency management
3. **Parallel Execution**: Concurrent agent execution for independent attacks
4. **Synergy Chains**: Exploits agent synergies for cascade amplification

### Synergy Matrix

The coordinator maintains a synergy matrix defining amplification effects between agents:

| Agent Pair | Synergy Score | Amplification |
|------------|---------------|---------------|
| Prompt Injection → Model Inversion | 2.5 | 150% effectiveness |
| Model Inversion → Data Poisoning | 2.0 | 100% effectiveness |
| Data Poisoning → Model Extraction | 2.2 | 120% effectiveness |
| Adversarial → Model Serialization | 1.8 | 80% effectiveness |

### Bayesian Learning

The coordinator adapts over time using Bayesian updates:
- Tracks historical attack success rates
- Updates confidence scores based on observed outcomes
- Recommends optimal strategies for similar targets

**Example**:
```python
from core.agent_coordinator import AgentCoordinator
from agents import PromptInjectionAgent, ModelInversionAgent

coordinator = AgentCoordinator()

# Register agents
coordinator.register_agent(PromptInjectionAgent())
coordinator.register_agent(ModelInversionAgent())

# Create optimal attack plan using Nash equilibrium
plan = coordinator.create_fusion_chain_plan(
    strategy="nash",
    max_chain_length=3,
    context=context
)

print(f"Strategy: {plan.strategy}")
print(f"Agent Sequence: {plan.agent_sequence}")
print(f"Expected Amplification: {plan.expected_amplification}x")

# Execute coordinated attack
results = coordinator.execute_coordinated_attack(context, plan)

# View synergy report
report = coordinator.get_synergy_report()
print(f"Total Attacks: {report['total_attacks']}")
print(f"Synergy Activations: {report['synergy_activations']}")
```

## 📊 Report Generation

ML-SecTest generates comprehensive security reports in multiple formats:

### HTML Reports
- Executive summary with visual indicators
- Detailed vulnerability findings
- Evidence and recommendations
- Color-coded severity levels

### JSON Reports
- Machine-readable format
- Complete test results
- Structured data for integration
- Timestamp and metadata

## 🎯 Example Workflow

```python
from core.orchestrator import SecurityOrchestrator, OrchestrationPlan
from agents import PromptInjectionAgent, ModelInversionAgent
from utils.report_generator import ReportGenerator

# Initialize components
orchestrator = SecurityOrchestrator()
report_gen = ReportGenerator()

# Register agents
orchestrator.register_agent(PromptInjectionAgent())
orchestrator.register_agent(ModelInversionAgent())

# Create test plan
plan = OrchestrationPlan(
    challenge_name="Vault Challenge",
    target_url="http://localhost:8000",
    difficulty_level="Hard",
    agent_sequence=["prompt_injection_001", "model_inversion_001"],
    parallel_execution=True,
    owasp_reference="OWASP ML03"
)

# Execute assessment
result = orchestrator.execute_plan(plan)

# Generate reports
html_report = report_gen.generate_html_report(result)
json_report = report_gen.generate_json_report(result)

print(f"Assessment complete!")
print(f"Status: {result.overall_status}")
print(f"Vulnerabilities: {len(result.vulnerabilities_found)}")
```

## 🛡️ Security & Ethics

**IMPORTANT**: This framework is designed for **DEFENSIVE SECURITY RESEARCH ONLY**.

### Acceptable Use
✅ Testing your own ML applications  
✅ Authorized penetration testing  
✅ Security research and education  
✅ CTF competitions and training  

### Prohibited Use
❌ Unauthorized testing of third-party systems  
❌ Malicious exploitation  
❌ Credential harvesting  
❌ Data theft or destruction  

## 🏆 Vulnerability Coverage

Aligned with industry standards:

- **OWASP Top 10 for LLM Applications**
  - LLM01: Prompt Injection
  - LLM03: Training Data Poisoning
  - LLM05: Supply Chain Vulnerabilities
  - LLM10: Model Theft

- **OWASP Top 10 for Machine Learning**
  - ML02: Data Poisoning Attack
  - ML03: Model Inversion Attack
  - ML06: Unsafe Model Deserialization

- **MITRE ATLAS (Adversarial ML)**
  - AML.T0010: ML Model Serialization
  - AML.T0020: Poison Training Data
  - AML.T0044: Full ML Model Access
  - AML.T0051: LLM Prompt Injection

## 📖 Advanced Usage

### Custom Agent Development

```python
from core.base_agent import BaseSecurityAgent, AgentContext, TestResult, VulnerabilityType

class CustomAgent(BaseSecurityAgent):
    def __init__(self):
        super().__init__(
            agent_id="custom_001",
            name="Custom Security Agent",
            description="Your custom vulnerability tests"
        )
    
    def _get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.PROMPT_INJECTION
    
    def analyze(self, context: AgentContext) -> TestResult:
        # Implement analysis logic
        pass
    
    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        # Implement exploitation logic
        pass
```

### Programmatic API

```python
from ml_sectest import MLSecTest

# Initialize framework
app = MLSecTest()

# Run assessment
app.test_challenge('vault', target_url='http://localhost:8000')

# Or custom scan
app.scan_target(
    target_url='http://custom-target.com',
    challenge_name='Custom Assessment',
    agents=['prompt_injection_001', 'model_inversion_001'],
    parallel=True,
    output_format='both'
)
```

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional security agents
- Enhanced detection techniques
- Improved reporting
- Extended CTF challenge support
- Performance optimizations

## 📚 References

- [Machine Learning CTF Challenges by alexdevassy](https://github.com/alexdevassy/Machine_Learning_CTF_Challenges)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Machine Learning Security Top 10](https://mltop10.info/)
- [MITRE ATLAS](https://atlas.mitre.org/)

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

This tool is provided for educational and defensive security purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors assume no liability for misuse of this software.

---

<div align="center">

**Built with ❤️ for the ML Security Community**

[Report Issues](https://github.com/yourusername/ml-sectest-framework/issues) • [Documentation](https://github.com/yourusername/ml-sectest-framework/wiki)

</div>
