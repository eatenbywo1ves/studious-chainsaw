# ML-SecTest Framework Architecture

## System Overview

ML-SecTest is a modular, extensible framework for automated security testing of Machine Learning and AI applications. The architecture follows a multi-agent pattern where specialized agents independently test for specific vulnerability types, coordinated by a central orchestrator.

## Architectural Principles

1. **Separation of Concerns**: Each agent focuses on a single vulnerability type
2. **Extensibility**: New agents can be added without modifying existing code
3. **Composability**: Agents can be combined in different configurations
4. **Observability**: Comprehensive logging and reporting at every level
5. **Defensive Security**: Built exclusively for authorized security testing

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ML-SecTest CLI                          │
│                   (ml_sectest.py)                          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Security Orchestrator                          │
│            (core/orchestrator.py)                          │
│  • Agent Registration                                      │
│  • Execution Planning                                      │
│  • Parallel/Sequential Coordination                        │
│  • Result Aggregation                                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
┌──────────────────┐        ┌──────────────────┐
│  Agent Pool      │        │  Report Gen      │
│                  │        │  (utils/)        │
├──────────────────┤        ├──────────────────┤
│ • Prompt Inj     │        │ • HTML Reports   │
│ • Model Inv      │        │ • JSON Exports   │
│ • Data Poison    │        │ • Visualizations │
│ • Model Extract  │        └──────────────────┘
│ • Serialization  │
│ • Adversarial    │
└──────────────────┘
```

## Core Components

### 1. Base Agent (`core/base_agent.py`)

**Purpose**: Abstract base class defining the agent contract

**Key Classes**:
- `BaseSecurityAgent`: Abstract agent implementation
- `AgentContext`: Execution context data
- `TestResult`: Result encapsulation
- `VulnerabilityType`: Enumeration of vulnerability types
- `AgentStatus`: Agent state tracking

**Lifecycle**:
```python
BaseSecurityAgent.execute(context)
    ├── analyze(context) → TestResult
    │   └── Identify potential vulnerabilities
    └── exploit(context, analysis_result) → TestResult
        └── Validate vulnerabilities through controlled exploitation
```

**Key Methods**:
- `analyze()`: Passive vulnerability detection
- `exploit()`: Active vulnerability validation
- `execute()`: Complete test workflow orchestration

### 2. Security Orchestrator (`core/orchestrator.py`)

**Purpose**: Coordinate multiple agents for comprehensive assessment

**Key Classes**:
- `SecurityOrchestrator`: Main coordination engine
- `OrchestrationPlan`: Test execution specification
- `OrchestrationResult`: Aggregated test results

**Execution Modes**:

#### Sequential Execution
```python
for agent in agent_sequence:
    result = agent.execute(context)
    aggregate_results(result)
```

#### Parallel Execution
```python
with ThreadPoolExecutor(max_workers=N) as executor:
    futures = [executor.submit(agent.execute, context) 
               for agent in agents]
    results = [f.result() for f in as_completed(futures)]
```

**Features**:
- Dynamic agent registration
- Flexible execution strategies
- Real-time progress tracking
- Result correlation and aggregation

### 3. Specialized Security Agents

Each agent inherits from `BaseSecurityAgent` and implements specialized testing logic:

#### Prompt Injection Agent (`agents/prompt_injection_agent.py`)
**Target**: LLM applications  
**Techniques**:
- System instruction override
- Delimiter escape
- Role manipulation
- Nested injections
- Secondary payload injection (SQL, RCE)

**Test Flow**:
```
1. Initialize 10 test payloads
2. Submit each to target
3. Analyze responses for vulnerability indicators
4. If found, attempt flag extraction
5. Generate recommendations
```

#### Model Inversion Agent (`agents/model_inversion_agent.py`)
**Target**: ML models with prediction APIs  
**Techniques**:
- Membership inference
- Attribute inference
- Training data extraction
- Confidence-based reconstruction

**Test Flow**:
```
1. Test confidence score exposure
2. Check model determinism
3. Measure output granularity
4. Probe for rate limiting
5. Attempt data extraction
```

#### Data Poisoning Agent (`agents/data_poisoning_agent.py`)
**Target**: ML training pipelines  
**Techniques**:
- Label flipping
- Backdoor insertion
- Feature corruption
- Availability degradation

#### Model Extraction Agent (`agents/model_extraction_agent.py`)
**Target**: ML model APIs  
**Techniques**:
- Query-based extraction
- Decision boundary mapping
- Architecture probing
- Knowledge distillation

#### Model Serialization Agent (`agents/model_serialization_agent.py`)
**Target**: Model upload/deserialization endpoints  
**Techniques**:
- Pickle exploitation
- Format confusion
- Malicious payload embedding
- Supply chain attacks

#### Adversarial Attack Agent (`agents/adversarial_attack_agent.py`)
**Target**: ML classifiers  
**Techniques**:
- Input perturbation (FGSM-inspired)
- Boundary attacks
- Transfer attacks
- Evasion optimization

### 4. Report Generator (`utils/report_generator.py`)

**Purpose**: Professional security report generation

**Output Formats**:

#### HTML Reports
- Executive summary with metrics
- Visual severity indicators
- Detailed vulnerability findings
- Evidence documentation
- Remediation recommendations
- Responsive design

#### JSON Reports
- Machine-readable structure
- Complete test metadata
- Structured evidence
- Programmatic integration support

**Report Structure**:
```json
{
  "metadata": {
    "generated_at": "ISO8601",
    "framework": "ML-SecTest",
    "version": "1.0.0"
  },
  "assessment": {
    "challenge_name": "...",
    "target_url": "...",
    "duration_seconds": 123.45
  },
  "results": {
    "overall_status": "vulnerable|secure|critical",
    "success_rate": 75.0,
    "vulnerabilities_found": [...],
    "agent_results": {...}
  }
}
```

## Data Flow

### Complete Assessment Flow

```
┌──────────────┐
│  User Input  │
│  (CLI/API)   │
└──────┬───────┘
       │
       ▼
┌────────────────────┐
│ Create             │
│ OrchestrationPlan  │
│  • Target URL      │
│  • Agent Selection │
│  • Parameters      │
└──────┬─────────────┘
       │
       ▼
┌─────────────────────┐
│ Orchestrator.       │
│ execute_plan()      │
└──────┬──────────────┘
       │
       ├──► Agent 1 ──► TestResult[]
       ├──► Agent 2 ──► TestResult[]
       └──► Agent N ──► TestResult[]
       │
       ▼
┌─────────────────────┐
│ Aggregate Results   │
│  • Calculate stats  │
│  • Identify vulns   │
│  • Determine status │
└──────┬──────────────┘
       │
       ▼
┌─────────────────────┐
│ OrchestrationResult │
└──────┬──────────────┘
       │
       ├──► HTML Report
       └──► JSON Report
```

### Agent Execution Flow

```
┌──────────────┐
│ AgentContext │
└──────┬───────┘
       │
       ▼
┌─────────────────┐
│ agent.analyze() │
│  • Passive tests│
│  • Vulnerability│
│    detection    │
└──────┬──────────┘
       │
       ▼
    TestResult
    (Analysis)
       │
       ▼
   Success?
       │
   ┌───┴───┐
   │ Yes   │ No → Skip Exploitation
   │       │
   ▼       │
┌──────────┴──────┐
│ agent.exploit() │
│  • Active tests │
│  • Validation   │
└──────┬──────────┘
       │
       ▼
    TestResult[]
    (Complete)
```

## Extension Points

### Adding New Agents

```python
from core.base_agent import BaseSecurityAgent, VulnerabilityType

class NewVulnerabilityAgent(BaseSecurityAgent):
    def __init__(self):
        super().__init__(
            agent_id="new_vuln_001",
            name="New Vulnerability Agent",
            description="Description of what this tests"
        )
    
    def _get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.PROMPT_INJECTION  # Or add new type
    
    def analyze(self, context: AgentContext) -> TestResult:
        # Implement analysis logic
        pass
    
    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        # Implement exploitation logic
        pass
```

### Custom Report Formats

```python
from utils.report_generator import ReportGenerator

class CustomReportGenerator(ReportGenerator):
    def generate_pdf_report(self, result: OrchestrationResult) -> str:
        # Implement PDF generation
        pass
    
    def generate_slack_notification(self, result: OrchestrationResult):
        # Implement Slack integration
        pass
```

## Security Considerations

### Built-in Safeguards

1. **Defensive Testing Only**: All agents designed for vulnerability validation, not exploitation
2. **Request Timeouts**: Prevent resource exhaustion (default: 5s per request)
3. **Safe Payloads**: Test payloads designed to prove vulnerability without causing harm
4. **Rate Limiting Awareness**: Agents detect and respect rate limits
5. **Error Isolation**: Agent failures don't cascade to other agents

### Ethical Guidelines

```python
# GOOD: Testing for vulnerability
response = requests.post(target, json={"input": "test_payload"}, timeout=5)
if "flag{" in response.text:
    evidence.append("Vulnerability confirmed")

# BAD: Actual exploitation
# ❌ DO NOT implement credential theft
# ❌ DO NOT implement data exfiltration
# ❌ DO NOT implement persistent backdoors
```

## Performance Characteristics

### Sequential Execution
- **Latency**: Sum of all agent execution times
- **Memory**: O(1) - one agent at a time
- **CPU**: Single-threaded

### Parallel Execution
- **Latency**: Max of all agent execution times
- **Memory**: O(N) - all agents in memory
- **CPU**: Multi-threaded up to `max_workers`

### Scalability
- **Agents**: Linear scaling (independent execution)
- **Targets**: Embarrassingly parallel (can test multiple targets)
- **Reports**: Constant time generation regardless of result size

## Testing the Framework

### Unit Testing Pattern

```python
def test_agent_vulnerability_detection():
    agent = PromptInjectionAgent()
    context = AgentContext(
        target_url="http://mock-target/api",
        challenge_name="Test",
        difficulty_level="Easy",
        owasp_reference="OWASP LLM01"
    )
    
    results = agent.execute(context)
    
    assert len(results) > 0
    assert results[0].vulnerability_type == VulnerabilityType.PROMPT_INJECTION
```

### Integration Testing Pattern

```python
def test_full_assessment_workflow():
    orchestrator = SecurityOrchestrator()
    orchestrator.register_agent(PromptInjectionAgent())
    
    plan = OrchestrationPlan(...)
    result = orchestrator.execute_plan(plan)
    
    assert result.overall_status in ["secure", "vulnerable", "critical"]
    assert result.total_duration_seconds > 0
```

## Future Architecture Enhancements

1. **Async Execution**: Replace threading with asyncio for better scalability
2. **Distributed Testing**: Support for multi-machine distributed assessment
3. **Real-time Streaming**: WebSocket-based progress updates
4. **Plugin System**: Dynamic agent loading from external packages
5. **ML-Powered Analysis**: Use ML to correlate findings across agents
6. **Continuous Monitoring**: Schedule periodic assessments
7. **Integration APIs**: REST API for programmatic access

## References

- OWASP Top 10 for LLM Applications
- OWASP Machine Learning Security Top 10
- MITRE ATLAS Framework
- NIST AI Risk Management Framework
