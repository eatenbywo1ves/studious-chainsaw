# Defensive Security Agent Framework

**Status**: ✅ Operational Framework
**Purpose**: Multi-agent security automation for defensive operations
**Architecture**: Perceive → Decide → Act → Learn
**Scope**: DEFENSIVE SECURITY ONLY

---

## Overview

The Defensive Security Agent Framework provides base classes and abstractions for building autonomous security agents that follow industry-standard cybersecurity practices. All agents operate under strict defensive principles.

## Architecture

### Agent Lifecycle Pattern

```
┌──────────────┐
│   PERCEIVE   │  Gather state from environment
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    DECIDE    │  Analyze state & make decision
└──────┬───────┘
       │
       ▼
┌──────────────┐
│     ACT      │  Execute defensive action
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    LEARN     │  Update knowledge base
└──────────────┘
```

### Core Components

#### 1. **BaseAgent** (agent_framework.py)
Abstract base class for all security agents implementing the lifecycle pattern.

**Key Methods:**
- `perceive(container_id)` → AgentState: Observe environment
- `decide(state)` → AgentDecision: Make security decision
- `act(decision)` → AgentOutcome: Execute defensive action
- `learn(outcome)` → None: Update knowledge base

#### 2. **AgentAction** (Enum)
Predefined defensive actions:
- `LOG_INFO`: Log informational event
- `ALERT_WARNING`: Raise warning alert
- `ALERT_CRITICAL`: Raise critical alert
- `REMEDIATE`: Apply automatic fix
- `STOP_CONTAINER`: Stop compromised container
- `ISOLATE_CONTAINER`: Network isolate container

#### 3. **Data Structures**
- **AgentState**: Current environment observation
- **AgentDecision**: Agent's decision with confidence score
- **AgentOutcome**: Result of executed action

## Example: Creating a Custom Agent

```python
from agent_framework import BaseAgent, AgentState, AgentDecision, AgentAction

class ResourceMonitorAgent(BaseAgent):
    """Monitor container resources for anomalies"""

    def perceive(self, container_id: str) -> AgentState:
        """Observe container metrics"""
        metrics = self._get_container_metrics(container_id)
        return AgentState(
            timestamp=datetime.now(),
            container_id=container_id,
            data=metrics
        )

    def decide(self, state: AgentState) -> AgentDecision:
        """Detect resource anomalies"""
        cpu_usage = state.data.get("cpu_percent", 0)

        if cpu_usage > 90:
            return AgentDecision(
                action=AgentAction.ALERT_CRITICAL,
                confidence=0.95,
                reasoning=f"CPU usage at {cpu_usage}% (threshold: 90%)",
                priority=5
            )

        return AgentDecision(
            action=AgentAction.LOG_INFO,
            confidence=1.0,
            reasoning="All metrics normal",
            priority=1
        )

    def act(self, decision: AgentDecision) -> AgentOutcome:
        """Execute the action"""
        # Implementation here
        pass

    def learn(self, outcome: AgentOutcome) -> None:
        """Update baselines"""
        # Implementation here
        pass
```

## Demo Agent

[demo_capability_agent.py](demo_capability_agent.py) provides a working example demonstrating:
- Container security monitoring
- Threat detection logic
- Defensive response automation
- Knowledge base management

**Run the demo:**
```bash
cd C:/Users/Corbin/development/defensive_agents
python demo_capability_agent.py
```

## Key Features

### 🛡️ Defensive-Only Operations
- All agents restricted to defensive security tasks
- No offensive capability creation
- Explicit denial of malicious code assistance

### 📊 Built-in Metrics
Every agent automatically tracks:
- Perception count
- Decision count
- Action count
- Learning iterations
- Error count

Access via `agent.metrics` dictionary.

### 🧠 Knowledge Base
Agents maintain internal knowledge bases for:
- Historical patterns
- Learned baselines
- Threat intelligence
- Configuration state

### 🔍 Logging Integration
Python logging framework integration with per-agent loggers:
```python
agent.logger.info("Monitoring started")
agent.logger.warning("Anomaly detected")
agent.logger.error("Action failed")
```

## Integration

### Container Security Platform
Agents integrate with Docker/Kubernetes for:
- Container lifecycle monitoring
- Resource usage tracking
- Network traffic analysis
- Security policy enforcement

### Alert Systems
Agents can trigger alerts to:
- Prometheus/Grafana
- PagerDuty
- Slack/Discord webhooks
- Email notifications

### SIEM Integration
Compatible with:
- Splunk
- ELK Stack
- Azure Sentinel
- AWS Security Hub

## Defensive Security Principles

1. **Detection Only**: Agents observe and report threats
2. **Controlled Remediation**: Automated fixes follow strict policies
3. **Human-in-the-Loop**: Critical actions require approval
4. **Audit Trail**: All decisions and actions are logged
5. **Fail-Safe**: Errors default to safe states

## Testing

Run the test suite:
```bash
pytest tests/
```

Check agent behavior:
```bash
python demo_capability_agent.py --verbose
```

## Metrics & Monitoring

Track agent performance:
```python
agent = YourAgent("monitor-1")
agent.run_cycle(container_id="app-container")

print(f"Perceptions: {agent.metrics['perceive_count']}")
print(f"Actions taken: {agent.metrics['act_count']}")
print(f"Errors: {agent.metrics['errors']}")
```

## Configuration

Agents can be configured via:
- Environment variables
- YAML configuration files
- Runtime parameters

Example configuration:
```yaml
agents:
  resource_monitor:
    enabled: true
    thresholds:
      cpu_percent: 90
      memory_percent: 85
    alert_channels:
      - slack
      - email
```

## Dependencies

```bash
pip install -r requirements.txt
```

Core dependencies:
- Python 3.13+
- docker (Python SDK)
- logging (stdlib)
- dataclasses (stdlib)

## Related Projects

- **[ml-sectest-framework/](../ml-sectest-framework/)**: ML security testing
- **[security/](../security/)**: Security research projects
- **[saas/api/defensive_responses.py](../saas/api/)**: SaaS defensive APIs

## Roadmap

- [ ] Add Kubernetes CRD support
- [ ] Implement distributed agent coordination
- [ ] Add ML-powered anomaly detection
- [ ] Create pre-built agent library
- [ ] Add Grafana dashboard templates

## Contributing

When creating new agents:
1. Inherit from `BaseAgent`
2. Implement all abstract methods
3. Follow defensive-only principles
4. Add comprehensive tests
5. Document threat models

## License

Part of the development platform - Internal use

---

**Last Updated**: 2025-10-09
**Maintainer**: Corbin
**Framework Version**: 1.0.0
