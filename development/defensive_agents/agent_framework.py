"""
Defensive Security Agent Framework
Base classes for multi-agent security automation

Architecture: Perceive → Decide → Act → Learn
Scope: DEFENSIVE SECURITY ONLY
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AgentAction(Enum):
    """Actions an agent can take"""
    LOG_INFO = "log_info"
    ALERT_WARNING = "alert_warning"
    ALERT_CRITICAL = "alert_critical"
    REMEDIATE = "remediate"
    STOP_CONTAINER = "stop_container"
    ISOLATE_CONTAINER = "isolate_container"


@dataclass
class AgentState:
    """Current state observed by agent"""
    timestamp: datetime
    container_id: str
    data: Dict[str, Any]


@dataclass
class AgentDecision:
    """Decision made by agent"""
    action: AgentAction
    confidence: float  # 0.0 to 1.0
    reasoning: str
    priority: int  # 1 (low) to 5 (critical)


@dataclass
class AgentOutcome:
    """Result of agent action"""
    success: bool
    action_taken: AgentAction
    details: str
    timestamp: datetime


class BaseAgent(ABC):
    """
    Base class for all security agents

    Implements Perceive → Decide → Act → Learn pattern
    """

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"Agent.{name}")
        self.knowledge_base = {}
        self.metrics = {
            'perceive_count': 0,
            'decide_count': 0,
            'act_count': 0,
            'learn_count': 0,
            'errors': 0
        }

    @abstractmethod
    def perceive(self, container_id: str) -> AgentState:
        """
        PERCEIVE: Collect data about container state

        Args:
            container_id: Container to observe

        Returns:
            AgentState with observed data
        """
        pass

    @abstractmethod
    def decide(self, state: AgentState) -> AgentDecision:
        """
        DECIDE: Analyze state and determine action

        Args:
            state: Current observed state

        Returns:
            AgentDecision with action to take
        """
        pass

    @abstractmethod
    def act(self, decision: AgentDecision, state: AgentState) -> AgentOutcome:
        """
        ACT: Execute the decided action

        Args:
            decision: What action to take
            state: Current state

        Returns:
            AgentOutcome with execution result
        """
        pass

    @abstractmethod
    def learn(self, state: AgentState, decision: AgentDecision, outcome: AgentOutcome):
        """
        LEARN: Update knowledge base based on outcomes

        Args:
            state: State that was observed
            decision: Decision that was made
            outcome: Result of the action
        """
        pass

    def run_cycle(self, container_id: str) -> AgentOutcome:
        """
        Execute one complete agent cycle: Perceive → Decide → Act → Learn

        Args:
            container_id: Container to process

        Returns:
            AgentOutcome with final result
        """
        try:
            # PERCEIVE
            self.logger.info(f"[{self.name}] Perceiving state for {container_id}")
            state = self.perceive(container_id)
            self.metrics['perceive_count'] += 1

            # DECIDE
            self.logger.info(f"[{self.name}] Making decision...")
            decision = self.decide(state)
            self.metrics['decide_count'] += 1

            # ACT
            self.logger.info(f"[{self.name}] Executing action: {decision.action.value}")
            outcome = self.act(decision, state)
            self.metrics['act_count'] += 1

            # LEARN
            self.logger.info(f"[{self.name}] Learning from outcome...")
            self.learn(state, decision, outcome)
            self.metrics['learn_count'] += 1

            return outcome

        except Exception as e:
            self.logger.error(f"[{self.name}] Error in agent cycle: {str(e)}")
            self.metrics['errors'] += 1
            raise

    def get_metrics(self) -> Dict[str, int]:
        """Get agent performance metrics"""
        return self.metrics.copy()


class DefensiveSecurityAgent(BaseAgent):
    """
    Base class for defensive security agents

    Adds security-specific methods and constraints
    """

    def __init__(self, name: str):
        super().__init__(name)
        self.security_policies = []
        self.threat_patterns = []

    def add_security_policy(self, policy: Dict[str, Any]):
        """Add a security policy to enforce"""
        self.security_policies.append(policy)
        self.logger.info(f"[{self.name}] Added security policy: {policy.get('name')}")

    def add_threat_pattern(self, pattern: Dict[str, Any]):
        """Add a threat pattern to detect"""
        self.threat_patterns.append(pattern)
        self.logger.info(f"[{self.name}] Added threat pattern: {pattern.get('name')}")

    def calculate_risk_score(self, state: AgentState) -> float:
        """
        Calculate security risk score (0.0 to 1.0)

        Args:
            state: Current container state

        Returns:
            Risk score (higher = more risky)
        """
        risk_score = 0.0

        # Check against security policies
        for policy in self.security_policies:
            if not self._check_policy_compliance(state, policy):
                risk_score += policy.get('weight', 0.1)

        # Check for threat patterns
        for pattern in self.threat_patterns:
            if self._matches_threat_pattern(state, pattern):
                risk_score += pattern.get('severity', 0.5)

        return min(risk_score, 1.0)  # Cap at 1.0

    def _check_policy_compliance(self, state: AgentState, policy: Dict) -> bool:
        """Check if state complies with security policy"""
        # Implementation depends on policy type
        return True

    def _matches_threat_pattern(self, state: AgentState, pattern: Dict) -> bool:
        """Check if state matches known threat pattern"""
        # Implementation depends on pattern type
        return False


# Example implementation: Capability Monitoring Agent
class CapabilityMonitorAgent(DefensiveSecurityAgent):
    """Agent that monitors and enforces capability restrictions"""

    DANGEROUS_CAPABILITIES = [
        'CAP_SYS_ADMIN',
        'CAP_SYS_MODULE',
        'CAP_SYS_PTRACE',
        'CAP_SYS_RAWIO'
    ]

    ALLOWED_CAPABILITIES = [
        'CAP_NET_BIND_SERVICE'
    ]

    def __init__(self):
        super().__init__("CapabilityMonitor")

        # Add default security policy: no dangerous capabilities
        self.add_security_policy({
            'name': 'no_dangerous_capabilities',
            'rule': 'capabilities not in DANGEROUS_CAPABILITIES',
            'weight': 1.0
        })

    def perceive(self, container_id: str) -> AgentState:
        """Observe container capabilities"""
        import docker

        client = docker.from_env()
        container = client.containers.get(container_id)

        # Get container capabilities from inspection
        inspect_data = client.api.inspect_container(container_id)
        cap_add = inspect_data.get('HostConfig', {}).get('CapAdd', [])
        cap_drop = inspect_data.get('HostConfig', {}).get('CapDrop', [])

        return AgentState(
            timestamp=datetime.now(),
            container_id=container_id,
            data={
                'cap_add': cap_add,
                'cap_drop': cap_drop,
                'name': container.name,
                'status': container.status
            }
        )

    def decide(self, state: AgentState) -> AgentDecision:
        """Decide if capabilities are acceptable"""
        cap_add = state.data.get('cap_add', [])

        # Check for dangerous capabilities
        dangerous_caps_present = []
        for cap in cap_add:
            if cap in self.DANGEROUS_CAPABILITIES:
                dangerous_caps_present.append(cap)

        if dangerous_caps_present:
            return AgentDecision(
                action=AgentAction.ALERT_CRITICAL,
                confidence=1.0,
                reasoning=f"Dangerous capabilities detected: {', '.join(dangerous_caps_present)}",
                priority=5
            )

        # Check for unexpected capabilities
        unexpected_caps = [c for c in cap_add if c not in self.ALLOWED_CAPABILITIES]
        if unexpected_caps:
            return AgentDecision(
                action=AgentAction.ALERT_WARNING,
                confidence=0.8,
                reasoning=f"Unexpected capabilities: {', '.join(unexpected_caps)}",
                priority=3
            )

        return AgentDecision(
            action=AgentAction.LOG_INFO,
            confidence=1.0,
            reasoning="Capabilities within acceptable limits",
            priority=1
        )

    def act(self, decision: AgentDecision, state: AgentState) -> AgentOutcome:
        """Execute capability enforcement action"""
        if decision.action == AgentAction.ALERT_CRITICAL:
            self.logger.critical(
                f"CRITICAL: {state.container_id} - {decision.reasoning}"
            )
            # In a real implementation, this would:
            # - Send alert to security team
            # - Optionally stop the container
            # - Create incident ticket

        elif decision.action == AgentAction.ALERT_WARNING:
            self.logger.warning(
                f"WARNING: {state.container_id} - {decision.reasoning}"
            )

        else:
            self.logger.info(
                f"INFO: {state.container_id} - {decision.reasoning}"
            )

        return AgentOutcome(
            success=True,
            action_taken=decision.action,
            details=decision.reasoning,
            timestamp=datetime.now()
        )

    def learn(self, state: AgentState, decision: AgentDecision, outcome: AgentOutcome):
        """Update knowledge about container capability patterns"""
        # Store in knowledge base for trend analysis
        container_id = state.container_id

        if container_id not in self.knowledge_base:
            self.knowledge_base[container_id] = {
                'history': [],
                'capability_patterns': []
            }

        self.knowledge_base[container_id]['history'].append({
            'timestamp': outcome.timestamp,
            'capabilities': state.data.get('cap_add', []),
            'action': decision.action.value,
            'risk_score': self.calculate_risk_score(state)
        })

        # Learn normal capability patterns over time
        # This allows detecting anomalies (e.g., sudden capability addition)


if __name__ == "__main__":
    # Example usage
    agent = CapabilityMonitorAgent()

    print("=== Defensive Security Agent Framework ===")
    print(f"Agent: {agent.name}")
    print(f"Policies: {len(agent.security_policies)}")
    print("Architecture: Perceive → Decide → Act → Learn")
    print("")
    print("Ready for deployment in defensive security automation")
