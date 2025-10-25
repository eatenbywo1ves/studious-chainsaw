"""
Advanced Agentic Extensions for ML-SecTest
==========================================
Implements 2025 agentic AI patterns including self-adaptation,
inter-agent communication, and autonomous decision-making.

Based on industry patterns from:
- AutoGen v0.4 (Actor Model)
- LangGraph (Graph-based reasoning)
- Enterprise production deployments
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import logging
from datetime import datetime


class AgentCapability(Enum):
    """Advanced agent capabilities."""
    SELF_HEALING = "self_healing"
    ADAPTIVE_STRATEGY = "adaptive_strategy"
    PEER_COMMUNICATION = "peer_communication"
    LEARNING = "learning"
    PLANNING = "planning"
    TOOL_SELECTION = "tool_selection"


class MessageType(Enum):
    """Inter-agent message types."""
    REQUEST = "request"
    RESPONSE = "response"
    BROADCAST = "broadcast"
    COLLABORATION = "collaboration"
    ALERT = "alert"
    KNOWLEDGE_SHARE = "knowledge_share"


@dataclass
class AgentMessage:
    """Message for inter-agent communication."""
    sender_id: str
    recipient_id: Optional[str]  # None for broadcast
    message_type: MessageType
    content: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    correlation_id: Optional[str] = None
    requires_response: bool = False


@dataclass
class AgentMemory:
    """Agent memory for learning and adaptation."""
    successful_strategies: List[Dict[str, Any]] = field(default_factory=list)
    failed_strategies: List[Dict[str, Any]] = field(default_factory=list)
    learned_patterns: Dict[str, Any] = field(default_factory=dict)
    target_characteristics: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class AgentGoal:
    """Hierarchical agent goal structure."""
    goal_id: str
    description: str
    priority: int  # 1-10, 10 highest
    status: str  # planned, active, completed, failed
    sub_goals: List['AgentGoal'] = field(default_factory=list)
    success_criteria: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)


class MessageBus:
    """
    Central message bus for inter-agent communication.
    Implements pub-sub pattern for agent collaboration.
    """

    def __init__(self) -> None:
        """Initialize message bus."""
        self.subscribers: Dict[str, List[Callable[[AgentMessage], None]]] = {}
        self.message_history: List[AgentMessage] = []
        self.logger = logging.getLogger("MLSecTest.MessageBus")

    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]) -> None:
        """Subscribe agent to message bus."""
        if agent_id not in self.subscribers:
            self.subscribers[agent_id] = []
        self.subscribers[agent_id].append(callback)
        self.logger.info(f"Agent {agent_id} subscribed to message bus")

    def publish(self, message: AgentMessage) -> None:
        """Publish message to subscribers."""
        self.message_history.append(message)

        # Direct message
        if message.recipient_id:
            if message.recipient_id in self.subscribers:
                for callback in self.subscribers[message.recipient_id]:
                    try:
                        callback(message)
                    except Exception as e:
                        self.logger.error(f"Callback error: {e}")
        # Broadcast message
        else:
            for agent_id, callbacks in self.subscribers.items():
                if agent_id != message.sender_id:  # Don't send to self
                    for callback in callbacks:
                        try:
                            callback(message)
                        except Exception as e:
                            self.logger.error(f"Broadcast error: {e}")

    def get_conversation_history(self, agent_id: str) -> List[AgentMessage]:
        """Get message history for specific agent."""
        return [
            msg for msg in self.message_history
            if msg.sender_id == agent_id or msg.recipient_id == agent_id
        ]


class AdaptiveStrategyEngine:
    """
    Implements adaptive strategy selection based on feedback.
    Learns from successes and failures to optimize approach.
    """

    def __init__(self) -> None:
        """Initialize strategy engine."""
        self.strategies: Dict[str, Dict[str, Any]] = {}
        self.performance_history: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("MLSecTest.StrategyEngine")

    def register_strategy(
        self,
        strategy_id: str,
        description: str,
        applicability_checker: Callable[[Dict[str, Any]], bool],
        execution_function: Callable[..., Any]
    ) -> None:
        """Register a strategy with the engine."""
        self.strategies[strategy_id] = {
            "description": description,
            "applicability_checker": applicability_checker,
            "execution_function": execution_function,
            "success_count": 0,
            "failure_count": 0,
            "avg_execution_time": 0.0,
            "avg_confidence": 0.0
        }
        self.logger.info(f"Registered strategy: {strategy_id}")

    def select_best_strategy(self, context: Dict[str, Any]) -> Optional[str]:
        """
        Select best strategy based on context and history.
        Uses adaptive selection with exploitation-exploration balance.
        """
        applicable_strategies = []

        for strategy_id, strategy_info in self.strategies.items():
            checker = strategy_info["applicability_checker"]
            if checker(context):
                # Calculate strategy score
                success_rate = (
                    strategy_info["success_count"] /
                    (strategy_info["success_count"] + strategy_info["failure_count"])
                    if (strategy_info["success_count"] + strategy_info["failure_count"]) > 0
                    else 0.5  # Neutral for untested strategies
                )

                score = (
                    success_rate * 0.6 +  # Historical performance
                    strategy_info["avg_confidence"] * 0.3 +  # Confidence
                    (1.0 / (strategy_info["avg_execution_time"] + 1)) * 0.1  # Speed
                )

                applicable_strategies.append((strategy_id, score))

        if not applicable_strategies:
            return None

        # Sort by score and return best
        applicable_strategies.sort(key=lambda x: x[1], reverse=True)
        selected_strategy = applicable_strategies[0][0]

        self.logger.info(f"Selected strategy: {selected_strategy}")
        return selected_strategy

    def record_outcome(
        self,
        strategy_id: str,
        success: bool,
        execution_time: float,
        confidence: float
    ) -> None:
        """Record strategy execution outcome for learning."""
        if strategy_id not in self.strategies:
            return

        strategy = self.strategies[strategy_id]

        if success:
            strategy["success_count"] += 1
        else:
            strategy["failure_count"] += 1

        # Update moving averages
        total_executions = strategy["success_count"] + strategy["failure_count"]
        strategy["avg_execution_time"] = (
            (strategy["avg_execution_time"] * (total_executions - 1) + execution_time) /
            total_executions
        )
        strategy["avg_confidence"] = (
            (strategy["avg_confidence"] * (total_executions - 1) + confidence) /
            total_executions
        )

        self.performance_history.append({
            "strategy_id": strategy_id,
            "success": success,
            "execution_time": execution_time,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat()
        })


class SelfHealingMixin:
    """
    Mixin providing self-healing capabilities to agents.
    Automatically handles failures and adapts behavior.
    """

    def __init__(self) -> None:
        """Initialize self-healing capabilities."""
        self.retry_count = 0
        self.max_retries = 3
        self.fallback_strategies: List[Callable[..., Any]] = []
        self.healing_logger = logging.getLogger("MLSecTest.SelfHealing")

    def execute_with_healing(
        self,
        primary_function: Callable[..., Any],
        *args: Any,
        **kwargs: Any
    ) -> Any:
        """
        Execute function with automatic retry and fallback.

        Args:
            primary_function: Main function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result or fallback result
        """
        last_exception = None

        # Try primary function with retries
        for attempt in range(self.max_retries):
            try:
                self.healing_logger.info(f"Attempt {attempt + 1}/{self.max_retries}")
                result = primary_function(*args, **kwargs)

                # Reset retry count on success
                if attempt > 0:
                    self.healing_logger.info("Recovery successful")
                self.retry_count = 0

                return result

            except Exception as e:
                last_exception = e
                self.healing_logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
                self.retry_count += 1

                # Exponential backoff
                if attempt < self.max_retries - 1:
                    import time
                    time.sleep(2 ** attempt)

        # Try fallback strategies
        self.healing_logger.info("Trying fallback strategies")
        for fallback in self.fallback_strategies:
            try:
                result = fallback(*args, **kwargs)
                self.healing_logger.info("Fallback strategy succeeded")
                return result
            except Exception as e:
                self.healing_logger.warning(f"Fallback failed: {str(e)}")

        # All attempts failed
        self.healing_logger.error("All recovery attempts failed")
        raise Exception(f"Self-healing failed after {self.max_retries} attempts") from last_exception

    def add_fallback_strategy(self, fallback_function: Callable[..., Any]) -> None:
        """Add a fallback strategy."""
        self.fallback_strategies.append(fallback_function)
        self.healing_logger.info(f"Added fallback strategy: {fallback_function.__name__}")


class GoalOrientedPlanner:
    """
    Implements hierarchical goal-oriented planning for agents.
    Breaks down high-level goals into executable sub-goals.
    """

    def __init__(self) -> None:
        """Initialize planner."""
        self.goals: List[AgentGoal] = []
        self.completed_goals: List[AgentGoal] = []
        self.logger = logging.getLogger("MLSecTest.Planner")

    def add_goal(self, goal: AgentGoal) -> None:
        """Add a goal to the planner."""
        self.goals.append(goal)
        self.goals.sort(key=lambda g: g.priority, reverse=True)
        self.logger.info(f"Added goal: {goal.goal_id} (priority: {goal.priority})")

    def get_next_action(self) -> Optional[AgentGoal]:
        """
        Get next actionable goal based on priority and dependencies.

        Returns:
            Next goal to execute or None if no goals available
        """
        for goal in self.goals:
            if goal.status == "planned":
                # Check if sub-goals are completed
                if goal.sub_goals:
                    if all(sg.status == "completed" for sg in goal.sub_goals):
                        goal.status = "active"
                        return goal
                else:
                    goal.status = "active"
                    return goal

        return None

    def mark_goal_completed(self, goal_id: str, success: bool = True) -> None:
        """Mark a goal as completed."""
        for goal in self.goals:
            if goal.goal_id == goal_id:
                goal.status = "completed" if success else "failed"
                self.completed_goals.append(goal)
                self.goals.remove(goal)
                self.logger.info(f"Goal {goal_id} marked as {goal.status}")
                return

    def adapt_plan(self, context: Dict[str, Any]) -> None:
        """
        Dynamically adapt plan based on context changes.
        Re-prioritizes goals and adds new sub-goals if needed.
        """
        self.logger.info("Adapting plan based on new context")

        # Re-evaluate goal priorities based on context
        for goal in self.goals:
            # Example: Increase priority if vulnerability found
            if context.get("vulnerability_detected"):
                if "exploit" in goal.description.lower():
                    goal.priority = min(goal.priority + 2, 10)

        # Re-sort by priority
        self.goals.sort(key=lambda g: g.priority, reverse=True)


class ToolSelectionEngine:
    """
    Intelligent tool selection engine for agents.
    Chooses optimal tools/techniques based on target characteristics.
    """

    def __init__(self) -> None:
        """Initialize tool selection engine."""
        self.available_tools: Dict[str, Dict[str, Any]] = {}
        self.tool_performance: Dict[str, List[float]] = {}
        self.logger = logging.getLogger("MLSecTest.ToolSelection")

    def register_tool(
        self,
        tool_id: str,
        tool_function: Callable[..., Any],
        characteristics: Dict[str, Any]
    ) -> None:
        """Register a tool with its characteristics."""
        self.available_tools[tool_id] = {
            "function": tool_function,
            "characteristics": characteristics,
            "usage_count": 0
        }
        self.tool_performance[tool_id] = []
        self.logger.info(f"Registered tool: {tool_id}")

    def select_tool(
        self,
        target_type: str,
        target_characteristics: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Optional[str]:
        """
        Select best tool for given target and context.

        Args:
            target_type: Type of target (e.g., "llm", "classifier")
            target_characteristics: Known characteristics of target
            context: Execution context

        Returns:
            Tool ID of selected tool or None
        """
        candidates = []

        for tool_id, tool_info in self.available_tools.items():
            # Check if tool matches target type
            if target_type in tool_info["characteristics"].get("applicable_targets", []):
                # Calculate match score
                score = self._calculate_match_score(
                    tool_info["characteristics"],
                    target_characteristics
                )

                # Consider historical performance
                if self.tool_performance[tool_id]:
                    avg_performance = sum(self.tool_performance[tool_id]) / len(self.tool_performance[tool_id])
                    score = score * 0.6 + avg_performance * 0.4

                candidates.append((tool_id, score))

        if not candidates:
            return None

        # Select best tool
        candidates.sort(key=lambda x: x[1], reverse=True)
        selected_tool = candidates[0][0]

        self.available_tools[selected_tool]["usage_count"] += 1
        self.logger.info(f"Selected tool: {selected_tool}")

        return selected_tool

    def record_tool_performance(self, tool_id: str, performance_score: float) -> None:
        """Record tool performance for future selection."""
        if tool_id in self.tool_performance:
            self.tool_performance[tool_id].append(performance_score)
            # Keep only last 100 performances
            if len(self.tool_performance[tool_id]) > 100:
                self.tool_performance[tool_id] = self.tool_performance[tool_id][-100:]

    def _calculate_match_score(
        self,
        tool_chars: Dict[str, Any],
        target_chars: Dict[str, Any]
    ) -> float:
        """Calculate how well tool matches target characteristics."""
        score = 0.5  # Base score

        # Check feature overlap
        tool_features = set(tool_chars.get("features", []))
        target_features = set(target_chars.get("features", []))

        if tool_features and target_features:
            overlap = len(tool_features & target_features)
            score += 0.3 * (overlap / len(tool_features))

        # Check complexity match
        if "complexity" in tool_chars and "complexity" in target_chars:
            complexity_match = 1.0 - abs(
                tool_chars["complexity"] - target_chars["complexity"]
            ) / 10.0
            score += 0.2 * complexity_match

        return min(score, 1.0)


# Factory function for creating enhanced agents
def create_enhanced_agent(
    base_agent_class: type,
    enable_self_healing: bool = True,
    enable_adaptive_strategy: bool = True,
    enable_communication: bool = True
) -> type:
    """
    Factory function to create agents with agentic enhancements.

    Args:
        base_agent_class: Base agent class to enhance
        enable_self_healing: Enable self-healing capabilities
        enable_adaptive_strategy: Enable adaptive strategy selection
        enable_communication: Enable inter-agent communication

    Returns:
        Enhanced agent class
    """
    class EnhancedAgent(base_agent_class):
        """Enhanced agent with agentic capabilities."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)

            # Add agentic components
            self.memory = AgentMemory()

            if enable_adaptive_strategy:
                self.strategy_engine = AdaptiveStrategyEngine()

            if enable_self_healing:
                self._init_self_healing()

            self.planner = GoalOrientedPlanner()
            self.tool_selector = ToolSelectionEngine()

            # Communication
            self.message_bus: Optional[MessageBus] = None
            self.received_messages: List[AgentMessage] = []

        def _init_self_healing(self) -> None:
            """Initialize self-healing capabilities."""
            self.retry_count = 0
            self.max_retries = 3
            self.fallback_strategies: List[Callable[..., Any]] = []

        def connect_to_message_bus(self, message_bus: MessageBus) -> None:
            """Connect agent to message bus for communication."""
            self.message_bus = message_bus
            self.message_bus.subscribe(self.agent_id, self._on_message_received)

        def _on_message_received(self, message: AgentMessage) -> None:
            """Handle received messages."""
            self.received_messages.append(message)
            self.logger.info(f"Received {message.message_type.value} from {message.sender_id}")

            # Auto-respond to requests
            if message.requires_response:
                self._send_response(message)

        def _send_response(self, original_message: AgentMessage) -> None:
            """Send response to a request message."""
            response = AgentMessage(
                sender_id=self.agent_id,
                recipient_id=original_message.sender_id,
                message_type=MessageType.RESPONSE,
                content={"status": "acknowledged"},
                correlation_id=original_message.correlation_id
            )

            if self.message_bus:
                self.message_bus.publish(response)

        def broadcast_finding(self, finding: Dict[str, Any]) -> None:
            """Broadcast vulnerability finding to other agents."""
            if self.message_bus:
                message = AgentMessage(
                    sender_id=self.agent_id,
                    recipient_id=None,  # Broadcast
                    message_type=MessageType.KNOWLEDGE_SHARE,
                    content={"finding": finding}
                )
                self.message_bus.publish(message)
                self.logger.info("Broadcasted finding to peer agents")

        def learn_from_execution(self, result: Any, success: bool) -> None:
            """Learn from execution outcome."""
            if success:
                self.memory.successful_strategies.append({
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                })
            else:
                self.memory.failed_strategies.append({
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                })

            # Update performance metrics
            self.memory.performance_metrics["success_rate"] = (
                len(self.memory.successful_strategies) /
                (len(self.memory.successful_strategies) + len(self.memory.failed_strategies))
                if (len(self.memory.successful_strategies) + len(self.memory.failed_strategies)) > 0
                else 0.0
            )

    return EnhancedAgent


# Example usage and testing
if __name__ == "__main__":
    # Demonstration of agentic extensions
    print("ML-SecTest Agentic Extensions")
    print("=" * 50)

    # Create message bus
    bus = MessageBus()

    # Create test message
    msg = AgentMessage(
        sender_id="agent_001",
        recipient_id="agent_002",
        message_type=MessageType.REQUEST,
        content={"action": "test"}
    )

    print(f"Created message from {msg.sender_id}")
    print(f"Message type: {msg.message_type.value}")
    print("\nAgentic extensions ready for integration!")
