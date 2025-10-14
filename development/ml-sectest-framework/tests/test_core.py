"""
Test suite for ML-SecTest Core Components
==========================================
Tests for SecurityOrchestrator and agent coordination.
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import SecurityOrchestrator
from core.base_agent import BaseSecurityAgent
from agents import (
    PromptInjectionAgent,
    ModelInversionAgent,
    DataPoisoningAgent,
    ModelExtractionAgent,
    ModelSerializationAgent,
    AdversarialAttackAgent,
    EdwardTellerAgent
)


@pytest.fixture
def orchestrator_with_agents():
    """Fixture that provides an orchestrator with all agents registered."""
    orchestrator = SecurityOrchestrator()
    agents = [
        PromptInjectionAgent(),
        ModelInversionAgent(),
        DataPoisoningAgent(),
        ModelExtractionAgent(),
        ModelSerializationAgent(),
        AdversarialAttackAgent(),
        EdwardTellerAgent()
    ]
    for agent in agents:
        orchestrator.register_agent(agent)
    return orchestrator


class TestSecurityOrchestrator:
    """Tests for SecurityOrchestrator class."""

    def test_orchestrator_initialization(self):
        """Test orchestrator initializes successfully."""
        orchestrator = SecurityOrchestrator()
        assert orchestrator is not None
        assert hasattr(orchestrator, 'agents')

    def test_agents_loaded(self, orchestrator_with_agents):
        """Test all agents are loaded after registration."""
        orchestrator = orchestrator_with_agents
        assert len(orchestrator.agents) >= 7, f"Expected at least 7 agents, got {len(orchestrator.agents)}"

    def test_agent_types(self, orchestrator_with_agents):
        """Test all loaded agents are BaseSecurityAgent instances."""
        orchestrator = orchestrator_with_agents

        for agent_id, agent in orchestrator.agents.items():
            assert isinstance(agent, BaseSecurityAgent), f"{agent} is not a BaseSecurityAgent"

    def test_agent_names_unique(self, orchestrator_with_agents):
        """Test all agent names are unique."""
        orchestrator = orchestrator_with_agents
        names = [agent.name for agent in orchestrator.agents.values()]

        assert len(names) == len(set(names)), "Agent names are not unique"

    def test_run_scan_method_not_exists(self):
        """Test run_scan method does not exist (orchestrator uses execute_plan instead)."""
        orchestrator = SecurityOrchestrator()
        assert not hasattr(orchestrator, 'run_scan')
        # Check that execute_plan exists instead
        assert hasattr(orchestrator, 'execute_plan')
        assert callable(orchestrator.execute_plan)


class TestBaseSecurityAgent:
    """Tests for BaseSecurityAgent functionality."""

    def test_base_agent_cannot_instantiate(self):
        """Test BaseSecurityAgent cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseSecurityAgent()  # Should raise TypeError for abstract class


class TestAgentCoordination:
    """Tests for agent coordination and execution."""

    def test_agent_has_execute_method(self, orchestrator_with_agents):
        """Test all agents have execute method."""
        orchestrator = orchestrator_with_agents

        for agent_id, agent in orchestrator.agents.items():
            assert hasattr(agent, 'execute'), f"{agent.name} missing execute method"
            assert callable(agent.execute)

    def test_agent_has_name(self, orchestrator_with_agents):
        """Test all agents have a name attribute."""
        orchestrator = orchestrator_with_agents

        for agent_id, agent in orchestrator.agents.items():
            assert hasattr(agent, 'name'), f"Agent missing name attribute"
            assert isinstance(agent.name, str)
            assert len(agent.name) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
