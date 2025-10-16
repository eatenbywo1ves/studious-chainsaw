"""
Unit Tests for Agent Coordinator
=================================
Tests for Von Neumann game-theoretic agent selection and Teller fusion chain coordination.
"""

import pytest

from core.base_agent import (
    BaseSecurityAgent,
    AgentContext,
    TestResult,
    VulnerabilityType
)
from core.agent_coordinator import (
    AgentCoordinator,
    CoordinationStrategy,
    AgentSynergy,
    CoordinationPlan,
    CoordinationResult
)


# ============================================================================
# Mock Agent Implementations
# ============================================================================

class MockPromptInjectionAgent(BaseSecurityAgent):
    """Mock agent for prompt injection testing."""

    def __init__(self):
        super().__init__(
            agent_id="mock_prompt_injection",
            name="Mock Prompt Injection Agent",
            description="Mock agent for testing"
        )

    def analyze(self, context: AgentContext) -> TestResult:
        return TestResult(
            test_name="prompt_injection_test",
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            success=True,
            confidence_score=0.85,
            evidence=["Mock evidence"]
        )

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        return TestResult(
            test_name="prompt_injection_exploit",
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            success=True,
            confidence_score=0.90,
            evidence=["Mock exploit"]
        )

    def _get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.PROMPT_INJECTION


class MockModelExtractionAgent(BaseSecurityAgent):
    """Mock agent for model extraction testing."""

    def __init__(self):
        super().__init__(
            agent_id="mock_model_extraction",
            name="Mock Model Extraction Agent",
            description="Mock agent for testing"
        )

    def analyze(self, context: AgentContext) -> TestResult:
        return TestResult(
            test_name="model_extraction_test",
            vulnerability_type=VulnerabilityType.MODEL_EXTRACTION,
            success=True,
            confidence_score=0.80,
            evidence=["Mock evidence"]
        )

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        return TestResult(
            test_name="model_extraction_exploit",
            vulnerability_type=VulnerabilityType.MODEL_EXTRACTION,
            success=True,
            confidence_score=0.75,
            evidence=["Mock exploit"]
        )

    def _get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MODEL_EXTRACTION


class MockDataPoisoningAgent(BaseSecurityAgent):
    """Mock agent for data poisoning testing."""

    def __init__(self):
        super().__init__(
            agent_id="mock_data_poisoning",
            name="Mock Data Poisoning Agent",
            description="Mock agent for testing"
        )

    def analyze(self, context: AgentContext) -> TestResult:
        return TestResult(
            test_name="data_poisoning_test",
            vulnerability_type=VulnerabilityType.DATA_POISONING,
            success=True,
            confidence_score=0.88,
            evidence=["Mock evidence"]
        )

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        return TestResult(
            test_name="data_poisoning_exploit",
            vulnerability_type=VulnerabilityType.DATA_POISONING,
            success=True,
            confidence_score=0.82,
            evidence=["Mock exploit"]
        )

    def _get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.DATA_POISONING


class MockModelInversionAgent(BaseSecurityAgent):
    """Mock agent for model inversion testing."""

    def __init__(self):
        super().__init__(
            agent_id="mock_model_inversion",
            name="Mock Model Inversion Agent",
            description="Mock agent for testing"
        )

    def analyze(self, context: AgentContext) -> TestResult:
        return TestResult(
            test_name="model_inversion_test",
            vulnerability_type=VulnerabilityType.MODEL_INVERSION,
            success=True,
            confidence_score=0.78,
            evidence=["Mock evidence"]
        )

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        return TestResult(
            test_name="model_inversion_exploit",
            vulnerability_type=VulnerabilityType.MODEL_INVERSION,
            success=True,
            confidence_score=0.80,
            evidence=["Mock exploit"]
        )

    def _get_vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MODEL_INVERSION


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_agents():
    """Create a set of mock agents for testing."""
    return [
        MockPromptInjectionAgent(),
        MockModelExtractionAgent(),
        MockDataPoisoningAgent(),
        MockModelInversionAgent()
    ]


@pytest.fixture
def coordinator(mock_agents):
    """Create coordinator with mock agents."""
    return AgentCoordinator(agents=mock_agents)


@pytest.fixture
def sample_context():
    """Create sample agent context."""
    return AgentContext(
        target_url="http://localhost:8000/test",
        challenge_name="Test Challenge",
        difficulty_level="hard",
        owasp_reference="LLM01",
        mitre_reference="T1234"
    )


# ============================================================================
# Initialization Tests
# ============================================================================

def test_coordinator_initialization_empty():
    """Test coordinator initialization without agents."""
    coordinator = AgentCoordinator()

    assert len(coordinator.agents) == 0
    assert len(coordinator.synergy_matrix) > 0  # Should have predefined synergies
    assert len(coordinator.historical_results) == 0
    assert coordinator.logger is not None


def test_coordinator_initialization_with_agents(mock_agents):
    """Test coordinator initialization with agents."""
    coordinator = AgentCoordinator(agents=mock_agents)

    assert len(coordinator.agents) == 4
    assert "mock_prompt_injection" in coordinator.agents
    assert "mock_model_extraction" in coordinator.agents
    assert "mock_data_poisoning" in coordinator.agents
    assert "mock_model_inversion" in coordinator.agents


def test_register_agent():
    """Test agent registration."""
    coordinator = AgentCoordinator()
    agent = MockPromptInjectionAgent()

    coordinator.register_agent(agent)

    assert "mock_prompt_injection" in coordinator.agents
    assert coordinator.agents["mock_prompt_injection"] == agent


# ============================================================================
# Synergy Matrix Tests
# ============================================================================

def test_synergy_matrix_initialization(coordinator):
    """Test synergy matrix contains expected pairs."""
    # Check for known high-value synergies
    prompt_to_extraction = coordinator.get_synergy(
        VulnerabilityType.PROMPT_INJECTION,
        VulnerabilityType.MODEL_EXTRACTION
    )
    assert prompt_to_extraction is not None
    assert prompt_to_extraction.amplification_factor == 2.5

    poisoning_to_inversion = coordinator.get_synergy(
        VulnerabilityType.DATA_POISONING,
        VulnerabilityType.MODEL_INVERSION
    )
    assert poisoning_to_inversion is not None
    assert poisoning_to_inversion.amplification_factor == 3.2


def test_synergy_matrix_lookup(coordinator):
    """Test synergy matrix lookup."""
    # Test existing synergy
    synergy = coordinator.get_synergy(
        VulnerabilityType.PROMPT_INJECTION,
        VulnerabilityType.MODEL_EXTRACTION
    )
    assert synergy is not None
    assert isinstance(synergy, AgentSynergy)
    assert synergy.amplification_factor > 1.0

    # Test non-existent synergy
    no_synergy = coordinator.get_synergy(
        VulnerabilityType.PROMPT_INJECTION,
        VulnerabilityType.FUSION_ATTACK
    )
    assert no_synergy is None


def test_synergy_properties(coordinator):
    """Test synergy object properties."""
    synergy = coordinator.get_synergy(
        VulnerabilityType.DATA_POISONING,
        VulnerabilityType.MODEL_INVERSION
    )

    assert synergy is not None
    assert synergy.agent1_type == VulnerabilityType.DATA_POISONING
    assert synergy.agent2_type == VulnerabilityType.MODEL_INVERSION
    assert synergy.amplification_factor == 3.2
    assert len(synergy.description) > 0


# ============================================================================
# Cascade Amplification Tests
# ============================================================================

def test_calculate_chain_amplification_single_agent(coordinator):
    """Test amplification calculation with single agent."""
    amplification = coordinator.calculate_chain_amplification(["mock_prompt_injection"])

    assert amplification == 1.0  # Single agent has no cascade


def test_calculate_chain_amplification_with_synergy(coordinator):
    """Test amplification with synergistic agent pair."""
    # Prompt Injection → Model Extraction should have 2.5x synergy
    amplification = coordinator.calculate_chain_amplification([
        "mock_prompt_injection",
        "mock_model_extraction"
    ])

    assert amplification == 2.5


def test_calculate_chain_amplification_without_synergy(coordinator):
    """Test amplification without known synergy."""
    # Model Extraction → Prompt Injection (reverse) should have base amplification
    amplification = coordinator.calculate_chain_amplification([
        "mock_model_extraction",
        "mock_prompt_injection"
    ])

    assert amplification == 1.2  # Base amplification


def test_calculate_chain_amplification_multiple_stages(coordinator):
    """Test cascade amplification through multiple stages."""
    # Data Poisoning → Model Inversion has 3.2x synergy
    # Model Inversion → ? should have base 1.2x
    amplification = coordinator.calculate_chain_amplification([
        "mock_data_poisoning",
        "mock_model_inversion",
        "mock_prompt_injection"
    ])

    expected = 3.2 * 1.2  # First synergy × second base
    assert abs(amplification - expected) < 0.01


def test_calculate_chain_amplification_invalid_agents(coordinator):
    """Test amplification with invalid agent IDs."""
    amplification = coordinator.calculate_chain_amplification([
        "invalid_agent_1",
        "invalid_agent_2"
    ])

    # Should handle gracefully
    assert amplification >= 1.0


# ============================================================================
# Nash Optimal Selection Tests
# ============================================================================

def test_select_optimal_sequence_nash_single_agent(coordinator):
    """Test Nash selection with single agent."""
    sequence = coordinator.select_optimal_sequence_nash(["mock_prompt_injection"])

    assert len(sequence) == 1
    assert sequence[0] == "mock_prompt_injection"


def test_select_optimal_sequence_nash_pair(coordinator):
    """Test Nash selection optimizes for synergy."""
    sequence = coordinator.select_optimal_sequence_nash([
        "mock_prompt_injection",
        "mock_model_extraction"
    ])

    # Should prefer prompt_injection → model_extraction (2.5x)
    # over model_extraction → prompt_injection (1.2x)
    assert len(sequence) == 2
    assert sequence[0] == "mock_prompt_injection"
    assert sequence[1] == "mock_model_extraction"


def test_select_optimal_sequence_nash_multiple_agents(coordinator):
    """Test Nash selection with multiple agents."""
    agents = [
        "mock_prompt_injection",
        "mock_model_extraction",
        "mock_data_poisoning"
    ]
    sequence = coordinator.select_optimal_sequence_nash(agents)

    assert len(sequence) == 3
    assert all(agent in sequence for agent in agents)

    # Calculate amplification to ensure it's optimal
    amplification = coordinator.calculate_chain_amplification(sequence)
    assert amplification > 1.0


def test_select_optimal_sequence_nash_max_length(coordinator):
    """Test Nash selection respects max length."""
    all_agents = list(coordinator.agents.keys())
    sequence = coordinator.select_optimal_sequence_nash(all_agents, max_sequence_length=2)

    assert len(sequence) <= 2


def test_greedy_nash_heuristic(coordinator):
    """Test greedy heuristic for large search spaces."""
    all_agents = list(coordinator.agents.keys())
    sequence = coordinator._greedy_nash_heuristic(all_agents, max_length=3)

    assert len(sequence) <= 3
    assert all(agent in all_agents for agent in sequence)


# ============================================================================
# Coordination Plan Tests
# ============================================================================

def test_create_fusion_chain_plan_nash(coordinator):
    """Test creating Nash optimal coordination plan."""
    plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.NASH_OPTIMAL)

    assert plan.strategy == CoordinationStrategy.NASH_OPTIMAL
    assert len(plan.agent_sequence) > 0
    assert plan.expected_amplification >= 1.0
    assert 0.0 <= plan.confidence <= 1.0


def test_create_fusion_chain_plan_sequential(coordinator):
    """Test creating sequential coordination plan."""
    plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.SEQUENTIAL)

    assert plan.strategy == CoordinationStrategy.SEQUENTIAL
    assert len(plan.agent_sequence) == len(coordinator.agents)


def test_create_fusion_chain_plan_parallel(coordinator):
    """Test creating parallel coordination plan."""
    plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.PARALLEL)

    assert plan.strategy == CoordinationStrategy.PARALLEL
    assert len(plan.agent_sequence) == len(coordinator.agents)


def test_create_fusion_chain_plan_synergy_chains(coordinator):
    """Test plan identifies synergy chains."""
    plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.NASH_OPTIMAL)

    # Should identify at least one synergy pair
    # (depends on optimal sequence selected)
    assert isinstance(plan.synergy_chains, list)


def test_coordination_plan_properties():
    """Test coordination plan data structure."""
    plan = CoordinationPlan(
        strategy=CoordinationStrategy.FUSION_CHAIN,
        agent_sequence=["agent1", "agent2"],
        synergy_chains=[("agent1", "agent2")],
        expected_amplification=2.5,
        confidence=0.75
    )

    assert plan.strategy == CoordinationStrategy.FUSION_CHAIN
    assert len(plan.agent_sequence) == 2
    assert len(plan.synergy_chains) == 1
    assert plan.expected_amplification == 2.5
    assert plan.confidence == 0.75


# ============================================================================
# Coordinated Execution Tests
# ============================================================================

def test_execute_coordinated_attack_with_plan(coordinator, sample_context):
    """Test executing coordinated attack with provided plan."""
    plan = CoordinationPlan(
        strategy=CoordinationStrategy.SEQUENTIAL,
        agent_sequence=["mock_prompt_injection", "mock_model_extraction"],
        expected_amplification=2.5,
        confidence=0.7
    )

    result = coordinator.execute_coordinated_attack(sample_context, plan)

    assert isinstance(result, CoordinationResult)
    assert result.plan == plan
    assert len(result.agent_results) == 2
    assert "mock_prompt_injection" in result.agent_results
    assert "mock_model_extraction" in result.agent_results
    assert result.observed_amplification > 0


def test_execute_coordinated_attack_without_plan(coordinator, sample_context):
    """Test executing coordinated attack generates optimal plan."""
    result = coordinator.execute_coordinated_attack(sample_context)

    assert isinstance(result, CoordinationResult)
    assert result.plan.strategy == CoordinationStrategy.NASH_OPTIMAL
    assert len(result.agent_results) > 0


def test_execute_coordinated_attack_synergy_activation(coordinator, sample_context):
    """Test synergy activation detection."""
    # Use known synergistic pair
    plan = CoordinationPlan(
        strategy=CoordinationStrategy.FUSION_CHAIN,
        agent_sequence=["mock_prompt_injection", "mock_model_extraction"],
        expected_amplification=2.5,
        confidence=0.8
    )

    result = coordinator.execute_coordinated_attack(sample_context, plan)

    # Should detect successful coordination
    assert isinstance(result.synergy_activated, bool)
    assert result.observed_amplification > 0


def test_execute_coordinated_attack_updates_history(coordinator, sample_context):
    """Test execution updates historical results."""
    initial_history_len = len(coordinator.historical_results)

    plan = CoordinationPlan(
        strategy=CoordinationStrategy.SEQUENTIAL,
        agent_sequence=["mock_prompt_injection"],
        expected_amplification=1.0,
        confidence=0.5
    )

    coordinator.execute_coordinated_attack(sample_context, plan)

    assert len(coordinator.historical_results) == initial_history_len + 1


def test_execute_coordinated_attack_invalid_agent(coordinator, sample_context):
    """Test execution handles invalid agent IDs gracefully."""
    plan = CoordinationPlan(
        strategy=CoordinationStrategy.SEQUENTIAL,
        agent_sequence=["invalid_agent", "mock_prompt_injection"],
        expected_amplification=1.0,
        confidence=0.5
    )

    result = coordinator.execute_coordinated_attack(sample_context, plan)

    # Should skip invalid agent and continue
    assert len(result.agent_results) == 1
    assert "mock_prompt_injection" in result.agent_results


# ============================================================================
# Bayesian Confidence Tests
# ============================================================================

def test_calculate_plan_confidence_no_history(coordinator):
    """Test confidence calculation with no history."""
    confidence = coordinator._calculate_plan_confidence(["mock_prompt_injection"])

    assert confidence == 0.5  # Prior confidence


def test_calculate_plan_confidence_with_history(coordinator, sample_context):
    """Test confidence calculation updates with history."""
    plan = CoordinationPlan(
        strategy=CoordinationStrategy.SEQUENTIAL,
        agent_sequence=["mock_prompt_injection", "mock_model_extraction"],
        expected_amplification=2.5,
        confidence=0.5
    )

    # Execute to build history
    coordinator.execute_coordinated_attack(sample_context, plan)

    # Calculate confidence for similar sequence
    new_confidence = coordinator._calculate_plan_confidence([
        "mock_prompt_injection",
        "mock_model_extraction"
    ])

    # Should be updated from prior (may be higher or lower depending on results)
    assert 0.0 <= new_confidence <= 1.0


# ============================================================================
# Observed Amplification Tests
# ============================================================================

def test_calculate_observed_amplification_empty_results(coordinator):
    """Test amplification calculation with no results."""
    plan = CoordinationPlan(
        strategy=CoordinationStrategy.SEQUENTIAL,
        agent_sequence=["agent1"],
        expected_amplification=1.0,
        confidence=0.5
    )

    amplification = coordinator._calculate_observed_amplification({}, plan)

    assert amplification == 1.0


def test_calculate_observed_amplification_successful_results(coordinator):
    """Test amplification with successful test results."""
    agent_results = {
        "mock_prompt_injection": [
            TestResult(
                test_name="test1",
                vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                success=True,
                confidence_score=0.9,
                evidence=[]
            )
        ],
        "mock_model_extraction": [
            TestResult(
                test_name="test2",
                vulnerability_type=VulnerabilityType.MODEL_EXTRACTION,
                success=True,
                confidence_score=0.8,
                evidence=[]
            )
        ]
    }

    plan = CoordinationPlan(
        strategy=CoordinationStrategy.FUSION_CHAIN,
        agent_sequence=["mock_prompt_injection", "mock_model_extraction"],
        expected_amplification=2.5,
        confidence=0.7
    )

    amplification = coordinator._calculate_observed_amplification(agent_results, plan)

    # success_rate=1.0, avg_confidence=0.85, sequence_length=2
    expected = 1.0 * 0.85 * 2
    assert abs(amplification - expected) < 0.01


def test_calculate_observed_amplification_mixed_results(coordinator):
    """Test amplification with mixed success/failure."""
    agent_results = {
        "mock_prompt_injection": [
            TestResult(
                test_name="test1",
                vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                success=True,
                confidence_score=0.9,
                evidence=[]
            )
        ],
        "mock_model_extraction": [
            TestResult(
                test_name="test2",
                vulnerability_type=VulnerabilityType.MODEL_EXTRACTION,
                success=False,
                confidence_score=0.3,
                evidence=[]
            )
        ]
    }

    plan = CoordinationPlan(
        strategy=CoordinationStrategy.SEQUENTIAL,
        agent_sequence=["mock_prompt_injection", "mock_model_extraction"],
        expected_amplification=1.5,
        confidence=0.6
    )

    amplification = coordinator._calculate_observed_amplification(agent_results, plan)

    # Success rate = 0.5 (1 success, 1 failure)
    # Only successful tests contribute to confidence
    assert amplification < 2.0


# ============================================================================
# Synergy Report Tests
# ============================================================================

def test_get_synergy_report_empty_history(coordinator):
    """Test synergy report with no execution history."""
    report = coordinator.get_synergy_report()

    assert report["total_agents"] == 4
    assert report["total_synergies"] > 0
    assert report["historical_executions"] == 0
    assert len(report["synergy_pairs"]) > 0
    assert report["avg_amplification"] == 0.0
    assert len(report["best_performing_sequences"]) == 0


def test_get_synergy_report_with_history(coordinator, sample_context):
    """Test synergy report after executions."""
    # Execute some coordinated attacks
    coordinator.execute_coordinated_attack(sample_context)

    report = coordinator.get_synergy_report()

    assert report["historical_executions"] > 0
    assert report["avg_amplification"] >= 0.0
    assert len(report["best_performing_sequences"]) > 0


def test_synergy_report_structure(coordinator):
    """Test synergy report structure."""
    report = coordinator.get_synergy_report()

    # Check required keys
    required_keys = [
        "total_agents",
        "total_synergies",
        "historical_executions",
        "synergy_pairs",
        "best_performing_sequences",
        "avg_amplification"
    ]

    for key in required_keys:
        assert key in report

    # Check synergy pair structure
    if report["synergy_pairs"]:
        pair = report["synergy_pairs"][0]
        assert "agent1" in pair
        assert "agent2" in pair
        assert "amplification" in pair
        assert "description" in pair


# ============================================================================
# Integration Tests
# ============================================================================

def test_full_coordination_workflow(coordinator, sample_context):
    """Test complete coordination workflow."""
    # 1. Create optimal plan
    plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.NASH_OPTIMAL)

    assert plan is not None
    assert len(plan.agent_sequence) > 0

    # 2. Execute coordinated attack
    result = coordinator.execute_coordinated_attack(sample_context, plan)

    assert result is not None
    assert len(result.agent_results) > 0

    # 3. Verify history updated
    assert len(coordinator.historical_results) > 0

    # 4. Generate report
    report = coordinator.get_synergy_report()

    assert report["historical_executions"] > 0
    assert report["avg_amplification"] > 0


def test_coordination_strategy_comparison(coordinator, sample_context):
    """Test different coordination strategies."""
    strategies = [
        CoordinationStrategy.SEQUENTIAL,
        CoordinationStrategy.NASH_OPTIMAL,
        CoordinationStrategy.FUSION_CHAIN
    ]

    results = []
    for strategy in strategies:
        plan = coordinator.create_fusion_chain_plan(strategy)
        result = coordinator.execute_coordinated_attack(sample_context, plan)
        results.append((strategy, result.observed_amplification))

    # All should complete successfully
    assert len(results) == 3

    # Nash and Fusion should generally outperform Sequential
    nash_amp = next(amp for strat, amp in results if strat == CoordinationStrategy.NASH_OPTIMAL)
    seq_amp = next(amp for strat, amp in results if strat == CoordinationStrategy.SEQUENTIAL)

    # Nash should find at least as good a sequence as sequential
    assert nash_amp >= seq_amp * 0.8  # Within 20% (accounting for variance)


def test_bayesian_learning_improves_confidence(coordinator, sample_context):
    """Test that repeated executions improve confidence estimates."""
    initial_plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.NASH_OPTIMAL)
    initial_confidence = initial_plan.confidence

    # Execute multiple times to build history
    for _ in range(5):
        coordinator.execute_coordinated_attack(sample_context, initial_plan)

    # Create new plan with same agents
    updated_plan = coordinator.create_fusion_chain_plan(CoordinationStrategy.NASH_OPTIMAL)

    # Confidence should be more certain (further from 0.5 prior)
    assert abs(updated_plan.confidence - 0.5) >= abs(initial_confidence - 0.5) * 0.9
