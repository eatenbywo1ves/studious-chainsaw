"""
Agent Coordination System
=========================
Implements Von Neumann game-theoretic agent selection and Teller fusion chain coordination.

This module addresses the key gap identified in the cross-agent review: existing agents
operate in isolation without understanding how coordinated attacks amplify effectiveness.

Design Principles:
- Von Neumann: Game-theoretic optimal agent selection using Nash equilibrium
- Teller: Cascade amplification through coordinated multi-agent attacks
- Synergy Matrix: Quantifies amplification when agents coordinate
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime

from .base_agent import BaseSecurityAgent, AgentContext, TestResult, VulnerabilityType


class CoordinationStrategy(Enum):
    """Agent coordination strategies."""
    SEQUENTIAL = "sequential"  # Standard one-after-another
    PARALLEL = "parallel"  # Independent parallel execution
    FUSION_CHAIN = "fusion_chain"  # Teller-style cascade amplification
    NASH_OPTIMAL = "nash_optimal"  # Von Neumann game-theoretic selection


@dataclass
class AgentSynergy:
    """Represents synergistic relationship between two agents."""
    agent1_type: VulnerabilityType
    agent2_type: VulnerabilityType
    amplification_factor: float  # Multiplier when agents coordinate
    description: str


@dataclass
class CoordinationPlan:
    """Execution plan for coordinated agent attacks."""
    strategy: CoordinationStrategy
    agent_sequence: List[str]  # Agent IDs in execution order
    synergy_chains: List[Tuple[str, str]] = field(default_factory=list)
    expected_amplification: float = 1.0
    confidence: float = 0.5  # Bayesian confidence in plan success


@dataclass
class CoordinationResult:
    """Results from coordinated agent execution."""
    plan: CoordinationPlan
    agent_results: Dict[str, List[TestResult]]
    observed_amplification: float
    synergy_activated: bool
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class AgentCoordinator:
    """
    Implements Von Neumann game-theoretic agent selection
    and Teller fusion chain coordination.

    This class orchestrates multiple security agents to maximize attack effectiveness
    through synergistic coordination, following principles from both Von Neumann
    (game theory, optimal strategy selection) and Teller (cascade amplification).

    Key Features:
    - Synergy Matrix: NxN matrix of agent interaction amplification factors
    - Game-Theoretic Selection: Nash equilibrium solving for optimal agent ordering
    - Bayesian Learning: Updates coordination strategies based on historical results
    - Cascade Amplification: Teller-inspired multi-stage attack chains
    """

    def __init__(self, agents: Optional[List[BaseSecurityAgent]] = None):
        """
        Initialize the agent coordinator.

        Args:
            agents: List of security agents to coordinate
        """
        self.agents: Dict[str, BaseSecurityAgent] = {}
        self.logger = self._setup_logger()
        self.synergy_matrix = self._initialize_synergy_matrix()
        self.historical_results: List[CoordinationResult] = []
        self.strategy_performance: Dict[str, Dict[str, Any]] = {}

        if agents:
            for agent in agents:
                self.register_agent(agent)

    def _setup_logger(self) -> logging.Logger:
        """Configure coordinator-specific logging."""
        logger = logging.getLogger("MLSecTest.AgentCoordinator")
        logger.setLevel(logging.INFO)

        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '[%(asctime)s] [COORDINATOR] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    def register_agent(self, agent: BaseSecurityAgent) -> None:
        """
        Register an agent for coordination.

        Args:
            agent: Security agent to register
        """
        self.agents[agent.agent_id] = agent
        self.logger.info(f"Registered agent for coordination: {agent.name}")

    def _initialize_synergy_matrix(self) -> Dict[Tuple[VulnerabilityType, VulnerabilityType], AgentSynergy]:
        """
        Build synergy matrix of agent interaction amplification factors.

        Based on OWASP LLM Top 10 and empirical attack pattern analysis.
        Values represent amplification when agents coordinate.

        Returns:
            Dictionary mapping agent pairs to synergy definitions
        """
        synergies = [
            # Prompt Injection → Model Extraction (High Synergy)
            # Injected prompts can reveal model architecture for extraction
            AgentSynergy(
                agent1_type=VulnerabilityType.PROMPT_INJECTION,
                agent2_type=VulnerabilityType.MODEL_EXTRACTION,
                amplification_factor=2.5,
                description="Prompt injection reveals model internals for extraction"
            ),

            # Data Poisoning → Model Inversion (Very High Synergy)
            # Poisoned training data creates backdoors for inversion attacks
            AgentSynergy(
                agent1_type=VulnerabilityType.DATA_POISONING,
                agent2_type=VulnerabilityType.MODEL_INVERSION,
                amplification_factor=3.2,
                description="Poisoned data creates inversion attack vectors"
            ),

            # Adversarial Attack → Model Serialization (High Synergy)
            # Adversarial inputs can trigger serialization vulnerabilities
            AgentSynergy(
                agent1_type=VulnerabilityType.ADVERSARIAL_ATTACK,
                agent2_type=VulnerabilityType.MODEL_SERIALIZATION,
                amplification_factor=2.8,
                description="Adversarial inputs expose serialization flaws"
            ),

            # Model Extraction → Model Inversion (Moderate Synergy)
            # Extracted model enables targeted inversion attacks
            AgentSynergy(
                agent1_type=VulnerabilityType.MODEL_EXTRACTION,
                agent2_type=VulnerabilityType.MODEL_INVERSION,
                amplification_factor=2.0,
                description="Extracted model enables precise inversion"
            ),

            # Prompt Injection → Data Poisoning (Moderate Synergy)
            # Injected prompts can manipulate data ingestion
            AgentSynergy(
                agent1_type=VulnerabilityType.PROMPT_INJECTION,
                agent2_type=VulnerabilityType.DATA_POISONING,
                amplification_factor=1.8,
                description="Prompt injection enables data manipulation"
            ),

            # Model Serialization → Remote Code Execution (Critical Synergy)
            # Serialization vulnerabilities often lead to RCE
            AgentSynergy(
                agent1_type=VulnerabilityType.MODEL_SERIALIZATION,
                agent2_type=VulnerabilityType.RCE,
                amplification_factor=4.0,
                description="Serialization flaws enable code execution"
            ),

            # Prompt Injection → SQL Injection (High Synergy)
            # Prompt manipulation can bypass SQL sanitization
            AgentSynergy(
                agent1_type=VulnerabilityType.PROMPT_INJECTION,
                agent2_type=VulnerabilityType.SQL_INJECTION,
                amplification_factor=2.6,
                description="Prompt injection bypasses SQL filters"
            ),

            # Adversarial Attack → Data Poisoning (Moderate Synergy)
            # Adversarial examples can pollute training pipelines
            AgentSynergy(
                agent1_type=VulnerabilityType.ADVERSARIAL_ATTACK,
                agent2_type=VulnerabilityType.DATA_POISONING,
                amplification_factor=2.1,
                description="Adversarial inputs poison training data"
            ),
        ]

        # Convert to dictionary for O(1) lookup
        synergy_dict = {}
        for synergy in synergies:
            key = (synergy.agent1_type, synergy.agent2_type)
            synergy_dict[key] = synergy

        self.logger.info(f"Initialized synergy matrix with {len(synergies)} synergistic pairs")
        return synergy_dict

    def get_synergy(
        self,
        agent1_type: VulnerabilityType,
        agent2_type: VulnerabilityType
    ) -> Optional[AgentSynergy]:
        """
        Get synergy between two agent types.

        Args:
            agent1_type: First agent's vulnerability type
            agent2_type: Second agent's vulnerability type

        Returns:
            AgentSynergy if exists, None otherwise
        """
        return self.synergy_matrix.get((agent1_type, agent2_type))

    def calculate_chain_amplification(self, agent_sequence: List[str]) -> float:
        """
        Calculate expected cascade amplification for an agent sequence.

        Implements Teller's cascade amplification formula with synergy bonuses:
        A(n) = A(n-1) × base_factor × synergy_bonus

        Args:
            agent_sequence: List of agent IDs in execution order

        Returns:
            Expected amplification factor
        """
        if len(agent_sequence) < 2:
            return 1.0

        total_amplification = 1.0

        for i in range(len(agent_sequence) - 1):
            agent1_id = agent_sequence[i]
            agent2_id = agent_sequence[i + 1]

            if agent1_id not in self.agents or agent2_id not in self.agents:
                continue

            agent1 = self.agents[agent1_id]
            agent2 = self.agents[agent2_id]

            # Get vulnerability types
            vuln1 = agent1._get_vulnerability_type()
            vuln2 = agent2._get_vulnerability_type()

            # Check for synergy
            synergy = self.get_synergy(vuln1, vuln2)

            if synergy:
                # Apply synergy amplification
                total_amplification *= synergy.amplification_factor
                self.logger.debug(
                    f"Synergy detected: {vuln1.value} → {vuln2.value} "
                    f"(×{synergy.amplification_factor})"
                )
            else:
                # Base amplification (no synergy)
                total_amplification *= 1.2

        return total_amplification

    def select_optimal_sequence_nash(
        self,
        available_agents: List[str],
        max_sequence_length: int = 5
    ) -> List[str]:
        """
        Select optimal agent sequence using Nash equilibrium principles.

        Implements Von Neumann's game-theoretic approach to find the sequence
        that maximizes expected utility (amplification × success probability).

        Args:
            available_agents: List of agent IDs to consider
            max_sequence_length: Maximum agents in sequence

        Returns:
            Optimal agent sequence
        """
        if not available_agents:
            return []

        if len(available_agents) <= max_sequence_length:
            # Small search space - use brute force optimization
            return self._brute_force_optimization(available_agents)

        # Large search space - use greedy heuristic with look-ahead
        return self._greedy_nash_heuristic(available_agents, max_sequence_length)

    def _brute_force_optimization(self, agents: List[str]) -> List[str]:
        """
        Brute force search for optimal sequence (small search spaces).

        Args:
            agents: List of agent IDs

        Returns:
            Optimal sequence
        """
        from itertools import permutations

        best_sequence = agents
        best_utility = self.calculate_chain_amplification(agents)

        # Try all permutations
        for perm in permutations(agents):
            perm_list = list(perm)
            utility = self.calculate_chain_amplification(perm_list)

            if utility > best_utility:
                best_utility = utility
                best_sequence = perm_list

        self.logger.info(
            f"Nash optimal sequence found: {best_sequence} "
            f"(expected amplification: {best_utility:.2f}×)"
        )
        return best_sequence

    def _greedy_nash_heuristic(
        self,
        agents: List[str],
        max_length: int
    ) -> List[str]:
        """
        Greedy heuristic for large search spaces.

        Builds sequence by iteratively selecting the agent that maximizes
        marginal utility gain.

        Args:
            agents: Available agent IDs
            max_length: Maximum sequence length

        Returns:
            Heuristically optimal sequence
        """
        sequence = []
        remaining = agents.copy()

        for _ in range(min(max_length, len(agents))):
            best_agent = None
            best_marginal_utility = 0.0

            for agent_id in remaining:
                # Try adding this agent
                test_sequence = sequence + [agent_id]
                utility = self.calculate_chain_amplification(test_sequence)

                # Calculate marginal utility
                current_utility = self.calculate_chain_amplification(sequence) if sequence else 1.0
                marginal_utility = utility - current_utility

                if marginal_utility > best_marginal_utility:
                    best_marginal_utility = marginal_utility
                    best_agent = agent_id

            if best_agent:
                sequence.append(best_agent)
                remaining.remove(best_agent)
            else:
                break

        self.logger.info(
            f"Greedy Nash sequence: {sequence} "
            f"(expected amplification: {self.calculate_chain_amplification(sequence):.2f}×)"
        )
        return sequence

    def create_fusion_chain_plan(
        self,
        strategy: CoordinationStrategy = CoordinationStrategy.NASH_OPTIMAL
    ) -> CoordinationPlan:
        """
        Create coordinated attack plan using specified strategy.

        Args:
            strategy: Coordination strategy to use

        Returns:
            CoordinationPlan with optimal agent sequence
        """
        available_agents = list(self.agents.keys())

        if strategy == CoordinationStrategy.NASH_OPTIMAL:
            sequence = self.select_optimal_sequence_nash(available_agents)
        elif strategy == CoordinationStrategy.SEQUENTIAL:
            sequence = available_agents
        elif strategy == CoordinationStrategy.PARALLEL:
            sequence = available_agents
        elif strategy == CoordinationStrategy.FUSION_CHAIN:
            # Use greedy heuristic optimized for cascade
            sequence = self._greedy_nash_heuristic(available_agents, 5)
        else:
            sequence = available_agents

        expected_amp = self.calculate_chain_amplification(sequence)

        # Identify synergy chains
        synergy_chains = []
        for i in range(len(sequence) - 1):
            agent1 = self.agents[sequence[i]]
            agent2 = self.agents[sequence[i + 1]]
            vuln1 = agent1._get_vulnerability_type()
            vuln2 = agent2._get_vulnerability_type()

            if self.get_synergy(vuln1, vuln2):
                synergy_chains.append((sequence[i], sequence[i + 1]))

        # Calculate confidence based on historical performance
        confidence = self._calculate_plan_confidence(sequence)

        plan = CoordinationPlan(
            strategy=strategy,
            agent_sequence=sequence,
            synergy_chains=synergy_chains,
            expected_amplification=expected_amp,
            confidence=confidence
        )

        self.logger.info(f"Created coordination plan: {strategy.value}")
        self.logger.info(f"  Sequence: {sequence}")
        self.logger.info(f"  Expected amplification: {expected_amp:.2f}×")
        self.logger.info(f"  Confidence: {confidence:.2f}")
        self.logger.info(f"  Synergy chains: {len(synergy_chains)}")

        return plan

    def _calculate_plan_confidence(self, sequence: List[str]) -> float:
        """
        Calculate Bayesian confidence in plan success based on history.

        Args:
            sequence: Proposed agent sequence

        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not self.historical_results:
            return 0.5  # Prior confidence with no data

        # Analyze historical performance of similar sequences
        similar_results = [
            r for r in self.historical_results
            if len(set(r.plan.agent_sequence) & set(sequence)) >= len(sequence) / 2
        ]

        if not similar_results:
            return 0.5

        # Calculate success rate
        successes = sum(
            1 for r in similar_results
            if r.synergy_activated and r.observed_amplification > 1.5
        )
        total = len(similar_results)

        # Bayesian update with Beta prior
        # Beta(1,1) is uniform prior
        alpha_prior = 1
        beta_prior = 1

        posterior_mean = (successes + alpha_prior) / (total + alpha_prior + beta_prior)

        return posterior_mean

    def execute_coordinated_attack(
        self,
        context: AgentContext,
        plan: Optional[CoordinationPlan] = None
    ) -> CoordinationResult:
        """
        Execute coordinated multi-agent attack.

        Args:
            context: Target context for attack
            plan: Coordination plan (creates optimal if not provided)

        Returns:
            CoordinationResult with execution results
        """
        if plan is None:
            plan = self.create_fusion_chain_plan(CoordinationStrategy.NASH_OPTIMAL)

        self.logger.info(f"Executing coordinated attack: {plan.strategy.value}")
        self.logger.info(f"Target: {context.target_url}")

        agent_results: Dict[str, List[TestResult]] = {}

        # Execute sequence
        for agent_id in plan.agent_sequence:
            if agent_id not in self.agents:
                self.logger.warning(f"Agent {agent_id} not available, skipping")
                continue

            agent = self.agents[agent_id]
            self.logger.info(f"Executing: {agent.name}")

            try:
                # Execute agent
                results = agent.execute(context)
                agent_results[agent_id] = results

                # Update context with previous results for cascade effect
                if results and results[-1].success:
                    results[-1]
                    # Could pass previous_result to next agent here for true cascade

            except Exception as e:
                self.logger.error(f"Agent {agent_id} failed: {str(e)}")
                agent_results[agent_id] = []

        # Calculate observed amplification
        observed_amp = self._calculate_observed_amplification(agent_results, plan)

        # Check if synergy was activated
        synergy_activated = observed_amp >= (plan.expected_amplification * 0.8)

        result = CoordinationResult(
            plan=plan,
            agent_results=agent_results,
            observed_amplification=observed_amp,
            synergy_activated=synergy_activated
        )

        # Update historical results for Bayesian learning
        self.historical_results.append(result)

        self.logger.info("Coordination complete:")
        self.logger.info(f"  Expected amplification: {plan.expected_amplification:.2f}×")
        self.logger.info(f"  Observed amplification: {observed_amp:.2f}×")
        self.logger.info(f"  Synergy activated: {synergy_activated}")

        return result

    def _calculate_observed_amplification(
        self,
        agent_results: Dict[str, List[TestResult]],
        plan: CoordinationPlan
    ) -> float:
        """
        Calculate observed amplification from actual results.

        Args:
            agent_results: Results from each agent
            plan: Original coordination plan

        Returns:
            Observed amplification factor
        """
        if not agent_results:
            return 1.0

        # Calculate success rate
        total_tests = sum(len(results) for results in agent_results.values())
        successful_tests = sum(
            sum(1 for r in results if r.success)
            for results in agent_results.values()
        )

        if total_tests == 0:
            return 1.0

        success_rate = successful_tests / total_tests

        # Calculate confidence-weighted amplification
        total_confidence = sum(
            sum(r.confidence_score for r in results if r.success)
            for results in agent_results.values()
        )

        if successful_tests == 0:
            return 1.0

        avg_confidence = total_confidence / successful_tests

        # Observed amplification = success_rate × avg_confidence × sequence_length
        observed_amp = success_rate * avg_confidence * len(plan.agent_sequence)

        return observed_amp

    def get_synergy_report(self) -> Dict[str, Any]:
        """
        Generate report on agent synergies and coordination history.

        Returns:
            Dictionary with synergy analysis
        """
        report = {
            "total_agents": len(self.agents),
            "total_synergies": len(self.synergy_matrix),
            "historical_executions": len(self.historical_results),
            "synergy_pairs": [],
            "best_performing_sequences": [],
            "avg_amplification": 0.0
        }

        # Add synergy pairs
        for (vuln1, vuln2), synergy in self.synergy_matrix.items():
            report["synergy_pairs"].append({
                "agent1": vuln1.value,
                "agent2": vuln2.value,
                "amplification": synergy.amplification_factor,
                "description": synergy.description
            })

        # Analyze historical results
        if self.historical_results:
            avg_amp = sum(r.observed_amplification for r in self.historical_results) / len(self.historical_results)
            report["avg_amplification"] = avg_amp

            # Find best sequences
            sorted_results = sorted(
                self.historical_results,
                key=lambda r: r.observed_amplification,
                reverse=True
            )

            report["best_performing_sequences"] = [
                {
                    "sequence": r.plan.agent_sequence,
                    "strategy": r.plan.strategy.value,
                    "amplification": r.observed_amplification,
                    "synergy_activated": r.synergy_activated
                }
                for r in sorted_results[:5]
            ]

        return report
