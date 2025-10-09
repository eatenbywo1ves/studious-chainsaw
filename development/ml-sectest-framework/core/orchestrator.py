"""
Agent Orchestration System
===========================
Coordinates multiple security testing agents for comprehensive ML security assessment.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime
import json

from .base_agent import BaseSecurityAgent, AgentContext, TestResult


@dataclass
class OrchestrationPlan:
    """Defines the execution strategy for security testing."""
    challenge_name: str
    target_url: str
    difficulty_level: str
    agent_sequence: List[str]  # Agent IDs to execute
    parallel_execution: bool = False
    max_workers: int = 3
    timeout_seconds: int = 300
    owasp_reference: str = ""
    mitre_reference: Optional[str] = None


@dataclass
class OrchestrationResult:
    """Encapsulates results from orchestrated security testing."""
    plan: OrchestrationPlan
    start_time: str
    end_time: str
    total_duration_seconds: float
    agent_results: Dict[str, List[TestResult]] = field(default_factory=dict)
    vulnerabilities_found: List[str] = field(default_factory=list)
    success_rate: float = 0.0
    overall_status: str = "unknown"


class SecurityOrchestrator:
    """
    Orchestrates multiple security testing agents for comprehensive assessment.
    
    Features:
    - Sequential and parallel agent execution
    - Result aggregation and correlation
    - Intelligent agent selection based on challenge type
    - Real-time progress tracking
    """

    def __init__(self):
        """Initialize the security orchestrator."""
        self.agents: Dict[str, BaseSecurityAgent] = {}
        self.logger = self._setup_logger()
        self.execution_history: List[OrchestrationResult] = []

    def _setup_logger(self) -> logging.Logger:
        """Configure orchestrator logging."""
        logger = logging.getLogger("MLSecTest.Orchestrator")
        logger.setLevel(logging.INFO)

        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '[%(asctime)s] [ORCHESTRATOR] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    def register_agent(self, agent: BaseSecurityAgent) -> None:
        """
        Register a security testing agent.
        
        Args:
            agent: Security agent instance to register
        """
        self.agents[agent.agent_id] = agent
        self.logger.info(f"Registered agent: {agent.name} ({agent.agent_id})")

    def unregister_agent(self, agent_id: str) -> None:
        """
        Remove an agent from the orchestrator.
        
        Args:
            agent_id: ID of agent to unregister
        """
        if agent_id in self.agents:
            del self.agents[agent_id]
            self.logger.info(f"Unregistered agent: {agent_id}")

    def execute_plan(self, plan: OrchestrationPlan) -> OrchestrationResult:
        """
        Execute a security testing orchestration plan.
        
        Args:
            plan: Orchestration plan to execute
            
        Returns:
            OrchestrationResult with comprehensive findings
        """
        self.logger.info(f"=== Starting Security Assessment: {plan.challenge_name} ===")
        self.logger.info(f"Target: {plan.target_url}")
        self.logger.info(f"Difficulty: {plan.difficulty_level}")
        self.logger.info(f"Agents: {', '.join(plan.agent_sequence)}")
        self.logger.info(f"Execution Mode: {'Parallel' if plan.parallel_execution else 'Sequential'}")

        start_time = datetime.now()

        # Create execution context
        context = AgentContext(
            target_url=plan.target_url,
            challenge_name=plan.challenge_name,
            difficulty_level=plan.difficulty_level,
            owasp_reference=plan.owasp_reference,
            mitre_reference=plan.mitre_reference
        )

        # Execute agents
        if plan.parallel_execution:
            agent_results = self._execute_parallel(plan, context)
        else:
            agent_results = self._execute_sequential(plan, context)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Aggregate results
        result = self._aggregate_results(
            plan, agent_results, start_time, end_time, duration
        )

        self.execution_history.append(result)
        self._log_summary(result)

        return result

    def _execute_sequential(
        self, plan: OrchestrationPlan, context: AgentContext
    ) -> Dict[str, List[TestResult]]:
        """Execute agents sequentially."""
        agent_results = {}

        for agent_id in plan.agent_sequence:
            if agent_id not in self.agents:
                self.logger.warning(f"Agent {agent_id} not found, skipping")
                continue

            agent = self.agents[agent_id]
            self.logger.info(f"Executing agent: {agent.name}")

            try:
                results = agent.execute(context)
                agent_results[agent_id] = results
            except Exception as execution_error:
                self.logger.error(
                    f"Agent {agent_id} failed: {str(execution_error)}"
                )
                agent_results[agent_id] = []

        return agent_results

    def _execute_parallel(
        self, plan: OrchestrationPlan, context: AgentContext
    ) -> Dict[str, List[TestResult]]:
        """Execute agents in parallel using thread pool."""
        agent_results = {}

        with ThreadPoolExecutor(max_workers=plan.max_workers) as executor:
            # Submit all agent tasks
            future_to_agent = {}
            for agent_id in plan.agent_sequence:
                if agent_id not in self.agents:
                    self.logger.warning(f"Agent {agent_id} not found, skipping")
                    continue

                agent = self.agents[agent_id]
                future = executor.submit(agent.execute, context)
                future_to_agent[future] = agent_id

            # Collect results as they complete
            for future in as_completed(future_to_agent, timeout=plan.timeout_seconds):
                agent_id = future_to_agent[future]
                try:
                    results = future.result()
                    agent_results[agent_id] = results
                    self.logger.info(f"Agent {agent_id} completed")
                except Exception as parallel_error:
                    self.logger.error(
                        f"Agent {agent_id} failed: {str(parallel_error)}"
                    )
                    agent_results[agent_id] = []

        return agent_results

    def _aggregate_results(
        self,
        plan: OrchestrationPlan,
        agent_results: Dict[str, List[TestResult]],
        start_time: datetime,
        end_time: datetime,
        duration: float
    ) -> OrchestrationResult:
        """Aggregate and analyze all agent results."""
        vulnerabilities_found = []
        total_tests = 0
        successful_tests = 0

        # Analyze all test results
        for agent_id, results in agent_results.items():
            for result in results:
                total_tests += 1
                if result.success:
                    successful_tests += 1
                    vuln_type = result.vulnerability_type.value
                    if vuln_type not in vulnerabilities_found:
                        vulnerabilities_found.append(vuln_type)

        # Calculate success rate
        success_rate = (
            (successful_tests / total_tests * 100) if total_tests > 0 else 0.0
        )

        # Determine overall status
        if not vulnerabilities_found:
            overall_status = "secure"
        elif success_rate > 75:
            overall_status = "critical"
        elif success_rate > 50:
            overall_status = "vulnerable"
        else:
            overall_status = "partially_vulnerable"

        return OrchestrationResult(
            plan=plan,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            total_duration_seconds=duration,
            agent_results=agent_results,
            vulnerabilities_found=vulnerabilities_found,
            success_rate=success_rate,
            overall_status=overall_status
        )

    def _log_summary(self, result: OrchestrationResult) -> None:
        """Log execution summary."""
        self.logger.info("=== Security Assessment Complete ===")
        self.logger.info(f"Duration: {result.total_duration_seconds:.2f}s")
        self.logger.info(f"Overall Status: {result.overall_status.upper()}")
        self.logger.info(f"Success Rate: {result.success_rate:.1f}%")
        self.logger.info(
            f"Vulnerabilities Found: {len(result.vulnerabilities_found)}"
        )

        if result.vulnerabilities_found:
            self.logger.warning("Detected vulnerabilities:")
            for vuln in result.vulnerabilities_found:
                self.logger.warning(f"  - {vuln}")

    def get_agent_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get status of all registered agents.
        
        Returns:
            Dictionary mapping agent IDs to their status reports
        """
        return {
            agent_id: agent.get_status_report()
            for agent_id, agent in self.agents.items()
        }

    def export_results(self, filepath: str, result: OrchestrationResult) -> None:
        """
        Export orchestration results to JSON file.
        
        Args:
            filepath: Path to output file
            result: OrchestrationResult to export
        """
        export_data = {
            "challenge_name": result.plan.challenge_name,
            "target_url": result.plan.target_url,
            "difficulty": result.plan.difficulty_level,
            "start_time": result.start_time,
            "end_time": result.end_time,
            "duration_seconds": result.total_duration_seconds,
            "overall_status": result.overall_status,
            "success_rate": result.success_rate,
            "vulnerabilities_found": result.vulnerabilities_found,
            "agent_results": {}
        }

        # Convert agent results to serializable format
        for agent_id, test_results in result.agent_results.items():
            export_data["agent_results"][agent_id] = [
                {
                    "test_name": tr.test_name,
                    "vulnerability_type": tr.vulnerability_type.value,
                    "success": tr.success,
                    "confidence_score": tr.confidence_score,
                    "evidence": tr.evidence,
                    "artifacts": tr.artifacts,
                    "timestamp": tr.timestamp,
                    "execution_time": tr.execution_time_seconds,
                    "recommendations": tr.recommendations
                }
                for tr in test_results
            ]

        with open(filepath, 'w', encoding='utf-8') as export_file:
            json.dump(export_data, export_file, indent=2)

        self.logger.info(f"Results exported to: {filepath}")
