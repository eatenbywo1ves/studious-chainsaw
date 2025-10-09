"""
Base Agent Framework for ML Security Testing
==============================================
Provides foundational classes for autonomous security testing agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import logging
import time
from datetime import datetime


class AgentStatus(Enum):
    """Agent execution status enumeration."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class VulnerabilityType(Enum):
    """ML/AI Security vulnerability classifications."""

    PROMPT_INJECTION = "prompt_injection"
    MODEL_INVERSION = "model_inversion"
    DATA_POISONING = "data_poisoning"
    MODEL_EXTRACTION = "model_extraction"
    MODEL_SERIALIZATION = "model_serialization"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    MCP_SIGNATURE_CLOAKING = "mcp_signature_cloaking"
    SQL_INJECTION = "sql_injection"
    RCE = "remote_code_execution"


@dataclass
class TestResult:
    """Encapsulates test execution results."""

    test_name: str
    vulnerability_type: VulnerabilityType
    success: bool
    confidence_score: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    execution_time_seconds: float = 0.0
    recommendations: List[str] = field(default_factory=list)


@dataclass
class AgentContext:
    """Context information for agent execution."""

    target_url: str
    challenge_name: str
    difficulty_level: str
    owasp_reference: str
    mitre_reference: Optional[str] = None
    custom_params: Dict[str, Any] = field(default_factory=dict)


class BaseSecurityAgent(ABC):
    """
    Abstract base class for all security testing agents.

    Each agent specializes in detecting and exploiting specific ML/AI vulnerabilities
    following defensive security principles.
    """

    def __init__(self, agent_id: str, name: str, description: str):
        """
        Initialize the base security agent.

        Args:
            agent_id: Unique identifier for this agent
            name: Human-readable agent name
            description: Agent capabilities description
        """
        self.agent_id = agent_id
        self.name = name
        self.description = description
        self.status = AgentStatus.IDLE
        self.logger = self._setup_logger()
        self.test_results: List[TestResult] = []

    def _setup_logger(self) -> logging.Logger:
        """Configure agent-specific logging."""
        logger = logging.getLogger(f"MLSecTest.{self.agent_id}")
        logger.setLevel(logging.INFO)

        # Create console handler with formatting
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            f"[%(asctime)s] [{self.agent_id}] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    @abstractmethod
    def analyze(self, context: AgentContext) -> TestResult:
        """
        Analyze target for vulnerabilities.

        Args:
            context: Execution context with target information

        Returns:
            TestResult containing analysis findings
        """
        pass

    @abstractmethod
    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        """
        Attempt defensive exploitation to validate vulnerability.

        Args:
            context: Execution context
            test_result: Previous analysis results

        Returns:
            TestResult with exploitation findings
        """
        pass

    def execute(self, context: AgentContext) -> List[TestResult]:
        """
        Execute full testing workflow: analyze then exploit.

        Args:
            context: Execution context

        Returns:
            List of test results from all phases
        """
        self.status = AgentStatus.RUNNING
        self.logger.info(f"Starting security analysis for {context.challenge_name}")

        results = []
        start_time = time.time()

        try:
            # Phase 1: Analysis
            self.logger.info("Phase 1: Vulnerability Analysis")
            analysis_result = self.analyze(context)
            analysis_result.execution_time_seconds = time.time() - start_time
            results.append(analysis_result)

            # Phase 2: Exploitation (only if analysis found vulnerability)
            if analysis_result.success and analysis_result.confidence_score > 0.5:
                self.logger.info("Phase 2: Defensive Exploitation")
                exploit_start = time.time()
                exploit_result = self.exploit(context, analysis_result)
                exploit_result.execution_time_seconds = time.time() - exploit_start
                results.append(exploit_result)
            else:
                self.logger.info("Skipping exploitation - vulnerability not confirmed")

            self.status = AgentStatus.COMPLETED
            self.logger.info(f"Testing completed in {time.time() - start_time:.2f}s")

        except Exception as agent_exception:
            self.status = AgentStatus.FAILED
            self.logger.error(f"Agent execution failed: {str(agent_exception)}")

            # Create failure result
            failure_result = TestResult(
                test_name=f"{self.name}_failure",
                vulnerability_type=self._get_vulnerability_type(),
                success=False,
                confidence_score=0.0,
                evidence=[f"Agent exception: {str(agent_exception)}"],
                execution_time_seconds=time.time() - start_time,
            )
            results.append(failure_result)

        self.test_results.extend(results)
        return results

    @abstractmethod
    def _get_vulnerability_type(self) -> VulnerabilityType:
        """Return the vulnerability type this agent targets."""
        pass

    def get_status_report(self) -> Dict[str, Any]:
        """
        Generate agent status report.

        Returns:
            Dictionary containing agent state and metrics
        """
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "status": self.status.value,
            "total_tests": len(self.test_results),
            "successful_tests": sum(1 for r in self.test_results if r.success),
            "failed_tests": sum(1 for r in self.test_results if not r.success),
            "average_confidence": (
                sum(r.confidence_score for r in self.test_results) / len(self.test_results)
                if self.test_results
                else 0.0
            ),
        }
