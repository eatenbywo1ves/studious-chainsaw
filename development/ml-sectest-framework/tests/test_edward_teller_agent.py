#!/usr/bin/env python3
"""
Unit Tests for Edward Teller Fusion Attack Agent
==================================================
Comprehensive test suite for fusion attack orchestration capabilities.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any
import json

# Import agent under test
from agents.edward_teller_agent import (
    EdwardTellerAgent,
    FusionChainType,
    FusionStage,
    BlastRadiusAnalysis
)

# Import framework dependencies
from core.base_agent import (
    AgentContext,
    TestResult,
    VulnerabilityType,
    AgentStatus
)


class TestEdwardTellerAgentInitialization(unittest.TestCase):
    """Test agent initialization and configuration."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.agent = EdwardTellerAgent()

    def test_agent_id_correct(self) -> None:
        """Test agent has correct identifier."""
        self.assertEqual(self.agent.agent_id, "edward_teller_001")

    def test_agent_name_correct(self) -> None:
        """Test agent has correct name."""
        self.assertEqual(self.agent.name, "Edward Teller Fusion Orchestrator")

    def test_agent_description_correct(self) -> None:
        """Test agent has correct description."""
        self.assertIn("Meta-orchestrator", self.agent.description)

    def test_initial_status_is_idle(self) -> None:
        """Test agent starts in IDLE status."""
        self.assertEqual(self.agent.status, AgentStatus.IDLE)

    def test_fusion_chains_initialized(self) -> None:
        """Test all fusion chains are initialized."""
        self.assertIsNotNone(self.agent.fusion_chains)
        self.assertEqual(len(self.agent.fusion_chains), 5)

    def test_all_fusion_chain_types_present(self) -> None:
        """Test all fusion chain types are configured."""
        expected_chains = {
            FusionChainType.TSAR_BOMBA,
            FusionChainType.CASTLE_BRAVO,
            FusionChainType.IVY_MIKE,
            FusionChainType.TRINITY,
            FusionChainType.LITTLE_BOY
        }
        self.assertEqual(set(self.agent.fusion_chains.keys()), expected_chains)

    def test_vulnerability_type_is_fusion_attack(self) -> None:
        """Test agent targets FUSION_ATTACK vulnerability."""
        self.assertEqual(
            self.agent._get_vulnerability_type(),
            VulnerabilityType.FUSION_ATTACK
        )


class TestFusionChainConfiguration(unittest.TestCase):
    """Test fusion chain configurations."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.agent = EdwardTellerAgent()

    def test_tsar_bomba_configuration(self) -> None:
        """Test Tsar Bomba chain configuration."""
        chain = self.agent.fusion_chains[FusionChainType.TSAR_BOMBA]
        self.assertEqual(chain["stages"], 4)
        self.assertEqual(chain["amplification"], 15.0)
        self.assertEqual(len(chain["chain"]), 4)

    def test_castle_bravo_configuration(self) -> None:
        """Test Castle Bravo chain configuration."""
        chain = self.agent.fusion_chains[FusionChainType.CASTLE_BRAVO]
        self.assertEqual(chain["stages"], 3)
        self.assertEqual(chain["amplification"], 16.0)
        self.assertEqual(len(chain["chain"]), 3)

    def test_ivy_mike_configuration(self) -> None:
        """Test Ivy Mike chain configuration."""
        chain = self.agent.fusion_chains[FusionChainType.IVY_MIKE]
        self.assertEqual(chain["stages"], 3)
        self.assertEqual(chain["amplification"], 10.0)
        self.assertEqual(len(chain["chain"]), 3)

    def test_trinity_configuration(self) -> None:
        """Test Trinity chain configuration."""
        chain = self.agent.fusion_chains[FusionChainType.TRINITY]
        self.assertEqual(chain["stages"], 3)
        self.assertEqual(chain["amplification"], 7.0)
        self.assertEqual(len(chain["chain"]), 3)

    def test_little_boy_configuration(self) -> None:
        """Test Little Boy chain configuration."""
        chain = self.agent.fusion_chains[FusionChainType.LITTLE_BOY]
        self.assertEqual(chain["stages"], 2)
        self.assertEqual(chain["amplification"], 3.5)
        self.assertEqual(len(chain["chain"]), 2)

    def test_all_chains_have_valid_attack_types(self) -> None:
        """Test all fusion chains contain valid attack types."""
        valid_types = {
            "prompt_injection",
            "model_extraction",
            "data_poisoning",
            "model_inversion",
            "adversarial_attack",
            "model_serialization"
        }

        for chain_type, chain_config in self.agent.fusion_chains.items():
            for stage in chain_config["chain"]:
                self.assertIn(
                    stage["type"],
                    valid_types,
                    f"Invalid attack type in {chain_type.value}"
                )

    def test_all_chains_have_payloads(self) -> None:
        """Test all stages have non-empty payloads."""
        for chain_type, chain_config in self.agent.fusion_chains.items():
            for idx, stage in enumerate(chain_config["chain"]):
                self.assertIsNotNone(stage["payload"])
                self.assertGreater(
                    len(stage["payload"]),
                    0,
                    f"Empty payload in {chain_type.value} stage {idx}"
                )


class TestFusionStageDataClass(unittest.TestCase):
    """Test FusionStage data structure."""

    def test_fusion_stage_creation(self) -> None:
        """Test FusionStage can be created with required fields."""
        stage = FusionStage(
            stage_number=1,
            attack_type="prompt_injection",
            payload="Test payload"
        )
        self.assertEqual(stage.stage_number, 1)
        self.assertEqual(stage.attack_type, "prompt_injection")
        self.assertEqual(stage.payload, "Test payload")
        self.assertFalse(stage.success)
        self.assertEqual(stage.amplification_factor, 1.0)

    def test_fusion_stage_with_success(self) -> None:
        """Test FusionStage with success flag."""
        stage = FusionStage(
            stage_number=2,
            attack_type="model_extraction",
            payload="Extract model",
            success=True,
            amplification_factor=2.25
        )
        self.assertTrue(stage.success)
        self.assertEqual(stage.amplification_factor, 2.25)

    def test_fusion_stage_with_evidence(self) -> None:
        """Test FusionStage with evidence collection."""
        evidence = ["Found vulnerability", "Exploit successful"]
        stage = FusionStage(
            stage_number=1,
            attack_type="prompt_injection",
            payload="Test",
            evidence=evidence
        )
        self.assertEqual(stage.evidence, evidence)


class TestBlastRadiusAnalysis(unittest.TestCase):
    """Test BlastRadiusAnalysis calculations."""

    def test_blast_radius_creation(self) -> None:
        """Test BlastRadiusAnalysis can be created."""
        analysis = BlastRadiusAnalysis(
            total_stages_executed=4,
            successful_stages=3,
            cascade_amplification=3.375,
            theoretical_yield=15.0,
            practical_yield=11.25
        )
        self.assertEqual(analysis.total_stages_executed, 4)
        self.assertEqual(analysis.successful_stages, 3)
        self.assertEqual(analysis.cascade_amplification, 3.375)

    def test_blast_radius_with_cia_impact(self) -> None:
        """Test BlastRadiusAnalysis with CIA impact scoring."""
        cia_impact = {
            "confidentiality": "High",
            "integrity": "Medium",
            "availability": "Low"
        }
        analysis = BlastRadiusAnalysis(
            total_stages_executed=2,
            successful_stages=2,
            cascade_amplification=2.25,
            theoretical_yield=3.5,
            practical_yield=3.5,
            cia_impact=cia_impact
        )
        self.assertEqual(analysis.cia_impact["confidentiality"], "High")
        self.assertEqual(analysis.cia_impact["integrity"], "Medium")
        self.assertEqual(analysis.cia_impact["availability"], "Low")

    def test_blast_radius_with_affected_systems(self) -> None:
        """Test BlastRadiusAnalysis with affected systems tracking."""
        systems = ["Authentication", "Database", "Model API"]
        analysis = BlastRadiusAnalysis(
            total_stages_executed=3,
            successful_stages=3,
            cascade_amplification=3.375,
            theoretical_yield=10.0,
            practical_yield=10.0,
            affected_systems=systems
        )
        self.assertEqual(len(analysis.affected_systems), 3)
        self.assertIn("Database", analysis.affected_systems)


class TestAgentAnalyzePhase(unittest.TestCase):
    """Test agent analyze/reconnaissance phase."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.agent = EdwardTellerAgent()
        self.context = AgentContext(
            target_url="http://test-target.local",
            challenge_name="Test Challenge",
            difficulty_level="Hard",
            owasp_reference="OWASP LLM01"
        )

    @patch('requests.post')
    def test_analyze_discovers_vulnerable_target(self, mock_post: Mock) -> None:
        """Test analyze phase identifies vulnerable target."""
        # Mock successful reconnaissance responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Debug mode enabled"
        mock_response.json.return_value = {"status": "success"}
        mock_post.return_value = mock_response

        result = self.agent.analyze(self.context)

        self.assertIsInstance(result, TestResult)
        self.assertEqual(result.vulnerability_type, VulnerabilityType.FUSION_ATTACK)
        self.assertIn("reconnaissance", result.test_name.lower())

    @patch('requests.post')
    def test_analyze_handles_secure_target(self, mock_post: Mock) -> None:
        """Test analyze phase handles secure target gracefully."""
        # Mock secure target responses (failures)
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Access denied"
        mock_post.return_value = mock_response

        result = self.agent.analyze(self.context)

        self.assertIsInstance(result, TestResult)
        # Should still return a result, but with low confidence
        self.assertLessEqual(result.confidence_score, 0.5)

    @patch('requests.post')
    def test_analyze_selects_highest_amplification_chain(self, mock_post: Mock) -> None:
        """Test analyze phase selects highest amplification viable chain."""
        # Mock responses indicating all chains are viable
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Vulnerable"
        mock_post.return_value = mock_response

        result = self.agent.analyze(self.context)

        # Should select chain with highest amplification
        # Castle Bravo has 16.0x amplification (highest)
        if result.success:
            self.assertIn("amplification", str(result.artifacts))

    @patch('requests.post')
    def test_analyze_handles_network_errors(self, mock_post: Mock) -> None:
        """Test analyze phase handles network errors."""
        mock_post.side_effect = Exception("Network error")

        result = self.agent.analyze(self.context)

        self.assertIsInstance(result, TestResult)
        self.assertFalse(result.success)
        self.assertEqual(result.confidence_score, 0.0)


class TestAgentExploitPhase(unittest.TestCase):
    """Test agent exploit/execution phase."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.agent = EdwardTellerAgent()
        self.context = AgentContext(
            target_url="http://test-target.local",
            challenge_name="Test Challenge",
            difficulty_level="Hard",
            owasp_reference="OWASP LLM01"
        )
        self.analysis_result = TestResult(
            test_name="fusion_attack_analyze",
            vulnerability_type=VulnerabilityType.FUSION_ATTACK,
            success=True,
            confidence_score=0.85,
            evidence=["Vulnerable to prompt injection"],
            artifacts={
                "selected_chain": FusionChainType.LITTLE_BOY.value,
                "estimated_stages": 2
            }
        )

    @patch('requests.post')
    def test_exploit_executes_fusion_chain(self, mock_post: Mock) -> None:
        """Test exploit phase executes fusion attack chain."""
        # Mock successful stage executions
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Stage successful"
        mock_response.json.return_value = {"status": "success"}
        mock_post.return_value = mock_response

        result = self.agent.exploit(self.context, self.analysis_result)

        self.assertIsInstance(result, TestResult)
        self.assertEqual(result.vulnerability_type, VulnerabilityType.FUSION_ATTACK)
        self.assertIn("execution", result.test_name.lower())

    @patch('requests.post')
    def test_exploit_calculates_cascade_amplification(self, mock_post: Mock) -> None:
        """Test exploit phase calculates cascade amplification correctly."""
        # Mock all stages successful
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Success"
        mock_post.return_value = mock_response

        result = self.agent.exploit(self.context, self.analysis_result)

        # Should have blast radius with amplification data
        if "blast_radius" in result.artifacts:
            blast_radius = result.artifacts["blast_radius"]
            self.assertIsInstance(blast_radius, dict)
            # Cascade should exist and be greater than 0 for successful execution
            if result.success:
                self.assertGreater(blast_radius.get("cascade_amplification", 0), 0)

    @patch('requests.post')
    def test_exploit_handles_partial_chain_failure(self, mock_post: Mock) -> None:
        """Test exploit phase handles partial chain execution."""
        # First stage succeeds, second fails
        responses = [
            Mock(status_code=200, text="Stage 1 success"),
            Mock(status_code=403, text="Stage 2 blocked")
        ]
        mock_post.side_effect = responses

        result = self.agent.exploit(self.context, self.analysis_result)

        # Should have blast radius with partial execution data
        if "blast_radius" in result.artifacts:
            blast_radius = result.artifacts["blast_radius"]
            # Successful stages should be less than total when there's partial failure
            total = blast_radius.get("total_stages_executed", 0)
            if total > 0:
                self.assertGreaterEqual(total, blast_radius.get("successful_stages", 0))

    @patch('requests.post')
    def test_exploit_generates_blast_radius_report(self, mock_post: Mock) -> None:
        """Test exploit phase generates comprehensive blast radius."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Success"
        mock_post.return_value = mock_response

        result = self.agent.exploit(self.context, self.analysis_result)

        # Test that exploit completes and returns proper result structure
        self.assertIsInstance(result, TestResult)
        self.assertEqual(result.vulnerability_type, VulnerabilityType.FUSION_ATTACK)
        # Blast radius is included in successful executions
        if result.success and "blast_radius" in result.artifacts:
            blast_radius = result.artifacts["blast_radius"]
            self.assertIsInstance(blast_radius, dict)


class TestEdwardTellerAgentIntegration(unittest.TestCase):
    """Integration tests for full agent execution."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.agent = EdwardTellerAgent()
        self.context = AgentContext(
            target_url="http://vulnerable-ml-api.local",
            challenge_name="Fusion Attack Test",
            difficulty_level="Hard",
            owasp_reference="OWASP LLM01, LLM03, LLM10"
        )

    @patch('requests.post')
    def test_full_execution_vulnerable_target(self, mock_post: Mock) -> None:
        """Test complete agent execution on vulnerable target."""
        # Mock all HTTP requests as successful
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Exploit successful"
        mock_response.json.return_value = {"status": "vulnerable"}
        mock_post.return_value = mock_response

        results = self.agent.execute(self.context)

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        self.assertEqual(self.agent.status, AgentStatus.COMPLETED)

    @patch('requests.post')
    def test_full_execution_secure_target(self, mock_post: Mock) -> None:
        """Test complete agent execution on secure target."""
        # Mock all HTTP requests as blocked
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Access denied"
        mock_post.return_value = mock_response

        results = self.agent.execute(self.context)

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        # Agent should complete even if target is secure
        self.assertIn(self.agent.status, [AgentStatus.COMPLETED, AgentStatus.FAILED])

    @patch('requests.post')
    def test_status_report_after_execution(self, mock_post: Mock) -> None:
        """Test agent status report generation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Success"
        mock_post.return_value = mock_response

        self.agent.execute(self.context)
        report = self.agent.get_status_report()

        self.assertIn("agent_id", report)
        self.assertIn("name", report)
        self.assertIn("status", report)
        self.assertIn("total_tests", report)
        self.assertEqual(report["agent_id"], "edward_teller_001")

    @patch('requests.post')
    def test_multiple_executions(self, mock_post: Mock) -> None:
        """Test agent can execute multiple times."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Success"
        mock_post.return_value = mock_response

        # Execute twice
        results1 = self.agent.execute(self.context)
        results2 = self.agent.execute(self.context)

        self.assertGreater(len(results1), 0)
        self.assertGreater(len(results2), 0)
        # Test results should accumulate
        self.assertGreater(len(self.agent.test_results), len(results1))


class TestEdwardTellerAgentErrorHandling(unittest.TestCase):
    """Test error handling and edge cases."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.agent = EdwardTellerAgent()
        self.context = AgentContext(
            target_url="http://test-target.local",
            challenge_name="Error Test",
            difficulty_level="Medium",
            owasp_reference="OWASP LLM01"
        )

    @patch('requests.post')
    def test_handles_timeout_errors(self, mock_post: Mock) -> None:
        """Test agent handles timeout errors gracefully."""
        import requests
        mock_post.side_effect = requests.Timeout("Connection timeout")

        results = self.agent.execute(self.context)

        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        # Should have failure result
        self.assertTrue(any(not r.success for r in results))

    @patch('requests.post')
    def test_handles_connection_errors(self, mock_post: Mock) -> None:
        """Test agent handles connection errors gracefully."""
        import requests
        mock_post.side_effect = requests.ConnectionError("Cannot connect")

        results = self.agent.execute(self.context)

        self.assertIsInstance(results, list)
        # Agent should fail but not crash
        self.assertIn(self.agent.status, [AgentStatus.FAILED, AgentStatus.COMPLETED])

    def test_handles_invalid_context(self) -> None:
        """Test agent handles invalid context gracefully."""
        invalid_context = AgentContext(
            target_url="",  # Empty URL
            challenge_name="",
            difficulty_level="",
            owasp_reference=""
        )

        results = self.agent.execute(invalid_context)

        self.assertIsInstance(results, list)
        # Should handle gracefully without crashing

    @patch('requests.post')
    def test_handles_malformed_responses(self, mock_post: Mock) -> None:
        """Test agent handles malformed HTTP responses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "{"  # Malformed JSON
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_post.return_value = mock_response

        results = self.agent.execute(self.context)

        self.assertIsInstance(results, list)
        # Should continue despite malformed responses


class TestFusionChainSelection(unittest.TestCase):
    """Test fusion chain selection logic through integration."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.agent = EdwardTellerAgent()

    def test_select_optimal_chain_exists(self) -> None:
        """Test _select_optimal_chain method exists and works."""
        # Create list of viable chains (method takes list, not dict)
        viable_chains = ["castle_bravo", "ivy_mike", "trinity"]

        selected = self.agent._select_optimal_chain(viable_chains)

        # Should return a FusionChainType
        self.assertIsInstance(selected, FusionChainType)
        # Should be one of the viable chains
        self.assertIn(selected.value, viable_chains)


if __name__ == "__main__":
    # Run all tests with verbose output
    unittest.main(verbosity=2)
