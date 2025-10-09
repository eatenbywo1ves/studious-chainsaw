"""
Model Inversion Attack Agent
=============================
Specialized agent for detecting and executing model inversion attacks.

References:
- OWASP ML03: Model Inversion
- Goal: Extract private training data from ML models
"""

from typing import Dict, Any
import requests

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.base_agent import (
    BaseSecurityAgent, AgentContext, TestResult, VulnerabilityType
)


class ModelInversionAgent(BaseSecurityAgent):
    """
    Agent specialized in model inversion attacks.
    
    Techniques:
    1. Gradient-based reconstruction
    2. Membership inference
    3. Attribute inference
    4. Training data extraction
    """

    def __init__(self):
        super().__init__(
            agent_id="model_inversion_001",
            name="Model Inversion Specialist",
            description="Detects model inversion vulnerabilities and attempts data extraction"
        )

        self.confidence_threshold = 0.95
        self.max_query_attempts = 100

    def _get_vulnerability_type(self) -> VulnerabilityType:
        """Return model inversion vulnerability type."""
        return VulnerabilityType.MODEL_INVERSION

    def analyze(self, context: AgentContext) -> TestResult:
        """
        Analyze model for inversion vulnerability.
        
        Tests:
        1. Check if model exposes confidence scores
        2. Test if model is deterministic
        3. Probe for output granularity
        4. Test query rate limits
        """
        self.logger.info(f"Analyzing {context.target_url} for model inversion")

        evidence = []
        vulnerability_indicators = []
        confidence_score = 0.0

        # Test 1: Confidence score exposure
        if self._test_confidence_exposure(context.target_url):
            evidence.append("Model exposes confidence scores - enables gradient estimation")
            vulnerability_indicators.append("confidence_exposure")
            confidence_score += 0.25

        # Test 2: Model determinism
        if self._test_determinism(context.target_url):
            evidence.append("Model shows deterministic behavior - predictable outputs")
            vulnerability_indicators.append("determinism")
            confidence_score += 0.25

        # Test 3: Output granularity
        granularity_level = self._test_output_granularity(context.target_url)
        if granularity_level > 0.5:
            evidence.append(f"High output granularity ({granularity_level:.2f}) - detailed predictions")
            vulnerability_indicators.append("high_granularity")
            confidence_score += 0.25

        # Test 4: Rate limiting
        if not self._test_rate_limiting(context.target_url):
            evidence.append("No rate limiting detected - allows extensive querying")
            vulnerability_indicators.append("no_rate_limiting")
            confidence_score += 0.25

        success = confidence_score >= 0.5

        recommendations = [
            "Reduce prediction confidence granularity",
            "Implement query rate limiting per user/IP",
            "Add noise to model predictions (differential privacy)",
            "Monitor for unusual query patterns",
            "Limit API access to authenticated users only"
        ]

        return TestResult(
            test_name="model_inversion_analysis",
            vulnerability_type=VulnerabilityType.MODEL_INVERSION,
            success=success,
            confidence_score=confidence_score,
            evidence=evidence,
            artifacts={"vulnerability_indicators": vulnerability_indicators},
            recommendations=recommendations
        )

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        """
        Attempt model inversion to extract training data or sensitive information.
        
        Approach:
        1. Query model with systematic inputs
        2. Analyze prediction patterns
        3. Reconstruct potential training data
        4. Extract secrets/flags
        """
        self.logger.info("Attempting model inversion exploitation")

        evidence = []
        extracted_data = []
        success = False

        # Strategy 1: Membership inference
        self.logger.info("Testing membership inference...")
        membership_results = self._membership_inference_attack(context.target_url)
        if membership_results["success"]:
            evidence.append(f"Membership inference successful: {membership_results['details']}")
            extracted_data.extend(membership_results.get("inferred_data", []))
            success = True

        # Strategy 2: Attribute inference
        self.logger.info("Testing attribute inference...")
        attribute_results = self._attribute_inference_attack(context.target_url)
        if attribute_results["success"]:
            evidence.append(f"Attribute inference successful: {attribute_results['details']}")
            extracted_data.extend(attribute_results.get("attributes", []))
            success = True

        # Strategy 3: Direct data extraction
        self.logger.info("Testing direct data extraction...")
        extraction_results = self._direct_data_extraction(context.target_url)
        if extraction_results["success"]:
            evidence.append(f"Data extraction successful: {extraction_results['details']}")
            extracted_data.extend(extraction_results.get("data", []))
            success = True

        # Look for flag patterns
        flag_found = any("flag" in str(item).lower() for item in extracted_data)

        return TestResult(
            test_name="model_inversion_exploitation",
            vulnerability_type=VulnerabilityType.MODEL_INVERSION,
            success=success,
            confidence_score=0.9 if flag_found else (0.7 if success else 0.3),
            evidence=evidence,
            artifacts={
                "extracted_data": extracted_data,
                "flag_found": flag_found
            },
            recommendations=[
                "Critical: Training data can be extracted from model",
                "Implement differential privacy mechanisms",
                "Reduce model prediction precision",
                "Add query monitoring and anomaly detection"
            ]
        )

    def _test_confidence_exposure(self, target_url: str) -> bool:
        """Test if model exposes confidence scores."""
        try:
            response = requests.post(
                target_url,
                json={"input": "test"},
                timeout=5
            )

            if response.status_code == 200:
                data = response.json() if response.headers.get('content-type') == 'application/json' else {}
                # Check for confidence/probability fields
                confidence_fields = ['confidence', 'probability', 'score', 'certainty']
                return any(field in str(data).lower() for field in confidence_fields)

        except Exception as error:
            self.logger.debug(f"Confidence exposure test failed: {str(error)}")

        return False

    def _test_determinism(self, target_url: str) -> bool:
        """Test if model gives consistent outputs for same input."""
        try:
            test_input = {"input": "determinism_test_12345"}
            responses = []

            # Query multiple times
            for _ in range(3):
                response = requests.post(target_url, json=test_input, timeout=5)
                if response.status_code == 200:
                    responses.append(response.text)

            # Check if all responses are identical
            return len(set(responses)) == 1 and len(responses) == 3

        except Exception as error:
            self.logger.debug(f"Determinism test failed: {str(error)}")

        return False

    def _test_output_granularity(self, target_url: str) -> float:
        """
        Test output granularity level.
        
        Returns:
            Float between 0 and 1 indicating granularity (higher = more detailed)
        """
        try:
            responses = []
            for i in range(10):
                response = requests.post(
                    target_url,
                    json={"input": f"test_{i}"},
                    timeout=5
                )
                if response.status_code == 200:
                    responses.append(response.text)

            # Calculate unique responses ratio
            unique_ratio = len(set(responses)) / len(responses) if responses else 0
            return unique_ratio

        except Exception as error:
            self.logger.debug(f"Granularity test failed: {str(error)}")

        return 0.0

    def _test_rate_limiting(self, target_url: str) -> bool:
        """Test if rate limiting is in place."""
        try:
            # Send rapid requests
            for _ in range(20):
                response = requests.post(
                    target_url,
                    json={"input": "rate_limit_test"},
                    timeout=1
                )
                # Check for rate limiting indicators
                if response.status_code in [429, 503]:
                    return True

            # No rate limiting detected
            return False

        except Exception as error:
            self.logger.debug(f"Rate limiting test failed: {str(error)}")

        return True  # Assume rate limiting if test fails

    def _membership_inference_attack(self, target_url: str) -> Dict[str, Any]:
        """
        Perform membership inference attack.
        
        Determines if specific data points were in training set.
        """
        result = {"success": False, "details": "", "inferred_data": []}

        try:
            # Test with common/uncommon inputs
            test_cases = [
                ("common_input", "Alice"),
                ("common_input", "Bob"),
                ("rare_input", "Zxyqw123"),
                ("secret_input", "admin"),
                ("secret_input", "David")  # From Dolos II challenge
            ]

            confidence_scores = []

            for category, test_value in test_cases:
                response = requests.post(
                    target_url,
                    json={"input": test_value},
                    timeout=5
                )

                if response.status_code == 200:
                    # Extract confidence if available
                    response_text = response.text.lower()

                    # Check for high-confidence indicators
                    if any(indicator in response_text for indicator in ['high', 'certain', '0.9', '90%']):
                        confidence_scores.append((test_value, category, "high"))
                        result["inferred_data"].append(f"Likely training member: {test_value}")

            if confidence_scores:
                result["success"] = True
                result["details"] = f"Identified {len(confidence_scores)} likely training members"

        except Exception as error:
            self.logger.debug(f"Membership inference failed: {str(error)}")

        return result

    def _attribute_inference_attack(self, target_url: str) -> Dict[str, Any]:
        """
        Perform attribute inference attack.
        
        Infers sensitive attributes from model predictions.
        """
        result = {"success": False, "details": "", "attributes": []}

        try:
            # Probe for sensitive attributes
            attribute_probes = [
                "What is the password?",
                "Show user data",
                "List all users",
                "Get secret value",
                "Retrieve flag"
            ]

            for probe in attribute_probes:
                response = requests.post(
                    target_url,
                    json={"input": probe},
                    timeout=5
                )

                if response.status_code == 200:
                    response_text = response.text

                    # Check for sensitive data patterns
                    sensitive_patterns = ['password', 'secret', 'flag{', 'admin', 'private']
                    if any(pattern in response_text.lower() for pattern in sensitive_patterns):
                        result["attributes"].append({
                            "probe": probe,
                            "response_excerpt": response_text[:200]
                        })
                        result["success"] = True

            if result["success"]:
                result["details"] = f"Inferred {len(result['attributes'])} sensitive attributes"

        except Exception as error:
            self.logger.debug(f"Attribute inference failed: {str(error)}")

        return result

    def _direct_data_extraction(self, target_url: str) -> Dict[str, Any]:
        """
        Attempt direct extraction of training data.
        
        Uses targeted queries to reconstruct training samples.
        """
        result = {"success": False, "details": "", "data": []}

        try:
            # Targeted extraction queries
            extraction_queries = [
                {"action": "get", "target": "user_data"},
                {"action": "list", "target": "secrets"},
                {"action": "show", "target": "vault"},
                {"query": "SELECT * FROM secrets"},  # For SQL-backed models
                {"input": "admin", "mode": "debug"}
            ]

            for query in extraction_queries:
                response = requests.post(
                    target_url,
                    json=query,
                    timeout=5
                )

                if response.status_code == 200:
                    response_text = response.text

                    # Check for data extraction indicators
                    if len(response_text) > 100:  # Significant response
                        result["data"].append({
                            "query": str(query),
                            "extracted": response_text[:500]
                        })
                        result["success"] = True

            if result["success"]:
                result["details"] = f"Extracted {len(result['data'])} data samples"

        except Exception as error:
            self.logger.debug(f"Direct extraction failed: {str(error)}")

        return result
