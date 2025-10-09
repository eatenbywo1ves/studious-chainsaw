"""
Model Extraction Attack Agent
==============================
Specialized agent for detecting and executing model extraction/stealing attacks.

References:
- OWASP LLM10: Model Theft
- MITRE AML.T0044: Full ML Model Access
"""

from typing import List, Dict, Any
import requests

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.base_agent import (
    BaseSecurityAgent, AgentContext, TestResult, VulnerabilityType
)


class ModelExtractionAgent(BaseSecurityAgent):
    """
    Agent specialized in model extraction attacks.
    
    Techniques:
    1. Query-based extraction: Build substitute model via queries
    2. Equation solving: Extract model parameters directly
    3. Architecture probing: Identify model structure
    4. Knowledge distillation: Clone model behavior
    """

    def __init__(self):
        super().__init__(
            agent_id="model_extraction_001",
            name="Model Extraction Specialist",
            description="Detects model extraction vulnerabilities and attempts model theft"
        )

        self.query_budget = 1000
        self.extracted_samples = []

    def _get_vulnerability_type(self) -> VulnerabilityType:
        """Return model extraction vulnerability type."""
        return VulnerabilityType.MODEL_EXTRACTION

    def analyze(self, context: AgentContext) -> TestResult:
        """
        Analyze system for model extraction vulnerabilities.
        
        Checks:
        1. Query limit enforcement
        2. Prediction detail level
        3. Model information leakage
        4. API access controls
        """
        self.logger.info(f"Analyzing {context.target_url} for model extraction")

        evidence = []
        vulnerability_indicators = []
        confidence_score = 0.0

        # Test 1: Query limits
        query_limit_info = self._test_query_limits(context.target_url)
        if not query_limit_info["enforced"]:
            evidence.append(f"No query limits detected - allows {query_limit_info['max_queries']} queries")
            vulnerability_indicators.append("no_query_limits")
            confidence_score += 0.3

        # Test 2: Prediction granularity
        granularity = self._test_prediction_granularity(context.target_url)
        if granularity > 0.7:
            evidence.append(f"High prediction granularity ({granularity:.2f}) enables accurate extraction")
            vulnerability_indicators.append("high_granularity")
            confidence_score += 0.3

        # Test 3: Model metadata exposure
        metadata = self._test_metadata_exposure(context.target_url)
        if metadata["exposed"]:
            evidence.append(f"Model metadata exposed: {metadata['info']}")
            vulnerability_indicators.append("metadata_exposure")
            confidence_score += 0.2

        # Test 4: Architecture probing
        architecture_info = self._probe_architecture(context.target_url)
        if architecture_info["success"]:
            evidence.append(f"Architecture identified: {architecture_info['details']}")
            vulnerability_indicators.append("architecture_identified")
            confidence_score += 0.2

        success = confidence_score >= 0.5

        recommendations = [
            "Implement strict query rate limiting per user/IP",
            "Add noise to predictions (differential privacy)",
            "Reduce prediction precision/granularity",
            "Hide model architecture and metadata",
            "Monitor for systematic querying patterns",
            "Require authentication for API access",
            "Implement query cost/throttling mechanisms"
        ]

        return TestResult(
            test_name="model_extraction_analysis",
            vulnerability_type=VulnerabilityType.MODEL_EXTRACTION,
            success=success,
            confidence_score=confidence_score,
            evidence=evidence,
            artifacts={"vulnerability_indicators": vulnerability_indicators},
            recommendations=recommendations
        )

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        """
        Attempt model extraction attack.
        
        Strategies:
        1. Active learning extraction
        2. Decision boundary extraction
        3. Knowledge distillation
        4. Direct parameter extraction
        """
        self.logger.info("Attempting model extraction")

        evidence = []
        success = False
        extraction_results = {}

        # Strategy 1: Query-based extraction
        self.logger.info("Testing query-based extraction...")
        query_result = self._query_based_extraction(context.target_url)
        if query_result["success"]:
            evidence.append(f"Query-based extraction: {query_result['details']}")
            extraction_results["query_extraction"] = query_result
            success = True

        # Strategy 2: Decision boundary extraction
        self.logger.info("Testing decision boundary extraction...")
        boundary_result = self._boundary_extraction(context.target_url)
        if boundary_result["success"]:
            evidence.append(f"Decision boundary extracted: {boundary_result['details']}")
            extraction_results["boundary_extraction"] = boundary_result
            success = True

        # Strategy 3: Model architecture extraction
        self.logger.info("Testing architecture extraction...")
        arch_result = self._architecture_extraction(context.target_url)
        if arch_result["success"]:
            evidence.append(f"Architecture extracted: {arch_result['details']}")
            extraction_results["architecture"] = arch_result
            success = True

        # Calculate extraction completeness
        completeness_score = self._calculate_extraction_completeness(extraction_results)

        return TestResult(
            test_name="model_extraction_exploitation",
            vulnerability_type=VulnerabilityType.MODEL_EXTRACTION,
            success=success,
            confidence_score=completeness_score,
            evidence=evidence,
            artifacts={
                "extraction_results": extraction_results,
                "completeness_score": completeness_score,
                "samples_collected": len(self.extracted_samples)
            },
            recommendations=[
                "Critical: Model can be extracted via systematic queries",
                "Implement query budget limits per user",
                "Add watermarking to detect model theft",
                "Monitor for adversarial query patterns"
            ]
        )

    def _test_query_limits(self, target_url: str) -> Dict[str, Any]:
        """Test query limit enforcement."""
        result = {"enforced": True, "max_queries": 0}

        try:
            successful_queries = 0

            for i in range(100):
                response = requests.post(
                    target_url,
                    json={"input": f"query_{i}"},
                    timeout=2
                )

                if response.status_code == 200:
                    successful_queries += 1
                elif response.status_code in [429, 403]:
                    # Rate limit hit
                    result["enforced"] = True
                    result["max_queries"] = successful_queries
                    return result

            # No rate limit detected
            result["enforced"] = False
            result["max_queries"] = successful_queries

        except Exception as error:
            self.logger.debug(f"Query limit test failed: {str(error)}")

        return result

    def _test_prediction_granularity(self, target_url: str) -> float:
        """Test prediction output granularity."""
        try:
            predictions = []

            for i in range(20):
                response = requests.post(
                    target_url,
                    json={"input": f"test_{i}"},
                    timeout=5
                )

                if response.status_code == 200:
                    predictions.append(response.text)

            # Calculate unique predictions ratio
            unique_ratio = len(set(predictions)) / len(predictions) if predictions else 0
            return unique_ratio

        except Exception as error:
            self.logger.debug(f"Granularity test failed: {str(error)}")

        return 0.0

    def _test_metadata_exposure(self, target_url: str) -> Dict[str, Any]:
        """Test for model metadata exposure."""
        result = {"exposed": False, "info": []}

        try:
            # Try metadata endpoints
            metadata_endpoints = [
                "/info",
                "/model",
                "/metadata",
                "/version",
                "/config"
            ]

            for endpoint in metadata_endpoints:
                test_url = target_url.rstrip('/') + endpoint
                try:
                    response = requests.get(test_url, timeout=5)
                    if response.status_code == 200:
                        result["exposed"] = True
                        result["info"].append(f"{endpoint}: {response.text[:100]}")
                except:
                    continue

            # Check response headers for model info
            response = requests.post(target_url, json={"input": "test"}, timeout=5)
            headers_to_check = ['X-Model', 'X-Version', 'Server', 'X-Framework']

            for header in headers_to_check:
                if header in response.headers:
                    result["exposed"] = True
                    result["info"].append(f"Header {header}: {response.headers[header]}")

        except Exception as error:
            self.logger.debug(f"Metadata exposure test failed: {str(error)}")

        return result

    def _probe_architecture(self, target_url: str) -> Dict[str, Any]:
        """Probe to identify model architecture."""
        result = {"success": False, "details": "", "architecture_hints": []}

        try:
            # Test input size limits
            for size in [10, 100, 1000, 10000]:
                test_input = "A" * size
                response = requests.post(
                    target_url,
                    json={"input": test_input},
                    timeout=5
                )

                if response.status_code in [400, 413]:
                    result["architecture_hints"].append(f"Max input size: ~{size}")
                    break

            # Test response time patterns (can indicate model complexity)
            response_times = []
            for i in range(10):
                import time
                start = time.time()
                requests.post(target_url, json={"input": f"test_{i}"}, timeout=5)
                response_times.append(time.time() - start)

            avg_time = sum(response_times) / len(response_times)
            result["architecture_hints"].append(f"Avg response time: {avg_time:.3f}s")

            # Classify based on response time
            if avg_time < 0.1:
                result["architecture_hints"].append("Likely: Simple model (linear/tree)")
            elif avg_time < 0.5:
                result["architecture_hints"].append("Likely: Medium complexity (shallow NN)")
            else:
                result["architecture_hints"].append("Likely: Complex model (deep NN/transformer)")

            if result["architecture_hints"]:
                result["success"] = True
                result["details"] = "; ".join(result["architecture_hints"])

        except Exception as error:
            self.logger.debug(f"Architecture probing failed: {str(error)}")

        return result

    def _query_based_extraction(self, target_url: str) -> Dict[str, Any]:
        """Extract model via systematic queries."""
        result = {"success": False, "details": "", "samples": []}

        try:
            # Systematic sampling strategy
            test_inputs = self._generate_strategic_inputs()

            samples_collected = 0
            for test_input in test_inputs[:min(50, len(test_inputs))]:
                response = requests.post(
                    target_url,
                    json={"input": test_input},
                    timeout=5
                )

                if response.status_code == 200:
                    self.extracted_samples.append({
                        "input": test_input,
                        "output": response.text
                    })
                    samples_collected += 1

            if samples_collected > 20:
                result["success"] = True
                result["details"] = f"Collected {samples_collected} input-output pairs"
                result["samples"] = self.extracted_samples

        except Exception as error:
            self.logger.debug(f"Query-based extraction failed: {str(error)}")

        return result

    def _boundary_extraction(self, target_url: str) -> Dict[str, Any]:
        """Extract decision boundaries."""
        result = {"success": False, "details": "", "boundaries": []}

        try:
            # Test binary decision boundaries
            boundary_tests = [
                ("yes", "no"),
                ("true", "false"),
                ("positive", "negative"),
                ("safe", "unsafe"),
                ("valid", "invalid")
            ]

            boundaries_found = 0

            for option_a, option_b in boundary_tests:
                response_a = requests.post(
                    target_url,
                    json={"input": option_a},
                    timeout=5
                )
                response_b = requests.post(
                    target_url,
                    json={"input": option_b},
                    timeout=5
                )

                if response_a.status_code == 200 and response_b.status_code == 200:
                    if response_a.text != response_b.text:
                        result["boundaries"].append({
                            "input_a": option_a,
                            "output_a": response_a.text[:50],
                            "input_b": option_b,
                            "output_b": response_b.text[:50]
                        })
                        boundaries_found += 1

            if boundaries_found > 0:
                result["success"] = True
                result["details"] = f"Identified {boundaries_found} decision boundaries"

        except Exception as error:
            self.logger.debug(f"Boundary extraction failed: {str(error)}")

        return result

    def _architecture_extraction(self, target_url: str) -> Dict[str, Any]:
        """Extract model architecture details."""
        result = {"success": False, "details": "", "architecture": {}}

        try:
            # Probe for architecture details via error messages
            edge_cases = [
                {"input": None},
                {"input": []},
                {"input": {}},
                {"input": {"nested": "value"}},
                {"invalid_field": "test"}
            ]

            for edge_case in edge_cases:
                response = requests.post(
                    target_url,
                    json=edge_case,
                    timeout=5
                )

                error_text = response.text.lower()

                # Extract framework hints from errors
                frameworks = {
                    "tensorflow": "TensorFlow",
                    "pytorch": "PyTorch",
                    "sklearn": "scikit-learn",
                    "keras": "Keras",
                    "transformers": "HuggingFace Transformers",
                    "fastapi": "FastAPI",
                    "flask": "Flask"
                }

                for keyword, framework in frameworks.items():
                    if keyword in error_text:
                        result["architecture"][keyword] = framework
                        result["success"] = True

            if result["success"]:
                result["details"] = f"Detected frameworks: {', '.join(result['architecture'].values())}"

        except Exception as error:
            self.logger.debug(f"Architecture extraction failed: {str(error)}")

        return result

    def _generate_strategic_inputs(self) -> List[str]:
        """Generate strategic inputs for extraction."""
        inputs = []

        # Common words
        inputs.extend(["test", "hello", "admin", "user", "data", "model", "predict"])

        # Numerical patterns
        inputs.extend([str(i) for i in range(0, 100, 10)])

        # Special characters
        inputs.extend(["!", "@", "#", "$", "%", "^", "&", "*"])

        # Edge cases
        inputs.extend(["", " ", "  ", "\n", "\t"])

        # Common test patterns
        inputs.extend([
            "a" * i for i in [1, 10, 100]
        ])

        return inputs

    def _calculate_extraction_completeness(
        self, extraction_results: Dict[str, Any]
    ) -> float:
        """Calculate how complete the model extraction is."""
        completeness = 0.0

        # Scoring based on what was extracted
        if "query_extraction" in extraction_results:
            completeness += 0.4

        if "boundary_extraction" in extraction_results:
            completeness += 0.3

        if "architecture" in extraction_results:
            completeness += 0.3

        return min(completeness, 1.0)
