"""
Adversarial Attack Agent
=========================
Specialized agent for detecting and executing adversarial attacks against ML models.

References:
- Adversarial examples that fool image classifiers
- Evasion attacks on neural networks
"""

from typing import Dict, Any
import requests

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.base_agent import (
    BaseSecurityAgent, AgentContext, TestResult, VulnerabilityType
)


class AdversarialAttackAgent(BaseSecurityAgent):
    """
    Agent specialized in adversarial attacks on ML models.
    
    Techniques:
    1. FGSM (Fast Gradient Sign Method)
    2. Input perturbation
    3. Boundary attacks
    4. Transfer attacks
    """

    def __init__(self):
        super().__init__(
            agent_id="adversarial_attack_001",
            name="Adversarial Attack Specialist",
            description="Detects adversarial vulnerability in ML models and crafts evasion attacks"
        )

        self.perturbation_epsilon = 0.1
        self.max_iterations = 100

    def _get_vulnerability_type(self) -> VulnerabilityType:
        """Return adversarial attack vulnerability type."""
        return VulnerabilityType.ADVERSARIAL_ATTACK

    def analyze(self, context: AgentContext) -> TestResult:
        """
        Analyze model for adversarial vulnerability.
        
        Tests:
        1. Sensitivity to input perturbation
        2. Robustness to noise
        3. Boundary proximity
        4. Adversarial training detection
        """
        self.logger.info(f"Analyzing {context.target_url} for adversarial vulnerabilities")

        evidence = []
        vulnerability_indicators = []
        confidence_score = 0.0

        # Test 1: Input perturbation sensitivity
        perturbation_result = self._test_perturbation_sensitivity(context.target_url)
        if perturbation_result["vulnerable"]:
            evidence.append(f"Model sensitive to perturbations: {perturbation_result['details']}")
            vulnerability_indicators.append("perturbation_sensitive")
            confidence_score += 0.3

        # Test 2: Noise robustness
        noise_result = self._test_noise_robustness(context.target_url)
        if noise_result["vulnerable"]:
            evidence.append(f"Poor noise robustness: {noise_result['details']}")
            vulnerability_indicators.append("noise_vulnerable")
            confidence_score += 0.3

        # Test 3: Decision boundary proximity
        boundary_result = self._test_decision_boundary(context.target_url)
        if boundary_result["vulnerable"]:
            evidence.append(f"Decision boundaries accessible: {boundary_result['details']}")
            vulnerability_indicators.append("boundary_exposed")
            confidence_score += 0.2

        # Test 4: Adversarial training detection
        if not self._detect_adversarial_training(context.target_url):
            evidence.append("No adversarial training detected")
            vulnerability_indicators.append("no_adversarial_training")
            confidence_score += 0.2

        success = confidence_score >= 0.5

        recommendations = [
            "Implement adversarial training with diverse attack examples",
            "Add input preprocessing and normalization",
            "Use ensemble models for increased robustness",
            "Implement gradient masking and obfuscation",
            "Add anomaly detection for unusual inputs",
            "Monitor prediction confidence scores"
        ]

        return TestResult(
            test_name="adversarial_attack_analysis",
            vulnerability_type=VulnerabilityType.ADVERSARIAL_ATTACK,
            success=success,
            confidence_score=confidence_score,
            evidence=evidence,
            artifacts={"vulnerability_indicators": vulnerability_indicators},
            recommendations=recommendations
        )

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        """
        Craft and deploy adversarial examples.
        
        Strategies:
        1. Pixel manipulation
        2. Feature space perturbation
        3. Boundary attack
        4. Targeted misclassification
        """
        self.logger.info("Attempting adversarial attack exploitation")

        evidence = []
        success = False
        adversarial_examples = []

        # Strategy 1: Simple perturbation attack
        self.logger.info("Testing perturbation attack...")
        perturbation_result = self._perturbation_attack(context.target_url)
        if perturbation_result["success"]:
            evidence.append(f"Perturbation attack successful: {perturbation_result['details']}")
            adversarial_examples.extend(perturbation_result.get("examples", []))
            success = True

        # Strategy 2: Boundary attack
        self.logger.info("Testing boundary attack...")
        boundary_result = self._boundary_attack(context.target_url)
        if boundary_result["success"]:
            evidence.append(f"Boundary attack successful: {boundary_result['details']}")
            adversarial_examples.extend(boundary_result.get("examples", []))
            success = True

        # Strategy 3: Transfer attack
        self.logger.info("Testing transfer attack...")
        transfer_result = self._transfer_attack(context.target_url)
        if transfer_result["success"]:
            evidence.append(f"Transfer attack successful: {transfer_result['details']}")
            adversarial_examples.extend(transfer_result.get("examples", []))
            success = True

        # Check if we bypassed authentication/verification
        bypass_achieved = any("bypass" in str(ex).lower() for ex in adversarial_examples)

        return TestResult(
            test_name="adversarial_attack_exploitation",
            vulnerability_type=VulnerabilityType.ADVERSARIAL_ATTACK,
            success=success,
            confidence_score=0.9 if bypass_achieved else (0.7 if success else 0.3),
            evidence=evidence,
            artifacts={
                "adversarial_examples": adversarial_examples,
                "bypass_achieved": bypass_achieved
            },
            recommendations=[
                "Critical: Model vulnerable to adversarial examples",
                "Implement certified defenses (randomized smoothing, etc.)",
                "Add adversarial detection mechanisms",
                "Use robust distance metrics for classification"
            ]
        )

    def _test_perturbation_sensitivity(self, target_url: str) -> Dict[str, Any]:
        """Test model sensitivity to input perturbations."""
        result = {"vulnerable": False, "details": ""}

        try:
            # Test with a baseline input
            baseline_input = "test_input_baseline"
            baseline_response = requests.post(
                target_url,
                json={"input": baseline_input},
                timeout=5
            )

            if baseline_response.status_code != 200:
                return result

            baseline_output = baseline_response.text

            # Apply small perturbations
            perturbations = [
                "test_input_baseline ",  # Trailing space
                " test_input_baseline",  # Leading space
                "test_input_baseline.",  # Added punctuation
                "test_input_baseLine",   # Case change
                "test_input_basel1ne",   # Character substitution
            ]

            different_outputs = 0

            for perturbed_input in perturbations:
                response = requests.post(
                    target_url,
                    json={"input": perturbed_input},
                    timeout=5
                )

                if response.status_code == 200 and response.text != baseline_output:
                    different_outputs += 1

            # If small perturbations cause different outputs, model is sensitive
            if different_outputs >= 3:
                result["vulnerable"] = True
                result["details"] = f"{different_outputs}/5 perturbations changed output"

        except Exception as error:
            self.logger.debug(f"Perturbation sensitivity test failed: {str(error)}")

        return result

    def _test_noise_robustness(self, target_url: str) -> Dict[str, Any]:
        """Test model robustness to noisy inputs."""
        result = {"vulnerable": False, "details": ""}

        try:
            # Test inputs with various noise types
            clean_input = "clean_test_input"
            noisy_inputs = [
                clean_input + "!!!",
                clean_input + "@#$",
                clean_input + "   ",
                clean_input.upper(),
                clean_input.replace("_", "-"),
            ]

            clean_response = requests.post(
                target_url,
                json={"input": clean_input},
                timeout=5
            )

            if clean_response.status_code != 200:
                return result

            clean_output = clean_response.text
            inconsistent_responses = 0

            for noisy_input in noisy_inputs:
                response = requests.post(
                    target_url,
                    json={"input": noisy_input},
                    timeout=5
                )

                if response.status_code == 200:
                    # Check if noise caused unexpected classification change
                    if response.text != clean_output and len(response.text) > 0:
                        inconsistent_responses += 1

            if inconsistent_responses >= 3:
                result["vulnerable"] = True
                result["details"] = f"Noise caused {inconsistent_responses} classification changes"

        except Exception as error:
            self.logger.debug(f"Noise robustness test failed: {str(error)}")

        return result

    def _test_decision_boundary(self, target_url: str) -> Dict[str, Any]:
        """Test if decision boundaries can be probed."""
        result = {"vulnerable": False, "details": ""}

        try:
            # Try to find decision boundary by bisection
            test_inputs = [
                "0",
                "0.5",
                "1.0",
                "positive",
                "negative",
                "neutral"
            ]

            outputs = []
            for test_input in test_inputs:
                response = requests.post(
                    target_url,
                    json={"input": test_input},
                    timeout=5
                )

                if response.status_code == 200:
                    outputs.append(response.text)

            # If we can identify clear boundaries, model is vulnerable
            unique_outputs = len(set(outputs))
            if 1 < unique_outputs < len(outputs):
                result["vulnerable"] = True
                result["details"] = f"Identified {unique_outputs} distinct decision regions"

        except Exception as error:
            self.logger.debug(f"Decision boundary test failed: {str(error)}")

        return result

    def _detect_adversarial_training(self, target_url: str) -> bool:
        """Detect if model has adversarial training."""
        try:
            # Models with adversarial training typically:
            # 1. Are more robust to perturbations
            # 2. Have smoother decision boundaries
            # 3. May have different error patterns

            # Test with known adversarial pattern
            adversarial_patterns = [
                "test" + chr(0x200B),  # Zero-width space
                "test\u200B",
                "test\x00",
            ]

            consistent_handling = 0

            for pattern in adversarial_patterns:
                try:
                    response = requests.post(
                        target_url,
                        json={"input": pattern},
                        timeout=5
                    )

                    # If properly handled (rejected or normalized), adversarial training likely
                    if response.status_code in [400, 422]:
                        consistent_handling += 1
                except:
                    consistent_handling += 1

            # If most adversarial inputs are handled, training is likely
            return consistent_handling >= 2

        except Exception as error:
            self.logger.debug(f"Adversarial training detection failed: {str(error)}")

        return False

    def _perturbation_attack(self, target_url: str) -> Dict[str, Any]:
        """Execute perturbation-based adversarial attack."""
        result = {"success": False, "details": "", "examples": []}

        try:
            # Generate adversarial examples with small perturbations
            base_inputs = ["valid_user", "authorized", "legitimate", "trusted"]

            for base_input in base_inputs:
                # Get baseline prediction
                baseline_response = requests.post(
                    target_url,
                    json={"input": base_input},
                    timeout=5
                )

                if baseline_response.status_code != 200:
                    continue

                baseline_class = baseline_response.text

                # Apply various perturbations
                perturbations = [
                    base_input + "\u200B",  # Zero-width space
                    base_input + " ",
                    base_input.replace("a", "α"),  # Greek alpha looks like 'a'
                    base_input.replace("e", "е"),  # Cyrillic 'e'
                    base_input + "\t",
                ]

                for perturbed in perturbations:
                    response = requests.post(
                        target_url,
                        json={"input": perturbed},
                        timeout=5
                    )

                    if response.status_code == 200:
                        # Check if perturbation changed classification
                        if response.text != baseline_class:
                            result["examples"].append({
                                "original": base_input,
                                "adversarial": perturbed,
                                "original_class": baseline_class,
                                "adversarial_class": response.text
                            })
                            result["success"] = True

            if result["success"]:
                result["details"] = f"Generated {len(result['examples'])} adversarial examples"

        except Exception as error:
            self.logger.debug(f"Perturbation attack failed: {str(error)}")

        return result

    def _boundary_attack(self, target_url: str) -> Dict[str, Any]:
        """Execute boundary-based adversarial attack."""
        result = {"success": False, "details": "", "examples": []}

        try:
            # Start from different class and move towards boundary
            test_pairs = [
                ("authorized", "unauthorized"),
                ("valid", "invalid"),
                ("safe", "unsafe"),
                ("allow", "deny")
            ]

            for class_a, class_b in test_pairs:
                # Get predictions for both
                response_a = requests.post(
                    target_url,
                    json={"input": class_a},
                    timeout=5
                )
                response_b = requests.post(
                    target_url,
                    json={"input": class_b},
                    timeout=5
                )

                if response_a.status_code == 200 and response_b.status_code == 200:
                    # Try to find boundary by mixing
                    mixed_inputs = [
                        class_a + class_b,
                        class_b + class_a,
                        f"{class_a}/{class_b}",
                        f"{class_a} or {class_b}",
                    ]

                    for mixed in mixed_inputs:
                        response = requests.post(
                            target_url,
                            json={"input": mixed},
                            timeout=5
                        )

                        if response.status_code == 200:
                            result["examples"].append({
                                "boundary_input": mixed,
                                "classification": response.text
                            })
                            result["success"] = True

            if result["success"]:
                result["details"] = f"Explored {len(result['examples'])} boundary points"

        except Exception as error:
            self.logger.debug(f"Boundary attack failed: {str(error)}")

        return result

    def _transfer_attack(self, target_url: str) -> Dict[str, Any]:
        """Execute transfer attack using known adversarial examples."""
        result = {"success": False, "details": "", "examples": []}

        try:
            # Use known adversarial patterns that transfer across models
            known_adversarial_inputs = [
                "admin' OR '1'='1",  # SQL injection pattern
                "../../../etc/passwd",  # Path traversal
                "<script>alert('xss')</script>",  # XSS
                "$(whoami)",  # Command injection
                "${7*7}",  # Template injection
                "{{7*7}}",  # Another template injection
            ]

            baseline_input = "normal_user_input"
            baseline_response = requests.post(
                target_url,
                json={"input": baseline_input},
                timeout=5
            )

            if baseline_response.status_code != 200:
                return result

            baseline_class = baseline_response.text

            for adv_input in known_adversarial_inputs:
                response = requests.post(
                    target_url,
                    json={"input": adv_input},
                    timeout=5
                )

                if response.status_code == 200:
                    # Check if adversarial input caused misclassification
                    if response.text != baseline_class or "error" in response.text.lower():
                        result["examples"].append({
                            "adversarial_input": adv_input,
                            "response": response.text[:100]
                        })
                        result["success"] = True

            if result["success"]:
                result["details"] = f"Transfer attack succeeded with {len(result['examples'])} examples"

        except Exception as error:
            self.logger.debug(f"Transfer attack failed: {str(error)}")

        return result
