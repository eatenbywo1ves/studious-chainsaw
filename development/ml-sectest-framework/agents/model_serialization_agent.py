"""
Model Serialization Attack Agent
=================================
Specialized agent for detecting and exploiting model serialization vulnerabilities.

References:
- OWASP LLM05: Supply Chain Vulnerabilities
- OWASP ML06: Unsafe Deserialization
- MITRE AML.T0010: ML Model Serialization
"""

from typing import List, Dict, Any
import requests
import base64
import pickle
import json

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.base_agent import (
    BaseSecurityAgent, AgentContext, TestResult, VulnerabilityType
)


class ModelSerializationAgent(BaseSecurityAgent):
    """
    Agent specialized in model serialization attacks.
    
    Techniques:
    1. Pickle deserialization exploitation
    2. Malicious model upload
    3. Model file tampering
    4. Supply chain poisoning
    """

    def __init__(self):
        super().__init__(
            agent_id="model_serialization_001",
            name="Model Serialization Specialist",
            description="Detects unsafe model serialization and deserialization vulnerabilities"
        )

    def _get_vulnerability_type(self) -> VulnerabilityType:
        """Return model serialization vulnerability type."""
        return VulnerabilityType.MODEL_SERIALIZATION

    def analyze(self, context: AgentContext) -> TestResult:
        """
        Analyze system for serialization vulnerabilities.
        
        Checks:
        1. Model upload capability
        2. File format acceptance
        3. Deserialization safeguards
        4. File validation mechanisms
        """
        self.logger.info(f"Analyzing {context.target_url} for serialization vulnerabilities")

        evidence = []
        vulnerability_indicators = []
        confidence_score = 0.0

        # Test 1: Model upload endpoints
        if self._test_model_upload(context.target_url):
            evidence.append("Model upload functionality detected")
            vulnerability_indicators.append("model_upload_enabled")
            confidence_score += 0.3

        # Test 2: Unsafe format acceptance
        unsafe_formats = self._test_file_formats(context.target_url)
        if unsafe_formats:
            evidence.append(f"Accepts unsafe formats: {', '.join(unsafe_formats)}")
            vulnerability_indicators.append("unsafe_formats")
            confidence_score += 0.3

        # Test 3: Deserialization testing
        if self._test_deserialization(context.target_url):
            evidence.append("Unsafe deserialization detected")
            vulnerability_indicators.append("unsafe_deserialization")
            confidence_score += 0.3

        # Test 4: File validation
        validation_strength = self._test_file_validation(context.target_url)
        if validation_strength < 0.5:
            evidence.append(f"Weak file validation (score: {validation_strength:.2f})")
            vulnerability_indicators.append("weak_validation")
            confidence_score += 0.1

        success = confidence_score >= 0.4

        recommendations = [
            "Never use pickle for model serialization in production",
            "Use safe formats like ONNX, SavedModel, or PMML",
            "Implement strict file type and signature validation",
            "Scan uploaded files for malicious content",
            "Use sandboxed environments for model loading",
            "Implement digital signatures for model verification",
            "Restrict model upload to authenticated admin users only"
        ]

        return TestResult(
            test_name="model_serialization_analysis",
            vulnerability_type=VulnerabilityType.MODEL_SERIALIZATION,
            success=success,
            confidence_score=confidence_score,
            evidence=evidence,
            artifacts={"vulnerability_indicators": vulnerability_indicators},
            recommendations=recommendations
        )

    def exploit(self, context: AgentContext, test_result: TestResult) -> TestResult:
        """
        Attempt serialization exploitation.
        
        Strategies:
        1. Pickle payload injection
        2. Malicious model upload
        3. Model tampering
        4. Code execution via deserialization
        """
        self.logger.info("Attempting serialization exploitation")

        evidence = []
        success = False
        exploitation_results = {}

        # Strategy 1: Pickle exploitation
        self.logger.info("Testing pickle exploitation...")
        pickle_result = self._pickle_exploitation(context.target_url)
        if pickle_result["success"]:
            evidence.append(f"Pickle exploitation successful: {pickle_result['details']}")
            exploitation_results["pickle"] = pickle_result
            success = True

        # Strategy 2: Malicious model upload
        self.logger.info("Testing malicious model upload...")
        upload_result = self._malicious_model_upload(context.target_url)
        if upload_result["success"]:
            evidence.append(f"Malicious model upload successful: {upload_result['details']}")
            exploitation_results["upload"] = upload_result
            success = True

        # Strategy 3: Format confusion
        self.logger.info("Testing format confusion attack...")
        format_result = self._format_confusion_attack(context.target_url)
        if format_result["success"]:
            evidence.append(f"Format confusion successful: {format_result['details']}")
            exploitation_results["format_confusion"] = format_result
            success = True

        return TestResult(
            test_name="model_serialization_exploitation",
            vulnerability_type=VulnerabilityType.MODEL_SERIALIZATION,
            success=success,
            confidence_score=0.9 if success else 0.3,
            evidence=evidence,
            artifacts={"exploitation_results": exploitation_results},
            recommendations=[
                "Critical: Unsafe deserialization allows code execution",
                "Immediately disable pickle-based model loading",
                "Implement safe model format standards",
                "Add integrity checking for all uploaded models"
            ]
        )

    def _test_model_upload(self, target_url: str) -> bool:
        """Test for model upload functionality."""
        try:
            # Try common upload endpoints
            upload_endpoints = [
                "/upload",
                "/model/upload",
                "/load",
                "/import"
            ]

            for endpoint in upload_endpoints:
                test_url = target_url.rstrip('/') + endpoint
                try:
                    # Try uploading a benign file
                    files = {'file': ('test.pkl', b'test_data', 'application/octet-stream')}
                    response = requests.post(test_url, files=files, timeout=5)

                    if response.status_code not in [404, 405]:
                        return True
                except:
                    continue

            # Test main endpoint with file upload
            files = {'model': ('model.pkl', b'test', 'application/octet-stream')}
            response = requests.post(target_url, files=files, timeout=5)

            return response.status_code not in [404, 405, 501]

        except Exception as error:
            self.logger.debug(f"Model upload test failed: {str(error)}")

        return False

    def _test_file_formats(self, target_url: str) -> List[str]:
        """Test which file formats are accepted."""
        unsafe_formats = []

        test_formats = {
            '.pkl': 'pickle (UNSAFE)',
            '.pickle': 'pickle (UNSAFE)',
            '.joblib': 'joblib (UNSAFE)',
            '.pt': 'pytorch (potentially unsafe)',
            '.pth': 'pytorch (potentially unsafe)',
            '.h5': 'keras/hdf5 (safer)',
            '.pb': 'tensorflow (safer)',
            '.onnx': 'onnx (safe)'
        }

        for ext, format_name in test_formats.items():
            try:
                files = {'file': (f'model{ext}', b'test_data', 'application/octet-stream')}
                response = requests.post(target_url, files=files, timeout=5)

                # If not rejected outright, format might be accepted
                if response.status_code in [200, 201, 202]:
                    if 'UNSAFE' in format_name or 'potentially unsafe' in format_name:
                        unsafe_formats.append(ext)

            except:
                continue

        return unsafe_formats

    def _test_deserialization(self, target_url: str) -> bool:
        """Test for unsafe deserialization."""
        try:
            # Create a test pickle payload (benign marker)
            class TestMarker:
                def __reduce__(self):
                    # This would normally be malicious, but we keep it safe for testing
                    return (str, ("DESERIALIZATION_TEST_MARKER",))

            test_payload = pickle.dumps(TestMarker())

            # Try to upload and trigger deserialization
            files = {'model': ('test.pkl', test_payload, 'application/octet-stream')}
            response = requests.post(target_url, files=files, timeout=5)

            # Check if our marker appears in response (indicates deserialization occurred)
            if "DESERIALIZATION_TEST_MARKER" in response.text:
                return True

            # Alternative: send as base64-encoded data
            encoded_payload = base64.b64encode(test_payload).decode()
            response = requests.post(
                target_url,
                json={"model_data": encoded_payload},
                timeout=5
            )

            return "DESERIALIZATION_TEST_MARKER" in response.text

        except Exception as error:
            self.logger.debug(f"Deserialization test failed: {str(error)}")

        return False

    def _test_file_validation(self, target_url: str) -> float:
        """Test strength of file validation."""
        validation_checks_passed = 0
        total_checks = 5

        malicious_tests = [
            # Test 1: Wrong file extension
            ('model.txt', b'fake_pickle_data'),
            # Test 2: Empty file
            ('model.pkl', b''),
            # Test 3: Oversized file
            ('model.pkl', b'X' * (10 * 1024 * 1024)),  # 10MB
            # Test 4: Invalid pickle data
            ('model.pkl', b'not_a_pickle'),
            # Test 5: Executable disguised as model
            ('model.pkl', b'\x7fELF')  # ELF header
        ]

        for filename, data in malicious_tests:
            try:
                files = {'file': (filename, data, 'application/octet-stream')}
                response = requests.post(target_url, files=files, timeout=5)

                # If rejected (400, 422, etc.), validation working
                if response.status_code in [400, 415, 422]:
                    validation_checks_passed += 1
                elif "error" in response.text.lower() or "invalid" in response.text.lower():
                    validation_checks_passed += 1

            except:
                validation_checks_passed += 1  # Assume rejection if error

        return validation_checks_passed / total_checks

    def _pickle_exploitation(self, target_url: str) -> Dict[str, Any]:
        """
        Attempt pickle exploitation (DEFENSIVE TESTING ONLY).
        
        Note: This creates a SAFE test payload that doesn't execute harmful code.
        """
        result = {"success": False, "details": ""}

        try:
            # Create a safe test payload that proves exploitation without harm
            class SafeExploitProof:
                def __reduce__(self):
                    # Instead of os.system, use a safe marker
                    return (str, ("PICKLE_EXPLOIT_SUCCESSFUL_FLAG_HERE",))

            malicious_payload = pickle.dumps(SafeExploitProof())

            # Try to upload the payload
            files = {'model': ('model.pkl', malicious_payload, 'application/octet-stream')}
            response = requests.post(target_url, files=files, timeout=5)

            # Check if exploitation was successful
            if "PICKLE_EXPLOIT_SUCCESSFUL" in response.text or response.status_code == 200:
                result["success"] = True
                result["details"] = "Pickle deserialization executed custom code"

            # Also try as POST data
            encoded = base64.b64encode(malicious_payload).decode()
            response = requests.post(
                target_url,
                json={"serialized_model": encoded},
                timeout=5
            )

            if "PICKLE_EXPLOIT_SUCCESSFUL" in response.text:
                result["success"] = True
                result["details"] = "Pickle deserialization via JSON payload succeeded"

        except Exception as error:
            self.logger.debug(f"Pickle exploitation failed: {str(error)}")

        return result

    def _malicious_model_upload(self, target_url: str) -> Dict[str, Any]:
        """Attempt to upload malicious model."""
        result = {"success": False, "details": ""}

        try:
            # Create a model-like payload with embedded code
            # This is a SAFE demonstration payload
            model_payload = {
                "__class__": "MaliciousModel",
                "__reduce__": ["system", ["echo EXPLOITED"]],
                "weights": "malicious_data",
                "_flag_extraction": True
            }

            # Serialize as JSON (safer than pickle for this test)
            json_payload = json.dumps(model_payload)

            # Try to upload
            files = {'model': ('model.json', json_payload.encode(), 'application/json')}
            response = requests.post(target_url, files=files, timeout=5)

            if response.status_code in [200, 201]:
                result["success"] = True
                result["details"] = "Malicious model file accepted"

            # Check if model was processed
            if "EXPLOITED" in response.text or "flag" in response.text.lower():
                result["success"] = True
                result["details"] = "Malicious model was processed and executed"

        except Exception as error:
            self.logger.debug(f"Malicious upload failed: {str(error)}")

        return result

    def _format_confusion_attack(self, target_url: str) -> Dict[str, Any]:
        """Attempt format confusion attack."""
        result = {"success": False, "details": ""}

        try:
            # Create file with misleading extension
            # Upload pickle data with .onnx extension
            fake_onnx = pickle.dumps({"fake": "onnx", "actually": "pickle"})

            files = {'model': ('safe_model.onnx', fake_onnx, 'application/octet-stream')}
            response = requests.post(target_url, files=files, timeout=5)

            if response.status_code == 200:
                result["success"] = True
                result["details"] = "Format confusion successful - pickle accepted as ONNX"

            # Try content-type mismatch
            files = {'model': ('model.pkl', b'test', 'application/xml')}
            response = requests.post(target_url, files=files, timeout=5)

            if response.status_code == 200:
                result["success"] = True
                result["details"] = "Content-type validation bypassed"

        except Exception as error:
            self.logger.debug(f"Format confusion attack failed: {str(error)}")

        return result
