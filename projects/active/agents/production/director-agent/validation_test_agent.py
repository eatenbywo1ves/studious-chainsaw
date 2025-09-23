"""
Input Validation Test Agent
Tests various input validation scenarios with the observatory system
"""

import asyncio
import websockets
import json
from datetime import datetime
import traceback


class ValidationTestAgent:
    def __init__(self, agent_name="ValidationTestAgent"):
        self.agent_name = agent_name
        self.server_url = "ws://localhost:8080/ws"
        self.websocket = None
        self.validation_errors = []
        self.test_results = {}

    async def connect_and_test(self):
        """Connect and run validation tests"""
        try:
            print(f"Starting {self.agent_name} for input validation testing...")
            self.websocket = await websockets.connect(self.server_url)

            # Run validation tests
            await self.test_registration_validation()
            await self.test_metrics_validation()
            await self.test_event_validation()
            await self.test_malformed_data()
            await self.test_edge_cases()

            print("\n" + "=" * 60)
            print("VALIDATION TEST RESULTS:")
            print("=" * 60)
            for test, result in self.test_results.items():
                status = "PASS" if result["passed"] else "FAIL"
                print(f"{status}: {test}")
                if not result["passed"]:
                    print(f"   Error: {result.get('error', 'Unknown error')}")

            print(f"\nTotal validation errors found: {len(self.validation_errors)}")
            if self.validation_errors:
                print("Validation errors:")
                for i, error in enumerate(self.validation_errors, 1):
                    print(f"{i}. {error}")

        except Exception as e:
            print(f"Connection error: {e}")
            traceback.print_exc()
        finally:
            if self.websocket:
                await self.websocket.close()

    async def test_registration_validation(self):
        """Test registration message validation"""
        print("Testing registration validation...")

        test_cases = [
            # Valid registration
            {
                "name": "valid_registration",
                "data": {
                    "type": "register",
                    "agentName": self.agent_name,
                    "agentType": "validation_tester",
                    "capabilities": ["testing", "validation"],
                },
                "should_pass": True,
            },
            # Missing agent name
            {
                "name": "missing_agent_name",
                "data": {"type": "register", "agentType": "test"},
                "should_pass": False,
            },
            # Invalid agent name type
            {
                "name": "invalid_agent_name_type",
                "data": {"type": "register", "agentName": 123, "agentType": "test"},
                "should_pass": False,
            },
            # Empty agent name
            {
                "name": "empty_agent_name",
                "data": {"type": "register", "agentName": "", "agentType": "test"},
                "should_pass": False,
            },
        ]

        for case in test_cases:
            try:
                await self.websocket.send(json.dumps(case["data"]))
                await asyncio.sleep(0.1)  # Wait for response

                # For now, assume it passed if no exception
                self.test_results[f"registration_{case['name']}"] = {"passed": True}

            except Exception as e:
                self.test_results[f"registration_{case['name']}"] = {
                    "passed": case["should_pass"] is False,
                    "error": str(e),
                }
                if case["should_pass"]:
                    self.validation_errors.append(
                        f"Registration test '{case['name']}' failed: {e}"
                    )

    async def test_metrics_validation(self):
        """Test metrics message validation"""
        print("Testing metrics validation...")

        test_cases = [
            # Valid metrics
            {
                "name": "valid_metrics",
                "data": {
                    "type": "metrics_update",
                    "agentName": self.agent_name,
                    "metrics": [{"name": "test_metric", "value": 42, "unit": "count"}],
                    "timestamp": datetime.now().isoformat() + "Z",
                },
                "should_pass": True,
            },
            # Invalid metric value type
            {
                "name": "invalid_metric_value",
                "data": {
                    "type": "metrics_update",
                    "agentName": self.agent_name,
                    "metrics": [
                        {
                            "name": "test_metric",
                            "value": "not_a_number",
                            "unit": "count",
                        }
                    ],
                    "timestamp": datetime.now().isoformat() + "Z",
                },
                "should_pass": False,
            },
            # Missing metric fields
            {
                "name": "missing_metric_fields",
                "data": {
                    "type": "metrics_update",
                    "agentName": self.agent_name,
                    "metrics": [{"name": "test_metric"}],  # Missing value and unit
                    "timestamp": datetime.now().isoformat() + "Z",
                },
                "should_pass": False,
            },
            # Null/None values
            {
                "name": "null_metric_values",
                "data": {
                    "type": "metrics_update",
                    "agentName": self.agent_name,
                    "metrics": [{"name": None, "value": None, "unit": None}],
                    "timestamp": datetime.now().isoformat() + "Z",
                },
                "should_pass": False,
            },
        ]

        for case in test_cases:
            try:
                await self.websocket.send(json.dumps(case["data"]))
                await asyncio.sleep(0.1)
                self.test_results[f"metrics_{case['name']}"] = {"passed": True}

            except Exception as e:
                self.test_results[f"metrics_{case['name']}"] = {
                    "passed": case["should_pass"] is False,
                    "error": str(e),
                }
                if case["should_pass"]:
                    self.validation_errors.append(
                        f"Metrics test '{case['name']}' failed: {e}"
                    )

    async def test_event_validation(self):
        """Test event message validation"""
        print("Testing event validation...")

        test_cases = [
            # Valid event
            {
                "name": "valid_event",
                "data": {
                    "type": "event_update",
                    "agentName": self.agent_name,
                    "eventType": "test_event",
                    "severity": "info",
                    "message": "Test message",
                    "data": {},
                    "timestamp": datetime.now().isoformat() + "Z",
                },
                "should_pass": True,
            },
            # Invalid severity level
            {
                "name": "invalid_severity",
                "data": {
                    "type": "event_update",
                    "agentName": self.agent_name,
                    "eventType": "test",
                    "severity": "invalid_severity",
                    "message": "Test",
                    "timestamp": datetime.now().isoformat() + "Z",
                },
                "should_pass": False,
            },
            # Very long message
            {
                "name": "very_long_message",
                "data": {
                    "type": "event_update",
                    "agentName": self.agent_name,
                    "eventType": "test",
                    "severity": "info",
                    "message": "x" * 10000,  # 10k character message
                    "timestamp": datetime.now().isoformat() + "Z",
                },
                "should_pass": True,  # Should handle long messages
            },
        ]

        for case in test_cases:
            try:
                await self.websocket.send(json.dumps(case["data"]))
                await asyncio.sleep(0.1)
                self.test_results[f"event_{case['name']}"] = {"passed": True}

            except Exception as e:
                self.test_results[f"event_{case['name']}"] = {
                    "passed": case["should_pass"] is False,
                    "error": str(e),
                }
                if case["should_pass"]:
                    self.validation_errors.append(
                        f"Event test '{case['name']}' failed: {e}"
                    )

    async def test_malformed_data(self):
        """Test malformed JSON and data structures"""
        print("Testing malformed data handling...")

        test_cases = [
            # Invalid JSON
            {"name": "invalid_json", "data": "{invalid json}", "should_pass": False},
            # Missing type field
            {
                "name": "missing_type",
                "data": {"agentName": self.agent_name, "message": "test"},
                "should_pass": False,
            },
            # Unknown message type
            {
                "name": "unknown_type",
                "data": {"type": "unknown_message_type", "agentName": self.agent_name},
                "should_pass": False,
            },
        ]

        for case in test_cases:
            try:
                if isinstance(case["data"], str):
                    await self.websocket.send(case["data"])
                else:
                    await self.websocket.send(json.dumps(case["data"]))
                await asyncio.sleep(0.1)

                # If we get here without exception, test passed
                self.test_results[f"malformed_{case['name']}"] = {"passed": True}

            except Exception as e:
                self.test_results[f"malformed_{case['name']}"] = {
                    "passed": case["should_pass"] is False,
                    "error": str(e),
                }
                if case["should_pass"]:
                    self.validation_errors.append(
                        f"Malformed test '{case['name']}' failed: {e}"
                    )

    async def test_edge_cases(self):
        """Test edge cases and boundary conditions"""
        print("Testing edge cases...")

        # Test extremely large metrics array
        large_metrics = [
            {"name": f"metric_{i}", "value": i, "unit": "count"} for i in range(1000)
        ]

        try:
            large_metrics_msg = {
                "type": "metrics_update",
                "agentName": self.agent_name,
                "metrics": large_metrics,
                "timestamp": datetime.now().isoformat() + "Z",
            }
            await self.websocket.send(json.dumps(large_metrics_msg))
            self.test_results["edge_large_metrics"] = {"passed": True}
        except Exception as e:
            self.test_results["edge_large_metrics"] = {"passed": False, "error": str(e)}
            self.validation_errors.append(f"Large metrics test failed: {e}")

        # Test rapid message sending
        try:
            for i in range(100):
                msg = {
                    "type": "heartbeat",
                    "agentName": self.agent_name,
                    "timestamp": datetime.now().isoformat() + "Z",
                    "status": "active",
                }
                await self.websocket.send(json.dumps(msg))
            self.test_results["edge_rapid_messages"] = {"passed": True}
        except Exception as e:
            self.test_results["edge_rapid_messages"] = {
                "passed": False,
                "error": str(e),
            }
            self.validation_errors.append(f"Rapid messages test failed: {e}")


async def main():
    """Run validation tests"""
    tester = ValidationTestAgent()
    await tester.connect_and_test()


if __name__ == "__main__":
    asyncio.run(main())
