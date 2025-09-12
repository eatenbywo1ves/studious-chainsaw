"""
Real-time Validation Error Monitor
Monitors the observatory system for input validation errors
"""

import asyncio
import websockets
import json
import time
from datetime import datetime

class ValidationMonitor:
    def __init__(self):
        self.server_url = "ws://localhost:8080/ws"
        self.websocket = None
        self.validation_errors = []
        self.message_count = 0
        self.error_patterns = [
            "validation",
            "invalid",
            "error",
            "failed",
            "exception",
            "malformed",
            "parse error",
            "bad request",
            "schema"
        ]

    async def connect_and_monitor(self):
        """Connect and monitor for validation errors"""
        try:
            print("Starting Validation Monitor...")
            print("Connecting to observatory WebSocket...")
            
            self.websocket = await websockets.connect(self.server_url)
            
            # Register as monitor
            registration = {
                "type": "register",
                "agentName": "ValidationMonitor",
                "agentType": "monitor",
                "capabilities": ["validation_monitoring", "error_detection"]
            }
            await self.websocket.send(json.dumps(registration))
            print("Validation Monitor registered successfully")
            
            # Listen for messages and analyze for validation issues
            print("Monitoring for validation errors...")
            print("=" * 50)
            
            start_time = time.time()
            
            async for message in self.websocket:
                self.message_count += 1
                await self.analyze_message(message)
                
                # Report status every 10 seconds
                if time.time() - start_time > 10:
                    await self.report_status()
                    start_time = time.time()
                
        except Exception as e:
            print(f"Monitor error: {e}")
        finally:
            if self.websocket:
                await self.websocket.close()

    async def analyze_message(self, raw_message):
        """Analyze message for validation issues"""
        try:
            # Try to parse JSON
            try:
                message = json.loads(raw_message)
            except json.JSONDecodeError as e:
                self.validation_errors.append({
                    "type": "json_parse_error",
                    "error": str(e),
                    "raw_message": raw_message[:200] + "..." if len(raw_message) > 200 else raw_message,
                    "timestamp": datetime.now().isoformat()
                })
                print(f"JSON PARSE ERROR: {e}")
                return
            
            # Check for error messages from server
            if isinstance(message, dict):
                msg_str = json.dumps(message).lower()
                
                # Look for error patterns
                for pattern in self.error_patterns:
                    if pattern in msg_str:
                        self.validation_errors.append({
                            "type": "error_pattern_match",
                            "pattern": pattern,
                            "message": message,
                            "timestamp": datetime.now().isoformat()
                        })
                        print(f"VALIDATION ERROR DETECTED: {pattern} in message: {message.get('type', 'unknown')}")
                        break
                
                # Check specific message types for validation issues
                await self.validate_message_structure(message)
                
        except Exception as e:
            self.validation_errors.append({
                "type": "analysis_error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            print(f"ANALYSIS ERROR: {e}")

    async def validate_message_structure(self, message):
        """Validate message structure against expected schemas"""
        if not isinstance(message, dict):
            return
            
        msg_type = message.get("type")
        
        if msg_type == "register":
            if not message.get("agentName"):
                self.validation_errors.append({
                    "type": "missing_agent_name",
                    "message": message,
                    "timestamp": datetime.now().isoformat()
                })
                print("VALIDATION ERROR: Missing agentName in registration")
                
        elif msg_type == "metrics_update":
            metrics = message.get("metrics", [])
            if not isinstance(metrics, list):
                self.validation_errors.append({
                    "type": "invalid_metrics_format",
                    "message": message,
                    "timestamp": datetime.now().isoformat()
                })
                print("VALIDATION ERROR: Metrics is not a list")
                
            # Check each metric
            for metric in metrics:
                if not isinstance(metric, dict):
                    continue
                if "name" not in metric or "value" not in metric:
                    self.validation_errors.append({
                        "type": "incomplete_metric",
                        "metric": metric,
                        "timestamp": datetime.now().isoformat()
                    })
                    print(f"VALIDATION ERROR: Incomplete metric: {metric}")
                    
        elif msg_type == "event_update":
            required_fields = ["agentName", "eventType", "severity", "message"]
            missing_fields = [field for field in required_fields if not message.get(field)]
            if missing_fields:
                self.validation_errors.append({
                    "type": "missing_event_fields",
                    "missing_fields": missing_fields,
                    "message": message,
                    "timestamp": datetime.now().isoformat()
                })
                print(f"VALIDATION ERROR: Missing event fields: {missing_fields}")

    async def report_status(self):
        """Report current status"""
        error_count = len(self.validation_errors)
        print(f"\nSTATUS UPDATE:")
        print(f"Messages processed: {self.message_count}")
        print(f"Validation errors found: {error_count}")
        
        if error_count > 0:
            print("Recent validation errors:")
            for error in self.validation_errors[-3:]:  # Show last 3 errors
                print(f"  - {error['type']}: {error.get('error', 'See message')}")
        else:
            print("No validation errors detected ✓")
        print("-" * 30)

    async def final_report(self):
        """Generate final validation report"""
        print("\n" + "=" * 60)
        print("FINAL VALIDATION REPORT")
        print("=" * 60)
        print(f"Total messages processed: {self.message_count}")
        print(f"Total validation errors: {len(self.validation_errors)}")
        
        if self.validation_errors:
            print("\nValidation errors by type:")
            error_types = {}
            for error in self.validation_errors:
                error_type = error['type']
                error_types[error_type] = error_types.get(error_type, 0) + 1
            
            for error_type, count in error_types.items():
                print(f"  {error_type}: {count}")
                
            print("\nDetailed validation errors:")
            for i, error in enumerate(self.validation_errors, 1):
                print(f"{i}. {error['type']}")
                print(f"   Time: {error['timestamp']}")
                if 'error' in error:
                    print(f"   Error: {error['error']}")
                if 'pattern' in error:
                    print(f"   Pattern: {error['pattern']}")
                print()
        else:
            print("✅ NO VALIDATION ERRORS DETECTED - System is operating correctly!")

async def main():
    """Run validation monitoring"""
    monitor = ValidationMonitor()
    
    try:
        await asyncio.wait_for(monitor.connect_and_monitor(), timeout=60.0)
    except asyncio.TimeoutError:
        print("\nMonitoring completed after 60 seconds")
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    finally:
        await monitor.final_report()

if __name__ == "__main__":
    asyncio.run(main())