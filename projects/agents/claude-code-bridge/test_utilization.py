#!/usr/bin/env python3
"""
Test script for agent utilization tracking
"""

import sys
import asyncio
from datetime import datetime
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import without Redis requirement for testing
import importlib.util
spec = importlib.util.spec_from_file_location("director_integration",
    os.path.join(os.path.dirname(__file__), 'src', 'director-integration.py'))
director_integration = importlib.util.module_from_spec(spec)

# Mock redis to avoid connection requirement
class MockRedis:
    def __init__(self, *args, **kwargs):
        pass
    def ping(self):
        return True
    def hset(self, *args, **kwargs):
        pass
    def sadd(self, *args, **kwargs):
        pass
    def publish(self, *args, **kwargs):
        pass

class MockRedisModule:
    @staticmethod
    def Redis(*args, **kwargs):
        return MockRedis()

sys.modules['redis'] = MockRedisModule()

# Now load the module
spec.loader.exec_module(director_integration)
ClaudeCodeDirectorIntegration = director_integration.ClaudeCodeDirectorIntegration


async def test_utilization_tracking():
    """Test utilization calculation methods"""
    print("=" * 80)
    print("Testing Agent Utilization Tracking Implementation")
    print("=" * 80)

    # Create integration instance (without Redis for testing)
    integration = ClaudeCodeDirectorIntegration()

    # Manually populate test data
    print("\n1. Setting up test data...")

    # Register test agents
    test_agents = [
        {
            'id': 'agent-1',
            'type': 'worker',
            'capabilities': ['code_generation', 'code_analysis'],
            'metadata': {'max_concurrent_tasks': 5, 'version': '1.0.0'}
        },
        {
            'id': 'agent-2',
            'type': 'worker',
            'capabilities': ['code_generation', 'documentation'],
            'metadata': {'max_concurrent_tasks': 10, 'version': '1.0.0'}
        },
        {
            'id': 'agent-3',
            'type': 'worker',
            'capabilities': ['code_analysis', 'debugging'],
            'metadata': {'max_concurrent_tasks': 3, 'version': '1.0.0'}
        }
    ]

    for agent in test_agents:
        agent_id = agent['id']
        integration.registered_agents[agent_id] = {
            'type': agent['type'],
            'capabilities': agent['capabilities'],
            'registered_at': datetime.now(),
            'last_seen': datetime.now(),
            'status': 'online',
            'current_tasks': [],
            'metadata': agent['metadata']
        }

        # Register capabilities
        await integration.register_agent_capabilities(
            agent_id,
            agent['type'],
            agent['capabilities'],
            agent['metadata']
        )

    print(f"   Registered {len(test_agents)} test agents")

    # Assign some tasks to agents to test utilization
    print("\n2. Assigning tasks to agents...")

    # Agent 1: 3/5 tasks (60% utilization)
    integration.registered_agents['agent-1']['current_tasks'] = ['task-1', 'task-2', 'task-3']
    print("   agent-1: 3/5 tasks (expected 60% utilization)")

    # Agent 2: 8/10 tasks (80% utilization)
    integration.registered_agents['agent-2']['current_tasks'] = [f'task-{i}' for i in range(4, 12)]
    print("   agent-2: 8/10 tasks (expected 80% utilization)")

    # Agent 3: 0/3 tasks (0% utilization)
    integration.registered_agents['agent-3']['current_tasks'] = []
    print("   agent-3: 0/3 tasks (expected 0% utilization)")

    # Test individual agent utilization
    print("\n3. Testing calculate_agent_utilization()...")

    for agent_id in ['agent-1', 'agent-2', 'agent-3']:
        utilization = integration.calculate_agent_utilization(agent_id)
        agent = integration.registered_agents[agent_id]
        current = len(agent['current_tasks'])
        max_capacity = agent['metadata']['max_concurrent_tasks']
        print(f"   {agent_id}: {utilization:.2f} ({current}/{max_capacity} tasks) OK")

    # Test utilization for non-existent agent
    utilization = integration.calculate_agent_utilization('non-existent')
    print(f"   non-existent: {utilization:.2f} (should be 0.0) OK")

    # Test capability utilization
    print("\n4. Testing calculate_capability_utilization()...")

    capabilities_to_test = ['code_generation', 'code_analysis', 'debugging', 'documentation']

    for capability in capabilities_to_test:
        metrics = integration.calculate_capability_utilization(capability)
        print(f"\n   {capability}:")
        print(f"      Agent count: {metrics['agent_count']}")
        print(f"      Utilization - avg: {metrics['utilization']['avg']:.2f}, "
              f"min: {metrics['utilization']['min']:.2f}, "
              f"max: {metrics['utilization']['max']:.2f}")
        print(f"      Capacity - total: {metrics['capacity']['total']}, "
              f"used: {metrics['capacity']['used']}, "
              f"available: {metrics['capacity']['available']}")

    # Test capability network map
    print("\n5. Testing get_capability_network_map()...")

    network_map = await integration.get_capability_network_map()

    print(f"\n   Statistics:")
    print(f"      Total agents: {network_map['statistics']['total_agents']}")
    print(f"      Total capabilities: {network_map['statistics']['total_capabilities']}")
    print(f"      System load: {network_map['statistics']['system_load']}")
    print(f"      Avg agent utilization: {network_map['statistics']['avg_agent_utilization']:.2f}")
    print(f"      Total capacity: {network_map['statistics']['total_capacity']}")
    print(f"      Used capacity: {network_map['statistics']['used_capacity']}")

    print(f"\n   Agents with utilization:")
    for agent_id, agent_info in network_map['agents'].items():
        print(f"      {agent_id}: {agent_info['utilization']:.2f} "
              f"({agent_info['current_load']}/{agent_info['max_capacity']})")

    print(f"\n   Capabilities with detailed metrics:")
    for capability, metrics in network_map['capabilities'].items():
        print(f"      {capability}:")
        print(f"         Agents: {metrics['agent_count']}, "
              f"Avg utilization: {metrics['utilization']['avg']:.2f}")

    # Validation tests
    print("\n6. Running validation tests...")

    tests_passed = 0
    tests_total = 0

    # Test 1: Agent utilization in valid range
    tests_total += 1
    agent_1_util = integration.calculate_agent_utilization('agent-1')
    if 0.0 <= agent_1_util <= 1.0:
        print("   [PASS] Agent utilization is in valid range [0.0, 1.0]")
        tests_passed += 1
    else:
        print(f"   [FAIL] Agent utilization out of range: {agent_1_util}")

    # Test 2: Agent utilization calculation accuracy
    tests_total += 1
    expected_util = 3 / 5
    if abs(agent_1_util - expected_util) < 0.01:
        print(f"   [PASS] Agent utilization calculated correctly (expected: {expected_util:.2f}, got: {agent_1_util:.2f})")
        tests_passed += 1
    else:
        print(f"   [FAIL] Agent utilization incorrect (expected: {expected_util:.2f}, got: {agent_1_util:.2f})")

    # Test 3: Capability utilization has correct structure
    tests_total += 1
    code_gen_metrics = integration.calculate_capability_utilization('code_generation')
    required_keys = ['agent_count', 'utilization', 'capacity']
    if all(key in code_gen_metrics for key in required_keys):
        print("   [PASS] Capability utilization has correct structure")
        tests_passed += 1
    else:
        print("   [FAIL] Capability utilization missing required keys")

    # Test 4: Network map includes utilization metrics
    tests_total += 1
    has_utilization = all('utilization' in agent for agent in network_map['agents'].values())
    if has_utilization:
        print("   [PASS] Network map includes agent utilization metrics")
        tests_passed += 1
    else:
        print("   [FAIL] Network map missing utilization metrics")

    # Test 5: Capability avg utilization calculation
    tests_total += 1
    # code_generation: agent-1 (0.6) + agent-2 (0.8) = avg 0.7
    expected_avg = (0.6 + 0.8) / 2
    actual_avg = code_gen_metrics['utilization']['avg']
    if abs(actual_avg - expected_avg) < 0.01:
        print(f"   [PASS] Capability avg utilization calculated correctly (expected: {expected_avg:.2f}, got: {actual_avg:.2f})")
        tests_passed += 1
    else:
        print(f"   [FAIL] Capability avg utilization incorrect (expected: {expected_avg:.2f}, got: {actual_avg:.2f})")

    print(f"\n{'=' * 80}")
    print(f"Test Results: {tests_passed}/{tests_total} tests passed")
    print(f"{'=' * 80}")

    if tests_passed == tests_total:
        print("\n[SUCCESS] All tests passed! Implementation is working correctly.")
        return True
    else:
        print(f"\n[FAILURE] {tests_total - tests_passed} test(s) failed. Please review implementation.")
        return False


if __name__ == "__main__":
    # Run the tests
    success = asyncio.run(test_utilization_tracking())
    sys.exit(0 if success else 1)
