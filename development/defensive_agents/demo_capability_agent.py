"""
Demonstration: Capability Monitoring Agent
Tests actual NVIDIA Container Toolkit deployment
"""

import sys
sys.path.append('C:/Users/Corbin/development/defensive_agents')

from agent_framework import CapabilityMonitorAgent, AgentAction
import docker


def main():
    print("=" * 70)
    print("Defensive Security Agent - Live Demonstration")
    print("=" * 70)
    print()

    # Initialize agent
    agent = CapabilityMonitorAgent()
    print(f"Agent: {agent.name}")
    print(f"Security Policies: {len(agent.security_policies)}")
    print("Architecture: Perceive -> Decide -> Act -> Learn")
    print()

    # Get containers
    client = docker.from_env()
    containers = client.containers.list()

    print(f"Found {len(containers)} running containers")
    print()

    # Test each container
    for container in containers:
        if 'ghidra-ml' not in container.name:
            continue  # Only test our containers

        print("-" * 70)
        print(f"Testing: {container.name}")
        print("-" * 70)

        try:
            # Run agent cycle
            outcome = agent.run_cycle(container.id)

            print(f"  Action Taken: {outcome.action_taken.value}")
            print(f"  Success: {outcome.success}")
            print(f"  Details: {outcome.details}")
            print()

            # Show what agent learned
            if container.id in agent.knowledge_base:
                kb = agent.knowledge_base[container.id]
                print(f"  Knowledge Base Entries: {len(kb['history'])}")

        except Exception as e:
            print(f"  ERROR: {str(e)}")
            print()

    # Show agent metrics
    print("=" * 70)
    print("Agent Performance Metrics")
    print("=" * 70)
    metrics = agent.get_metrics()
    for key, value in metrics.items():
        print(f"  {key}: {value}")
    print()

    # Demonstrate specific tests
    print("=" * 70)
    print("Defensive Security Tests")
    print("=" * 70)

    print("\n[Test 1] Checking ML Container Capabilities")
    try:
        ml_container = client.containers.get('ghidra-ml-similarity')
        state = agent.perceive(ml_container.id)

        print(f"  Capabilities Added: {state.data['cap_add']}")
        print(f"  Capabilities Dropped: {state.data['cap_drop']}")

        decision = agent.decide(state)
        print(f"  Risk Assessment: {decision.reasoning}")
        print(f"  Recommended Action: {decision.action.value}")

        if decision.action == AgentAction.LOG_INFO:
            print("  Result: PASS - Container is secure")
        elif decision.action == AgentAction.ALERT_WARNING:
            print("  Result: WARNING - Review recommended")
        else:
            print("  Result: CRITICAL - Immediate action needed")

    except docker.errors.NotFound:
        print("  Container not found (may not be running)")

    print("\n[Test 2] Checking GPU Exporter Capabilities")
    try:
        gpu_container = client.containers.get('ghidra-ml-gpu-exporter')
        state = agent.perceive(gpu_container.id)

        print(f"  Capabilities Added: {state.data['cap_add']}")
        print(f"  Capabilities Dropped: {state.data['cap_drop']}")

        decision = agent.decide(state)
        print(f"  Risk Assessment: {decision.reasoning}")
        print(f"  Recommended Action: {decision.action.value}")

        if decision.action == AgentAction.ALERT_CRITICAL:
            print("  Result: FAIL - Dangerous capabilities detected")
        elif decision.action == AgentAction.ALERT_WARNING:
            print("  Result: WARNING - Unexpected capabilities")
        else:
            print("  Result: PASS - Capabilities acceptable")

    except docker.errors.NotFound:
        print("  Container not found (may not be running)")

    print()
    print("=" * 70)
    print("Demonstration Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
