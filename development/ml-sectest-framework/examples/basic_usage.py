#!/usr/bin/env python3
"""
ML-SecTest Basic Usage Examples
================================
Demonstrates various ways to use the ML security testing framework.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import SecurityOrchestrator, OrchestrationPlan
from core.base_agent import AgentContext
from agents import (
    PromptInjectionAgent,
    ModelInversionAgent,
    DataPoisoningAgent
)
from utils.report_generator import ReportGenerator


def example_1_single_agent():
    """Example 1: Testing with a single agent."""
    print("=" * 70)
    print("EXAMPLE 1: Single Agent Testing")
    print("=" * 70)

    # Initialize agent
    agent = PromptInjectionAgent()

    # Create context
    context = AgentContext(
        target_url="http://localhost:8000/api/chat",
        challenge_name="Dolos - Prompt Injection",
        difficulty_level="Easy",
        owasp_reference="OWASP LLM01"
    )

    # Execute agent
    print(f"\nTesting {context.target_url}...")
    results = agent.execute(context)

    # Display results
    for result in results:
        print(f"\n✓ Test: {result.test_name}")
        print(f"  Success: {result.success}")
        print(f"  Confidence: {result.confidence_score:.2%}")
        print(f"  Evidence: {len(result.evidence)} items found")


def example_2_orchestrated_testing():
    """Example 2: Orchestrated multi-agent testing."""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Orchestrated Multi-Agent Testing")
    print("=" * 70)

    # Initialize orchestrator
    orchestrator = SecurityOrchestrator()

    # Register multiple agents
    orchestrator.register_agent(PromptInjectionAgent())
    orchestrator.register_agent(ModelInversionAgent())
    orchestrator.register_agent(DataPoisoningAgent())

    # Create orchestration plan
    plan = OrchestrationPlan(
        challenge_name="Comprehensive ML Security Assessment",
        target_url="http://localhost:8000",
        difficulty_level="Medium",
        agent_sequence=[
            "prompt_injection_001",
            "model_inversion_001",
            "data_poisoning_001"
        ],
        parallel_execution=False,  # Sequential execution
        owasp_reference="OWASP LLM/ML Top 10"
    )

    # Execute plan
    print("\nExecuting security assessment...")
    result = orchestrator.execute_plan(plan)

    # Display summary
    print("\n📊 Assessment Complete!")
    print(f"   Status: {result.overall_status}")
    print(f"   Success Rate: {result.success_rate:.1f}%")
    print(f"   Duration: {result.total_duration_seconds:.2f}s")
    print(f"   Vulnerabilities: {len(result.vulnerabilities_found)}")


def example_3_parallel_execution():
    """Example 3: Parallel agent execution for faster testing."""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: Parallel Agent Execution")
    print("=" * 70)

    orchestrator = SecurityOrchestrator()

    # Register agents
    orchestrator.register_agent(PromptInjectionAgent())
    orchestrator.register_agent(ModelInversionAgent())

    # Create plan with parallel execution
    plan = OrchestrationPlan(
        challenge_name="Fast Parallel Assessment",
        target_url="http://localhost:8000",
        difficulty_level="Medium",
        agent_sequence=["prompt_injection_001", "model_inversion_001"],
        parallel_execution=True,  # Enable parallel execution
        max_workers=2
    )

    print("\nExecuting agents in parallel...")
    result = orchestrator.execute_plan(plan)

    print(f"\n⚡ Parallel execution completed in {result.total_duration_seconds:.2f}s")


def example_4_report_generation():
    """Example 4: Generating security reports."""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Report Generation")
    print("=" * 70)

    # Run a quick assessment
    orchestrator = SecurityOrchestrator()
    orchestrator.register_agent(PromptInjectionAgent())

    plan = OrchestrationPlan(
        challenge_name="Report Demo",
        target_url="http://localhost:8000",
        difficulty_level="Easy",
        agent_sequence=["prompt_injection_001"],
        owasp_reference="OWASP LLM01"
    )

    result = orchestrator.execute_plan(plan)

    # Generate reports
    report_gen = ReportGenerator(output_directory="../reports")

    print("\n📄 Generating reports...")

    html_report = report_gen.generate_html_report(result, "demo_report.html")
    print(f"   HTML Report: {html_report}")

    json_report = report_gen.generate_json_report(result, "demo_report.json")
    print(f"   JSON Report: {json_report}")


def example_5_custom_configuration():
    """Example 5: Custom agent configuration and CTF challenge testing."""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: CTF Challenge Testing")
    print("=" * 70)

    orchestrator = SecurityOrchestrator()

    # Register all agents
    orchestrator.register_agent(PromptInjectionAgent())
    orchestrator.register_agent(ModelInversionAgent())

    # Configure for Vault challenge (Model Inversion - Hard)
    vault_plan = OrchestrationPlan(
        challenge_name="Vault - Model Inversion Attack",
        target_url="http://localhost:8000/vault",
        difficulty_level="Hard",
        agent_sequence=["model_inversion_001"],
        owasp_reference="OWASP ML03",
        timeout_seconds=600  # 10 minute timeout for hard challenges
    )

    print("\n🎯 Testing CTF Challenge: Vault")
    print("   Difficulty: Hard")
    print("   Attack Type: Model Inversion")

    result = orchestrator.execute_plan(vault_plan)

    if result.vulnerabilities_found:
        print("\n✅ Challenge exploitable!")
        print(f"   Vulnerabilities: {', '.join(result.vulnerabilities_found)}")
    else:
        print("\n❌ Challenge secure or exploitation failed")


def example_6_agent_status_monitoring():
    """Example 6: Monitoring agent status during execution."""
    print("\n" + "=" * 70)
    print("EXAMPLE 6: Agent Status Monitoring")
    print("=" * 70)

    orchestrator = SecurityOrchestrator()

    # Register agents
    agents = [
        PromptInjectionAgent(),
        ModelInversionAgent(),
        DataPoisoningAgent()
    ]

    for agent in agents:
        orchestrator.register_agent(agent)

    # Get initial status
    print("\n📊 Agent Status Before Testing:")
    status = orchestrator.get_agent_status()
    for agent_id, agent_status in status.items():
        print(f"   {agent_id}: {agent_status['status']}")

    # Run a test
    plan = OrchestrationPlan(
        challenge_name="Status Demo",
        target_url="http://localhost:8000",
        difficulty_level="Medium",
        agent_sequence=["prompt_injection_001"],
        owasp_reference="OWASP LLM01"
    )

    orchestrator.execute_plan(plan)

    # Get updated status
    print("\n📊 Agent Status After Testing:")
    status = orchestrator.get_agent_status()
    for agent_id, agent_status in status.items():
        print(f"   {agent_id}:")
        print(f"      Status: {agent_status['status']}")
        print(f"      Total Tests: {agent_status['total_tests']}")
        print(f"      Successful: {agent_status['successful_tests']}")


def main():
    """Run all examples."""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║              ML-SecTest Framework Examples                    ║
    ║                                                               ║
    ║  These examples demonstrate various usage patterns           ║
    ║  Note: Examples require a running target application         ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    try:
        # Run examples
        example_1_single_agent()
        example_2_orchestrated_testing()
        example_3_parallel_execution()
        example_4_report_generation()
        example_5_custom_configuration()
        example_6_agent_status_monitoring()

        print("\n" + "=" * 70)
        print("✅ All examples completed!")
        print("=" * 70)

    except Exception as e:
        print("\n⚠️  Note: Examples require a running target application")
        print(f"   Error: {str(e)}")
        print("\n   To run these examples:")
        print("   1. Start your ML application server")
        print("   2. Update target URLs in the examples")
        print("   3. Run: python examples/basic_usage.py")


if __name__ == "__main__":
    main()
