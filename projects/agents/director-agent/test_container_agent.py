#!/usr/bin/env python3
"""
Simple test script for Container Optimization Agent
"""
import asyncio
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from container_optimization_agent import ContainerOptimizationAgent
from redis_communication import RedisConfig

async def test_container_agent():
    """Test the container optimization agent with proper Redis config"""
    print("Starting Container Optimization Agent test...")

    # Configure Redis to use the correct port
    redis_config = RedisConfig(
        host='localhost',
        port=6380,  # Using catalytic-redis port
        db=0
    )

    agent = ContainerOptimizationAgent(redis_config)

    # Start the agent
    started = await agent.start()
    if not started:
        print("ERROR: Failed to start Container Optimization Agent")
        return False

    print("SUCCESS: Container Optimization Agent started")

    # Wait for some optimization cycles
    print("Running optimization cycles for 10 seconds...")
    await asyncio.sleep(10)

    # Get optimization status
    try:
        status = await agent.get_optimization_status()
        print("Optimization Status:")
        print(f"  - Agent ID: {status.get('agent_id', 'N/A')}")
        print(f"  - Status: {status.get('status', 'N/A')}")
        print(f"  - Optimization cycles: {status.get('optimization_cycles_completed', 0)}")
        print(f"  - Optimizations applied: {status.get('optimizations_applied', 0)}")
    except Exception as e:
        print(f"Error getting status: {e}")

    await agent.stop()
    print("SUCCESS: Container Optimization Agent stopped")
    return True

if __name__ == "__main__":
    success = asyncio.run(test_container_agent())
    sys.exit(0 if success else 1)