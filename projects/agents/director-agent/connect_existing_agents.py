"""
Connect All Existing Agents to Observatory
Main script to connect VonNeumann Agent and Director Agent to the observatory system
"""

import asyncio
import sys
import os

# Add paths for agent imports
sys.path.append(os.path.join(os.getcwd(), 'von_neumann_agent'))
sys.path.append(os.getcwd())

async def connect_vonneumann_agent():
    """Connect VonNeumann Agent to observatory"""
    try:
        sys.path.append('C:/Users/Corbin/von_neumann_agent')
        from observatory_adapter import ObservatoryEnabledVonNeumannAgent
        from von_neumann_agent import VonNeumannAgent
        
        print("Initializing VonNeumann Agent...")
        original_agent = VonNeumannAgent()
        monitored_agent = ObservatoryEnabledVonNeumannAgent(original_agent)
        
        await monitored_agent.start_monitoring()
        print("VonNeumann Agent connected to observatory")
        
        # Keep running and perform periodic tasks
        for i in range(100):  # Run for extended period
            await asyncio.sleep(10)
            try:
                # Simulate reasoning tasks
                monitored_agent.reason_about(f"problem_{i}", {"complexity": i % 5})
                if i % 3 == 0:
                    monitored_agent.synthesize_knowledge()
            except Exception as e:
                print(f"VonNeumann task error: {e}")
        
    except ImportError as e:
        print(f"Could not import VonNeumann Agent: {e}")
    except Exception as e:
        print(f"VonNeumann Agent connection error: {e}")

async def connect_director_agent():
    """Connect Director Agent to observatory"""
    try:
        from director_agent_observatory_adapter import ObservatoryEnabledDirectorAgent
        
        # Mock director for now (replace with actual director import)
        class MockDirectorAgent:
            def create_project(self, *args, **kwargs):
                return {"status": "created", "id": f"project_{len(args)}"}
            
            def orchestrate_agent(self, agent_type, task, *args, **kwargs):
                return {"status": "orchestrated", "agent": agent_type, "task": task}
            
            def execute_pipeline(self, pipeline_name, steps, *args, **kwargs):
                return {"status": "executed", "pipeline": pipeline_name}
            
            def allocate_resources(self, resource_type, amount, agent, *args, **kwargs):
                return {"status": "allocated", "resource": resource_type, "amount": amount}
        
        print("Initializing Director Agent...")
        original_director = MockDirectorAgent()
        monitored_director = ObservatoryEnabledDirectorAgent(original_director)
        
        await monitored_director.start_monitoring()
        print("Director Agent connected to observatory")
        
        # Keep running and perform periodic operations
        for i in range(100):
            await asyncio.sleep(15)
            try:
                # Simulate director operations
                monitored_director.create_project("video_generation", ["script_agent", "visual_agent"])
                monitored_director.orchestrate_agent("script_agent", f"generate_script_{i}", priority=1)
                
                if i % 2 == 0:
                    monitored_director.execute_pipeline("video_pipeline", ["script", "visual", "audio"])
                    monitored_director.allocate_resources("gpu_memory", 2.0 + i, "visual_agent")
                
            except Exception as e:
                print(f"Director task error: {e}")
                
    except ImportError as e:
        print(f"Could not import Director Agent: {e}")
    except Exception as e:
        print(f"Director Agent connection error: {e}")

async def main():
    """Main function to connect all agents"""
    print("Connecting existing agents to Multi-Agent Observatory...")
    print("Make sure the observatory server is running at http://localhost:8080")
    
    # Wait a moment for server to be ready
    await asyncio.sleep(2)
    
    # Start both agents concurrently
    tasks = [
        asyncio.create_task(connect_vonneumann_agent()),
        asyncio.create_task(connect_director_agent())
    ]
    
    try:
        # Run both agents
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        print("\nShutting down agents...")
    except Exception as e:
        print(f"Error running agents: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("Multi-Agent Observatory - Existing Agent Connector")
    print("=" * 60)
    asyncio.run(main())