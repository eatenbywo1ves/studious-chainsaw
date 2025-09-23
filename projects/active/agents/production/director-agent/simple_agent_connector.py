"""
Simple Agent Connector - Test connection to observatory
"""

import asyncio
import websockets
import json
import psutil
from datetime import datetime


async def connect_test_agent(agent_name):
    """Connect a simple test agent"""
    server_url = "ws://localhost:8080/ws"

    try:
        print(f"Connecting {agent_name} to observatory...")
        websocket = await websockets.connect(server_url)

        # Register agent
        registration = {
            "type": "register",
            "agentName": agent_name,
            "agentType": "test_agent",
            "capabilities": ["testing", "monitoring"],
        }
        await websocket.send(json.dumps(registration))
        print(f"{agent_name} registered successfully")

        # Send metrics periodically
        for i in range(10):
            metrics = {
                "type": "metrics_update",
                "agentName": agent_name,
                "metrics": [
                    {"name": "test_counter", "value": i, "unit": "count"},
                    {
                        "name": "memory_usage",
                        "value": psutil.Process().memory_info().rss / 1024 / 1024,
                        "unit": "MB",
                    },
                ],
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            await websocket.send(json.dumps(metrics))
            print(f"{agent_name} sent metrics #{i}")

            # Send heartbeat
            heartbeat = {
                "type": "heartbeat",
                "agentName": agent_name,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "status": "active",
            }
            await websocket.send(json.dumps(heartbeat))

            await asyncio.sleep(2)

        print(f"{agent_name} test completed successfully")
        await websocket.close()

    except Exception as e:
        print(f"Error connecting {agent_name}: {e}")


async def main():
    """Test connecting multiple agents"""
    print("Testing agent connections to observatory...")

    # Test multiple agents concurrently
    tasks = [
        connect_test_agent("TestAgent-VonNeumann"),
        connect_test_agent("TestAgent-Director"),
    ]

    await asyncio.gather(*tasks)
    print("All test agents completed")


if __name__ == "__main__":
    asyncio.run(main())
