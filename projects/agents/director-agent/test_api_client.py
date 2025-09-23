"""
Test client for the Multi-Agent Video Generation API
"""

import asyncio
import aiohttp
import json
from datetime import datetime
import sys


async def test_api():
    """Test the API endpoints"""

    base_url = "http://localhost:8080"

    async with aiohttp.ClientSession() as session:
        print("\n" + "="*60)
        print("  MULTI-AGENT VIDEO API TEST CLIENT")
        print("="*60 + "\n")

        # 1. Test health endpoint
        print("[1] Testing health endpoint...")
        try:
            async with session.get(f"{base_url}/api/health") as response:
                health = await response.json()
                print(f"   Status: {health['status']}")
                print(f"   Redis: {health['services']['redis']}")
                print(f"   Agents: {health['services']['agents']['online']}/{health['services']['agents']['total']} online")
                print("   [OK] Health check passed\n")
        except Exception as e:
            print(f"   [ERROR] Health check failed: {e}\n")
            return

        # 2. Submit a test project
        print("[2] Submitting test project...")
        test_project = {
            "title": "Test Video Project",
            "description": "A test project for the API",
            "scenes": [
                {
                    "description": "Opening scene",
                    "duration": 5.0,
                    "visual_prompt": "A beautiful sunrise over mountains",
                    "style": "realistic",
                    "mood": "peaceful",
                    "motion_type": "pan",
                    "transition_out": "fade"
                },
                {
                    "description": "Main scene",
                    "duration": 10.0,
                    "visual_prompt": "A bustling futuristic city",
                    "style": "cyberpunk",
                    "mood": "energetic",
                    "motion_type": "track",
                    "transition_in": "fade",
                    "sound_effects": ["traffic", "crowd"]
                }
            ]
        }

        try:
            async with session.post(
                f"{base_url}/api/projects/submit",
                json=test_project
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    project_id = result["project_id"]
                    print(f"   Project ID: {project_id}")
                    print(f"   Status: {result['status']}")
                    print(f"   Message: {result['message']}")
                    print("   [OK] Project submitted successfully\n")
                else:
                    print(f"   [ERROR] Failed to submit project: {response.status}\n")
                    return
        except Exception as e:
            print(f"   [ERROR] Failed to submit project: {e}\n")
            return

        # 3. Wait and check project status
        print("[3] Checking project status...")
        await asyncio.sleep(2)

        try:
            async with session.get(
                f"{base_url}/api/projects/{project_id}/status"
            ) as response:
                if response.status == 200:
                    status = await response.json()
                    print(f"   Project: {project_id}")
                    print(f"   Status: {status['status']}")
                    print(f"   Progress: {status['progress']:.1f}%")
                    print(f"   Scenes: {status['completed_scenes']}/{status['total_scenes']}")
                    if status['agents_assigned']:
                        print("   Agents assigned:")
                        for agent_type, agents in status['agents_assigned'].items():
                            print(f"     - {agent_type}: {len(agents)} agent(s)")
                    print("   [OK] Status retrieved\n")
                else:
                    print(f"   [ERROR] Failed to get status: {response.status}\n")
        except Exception as e:
            print(f"   [ERROR] Failed to get status: {e}\n")

        # 4. List all projects
        print("[4] Listing all projects...")
        try:
            async with session.get(f"{base_url}/api/projects") as response:
                if response.status == 200:
                    data = await response.json()
                    print(f"   Total projects: {data['total']}")
                    if data['projects']:
                        print("   Recent projects:")
                        for p in data['projects'][:3]:
                            print(f"     - {p['title']} ({p['status']}) - {p['id'][:8]}...")
                    print("   [OK] Projects listed\n")
                else:
                    print(f"   [ERROR] Failed to list projects: {response.status}\n")
        except Exception as e:
            print(f"   [ERROR] Failed to list projects: {e}\n")

        # 5. Check agents status
        print("[5] Checking agents status...")
        try:
            async with session.get(f"{base_url}/api/agents/status") as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data['statistics']
                    print(f"   Total agents: {stats.get('total_agents', 0)}")
                    print(f"   Online agents: {stats.get('online_agents', 0)}")
                    if 'agent_types' in stats:
                        print("   Agent types:")
                        for agent_type, type_stats in stats['agent_types'].items():
                            print(f"     - {agent_type}: {type_stats.get('online', 0)}/{type_stats.get('total', 0)} online")
                    print("   [OK] Agent status retrieved\n")
                else:
                    print(f"   [ERROR] Failed to get agent status: {response.status}\n")
        except Exception as e:
            print(f"   [ERROR] Failed to get agent status: {e}\n")

        print("="*60)
        print("  API TEST COMPLETE")
        print("="*60)


async def test_websocket():
    """Test WebSocket connection"""

    print("\n[WS] Testing WebSocket connection...")

    session = aiohttp.ClientSession()
    try:
        async with session.ws_connect(
            'ws://localhost:8080/ws/test_client'
        ) as ws:
            print("[WS] Connected to WebSocket")

            # Send ping
            await ws.send_str("ping")
            msg = await ws.receive()
            if msg.type == aiohttp.WSMsgType.TEXT:
                print(f"[WS] Received: {msg.data}")

            # Send test message
            await ws.send_str("Hello from test client")
            msg = await ws.receive()
            if msg.type == aiohttp.WSMsgType.TEXT:
                print(f"[WS] Received: {msg.data}")

            print("[WS] WebSocket test complete\n")

    except Exception as e:
        print(f"[WS] WebSocket error: {e}\n")
    finally:
        await session.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--ws":
        asyncio.run(test_websocket())
    else:
        asyncio.run(test_api())