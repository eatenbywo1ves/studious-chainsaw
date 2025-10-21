#!/usr/bin/env python3
"""
Quick Start Script for Agentic Project Management Automation System
Simplified launcher for the automation system
"""

import asyncio
import sys
import logging
from pathlib import Path

# Add agent directories to path
agents_root = Path(__file__).parent
sys.path.insert(0, str(agents_root))

from master_orchestrator import MasterOrchestrator
from daily_briefing_scheduler import DailyBriefingScheduler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """Quick start the automation system"""

    print("""
================================================================================
    AGENTIC PROJECT MANAGEMENT AUTOMATION SYSTEM
================================================================================

Starting the automated project management system...

This will:
  1. Start the Master Orchestrator
  2. Initialize all three agents (Strategic Planner, Log Analyzer, Progress Tracker)
  3. Start the Daily Briefing Scheduler (scheduled for 9 AM)
  4. Begin monitoring your projects 24/7

Press Ctrl+C to stop the system.

================================================================================
""")

    orchestrator = None
    scheduler = None

    try:
        # Create and start orchestrator
        logger.info("Creating Master Orchestrator...")
        orchestrator = MasterOrchestrator()

        started = await orchestrator.start()

        if not started:
            logger.error("Failed to start Master Orchestrator")
            return 1

        # Wait for agents to initialize
        logger.info("Waiting for agents to initialize...")
        await asyncio.sleep(5)

        # Create and start scheduler
        logger.info("Starting Daily Briefing Scheduler...")
        scheduler = DailyBriefingScheduler(
            orchestrator=orchestrator,
            briefing_time="09:00"
        )
        scheduler.start()

        # Get initial status
        status = await orchestrator.get_system_status()

        print(f"""
================================================================================
    SYSTEM STATUS
================================================================================

Uptime: {status.get('uptime_formatted', 'N/A')}
Redis: {'Enabled' if status.get('redis_enabled') else 'Disabled'}

Agents:
""")

        for agent_name, agent_info in status.get('agents', {}).items():
            status_icon = '✓' if agent_info.get('status') == 'running' else '✗'
            print(f"  {status_icon} {agent_info.get('name')}: {agent_info.get('status')}")

            metrics = agent_info.get('metrics', {})
            if metrics:
                for key, value in metrics.items():
                    print(f"     - {key.replace('_', ' ').title()}: {value}")

        print(f"""
================================================================================
    AUTOMATION ACTIVE
================================================================================

Daily briefings will be generated at 9:00 AM and saved to:
  C:/Users/Corbin/daily-briefings/

Notifications will be saved to:
  C:/Users/Corbin/notifications/

Service logs are available at:
  C:/Users/Corbin/projects/agents/logs/

The system is now running. Press Ctrl+C to stop.

================================================================================
""")

        # Keep running
        while True:
            await asyncio.sleep(60)

    except KeyboardInterrupt:
        logger.info("\nShutdown requested by user...")
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    finally:
        # Cleanup
        if scheduler:
            scheduler.stop()

        if orchestrator:
            await orchestrator.stop()

        print("\nAutomation system stopped. Goodbye!\n")

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
