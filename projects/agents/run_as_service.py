#!/usr/bin/env python3
"""
Background Service Runner
Runs the agentic project management system as a background service
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

from master_orchestrator import MasterOrchestrator
from daily_briefing_scheduler import DailyBriefingScheduler

# Configure logging
log_dir = Path("C:/Users/Corbin/projects/agents/logs")
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / f"service-{datetime.now().strftime('%Y-%m-%d')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ServiceRunner:
    """Background service runner for the agentic system"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.orchestrator = None
        self.scheduler = None
        self.running = False
        self.restart_count = 0
        self.max_restarts = 5
        
        logger.info("Service Runner initialized")
    
    async def start(self):
        """Start the service"""
        logger.info("=" * 80)
        logger.info("STARTING AGENTIC PROJECT MANAGEMENT SERVICE")
        logger.info(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 80)
        
        self.running = True
        
        try:
            # Start orchestrator
            logger.info("Starting Master Orchestrator...")
            self.orchestrator = MasterOrchestrator(self.config_path)
            success = await self.orchestrator.start()
            
            if not success:
                logger.error("Failed to start Master Orchestrator")
                return False
            
            # Start daily briefing scheduler
            logger.info("Starting Daily Briefing Scheduler...")
            self.scheduler = DailyBriefingScheduler(self.config_path)
            self.scheduler.start_scheduler()
            
            logger.info("=" * 80)
            logger.info("SERVICE STARTED SUCCESSFULLY")
            logger.info("All agents operational and monitoring...")
            logger.info("=" * 80)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start service: {e}")
            await self.stop()
            return False
    
    async def stop(self):
        """Stop the service"""
        logger.info("=" * 80)
        logger.info("STOPPING SERVICE")
        logger.info("=" * 80)
        
        self.running = False
        
        # Stop scheduler
        if self.scheduler:
            self.scheduler.stop_scheduler()
        
        # Stop orchestrator
        if self.orchestrator:
            await self.orchestrator.stop()
        
        logger.info("Service stopped")
    
    async def restart(self):
        """Restart the service"""
        logger.info("RESTARTING SERVICE...")
        
        self.restart_count += 1
        
        if self.restart_count > self.max_restarts:
            logger.error(f"Max restart attempts ({self.max_restarts}) exceeded")
            return False
        
        await self.stop()
        await asyncio.sleep(5)  # Wait before restart
        return await self.start()
    
    async def run_forever(self):
        """Run service continuously with auto-restart on failure"""
        # Start service
        success = await self.start()
        
        if not success:
            logger.error("Failed to start service")
            return
        
        # Setup signal handlers
        def signal_handler(sig, frame):
            logger.info(f"Received signal {sig}, shutting down...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Main service loop
        try:
            while self.running:
                # Check orchestrator health
                if self.orchestrator and self.orchestrator.running:
                    # Service is healthy
                    await asyncio.sleep(60)
                else:
                    # Service stopped unexpectedly
                    logger.warning("Service stopped unexpectedly, attempting restart...")
                    success = await self.restart()
                    
                    if not success:
                        logger.error("Failed to restart service, exiting")
                        break
                    
                    await asyncio.sleep(10)
        
        except Exception as e:
            logger.error(f"Service error: {e}")
        
        finally:
            await self.stop()
    
    async def health_check(self):
        """Perform health check"""
        if not self.orchestrator or not self.orchestrator.running:
            return {
                'status': 'stopped',
                'healthy': False
            }
        
        try:
            status = await self.orchestrator.get_system_status()
            
            healthy_agents = sum(
                1 for agent in status['agents'].values() 
                if agent['enabled'] and agent['status'] == 'running'
            )
            
            total_agents = sum(1 for agent in status['agents'].values() if agent['enabled'])
            
            return {
                'status': 'running',
                'healthy': healthy_agents == total_agents,
                'agents': status['agents'],
                'uptime': status['uptime_seconds'],
                'restart_count': self.restart_count
            }
            
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return {
                'status': 'error',
                'healthy': False,
                'error': str(e)
            }


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Agentic Project Management Service')
    parser.add_argument('command', choices=['start', 'stop', 'restart', 'status', 'health'], 
                       help='Service command')
    parser.add_argument('--config', help='Config file path')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    
    args = parser.parse_args()
    
    service = ServiceRunner(args.config)
    
    if args.command == 'start':
        if args.daemon:
            logger.info("Starting service in daemon mode...")
            # For Windows, use pythonw.exe or create a Windows service
            # For now, run in foreground
            await service.run_forever()
        else:
            logger.info("Starting service in foreground mode...")
            await service.run_forever()
    
    elif args.command == 'stop':
        logger.info("Stop command - service should be managed by process manager")
        print("To stop service, use Ctrl+C or kill the process")
    
    elif args.command == 'restart':
        logger.info("Restart command")
        await service.restart()
    
    elif args.command == 'status':
        # Quick status check
        try:
            orchestrator = MasterOrchestrator(args.config)
            if orchestrator.running:
                print("Status: RUNNING")
            else:
                print("Status: STOPPED")
        except:
            print("Status: UNKNOWN")
    
    elif args.command == 'health':
        # Health check
        health = await service.health_check()
        print(f"Health Status: {'HEALTHY' if health['healthy'] else 'UNHEALTHY'}")
        print(f"Status: {health['status']}")
        if 'uptime' in health:
            print(f"Uptime: {health['uptime']:.0f} seconds")
        if 'agents' in health:
            print("\nAgent Status:")
            for name, info in health['agents'].items():
                status_icon = "✓" if info['status'] == 'running' else "✗"
                print(f"  {status_icon} {name}: {info['status']}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nService stopped by user")
        logger.info("Service stopped by user (Ctrl+C)")
