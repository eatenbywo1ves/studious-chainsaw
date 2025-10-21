#!/usr/bin/env python3
"""
Daily Briefing Scheduler
Schedules and generates daily project management briefings at 9 AM
"""

import asyncio
import logging
import schedule
import time
from datetime import datetime, time as datetime_time
from pathlib import Path
from typing import Optional
import threading

from master_orchestrator import MasterOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DailyBriefingScheduler:
    """Scheduler for automated daily briefings"""
    
    def __init__(self, config_path: Optional[str] = None, briefing_time: str = "09:00"):
        self.orchestrator = MasterOrchestrator(config_path)
        self.briefing_time = briefing_time
        self.running = False
        self.scheduler_thread = None
        
        logger.info(f"Daily Briefing Scheduler initialized - scheduled for {briefing_time}")
    
    async def generate_daily_briefing(self):
        """Generate and save daily briefing"""
        logger.info("=" * 80)
        logger.info(f"GENERATING DAILY BRIEFING - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("=" * 80)
        
        try:
            # Ensure orchestrator is running
            if not self.orchestrator.running:
                logger.info("Starting orchestrator for briefing generation...")
                await self.orchestrator.start()
                # Give agents time to initialize
                await asyncio.sleep(5)
            
            # Generate unified report
            report = await self.orchestrator.generate_unified_report()
            
            # Save report
            filename = f"briefing-{datetime.now().strftime('%Y-%m-%d')}.md"
            filepath = await self.orchestrator.save_report(report, filename)
            
            if filepath:
                logger.info(f"✓ Daily briefing generated: {filepath}")
                return filepath
            else:
                logger.error("✗ Failed to save daily briefing")
                return None
                
        except Exception as e:
            logger.error(f"Error generating daily briefing: {e}")
            return None
    
    def schedule_briefing(self):
        """Schedule the daily briefing"""
        schedule.every().day.at(self.briefing_time).do(self._run_briefing_job)
        logger.info(f"Daily briefing scheduled for {self.briefing_time}")
    
    def _run_briefing_job(self):
        """Run briefing job (sync wrapper for async function)"""
        logger.info("Daily briefing job triggered")
        asyncio.run(self.generate_daily_briefing())
    
    def start_scheduler(self):
        """Start the scheduler in a separate thread"""
        if self.running:
            logger.warning("Scheduler already running")
            return
        
        self.running = True
        self.schedule_briefing()
        
        # Start scheduler in thread
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("Daily Briefing Scheduler started")
    
    def _scheduler_loop(self):
        """Scheduler loop running in thread"""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def stop_scheduler(self):
        """Stop the scheduler"""
        logger.info("Stopping Daily Briefing Scheduler...")
        self.running = False
        
        # Stop orchestrator
        if self.orchestrator.running:
            asyncio.run(self.orchestrator.stop())
        
        logger.info("Daily Briefing Scheduler stopped")
    
    async def run_continuous(self):
        """Run scheduler continuously with orchestrator"""
        try:
            # Start orchestrator
            await self.orchestrator.start()
            
            # Schedule briefings
            self.start_scheduler()
            
            logger.info("=" * 80)
            logger.info("CONTINUOUS BRIEFING SCHEDULER RUNNING")
            logger.info(f"Next briefing: {self.briefing_time}")
            logger.info("Press Ctrl+C to stop")
            logger.info("=" * 80)
            
            # Keep running
            while self.running:
                await asyncio.sleep(60)
                
        except KeyboardInterrupt:
            logger.info("Shutdown requested")
        finally:
            self.stop_scheduler()


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Daily Briefing Scheduler')
    parser.add_argument('--time', default='09:00', help='Briefing time (HH:MM)')
    parser.add_argument('--config', help='Config file path')
    parser.add_argument('--once', action='store_true', help='Generate briefing once and exit')
    parser.add_argument('--continuous', action='store_true', help='Run continuously with scheduler')
    
    args = parser.parse_args()
    
    scheduler = DailyBriefingScheduler(args.config, args.time)
    
    if args.once:
        # Generate briefing once
        print("Generating daily briefing...")
        filepath = await scheduler.generate_daily_briefing()
        if filepath:
            print(f"\n✓ Briefing generated: {filepath}")
        else:
            print("\n✗ Briefing generation failed")
        
        # Stop orchestrator
        if scheduler.orchestrator.running:
            await scheduler.orchestrator.stop()
    
    elif args.continuous:
        # Run continuously with scheduler
        await scheduler.run_continuous()
    
    else:
        print("Usage:")
        print("  Generate briefing once:  python daily_briefing_scheduler.py --once")
        print("  Run continuously:        python daily_briefing_scheduler.py --continuous")
        print("  Custom time:             python daily_briefing_scheduler.py --continuous --time 08:30")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete")
