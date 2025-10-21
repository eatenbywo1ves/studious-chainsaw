#!/usr/bin/env python3
"""
Master Orchestrator
Coordinates all project management agents using hierarchical multi-agent pattern
"""

import asyncio
import json
import logging
import sys
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
from enum import Enum

# Import agents
sys.path.append(str(Path(__file__).parent / "strategic-planner-agent"))
sys.path.append(str(Path(__file__).parent / "log-analyzer-agent"))
sys.path.append(str(Path(__file__).parent / "progress-tracker-agent"))

from strategic_planner import StrategicPlannerAgent
from log_analyzer import LogAnalyzerAgent
from progress_tracker import ProgressTrackerAgent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AgentStatus(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"
    STOPPING = "stopping"


class MasterOrchestrator:
    """
    Master Orchestrator coordinating all project management agents
    Uses hierarchical multi-agent orchestration pattern
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.orchestrator_id = f"master-orchestrator-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        # Load configuration
        if config_path:
            self.config = self._load_config(config_path)
        else:
            self.config = self._default_config()
        
        # Initialize agents
        self.agents = {
            'strategic_planner': None,
            'log_analyzer': None,
            'progress_tracker': None
        }
        
        self.agent_status = {
            'strategic_planner': AgentStatus.STOPPED,
            'log_analyzer': AgentStatus.STOPPED,
            'progress_tracker': AgentStatus.STOPPED
        }
        
        # System state
        self.running = False
        self.start_time = None
        self.last_health_check = None
        self.health_check_interval = 60  # 1 minute
        
        # Report storage
        self.reports_dir = Path(self.config.get('reports_dir', 'C:/Users/Corbin/daily-briefings'))
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Master Orchestrator initialized: {self.orchestrator_id}")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load config from {config_path}: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'workspace_root': 'C:/Users/Corbin',
            'reports_dir': 'C:/Users/Corbin/daily-briefings',
            'logs_dir': 'C:/Users/Corbin/projects/agents/logs',
            'health_check_interval': 60,
            'enable_strategic_planner': True,
            'enable_log_analyzer': True,
            'enable_progress_tracker': True,
            'briefing_schedule': '09:00',
            'notification_enabled': False
        }
    
    async def start(self):
        """Start the master orchestrator and all agents"""
        logger.info("=" * 80)
        logger.info("STARTING MASTER ORCHESTRATOR")
        logger.info("=" * 80)
        
        self.running = True
        self.start_time = datetime.now()
        
        try:
            # Initialize agents
            workspace_root = self.config.get('workspace_root', 'C:/Users/Corbin')
            
            if self.config.get('enable_strategic_planner', True):
                logger.info("Initializing Strategic Planner Agent...")
                self.agents['strategic_planner'] = StrategicPlannerAgent(workspace_root)
            
            if self.config.get('enable_log_analyzer', True):
                logger.info("Initializing Log Analyzer Agent...")
                self.agents['log_analyzer'] = LogAnalyzerAgent(workspace_root)
            
            if self.config.get('enable_progress_tracker', True):
                logger.info("Initializing Progress Tracker Agent...")
                self.agents['progress_tracker'] = ProgressTrackerAgent(workspace_root)
            
            # Start all agents
            await self._start_all_agents()
            
            # Start monitoring loops
            asyncio.create_task(self.health_monitoring_loop())
            asyncio.create_task(self.coordination_loop())
            
            logger.info("=" * 80)
            logger.info("MASTER ORCHESTRATOR STARTED SUCCESSFULLY")
            logger.info(f"Active Agents: {len([a for a in self.agents.values() if a])}")
            logger.info("=" * 80)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Master Orchestrator: {e}")
            await self.stop()
            return False
    
    async def _start_all_agents(self):
        """Start all enabled agents"""
        for agent_name, agent in self.agents.items():
            if agent:
                try:
                    logger.info(f"Starting {agent_name}...")
                    self.agent_status[agent_name] = AgentStatus.STARTING
                    
                    success = await agent.start()
                    
                    if success:
                        self.agent_status[agent_name] = AgentStatus.RUNNING
                        logger.info(f"✓ {agent_name} started successfully")
                    else:
                        self.agent_status[agent_name] = AgentStatus.ERROR
                        logger.error(f"✗ {agent_name} failed to start")
                        
                except Exception as e:
                    self.agent_status[agent_name] = AgentStatus.ERROR
                    logger.error(f"✗ Error starting {agent_name}: {e}")
    
    async def stop(self):
        """Stop the master orchestrator and all agents"""
        logger.info("=" * 80)
        logger.info("STOPPING MASTER ORCHESTRATOR")
        logger.info("=" * 80)
        
        self.running = False
        
        # Stop all agents
        for agent_name, agent in self.agents.items():
            if agent and self.agent_status[agent_name] == AgentStatus.RUNNING:
                try:
                    logger.info(f"Stopping {agent_name}...")
                    self.agent_status[agent_name] = AgentStatus.STOPPING
                    
                    await agent.stop()
                    
                    self.agent_status[agent_name] = AgentStatus.STOPPED
                    logger.info(f"✓ {agent_name} stopped")
                    
                except Exception as e:
                    logger.error(f"Error stopping {agent_name}: {e}")
        
        runtime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        logger.info(f"Master Orchestrator stopped after {runtime:.0f} seconds")
    
    async def health_monitoring_loop(self):
        """Monitor health of all agents"""
        while self.running:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self.check_agent_health()
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
    
    async def check_agent_health(self):
        """Check health status of all agents"""
        self.last_health_check = datetime.now()
        
        health_status = {
            'timestamp': self.last_health_check.isoformat(),
            'agents': {}
        }
        
        for agent_name, agent in self.agents.items():
            if agent:
                status = self.agent_status[agent_name]
                health_status['agents'][agent_name] = {
                    'status': status.value,
                    'healthy': status == AgentStatus.RUNNING
                }
                
                # Check if agent needs restart
                if status == AgentStatus.ERROR:
                    logger.warning(f"Agent {agent_name} in ERROR state, attempting restart...")
                    await self._restart_agent(agent_name)
        
        logger.debug(f"Health check completed: {sum(1 for a in health_status['agents'].values() if a['healthy'])}/{len(health_status['agents'])} agents healthy")
        
        return health_status
    
    async def _restart_agent(self, agent_name: str):
        """Restart a failed agent"""
        agent = self.agents.get(agent_name)
        if not agent:
            return
        
        try:
            logger.info(f"Restarting {agent_name}...")
            
            # Stop if running
            if self.agent_status[agent_name] != AgentStatus.STOPPED:
                await agent.stop()
            
            # Start again
            self.agent_status[agent_name] = AgentStatus.STARTING
            success = await agent.start()
            
            if success:
                self.agent_status[agent_name] = AgentStatus.RUNNING
                logger.info(f"✓ {agent_name} restarted successfully")
            else:
                self.agent_status[agent_name] = AgentStatus.ERROR
                logger.error(f"✗ {agent_name} restart failed")
                
        except Exception as e:
            self.agent_status[agent_name] = AgentStatus.ERROR
            logger.error(f"Error restarting {agent_name}: {e}")
    
    async def coordination_loop(self):
        """Main coordination loop"""
        while self.running:
            try:
                # Coordinate agents every 5 minutes
                await asyncio.sleep(300)
                await self.coordinate_agents()
            except Exception as e:
                logger.error(f"Coordination loop error: {e}")
    
    async def coordinate_agents(self):
        """Coordinate activities between agents"""
        logger.info("Coordinating agents...")
        
        # Check if all agents are healthy
        health = await self.check_agent_health()
        healthy_count = sum(1 for a in health['agents'].values() if a['healthy'])
        
        if healthy_count < len(self.agents):
            logger.warning(f"Only {healthy_count}/{len(self.agents)} agents healthy")
    
    async def generate_unified_report(self) -> str:
        """Generate unified report from all agents"""
        logger.info("Generating unified report...")
        
        report_parts = []
        report_parts.append(f"# Unified Project Management Report")
        report_parts.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_parts.append(f"**Orchestrator:** {self.orchestrator_id}")
        report_parts.append("")
        
        # Strategic Planner Report
        if self.agents['strategic_planner'] and self.agent_status['strategic_planner'] == AgentStatus.RUNNING:
            try:
                briefing = await self.agents['strategic_planner'].get_daily_briefing()
                report_parts.append("## Strategic Overview")
                report_parts.append(briefing)
                report_parts.append("")
            except Exception as e:
                logger.error(f"Error getting strategic briefing: {e}")
                report_parts.append("## Strategic Overview")
                report_parts.append("*Error generating strategic briefing*")
                report_parts.append("")
        
        # Log Analysis Report
        if self.agents['log_analyzer'] and self.agent_status['log_analyzer'] == AgentStatus.RUNNING:
            try:
                digest = await self.agents['log_analyzer'].get_daily_digest()
                report_parts.append("## Log Analysis")
                report_parts.append(digest)
                report_parts.append("")
            except Exception as e:
                logger.error(f"Error getting log digest: {e}")
                report_parts.append("## Log Analysis")
                report_parts.append("*Error generating log analysis*")
                report_parts.append("")
        
        # Progress Report
        if self.agents['progress_tracker'] and self.agent_status['progress_tracker'] == AgentStatus.RUNNING:
            try:
                progress = await self.agents['progress_tracker'].get_progress_report()
                report_parts.append("## Progress Tracking")
                report_parts.append(progress)
                report_parts.append("")
            except Exception as e:
                logger.error(f"Error getting progress report: {e}")
                report_parts.append("## Progress Tracking")
                report_parts.append("*Error generating progress report*")
                report_parts.append("")
        
        # System Health
        health = await self.check_agent_health()
        report_parts.append("## System Health")
        for agent_name, status in health['agents'].items():
            status_icon = "✓" if status['healthy'] else "✗"
            report_parts.append(f"- {status_icon} {agent_name}: {status['status']}")
        
        report_parts.append("")
        report_parts.append("---")
        report_parts.append("*Generated by Master Orchestrator - Agentic Project Management System*")
        
        return "\n".join(report_parts)
    
    async def save_report(self, report: str, filename: Optional[str] = None):
        """Save report to file"""
        if not filename:
            filename = f"briefing-{datetime.now().strftime('%Y-%m-%d')}.md"
        
        filepath = self.reports_dir / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
            
            logger.info(f"Report saved: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")
            return None
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        status = {
            'orchestrator_id': self.orchestrator_id,
            'running': self.running,
            'uptime_seconds': uptime,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'agents': {},
            'last_health_check': self.last_health_check.isoformat() if self.last_health_check else None
        }
        
        for agent_name in self.agents.keys():
            status['agents'][agent_name] = {
                'enabled': self.agents[agent_name] is not None,
                'status': self.agent_status[agent_name].value
            }
        
        return status


async def main():
    """Main entry point for testing"""
    # Configure console for UTF-8 output
    import sys

    # Try to reconfigure stdout for UTF-8 (Python 3.7+)
    utf8_enabled = False
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
            utf8_enabled = True
            logger.debug("Console configured for UTF-8 output")
    except Exception as e:
        logger.debug(f"Could not enable UTF-8 console: {e}")

    # Create orchestrator
    orchestrator = MasterOrchestrator()

    # Start system
    success = await orchestrator.start()

    if not success:
        print("Failed to start Master Orchestrator")
        return

    try:
        # Run for 10 seconds
        print("\nMaster Orchestrator running...")
        print("Press Ctrl+C to stop\n")

        await asyncio.sleep(10)

        # Generate report
        print("\nGenerating unified report...\n")
        report = await orchestrator.generate_unified_report()

        # Try to print with UTF-8, fallback to ASCII-safe version
        try:
            print(report)
        except UnicodeEncodeError:
            # Replace Unicode characters with ASCII alternatives
            safe_report = report
            unicode_replacements = {
                '✓': '[OK]',
                '✗': '[X]',
                '✅': '[DONE]',
                '❌': '[FAIL]',
                '🔄': '[ACTIVE]',
                '⏸️': '[PAUSE]',
                '🚫': '[BLOCK]',
                '⚠️': '[!]',
                '█': '#',
                '░': '-',
                '📊': '[CHART]',
                '📰': '[NEWS]'
            }
            for unicode_char, ascii_char in unicode_replacements.items():
                safe_report = safe_report.replace(unicode_char, ascii_char)

            print(safe_report)
            print("\n[Note: Unicode characters replaced with ASCII. See saved file for full version.]")

        # Save report
        filepath = await orchestrator.save_report(report)
        print(f"\nReport saved to: {filepath}")

        # Get status
        status = await orchestrator.get_system_status()
        print(f"\nSystem Status:")
        print(f"  Uptime: {status['uptime_seconds']:.0f} seconds")
        print(f"  Running: {status['running']}")
        print(f"  Agents: {len(status['agents'])}")

    except KeyboardInterrupt:
        print("\nShutdown requested...")
    finally:
        await orchestrator.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete")
