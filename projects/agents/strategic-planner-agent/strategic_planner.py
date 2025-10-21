#!/usr/bin/env python3
"""
Strategic Planner Agent
Monitors roadmaps, tracks phases, and provides strategic insights for project management
"""

import asyncio
import json
import logging
import os
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProjectPriority(Enum):
    CRITICAL = "critical"  # Must ship
    HIGH = "high"          # Core project
    MEDIUM = "medium"      # Secondary
    LOW = "low"            # Backlog
    ARCHIVED = "archived"   # Not active


class PhaseStatus(Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


@dataclass
class Roadmap:
    file_path: str
    project_name: str
    last_modified: datetime
    phases: List[Dict[str, Any]] = field(default_factory=list)
    current_phase: Optional[str] = None
    completion_percentage: float = 0.0
    key_metrics: Dict[str, Any] = field(default_factory=dict)
    blockers: List[str] = field(default_factory=list)


@dataclass
class ProjectStatus:
    name: str
    priority: ProjectPriority
    roadmap_file: Optional[str]
    current_phase: str
    completion: float
    test_coverage: Optional[float]
    production_ready: bool
    last_commit: Optional[datetime]
    blockers: List[str] = field(default_factory=list)
    next_milestones: List[str] = field(default_factory=list)


class StrategicPlannerAgent:
    """Agent that monitors and analyzes project roadmaps and strategic plans"""
    
    def __init__(self, workspace_root: str = "C:/Users/Corbin"):
        self.workspace_root = Path(workspace_root)
        self.development_root = self.workspace_root / "development"
        self.projects_root = self.workspace_root / "projects"
        
        # Roadmap tracking
        self.roadmaps: Dict[str, Roadmap] = {}
        self.core_projects: Dict[str, ProjectStatus] = {}
        
        # Configuration
        self.scan_interval = 300  # 5 minutes
        self.running = False
        
        # Known roadmap files
        self.roadmap_files = [
            self.workspace_root / "MASTER_IMPLEMENTATION_PLAN.md",
            self.development_root / "PLUGIN_ROADMAP_2025.md",
            self.development_root / "DIRECTORY_ORGANIZATION_ROADMAP.md",
            self.development_root / "docs" / "specifications" / "FRAMEWORK_CAPABILITY_ASSESSMENT.md",
        ]
        
        logger.info("Strategic Planner Agent initialized")
    
    async def start(self):
        """Start the strategic planner agent"""
        logger.info("Starting Strategic Planner Agent...")
        self.running = True
        
        # Initial scan
        await self.scan_all_roadmaps()
        await self.analyze_core_projects()
        
        # Start monitoring loops
        asyncio.create_task(self.roadmap_monitoring_loop())
        asyncio.create_task(self.metrics_tracking_loop())
        
        logger.info("Strategic Planner Agent started successfully")
        return True
    
    async def stop(self):
        """Stop the strategic planner agent"""
        logger.info("Stopping Strategic Planner Agent...")
        self.running = False
    
    async def roadmap_monitoring_loop(self):
        """Continuously monitor roadmaps for changes"""
        while self.running:
            try:
                await self.scan_all_roadmaps()
                await self.check_for_blockers()
                await asyncio.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Roadmap monitoring error: {e}")
                await asyncio.sleep(self.scan_interval)
    
    async def metrics_tracking_loop(self):
        """Track key metrics across all projects"""
        while self.running:
            try:
                await self.analyze_core_projects()
                await self.calculate_strategic_metrics()
                await asyncio.sleep(self.scan_interval * 2)  # Every 10 minutes
            except Exception as e:
                logger.error(f"Metrics tracking error: {e}")
                await asyncio.sleep(self.scan_interval * 2)
    
    async def scan_all_roadmaps(self):
        """Scan all known roadmap files"""
        for roadmap_file in self.roadmap_files:
            if roadmap_file.exists():
                await self.parse_roadmap(roadmap_file)
    
    async def parse_roadmap(self, file_path: Path):
        """Parse a roadmap file and extract key information"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract project name from filename
            project_name = file_path.stem.replace('_', ' ').title()
            
            # Get last modified time
            last_modified = datetime.fromtimestamp(file_path.stat().st_mtime)
            
            # Parse phases
            phases = self._extract_phases(content)
            
            # Parse current phase
            current_phase = self._extract_current_phase(content, phases)
            
            # Calculate completion
            completion = self._calculate_completion(phases)
            
            # Extract metrics
            metrics = self._extract_metrics(content)
            
            # Extract blockers
            blockers = self._extract_blockers(content)
            
            roadmap = Roadmap(
                file_path=str(file_path),
                project_name=project_name,
                last_modified=last_modified,
                phases=phases,
                current_phase=current_phase,
                completion_percentage=completion,
                key_metrics=metrics,
                blockers=blockers
            )
            
            self.roadmaps[project_name] = roadmap
            logger.info(f"Parsed roadmap: {project_name} ({completion:.1f}% complete)")
            
        except Exception as e:
            logger.error(f"Error parsing roadmap {file_path}: {e}")
    
    def _extract_phases(self, content: str) -> List[Dict[str, Any]]:
        """Extract phases from roadmap content"""
        phases = []
        
        # Look for phase patterns
        phase_pattern = r'###?\s+Phase\s+(\d+):\s+(.+?)(?:\s+✅|\s+\(.*?\))?$'
        
        for match in re.finditer(phase_pattern, content, re.MULTILINE):
            phase_num = int(match.group(1))
            phase_name = match.group(2).strip()
            
            # Determine status from markers
            phase_text = match.group(0)
            if '✅' in phase_text or 'COMPLETE' in phase_text:
                status = PhaseStatus.COMPLETED
            elif '🔄' in phase_text or 'in progress' in phase_text.lower():
                status = PhaseStatus.IN_PROGRESS
            elif '⏸️' in phase_text or 'pending' in phase_text.lower():
                status = PhaseStatus.NOT_STARTED
            elif '🚫' in phase_text or 'blocked' in phase_text.lower():
                status = PhaseStatus.BLOCKED
            else:
                status = PhaseStatus.NOT_STARTED
            
            phases.append({
                'number': phase_num,
                'name': phase_name,
                'status': status.value,
                'raw_text': phase_text
            })
        
        return sorted(phases, key=lambda x: x['number'])
    
    def _extract_current_phase(self, content: str, phases: List[Dict[str, Any]]) -> Optional[str]:
        """Determine the current active phase"""
        # Look for explicit current phase markers
        current_match = re.search(r'current[_\s]phase[:\s]+["\']?(\w+)', content, re.IGNORECASE)
        if current_match:
            return current_match.group(1)
        
        # Find first incomplete phase
        for phase in phases:
            if phase['status'] != PhaseStatus.COMPLETED.value:
                return f"Phase {phase['number']}"
        
        return None
    
    def _calculate_completion(self, phases: List[Dict[str, Any]]) -> float:
        """Calculate overall completion percentage from phases"""
        if not phases:
            return 0.0
        
        completed = sum(1 for p in phases if p['status'] == PhaseStatus.COMPLETED.value)
        return (completed / len(phases)) * 100.0
    
    def _extract_metrics(self, content: str) -> Dict[str, Any]:
        """Extract key metrics from roadmap content"""
        metrics = {}
        
        # Common metric patterns
        patterns = {
            'feature_doc_ratio': r'Feature:Doc\s+ratio[:\s]+(\d+\.?\d*):1',
            'test_coverage': r'[Tt]est\s+[Cc]overage[:\s]+(\d+)%',
            'organization_score': r'[Oo]rganization\s+[Ss]core[:\s]+(\d+\.?\d*)/10',
            'production_readiness': r'[Pp]roduction\s+[Rr]eadiness[:\s]+(\d+\.?\d*)/10',
            'active_projects': r'[Aa]ctive\s+[Pp]rojects[:\s]+(\d+)',
            'directory_count': r'(\d+)\+?\s+directories'
        }
        
        for metric_name, pattern in patterns.items():
            match = re.search(pattern, content)
            if match:
                try:
                    metrics[metric_name] = float(match.group(1))
                except ValueError:
                    metrics[metric_name] = match.group(1)
        
        return metrics
    
    def _extract_blockers(self, content: str) -> List[str]:
        """Extract blockers or issues from roadmap content"""
        blockers = []
        
        # Look for blocker sections
        blocker_section = re.search(r'##\s+(?:Blockers|Issues|Problems)(.*?)(?=##|$)', content, re.DOTALL | re.IGNORECASE)
        if blocker_section:
            blocker_text = blocker_section.group(1)
            # Extract list items
            for match in re.finditer(r'[-*]\s+(.+?)$', blocker_text, re.MULTILINE):
                blockers.append(match.group(1).strip())
        
        return blockers
    
    async def analyze_core_projects(self):
        """Analyze the 4 core projects"""
        core_projects_config = {
            'ML Security Framework': {
                'priority': ProjectPriority.CRITICAL,
                'roadmap': 'Framework Capability Assessment',
                'path': self.development_root / 'ml-sectest-framework'
            },
            'GhidraGo Tools': {
                'priority': ProjectPriority.HIGH,
                'roadmap': 'Plugin Roadmap 2025',
                'path': self.development_root / 'GhidraGo'
            },
            'Financial Modeling': {
                'priority': ProjectPriority.HIGH,
                'roadmap': None,
                'path': self.projects_root / 'financial-apps'
            },
            'Multi-Agent System': {
                'priority': ProjectPriority.HIGH,
                'roadmap': None,
                'path': self.projects_root / 'agents'
            }
        }
        
        for project_name, config in core_projects_config.items():
            status = await self._analyze_project(project_name, config)
            self.core_projects[project_name] = status
    
    async def _analyze_project(self, name: str, config: Dict[str, Any]) -> ProjectStatus:
        """Analyze a single project's status"""
        project_path = config.get('path')
        
        # Get roadmap info if available
        roadmap_name = config.get('roadmap')
        roadmap = self.roadmaps.get(roadmap_name) if roadmap_name else None
        
        status = ProjectStatus(
            name=name,
            priority=config['priority'],
            roadmap_file=roadmap.file_path if roadmap else None,
            current_phase=roadmap.current_phase if roadmap else "Unknown",
            completion=roadmap.completion_percentage if roadmap else 0.0,
            test_coverage=roadmap.key_metrics.get('test_coverage') if roadmap else None,
            production_ready=False,
            last_commit=None,
            blockers=roadmap.blockers if roadmap else [],
            next_milestones=[]
        )
        
        return status
    
    async def calculate_strategic_metrics(self):
        """Calculate strategic-level metrics across all projects"""
        total_projects = len(self.core_projects)
        completed_phases = 0
        total_phases = 0
        
        for roadmap in self.roadmaps.values():
            total_phases += len(roadmap.phases)
            completed_phases += sum(1 for p in roadmap.phases if p['status'] == PhaseStatus.COMPLETED.value)
        
        overall_completion = (completed_phases / total_phases * 100) if total_phases > 0 else 0.0
        
        logger.info(f"Strategic Metrics: {total_projects} core projects, {overall_completion:.1f}% complete")
    
    async def check_for_blockers(self):
        """Check all projects for blockers and alert"""
        all_blockers = []
        
        for project_name, status in self.core_projects.items():
            if status.blockers:
                all_blockers.extend([(project_name, blocker) for blocker in status.blockers])
        
        if all_blockers:
            logger.warning(f"Found {len(all_blockers)} blockers across projects")
            for project, blocker in all_blockers:
                logger.warning(f"  [{project}] {blocker}")
    
    async def generate_strategic_report(self) -> Dict[str, Any]:
        """Generate comprehensive strategic status report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_core_projects': len(self.core_projects),
                'total_roadmaps': len(self.roadmaps),
                'active_blockers': sum(len(p.blockers) for p in self.core_projects.values())
            },
            'core_projects': {},
            'roadmaps': {},
            'recommendations': []
        }
        
        # Add core projects
        for name, status in self.core_projects.items():
            report['core_projects'][name] = {
                'priority': status.priority.value,
                'current_phase': status.current_phase,
                'completion': status.completion,
                'test_coverage': status.test_coverage,
                'blockers': status.blockers,
                'next_milestones': status.next_milestones
            }
        
        # Add roadmaps
        for name, roadmap in self.roadmaps.items():
            report['roadmaps'][name] = {
                'file_path': roadmap.file_path,
                'last_modified': roadmap.last_modified.isoformat(),
                'completion': roadmap.completion_percentage,
                'current_phase': roadmap.current_phase,
                'total_phases': len(roadmap.phases),
                'completed_phases': sum(1 for p in roadmap.phases if p['status'] == PhaseStatus.COMPLETED.value),
                'blockers': roadmap.blockers,
                'key_metrics': roadmap.key_metrics
            }
        
        # Generate recommendations
        report['recommendations'] = await self._generate_recommendations()
        
        return report
    
    async def _generate_recommendations(self) -> List[str]:
        """Generate strategic recommendations based on current state"""
        recommendations = []
        
        # Check for blocked projects
        blocked_projects = [name for name, status in self.core_projects.items() if status.blockers]
        if blocked_projects:
            recommendations.append(f"PRIORITY: Resolve blockers in {', '.join(blocked_projects)}")
        
        # Check for stalled projects
        low_completion = [name for name, status in self.core_projects.items() if status.completion < 25]
        if low_completion:
            recommendations.append(f"ATTENTION: Projects with <25% completion: {', '.join(low_completion)}")
        
        # Check Master Implementation Plan
        master_plan = self.roadmaps.get('Master Implementation Plan')
        if master_plan and master_plan.current_phase:
            recommendations.append(f"Focus: {master_plan.current_phase} of Master Implementation Plan")
        
        return recommendations
    
    async def get_daily_briefing(self) -> str:
        """Generate a daily briefing for the user"""
        report = await self.generate_strategic_report()
        
        briefing = f"""
# Strategic Daily Briefing - {datetime.now().strftime('%Y-%m-%d')}

## Core Projects Status
"""
        for name, project in report['core_projects'].items():
            completion_bar = '█' * int(project['completion'] / 10) + '░' * (10 - int(project['completion'] / 10))
            briefing += f"\n**{name}** [{project['priority']}]\n"
            briefing += f"  Progress: {completion_bar} {project['completion']:.1f}%\n"
            briefing += f"  Phase: {project['current_phase']}\n"
            if project['blockers']:
                briefing += f"  ⚠️ Blockers: {len(project['blockers'])}\n"
        
        briefing += "\n## Roadmap Progress\n"
        for name, roadmap in report['roadmaps'].items():
            briefing += f"\n**{name}**\n"
            briefing += f"  {roadmap['completed_phases']}/{roadmap['total_phases']} phases complete ({roadmap['completion']:.1f}%)\n"
            if roadmap['current_phase']:
                briefing += f"  Current: {roadmap['current_phase']}\n"
        
        if report['recommendations']:
            briefing += "\n## Recommendations\n"
            for rec in report['recommendations']:
                briefing += f"- {rec}\n"
        
        return briefing


async def test_strategic_planner():
    """Test the strategic planner agent"""
    planner = StrategicPlannerAgent()
    
    started = await planner.start()
    if started:
        print("✅ Strategic Planner Agent started")
        
        # Wait for initial scan
        await asyncio.sleep(2)
        
        # Generate report
        report = await planner.generate_strategic_report()
        print(f"\n📊 Strategic Report:")
        print(json.dumps(report, indent=2, default=str))
        
        # Generate daily briefing
        briefing = await planner.get_daily_briefing()
        print(f"\n📰 Daily Briefing:\n{briefing}")
        
        await planner.stop()
        print("\n✅ Strategic Planner Agent stopped")
    else:
        print("❌ Failed to start Strategic Planner Agent")


if __name__ == "__main__":
    asyncio.run(test_strategic_planner())
