#!/usr/bin/env python3
"""
Progress Tracker Agent
Metrics collection, progress monitoring, and dashboard generation
"""

import asyncio
import json
import logging
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CommitType(Enum):
    FEATURE = "feat"
    FIX = "fix"
    DOCS = "docs"
    CHORE = "chore"
    REFACTOR = "refactor"
    TEST = "test"
    STYLE = "style"
    PERF = "perf"


@dataclass
class GitCommit:
    hash: str
    author: str
    date: datetime
    message: str
    commit_type: Optional[CommitType]
    files_changed: int
    insertions: int
    deletions: int


@dataclass
class ProjectMetrics:
    name: str
    total_commits: int
    commits_by_type: Dict[str, int]
    feature_to_doc_ratio: float
    last_commit_date: Optional[datetime]
    active_contributors: int
    lines_of_code: int
    test_coverage: Optional[float]
    directory_count: int
    file_count: int


@dataclass
class ProgressSnapshot:
    timestamp: datetime
    master_plan_phase: str
    master_plan_completion: float
    core_projects: Dict[str, ProjectMetrics]
    overall_metrics: Dict[str, Any]
    weekly_velocity: Dict[str, Any]


class ProgressTrackerAgent:
    """Agent that tracks metrics, progress, and generates dashboards"""
    
    def __init__(self, workspace_root: str = "C:/Users/Corbin"):
        self.workspace_root = Path(workspace_root)
        self.development_root = self.workspace_root / "development"
        self.projects_root = self.workspace_root / "projects"
        
        # Core project paths
        self.core_projects = {
            'ML Security Framework': self.development_root / 'ml-sectest-framework',
            'GhidraGo Tools': self.development_root / 'GhidraGo',
            'Financial Modeling': self.projects_root / 'financial-apps',
            'Multi-Agent System': self.projects_root / 'agents'
        }
        
        # Tracking state
        self.progress_history: List[ProgressSnapshot] = []
        self.git_cache: Dict[str, List[GitCommit]] = {}
        
        # Configuration
        self.tracking_interval = 3600  # 1 hour
        self.running = False
        
        # Baseline metrics (from Master Implementation Plan)
        self.baseline_metrics = {
            'feature_doc_ratio': 0.73,
            'organization_score': 6.5,
            'active_projects': 10,
            'directory_count': 65
        }
        
        # Targets
        self.target_metrics = {
            'feature_doc_ratio': 3.0,
            'organization_score': 9.5,
            'active_projects': 4,
            'directory_count': 45
        }
        
        logger.info("Progress Tracker Agent initialized")
    
    async def start(self):
        """Start the progress tracker agent"""
        logger.info("Starting Progress Tracker Agent...")
        self.running = True

        # Initial snapshot (run in background to avoid blocking)
        asyncio.create_task(self.capture_progress_snapshot())

        # Start tracking loops
        asyncio.create_task(self.continuous_tracking_loop())
        asyncio.create_task(self.metrics_calculation_loop())

        logger.info("Progress Tracker Agent started successfully")
        return True
    
    async def stop(self):
        """Stop the progress tracker agent"""
        logger.info("Stopping Progress Tracker Agent...")
        self.running = False
    
    async def continuous_tracking_loop(self):
        """Continuously track progress"""
        # Wait for interval before first capture (initial capture happens in start())
        await asyncio.sleep(self.tracking_interval)

        while self.running:
            try:
                await self.capture_progress_snapshot()
                await asyncio.sleep(self.tracking_interval)
            except Exception as e:
                logger.error(f"Tracking loop error: {e}")
                await asyncio.sleep(self.tracking_interval)
    
    async def metrics_calculation_loop(self):
        """Calculate and update metrics"""
        while self.running:
            try:
                await self.calculate_velocity_metrics()
                await asyncio.sleep(self.tracking_interval * 2)  # Every 2 hours
            except Exception as e:
                logger.error(f"Metrics calculation error: {e}")
                await asyncio.sleep(self.tracking_interval * 2)
    
    async def capture_progress_snapshot(self):
        """Capture a progress snapshot"""
        logger.info("Capturing progress snapshot...")
        
        # Analyze each core project
        project_metrics = {}
        for project_name, project_path in self.core_projects.items():
            if project_path.exists():
                metrics = await self.analyze_project(project_name, project_path)
                project_metrics[project_name] = metrics
        
        # Calculate overall metrics
        overall_metrics = await self.calculate_overall_metrics(project_metrics)
        
        # Determine master plan phase
        master_plan_phase, completion = await self.get_master_plan_status()
        
        # Calculate weekly velocity
        velocity = await self.calculate_velocity_metrics()
        
        snapshot = ProgressSnapshot(
            timestamp=datetime.now(),
            master_plan_phase=master_plan_phase,
            master_plan_completion=completion,
            core_projects=project_metrics,
            overall_metrics=overall_metrics,
            weekly_velocity=velocity
        )
        
        self.progress_history.append(snapshot)
        
        # Keep only last 30 days of snapshots
        cutoff = datetime.now() - timedelta(days=30)
        self.progress_history = [s for s in self.progress_history if s.timestamp > cutoff]
        
        logger.info(f"Progress snapshot captured: {len(project_metrics)} projects analyzed")
    
    async def analyze_project(self, name: str, path: Path) -> ProjectMetrics:
        """Analyze a single project"""
        try:
            # Get git commits
            commits = await self._get_git_commits(path, days=30)
            
            # Count by type
            commits_by_type = {}
            for commit_type in CommitType:
                count = sum(1 for c in commits if c.commit_type == commit_type)
                if count > 0:
                    commits_by_type[commit_type.value] = count
            
            # Calculate feature:doc ratio
            feature_count = commits_by_type.get('feat', 0)
            doc_count = commits_by_type.get('docs', 0)
            chore_count = commits_by_type.get('chore', 0)
            
            feature_to_doc_ratio = feature_count / (doc_count + chore_count) if (doc_count + chore_count) > 0 else 0.0
            
            # Get last commit date
            last_commit_date = commits[0].date if commits else None
            
            # Count contributors
            contributors = set(c.author for c in commits)
            
            # Count directories and files
            dir_count, file_count = await self._count_dirs_and_files(path)
            
            # Estimate lines of code
            loc = await self._count_lines_of_code(path)
            
            return ProjectMetrics(
                name=name,
                total_commits=len(commits),
                commits_by_type=commits_by_type,
                feature_to_doc_ratio=feature_to_doc_ratio,
                last_commit_date=last_commit_date,
                active_contributors=len(contributors),
                lines_of_code=loc,
                test_coverage=None,  # Would need to parse test results
                directory_count=dir_count,
                file_count=file_count
            )
            
        except Exception as e:
            logger.error(f"Error analyzing project {name}: {e}")
            return ProjectMetrics(
                name=name,
                total_commits=0,
                commits_by_type={},
                feature_to_doc_ratio=0.0,
                last_commit_date=None,
                active_contributors=0,
                lines_of_code=0,
                test_coverage=None,
                directory_count=0,
                file_count=0
            )
    
    async def _get_git_commits(self, repo_path: Path, days: int = 30) -> List[GitCommit]:
        """Get git commits for a repository"""
        commits = []
        
        try:
            # Check if it's a git repo
            if not (repo_path / '.git').exists():
                # Try parent directory
                parent = repo_path.parent
                if not (parent / '.git').exists():
                    return commits
                repo_path = parent
            
            # Get commits from last N days
            since_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            # Git log command
            cmd = [
                'git', '-C', str(repo_path),
                'log', f'--since={since_date}',
                '--pretty=format:%H|%an|%ai|%s',
                '--numstat'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                commits = self._parse_git_log(result.stdout)
            
        except Exception as e:
            logger.debug(f"Could not get git commits for {repo_path}: {e}")
        
        return commits
    
    def _parse_git_log(self, log_output: str) -> List[GitCommit]:
        """Parse git log output"""
        commits = []
        
        lines = log_output.split('\n')
        current_commit = None
        
        for line in lines:
            if '|' in line and len(line.split('|')) == 4:
                # Commit line
                if current_commit:
                    commits.append(current_commit)
                
                hash_val, author, date_str, message = line.split('|')
                
                # Parse commit type from message
                commit_type = None
                for ctype in CommitType:
                    if message.startswith(f"{ctype.value}:") or message.startswith(f"{ctype.value}("):
                        commit_type = ctype
                        break
                
                current_commit = GitCommit(
                    hash=hash_val,
                    author=author,
                    date=datetime.fromisoformat(date_str.replace(' ', 'T').split('+')[0].split('-')[0].strip()),
                    message=message,
                    commit_type=commit_type,
                    files_changed=0,
                    insertions=0,
                    deletions=0
                )
            elif current_commit and line.strip() and '\t' in line:
                # Numstat line
                parts = line.split('\t')
                if len(parts) >= 2:
                    try:
                        insertions = int(parts[0]) if parts[0] != '-' else 0
                        deletions = int(parts[1]) if parts[1] != '-' else 0
                        current_commit.insertions += insertions
                        current_commit.deletions += deletions
                        current_commit.files_changed += 1
                    except ValueError:
                        pass
        
        if current_commit:
            commits.append(current_commit)
        
        return commits
    
    async def _count_dirs_and_files(self, path: Path) -> Tuple[int, int]:
        """Count directories and files in a path"""
        dir_count = 0
        file_count = 0
        
        try:
            for item in path.rglob('*'):
                if item.is_dir() and not any(part.startswith('.') for part in item.parts):
                    dir_count += 1
                elif item.is_file():
                    file_count += 1
        except Exception as e:
            logger.debug(f"Error counting dirs/files: {e}")
        
        return dir_count, file_count
    
    async def _count_lines_of_code(self, path: Path) -> int:
        """Estimate lines of code"""
        loc = 0
        
        try:
            # Count lines in Python, JavaScript, TypeScript files
            extensions = ['.py', '.js', '.ts', '.tsx', '.jsx']
            
            for ext in extensions:
                for file in path.rglob(f'*{ext}'):
                    try:
                        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                            loc += sum(1 for line in f if line.strip())
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Error counting LOC: {e}")
        
        return loc
    
    async def calculate_overall_metrics(self, project_metrics: Dict[str, ProjectMetrics]) -> Dict[str, Any]:
        """Calculate overall metrics across all projects"""
        total_commits = sum(m.total_commits for m in project_metrics.values())
        
        # Calculate aggregate feature:doc ratio
        total_features = sum(m.commits_by_type.get('feat', 0) for m in project_metrics.values())
        total_docs = sum(m.commits_by_type.get('docs', 0) + m.commits_by_type.get('chore', 0) for m in project_metrics.values())
        
        feature_doc_ratio = total_features / total_docs if total_docs > 0 else 0.0
        
        # Count active projects (projects with commits in last 7 days)
        cutoff = datetime.now() - timedelta(days=7)
        active_projects = sum(1 for m in project_metrics.values() if m.last_commit_date and m.last_commit_date > cutoff)
        
        # Total LOC
        total_loc = sum(m.lines_of_code for m in project_metrics.values())
        
        # Progress toward targets
        progress_to_target = {
            'feature_doc_ratio': (feature_doc_ratio / self.target_metrics['feature_doc_ratio']) * 100,
            'active_projects': (self.target_metrics['active_projects'] / max(active_projects, 1)) * 100
        }
        
        return {
            'total_commits_30d': total_commits,
            'feature_doc_ratio': feature_doc_ratio,
            'active_projects': active_projects,
            'total_loc': total_loc,
            'progress_to_target': progress_to_target,
            'baseline_comparison': {
                'feature_doc_ratio_change': feature_doc_ratio - self.baseline_metrics['feature_doc_ratio'],
                'active_projects_change': active_projects - self.baseline_metrics['active_projects']
            }
        }
    
    async def get_master_plan_status(self) -> Tuple[str, float]:
        """Get Master Implementation Plan status"""
        try:
            plan_file = self.workspace_root / 'MASTER_IMPLEMENTATION_PLAN.md'
            
            if plan_file.exists():
                with open(plan_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Count completed phases
                import re
                phases = re.findall(r'###\s+Phase\s+\d+:', content)
                completed = len(re.findall(r'###\s+Phase\s+\d+:.*✅', content))
                
                if phases:
                    completion = (completed / len(phases)) * 100
                    current_phase = f"Phase {completed + 1}" if completed < len(phases) else "Complete"
                    return current_phase, completion
        except Exception as e:
            logger.debug(f"Could not read master plan: {e}")
        
        return "Unknown", 0.0
    
    async def calculate_velocity_metrics(self) -> Dict[str, Any]:
        """Calculate weekly velocity metrics"""
        if len(self.progress_history) < 2:
            return {
                'commits_per_week': 0,
                'features_per_week': 0,
                'velocity_trend': 'stable'
            }
        
        # Get snapshots from last 7 days
        cutoff = datetime.now() - timedelta(days=7)
        recent_snapshots = [s for s in self.progress_history if s.timestamp > cutoff]
        
        if len(recent_snapshots) < 2:
            recent_snapshots = self.progress_history[-2:]
        
        # Calculate velocity
        first = recent_snapshots[0]
        last = recent_snapshots[-1]
        
        days_elapsed = (last.timestamp - first.timestamp).days
        if days_elapsed == 0:
            days_elapsed = 1
        
        # Commits velocity
        commits_first = first.overall_metrics.get('total_commits_30d', 0)
        commits_last = last.overall_metrics.get('total_commits_30d', 0)
        commits_per_week = ((commits_last - commits_first) / days_elapsed) * 7
        
        # Feature:Doc ratio trend
        ratio_first = first.overall_metrics.get('feature_doc_ratio', 0)
        ratio_last = last.overall_metrics.get('feature_doc_ratio', 0)
        
        velocity_trend = 'improving' if ratio_last > ratio_first else 'declining' if ratio_last < ratio_first else 'stable'
        
        return {
            'commits_per_week': commits_per_week,
            'features_per_week': commits_per_week * 0.3,  # Estimate ~30% are features
            'velocity_trend': velocity_trend,
            'feature_doc_ratio_trend': ratio_last - ratio_first
        }
    
    async def generate_dashboard_data(self) -> Dict[str, Any]:
        """Generate comprehensive dashboard data"""
        if not self.progress_history:
            await self.capture_progress_snapshot()
        
        latest = self.progress_history[-1] if self.progress_history else None
        
        if not latest:
            return {}
        
        dashboard = {
            'timestamp': latest.timestamp.isoformat(),
            'master_plan': {
                'current_phase': latest.master_plan_phase,
                'completion': latest.master_plan_completion,
                'target_date': '2025-10-28'
            },
            'core_projects': {},
            'overall_metrics': latest.overall_metrics,
            'weekly_velocity': latest.weekly_velocity,
            'progress_charts': await self._generate_progress_charts(),
            'recommendations': await self._generate_recommendations()
        }
        
        # Add project details
        for name, metrics in latest.core_projects.items():
            dashboard['core_projects'][name] = {
                'total_commits': metrics.total_commits,
                'commits_by_type': metrics.commits_by_type,
                'feature_doc_ratio': metrics.feature_to_doc_ratio,
                'last_commit': metrics.last_commit_date.isoformat() if metrics.last_commit_date else None,
                'contributors': metrics.active_contributors,
                'loc': metrics.lines_of_code
            }
        
        return dashboard
    
    async def _generate_progress_charts(self) -> Dict[str, Any]:
        """Generate data for progress charts"""
        if len(self.progress_history) < 2:
            return {}
        
        # Feature:Doc ratio over time
        ratio_chart = {
            'labels': [s.timestamp.strftime('%Y-%m-%d') for s in self.progress_history[-30:]],
            'data': [s.overall_metrics.get('feature_doc_ratio', 0) for s in self.progress_history[-30:]],
            'target': self.target_metrics['feature_doc_ratio']
        }
        
        # Commit velocity over time
        velocity_chart = {
            'labels': [s.timestamp.strftime('%Y-%m-%d') for s in self.progress_history[-30:]],
            'data': [s.overall_metrics.get('total_commits_30d', 0) for s in self.progress_history[-30:]]
        }
        
        return {
            'feature_doc_ratio': ratio_chart,
            'commit_velocity': velocity_chart
        }
    
    async def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if not self.progress_history:
            return recommendations
        
        latest = self.progress_history[-1]
        
        # Check feature:doc ratio
        ratio = latest.overall_metrics.get('feature_doc_ratio', 0)
        if ratio < 1.0:
            recommendations.append(f"LOW PRIORITY: Feature:Doc ratio ({ratio:.2f}:1) below target (3:1). Focus on feature development.")
        elif ratio >= 3.0:
            recommendations.append(f"ACHIEVED: Feature:Doc ratio target met ({ratio:.2f}:1)!")
        
        # Check active projects
        active = latest.overall_metrics.get('active_projects', 0)
        if active > 4:
            recommendations.append(f"ATTENTION: {active} active projects (target: 4). Consider consolidating.")
        
        # Check master plan progress
        if latest.master_plan_completion < 20:
            recommendations.append(f"FOCUS: Master Implementation Plan {latest.master_plan_completion:.0f}% complete. Current phase: {latest.master_plan_phase}")
        
        # Check velocity
        velocity = latest.weekly_velocity.get('velocity_trend', 'stable')
        if velocity == 'declining':
            recommendations.append("ALERT: Velocity declining. Review blockers and resource allocation.")
        elif velocity == 'improving':
            recommendations.append("POSITIVE: Velocity improving. Maintain momentum!")
        
        return recommendations
    
    async def get_progress_report(self) -> str:
        """Generate comprehensive progress report"""
        dashboard = await self.generate_dashboard_data()
        
        if not dashboard:
            return "No progress data available."
        
        report = f"""
# Progress Report - {datetime.now().strftime('%Y-%m-%d')}

## Master Implementation Plan
- Current Phase: {dashboard['master_plan']['current_phase']}
- Completion: {dashboard['master_plan']['completion']:.1f}%
- Target Date: {dashboard['master_plan']['target_date']}

## Overall Metrics
- Feature:Doc Ratio: {dashboard['overall_metrics']['feature_doc_ratio']:.2f}:1 (Target: 3.0:1)
- Active Projects: {dashboard['overall_metrics']['active_projects']} (Target: 4)
- Total Commits (30d): {dashboard['overall_metrics']['total_commits_30d']}
- Total LOC: {dashboard['overall_metrics']['total_loc']:,}

## Core Projects
"""
        
        for name, metrics in dashboard['core_projects'].items():
            report += f"\n### {name}\n"
            report += f"- Commits (30d): {metrics['total_commits']}\n"
            report += f"- Feature:Doc: {metrics['feature_doc_ratio']:.2f}:1\n"
            report += f"- Contributors: {metrics['contributors']}\n"
            report += f"- Lines of Code: {metrics['loc']:,}\n"
            if metrics['last_commit']:
                report += f"- Last Commit: {metrics['last_commit']}\n"
        
        report += "\n## Weekly Velocity\n"
        report += f"- Commits/Week: {dashboard['weekly_velocity']['commits_per_week']:.1f}\n"
        report += f"- Trend: {dashboard['weekly_velocity']['velocity_trend']}\n"
        
        if dashboard['recommendations']:
            report += "\n## Recommendations\n"
            for rec in dashboard['recommendations']:
                report += f"- {rec}\n"
        
        return report


async def test_progress_tracker():
    """Test the progress tracker agent"""
    tracker = ProgressTrackerAgent()
    
    started = await tracker.start()
    if started:
        print("Progress Tracker Agent started")
        
        # Wait for initial snapshot
        await asyncio.sleep(3)
        
        # Generate progress report
        report = await tracker.get_progress_report()
        print(f"\nProgress Report:\n{report}")
        
        # Generate dashboard data
        dashboard = await tracker.generate_dashboard_data()
        print(f"\nDashboard Data Generated: {len(dashboard)} sections")
        
        await tracker.stop()
        print("\nProgress Tracker Agent stopped")
    else:
        print("Failed to start Progress Tracker Agent")


if __name__ == "__main__":
    asyncio.run(test_progress_tracker())
