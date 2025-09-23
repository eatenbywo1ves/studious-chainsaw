"""
Remote Work Activity Logger
A comprehensive utility for tracking remote work activities, sessions, and productivity metrics.
"""

import logging
import json
import sqlite3
import datetime
import time
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import atexit

# Configure SQLite3 for Python 3.12+ compatibility
sqlite3.register_adapter(datetime.datetime, lambda dt: dt.isoformat())
sqlite3.register_adapter(datetime.date, lambda d: d.isoformat())
sqlite3.register_converter("TIMESTAMP", lambda b: datetime.datetime.fromisoformat(b.decode()))
sqlite3.register_converter("DATE", lambda b: datetime.date.fromisoformat(b.decode()))


class ActivityType(Enum):
    """Types of work activities that can be logged"""
    CODING = "coding"
    MEETING = "meeting"
    RESEARCH = "research"
    DOCUMENTATION = "documentation"
    BREAK = "break"
    LUNCH = "lunch"
    PLANNING = "planning"
    REVIEW = "review"
    DEBUGGING = "debugging"
    TESTING = "testing"
    DEPLOYMENT = "deployment"
    COMMUNICATION = "communication"
    LEARNING = "learning"
    ADMIN = "admin"
    OTHER = "other"


class LogLevel(Enum):
    """Custom log levels for work tracking"""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    ACTIVITY = 25  # Custom level between INFO and WARNING
    MILESTONE = 35  # Custom level for important achievements
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


@dataclass
class WorkSession:
    """Represents a work session"""
    session_id: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime]
    total_duration: Optional[float]
    activities: List[Dict[str, Any]]
    breaks: List[Dict[str, Any]]
    notes: str
    project: str
    tags: List[str]


@dataclass
class Activity:
    """Represents a single work activity"""
    activity_id: str
    type: ActivityType
    description: str
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime]
    duration: Optional[float]
    project: str
    tags: List[str]
    metadata: Dict[str, Any]


class RemoteWorkLogger:
    """Main logger class for tracking remote work activities"""
    
    def __init__(self, 
                 log_dir: str = None,
                 db_file: str = None,
                 console_output: bool = True,
                 file_output: bool = True,
                 auto_save: bool = True):
        """
        Initialize the Remote Work Logger
        
        Args:
            log_dir: Directory to store log files (default: ~/remote_work_logs)
            db_file: SQLite database file for persistent storage
            console_output: Whether to output logs to console
            file_output: Whether to output logs to file
            auto_save: Whether to automatically save sessions
        """
        # Set up directories
        self.log_dir = Path(log_dir) if log_dir else Path.home() / "remote_work_logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Database setup
        self.db_file = db_file or str(self.log_dir / "work_tracking.db")
        self._init_database()
        
        # Logger setup
        self.logger = self._setup_logger(console_output, file_output)
        
        # Session tracking
        self.current_session = None
        self.current_activity = None
        self.session_timer = None
        self.auto_save = auto_save
        
        # Statistics tracking
        self.daily_stats = {}
        self.weekly_stats = {}
        
        # Register cleanup on exit
        atexit.register(self.cleanup)
        
        # Add custom log levels
        logging.addLevelName(LogLevel.ACTIVITY.value, "ACTIVITY")
        logging.addLevelName(LogLevel.MILESTONE.value, "MILESTONE")

    def _setup_logger(self, console_output: bool, file_output: bool) -> logging.Logger:
        """Set up the logging configuration"""
        logger = logging.getLogger("RemoteWorkLogger")
        logger.setLevel(logging.DEBUG)
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        simple_formatter = logging.Formatter(
            '%(asctime)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        
        # Console handler with UTF-8 encoding for Windows
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(simple_formatter)
            # Fix encoding for Windows console
            if sys.platform == "win32":
                import io
                sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
            logger.addHandler(console_handler)
        
        # File handler - daily rotating files
        if file_output:
            today = datetime.date.today().strftime("%Y-%m-%d")
            file_handler = logging.FileHandler(
                self.log_dir / f"work_log_{today}.log"
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)
        
        return logger

    def _init_database(self):
        """Initialize SQLite database for persistent storage"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                total_duration REAL,
                project TEXT,
                notes TEXT,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activities (
                activity_id TEXT PRIMARY KEY,
                session_id TEXT,
                type TEXT,
                description TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                duration REAL,
                project TEXT,
                tags TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS breaks (
                break_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                duration REAL,
                reason TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS milestones (
                milestone_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp TIMESTAMP,
                description TEXT,
                project TEXT,
                impact TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def start_session(self, project: str = "General", notes: str = "", tags: List[str] = None) -> str:
        """Start a new work session"""
        if self.current_session:
            self.logger.warning("A session is already active. Ending previous session.")
            self.end_session()
        
        session_id = f"session_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.current_session = WorkSession(
            session_id=session_id,
            start_time=datetime.datetime.now(),
            end_time=None,
            total_duration=None,
            activities=[],
            breaks=[],
            notes=notes,
            project=project,
            tags=tags or []
        )
        
        self.logger.info(f"[START] Work session: {session_id} | Project: {project}")
        self._log_activity(f"Work session started - Project: {project}")
        
        if self.auto_save:
            self._save_session_to_db(self.current_session)
        
        return session_id

    def end_session(self, notes: str = "") -> Dict[str, Any]:
        """End the current work session"""
        if not self.current_session:
            self.logger.warning("No active session to end")
            return {}
        
        # End any active activity
        if self.current_activity:
            self.end_activity()
        
        # Calculate session duration
        self.current_session.end_time = datetime.datetime.now()
        duration = (self.current_session.end_time - self.current_session.start_time).total_seconds()
        self.current_session.total_duration = duration
        
        if notes:
            self.current_session.notes += f"\n{notes}"
        
        # Generate session summary
        summary = self._generate_session_summary(self.current_session)
        
        self.logger.info(f"[END] Work session: {self.current_session.session_id}")
        self.logger.info(f"   Total duration: {self._format_duration(duration)}")
        
        # Save to database
        self._save_session_to_db(self.current_session)
        
        # Reset current session
        self.current_session = None
        
        return summary

    def start_activity(self, 
                      activity_type: ActivityType,
                      description: str,
                      project: str = None,
                      tags: List[str] = None,
                      metadata: Dict[str, Any] = None) -> str:
        """Start a new activity within the current session"""
        if not self.current_session:
            self.logger.warning("No active session. Starting a new session.")
            self.start_session(project=project or "General")
        
        # End previous activity if exists
        if self.current_activity:
            self.end_activity()
        
        activity_id = f"act_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.current_activity = Activity(
            activity_id=activity_id,
            type=activity_type,
            description=description,
            start_time=datetime.datetime.now(),
            end_time=None,
            duration=None,
            project=project or self.current_session.project,
            tags=tags or [],
            metadata=metadata or {}
        )
        
        self.logger.info(f"[ACTIVITY START] {activity_type.value}: {description}")
        self._log_activity(f"Activity started: {activity_type.value} - {description}")
        
        return activity_id

    def end_activity(self, notes: str = "") -> Dict[str, Any]:
        """End the current activity"""
        if not self.current_activity:
            self.logger.warning("No active activity to end")
            return {}
        
        self.current_activity.end_time = datetime.datetime.now()
        duration = (self.current_activity.end_time - self.current_activity.start_time).total_seconds()
        self.current_activity.duration = duration
        
        if notes:
            self.current_activity.metadata["notes"] = notes
        
        # Add to session
        if self.current_session:
            self.current_session.activities.append(asdict(self.current_activity))
        
        self.logger.info(f"[ACTIVITY END] {self.current_activity.type.value}: {self.current_activity.description}")
        self.logger.info(f"   Duration: {self._format_duration(duration)}")
        
        # Save to database
        self._save_activity_to_db(self.current_activity)
        
        activity_summary = asdict(self.current_activity)
        self.current_activity = None
        
        return activity_summary

    def take_break(self, reason: str = "Break", duration_minutes: int = None) -> str:
        """Log a break in work"""
        if self.current_activity:
            self.end_activity()
        
        break_start = datetime.datetime.now()
        self.logger.info(f"[BREAK] {reason}")
        
        if self.current_session:
            break_info = {
                "start_time": break_start.isoformat(),
                "reason": reason,
                "planned_duration": duration_minutes
            }
            self.current_session.breaks.append(break_info)
        
        return f"Break started at {break_start.strftime('%H:%M:%S')}"

    def end_break(self) -> Dict[str, Any]:
        """End the current break"""
        if self.current_session and self.current_session.breaks:
            last_break = self.current_session.breaks[-1]
            if "end_time" not in last_break:
                end_time = datetime.datetime.now()
                last_break["end_time"] = end_time.isoformat()
                start_time = datetime.datetime.fromisoformat(last_break["start_time"])
                duration = (end_time - start_time).total_seconds()
                last_break["duration"] = duration
                
                self.logger.info(f"[BREAK END] Duration: {self._format_duration(duration)}")
                return last_break
        
        self.logger.warning("No active break to end")
        return {}

    def log_milestone(self, description: str, impact: str = "", project: str = None):
        """Log a significant achievement or milestone"""
        timestamp = datetime.datetime.now()
        self.logger.log(LogLevel.MILESTONE.value, f"[MILESTONE] {description}")
        
        if self.current_session:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO milestones (session_id, timestamp, description, project, impact)
                VALUES (?, ?, ?, ?, ?)
            ''', (self.current_session.session_id, timestamp, description, 
                  project or self.current_session.project, impact))
            conn.commit()
            conn.close()

    def get_daily_summary(self, date: datetime.date = None) -> Dict[str, Any]:
        """Get summary of work done on a specific day"""
        target_date = date or datetime.date.today()
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get all sessions for the day
        cursor.execute('''
            SELECT * FROM sessions 
            WHERE DATE(start_time) = DATE(?)
        ''', (target_date,))
        
        sessions = cursor.fetchall()
        
        # Get all activities for the day
        cursor.execute('''
            SELECT * FROM activities 
            WHERE DATE(start_time) = DATE(?)
        ''', (target_date,))
        
        activities = cursor.fetchall()
        
        conn.close()
        
        # Calculate statistics
        total_work_time = sum(s[3] or 0 for s in sessions if s[3])
        activity_breakdown = self._calculate_activity_breakdown(activities)
        
        return {
            "date": target_date.isoformat(),
            "total_sessions": len(sessions),
            "total_work_time": self._format_duration(total_work_time),
            "total_activities": len(activities),
            "activity_breakdown": activity_breakdown,
            "sessions": [self._session_tuple_to_dict(s) for s in sessions]
        }

    def get_weekly_summary(self, week_start: datetime.date = None) -> Dict[str, Any]:
        """Get summary of work done in a week"""
        if not week_start:
            today = datetime.date.today()
            week_start = today - datetime.timedelta(days=today.weekday())
        
        week_end = week_start + datetime.timedelta(days=6)
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get all sessions for the week
        cursor.execute('''
            SELECT * FROM sessions 
            WHERE DATE(start_time) BETWEEN DATE(?) AND DATE(?)
        ''', (week_start, week_end))
        
        sessions = cursor.fetchall()
        
        # Get all activities for the week
        cursor.execute('''
            SELECT * FROM activities 
            WHERE DATE(start_time) BETWEEN DATE(?) AND DATE(?)
        ''', (week_start, week_end))
        
        activities = cursor.fetchall()
        
        conn.close()
        
        # Calculate statistics
        total_work_time = sum(s[3] or 0 for s in sessions if s[3])
        daily_breakdown = self._calculate_daily_breakdown(sessions)
        activity_breakdown = self._calculate_activity_breakdown(activities)
        
        return {
            "week_start": week_start.isoformat(),
            "week_end": week_end.isoformat(),
            "total_sessions": len(sessions),
            "total_work_time": self._format_duration(total_work_time),
            "average_daily_time": self._format_duration(total_work_time / 7),
            "total_activities": len(activities),
            "daily_breakdown": daily_breakdown,
            "activity_breakdown": activity_breakdown
        }

    def export_logs(self, 
                   start_date: datetime.date,
                   end_date: datetime.date,
                   format: str = "json",
                   output_file: str = None) -> str:
        """Export logs for a date range"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Get all data for the date range
        cursor.execute('''
            SELECT * FROM sessions 
            WHERE DATE(start_time) BETWEEN DATE(?) AND DATE(?)
            ORDER BY start_time
        ''', (start_date, end_date))
        
        sessions = cursor.fetchall()
        
        cursor.execute('''
            SELECT * FROM activities 
            WHERE DATE(start_time) BETWEEN DATE(?) AND DATE(?)
            ORDER BY start_time
        ''', (start_date, end_date))
        
        activities = cursor.fetchall()
        
        conn.close()
        
        # Prepare export data
        export_data = {
            "export_date": datetime.datetime.now().isoformat(),
            "date_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "sessions": [self._session_tuple_to_dict(s) for s in sessions],
            "activities": [self._activity_tuple_to_dict(a) for a in activities],
            "summary": {
                "total_sessions": len(sessions),
                "total_activities": len(activities),
                "total_work_time": self._format_duration(
                    sum(s[3] or 0 for s in sessions if s[3])
                )
            }
        }
        
        # Export based on format
        if format == "json":
            output = json.dumps(export_data, indent=2, default=str)
        elif format == "csv":
            output = self._export_to_csv(export_data)
        elif format == "markdown":
            output = self._export_to_markdown(export_data)
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        # Save to file if specified
        if output_file:
            output_path = Path(output_file)
            output_path.write_text(output)
            self.logger.info(f"Logs exported to {output_file}")
            return str(output_path)
        
        return output

    def _save_session_to_db(self, session: WorkSession):
        """Save session to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO sessions 
            (session_id, start_time, end_time, total_duration, project, notes, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.session_id,
            session.start_time,
            session.end_time,
            session.total_duration,
            session.project,
            session.notes,
            json.dumps(session.tags)
        ))
        
        conn.commit()
        conn.close()

    def _save_activity_to_db(self, activity: Activity):
        """Save activity to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        session_id = self.current_session.session_id if self.current_session else None
        
        cursor.execute('''
            INSERT OR REPLACE INTO activities 
            (activity_id, session_id, type, description, start_time, end_time, 
             duration, project, tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            activity.activity_id,
            session_id,
            activity.type.value,
            activity.description,
            activity.start_time,
            activity.end_time,
            activity.duration,
            activity.project,
            json.dumps(activity.tags),
            json.dumps(activity.metadata)
        ))
        
        conn.commit()
        conn.close()

    def _generate_session_summary(self, session: WorkSession) -> Dict[str, Any]:
        """Generate a summary of a work session"""
        total_activity_time = sum(a.get("duration", 0) for a in session.activities)
        total_break_time = sum(b.get("duration", 0) for b in session.breaks)
        
        activity_types = {}
        for activity in session.activities:
            act_type = activity.get("type")
            if act_type:
                # Convert ActivityType enum to string if needed
                if isinstance(act_type, ActivityType):
                    act_type = act_type.value
                if act_type not in activity_types:
                    activity_types[act_type] = 0
                activity_types[act_type] += activity.get("duration", 0)
        
        return {
            "session_id": session.session_id,
            "start_time": session.start_time.isoformat(),
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "total_duration": self._format_duration(session.total_duration or 0),
            "active_time": self._format_duration(total_activity_time),
            "break_time": self._format_duration(total_break_time),
            "num_activities": len(session.activities),
            "num_breaks": len(session.breaks),
            "activity_breakdown": {
                k: self._format_duration(v) for k, v in activity_types.items()
            },
            "project": session.project,
            "tags": session.tags,
            "notes": session.notes
        }

    def _calculate_activity_breakdown(self, activities: List[tuple]) -> Dict[str, Any]:
        """Calculate breakdown of activities by type"""
        breakdown = {}
        for activity in activities:
            act_type = activity[2]  # type column
            duration = activity[6] or 0  # duration column
            
            if act_type not in breakdown:
                breakdown[act_type] = {
                    "count": 0,
                    "total_duration": 0
                }
            
            breakdown[act_type]["count"] += 1
            breakdown[act_type]["total_duration"] += duration
        
        # Format durations
        for act_type in breakdown:
            breakdown[act_type]["total_duration"] = self._format_duration(
                breakdown[act_type]["total_duration"]
            )
        
        return breakdown

    def _calculate_daily_breakdown(self, sessions: List[tuple]) -> Dict[str, Any]:
        """Calculate breakdown of work by day"""
        breakdown = {}
        for session in sessions:
            start_time = datetime.datetime.fromisoformat(session[1])
            day = start_time.date().isoformat()
            duration = session[3] or 0
            
            if day not in breakdown:
                breakdown[day] = {
                    "sessions": 0,
                    "total_duration": 0
                }
            
            breakdown[day]["sessions"] += 1
            breakdown[day]["total_duration"] += duration
        
        # Format durations
        for day in breakdown:
            breakdown[day]["total_duration"] = self._format_duration(
                breakdown[day]["total_duration"]
            )
        
        return breakdown

    def _session_tuple_to_dict(self, session_tuple: tuple) -> Dict[str, Any]:
        """Convert session tuple from database to dictionary"""
        return {
            "session_id": session_tuple[0],
            "start_time": session_tuple[1],
            "end_time": session_tuple[2],
            "total_duration": self._format_duration(session_tuple[3] or 0),
            "project": session_tuple[4],
            "notes": session_tuple[5],
            "tags": json.loads(session_tuple[6]) if session_tuple[6] else []
        }

    def _activity_tuple_to_dict(self, activity_tuple: tuple) -> Dict[str, Any]:
        """Convert activity tuple from database to dictionary"""
        return {
            "activity_id": activity_tuple[0],
            "session_id": activity_tuple[1],
            "type": activity_tuple[2],
            "description": activity_tuple[3],
            "start_time": activity_tuple[4],
            "end_time": activity_tuple[5],
            "duration": self._format_duration(activity_tuple[6] or 0),
            "project": activity_tuple[7],
            "tags": json.loads(activity_tuple[8]) if activity_tuple[8] else [],
            "metadata": json.loads(activity_tuple[9]) if activity_tuple[9] else {}
        }

    def _export_to_csv(self, data: Dict[str, Any]) -> str:
        """Export data to CSV format"""
        import csv
        from io import StringIO
        
        output = StringIO()
        
        # Write sessions
        if data["sessions"]:
            writer = csv.DictWriter(output, fieldnames=data["sessions"][0].keys())
            writer.writeheader()
            writer.writerows(data["sessions"])
            output.write("\n\n")
        
        # Write activities
        if data["activities"]:
            writer = csv.DictWriter(output, fieldnames=data["activities"][0].keys())
            writer.writeheader()
            writer.writerows(data["activities"])
        
        return output.getvalue()

    def _export_to_markdown(self, data: Dict[str, Any]) -> str:
        """Export data to Markdown format"""
        lines = []
        lines.append(f"# Work Log Export")
        lines.append(f"\n**Date Range:** {data['date_range']['start']} to {data['date_range']['end']}")
        lines.append(f"\n**Export Date:** {data['export_date']}")
        
        lines.append(f"\n## Summary")
        for key, value in data["summary"].items():
            lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")
        
        lines.append(f"\n## Sessions")
        for session in data["sessions"]:
            lines.append(f"\n### {session['session_id']}")
            lines.append(f"- **Project:** {session['project']}")
            lines.append(f"- **Duration:** {session['total_duration']}")
            lines.append(f"- **Start:** {session['start_time']}")
            lines.append(f"- **End:** {session['end_time']}")
        
        return "\n".join(lines)

    def _format_duration(self, seconds: float) -> str:
        """Format duration in seconds to human-readable string"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def _log_activity(self, message: str):
        """Log an activity-level message"""
        self.logger.log(LogLevel.ACTIVITY.value, message)

    def cleanup(self):
        """Cleanup method called on exit"""
        if self.current_session:
            self.logger.info("Auto-saving session on exit...")
            self.end_session(notes="Session auto-ended on program exit")


# Convenience functions for quick logging
def quick_log(activity_type: str, description: str, project: str = "General"):
    """Quick function to log a single activity"""
    logger = RemoteWorkLogger()
    logger.start_session(project=project)
    logger.start_activity(
        ActivityType[activity_type.upper()] if activity_type.upper() in ActivityType.__members__ 
        else ActivityType.OTHER,
        description
    )
    return logger


def get_todays_summary():
    """Get today's work summary"""
    logger = RemoteWorkLogger()
    return logger.get_daily_summary()


def get_this_weeks_summary():
    """Get this week's work summary"""
    logger = RemoteWorkLogger()
    return logger.get_weekly_summary()


# Example usage and testing
if __name__ == "__main__":
    # Create logger instance
    logger = RemoteWorkLogger()
    
    print("Remote Work Logger initialized successfully!")
    print("\nExample usage:")
    print("-" * 50)
    
    # Start a work session
    session_id = logger.start_session(
        project="Python Development",
        notes="Working on logging utility",
        tags=["development", "utilities"]
    )
    print(f"Started session: {session_id}")
    
    # Log some activities
    logger.start_activity(
        ActivityType.CODING,
        "Creating utillogging.py module",
        tags=["python", "logging"]
    )
    time.sleep(2)  # Simulate work
    logger.end_activity(notes="Basic structure complete")
    
    # Take a break
    logger.take_break("Coffee break", duration_minutes=15)
    time.sleep(1)  # Simulate break
    logger.end_break()
    
    # Log a milestone
    logger.log_milestone(
        "Completed remote work logging utility",
        impact="Improved productivity tracking"
    )
    
    # Another activity
    logger.start_activity(
        ActivityType.TESTING,
        "Testing logging functionality"
    )
    time.sleep(1)
    logger.end_activity()
    
    # End session
    summary = logger.end_session(notes="Initial development complete")
    
    print("\nSession Summary:")
    print(json.dumps(summary, indent=2, default=str))
    
    # Get daily summary
    daily = logger.get_daily_summary()
    print("\nToday's Summary:")
    print(json.dumps(daily, indent=2, default=str))