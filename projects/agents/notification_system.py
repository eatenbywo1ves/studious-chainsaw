#!/usr/bin/env python3
"""
Notification System
Handles alerts, notifications, and report distribution
"""

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NotificationLevel:
    """Notification severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationSystem:
    """
    Notification system for alerts and reports
    Supports multiple channels: file, email, webhook
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path) if config_path else self._default_config()
        
        # Notification storage
        self.notifications_dir = Path(self.config.get('notifications_dir', 'C:/Users/Corbin/notifications'))
        self.notifications_dir.mkdir(parents=True, exist_ok=True)
        
        # Email configuration
        self.email_enabled = self.config.get('email_enabled', False)
        self.smtp_server = self.config.get('smtp_server')
        self.smtp_port = self.config.get('smtp_port', 587)
        self.smtp_username = self.config.get('smtp_username')
        self.smtp_password = self.config.get('smtp_password')
        self.from_email = self.config.get('from_email')
        self.to_emails = self.config.get('to_emails', [])
        
        # Notification history
        self.notification_history: List[Dict[str, Any]] = []
        self.max_history = 1000
        
        logger.info("Notification System initialized")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f).get('notification', {})
        except Exception as e:
            logger.warning(f"Could not load notification config: {e}")
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Default notification configuration"""
        return {
            'notifications_dir': 'C:/Users/Corbin/notifications',
            'email_enabled': False,
            'file_notifications_enabled': True,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'smtp_username': '',
            'smtp_password': '',
            'from_email': '',
            'to_emails': []
        }
    
    async def send_notification(self, 
                               title: str, 
                               message: str, 
                               level: str = NotificationLevel.INFO,
                               data: Optional[Dict[str, Any]] = None):
        """Send a notification through all enabled channels"""
        
        notification = {
            'timestamp': datetime.now().isoformat(),
            'title': title,
            'message': message,
            'level': level,
            'data': data or {}
        }
        
        # Add to history
        self.notification_history.append(notification)
        if len(self.notification_history) > self.max_history:
            self.notification_history = self.notification_history[-self.max_history:]
        
        logger.info(f"Sending notification [{level}]: {title}")
        
        # Send through enabled channels
        tasks = []
        
        if self.config.get('file_notifications_enabled', True):
            tasks.append(self._save_notification_to_file(notification))
        
        if self.email_enabled and self.to_emails:
            tasks.append(self._send_email_notification(notification))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _save_notification_to_file(self, notification: Dict[str, Any]):
        """Save notification to file"""
        try:
            filename = f"notification-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}.json"
            filepath = self.notifications_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(notification, f, indent=2)
            
            logger.debug(f"Notification saved to file: {filepath}")
            
        except Exception as e:
            logger.error(f"Error saving notification to file: {e}")
    
    async def _send_email_notification(self, notification: Dict[str, Any]):
        """Send notification via email"""
        if not self.smtp_server or not self.from_email or not self.to_emails:
            logger.warning("Email configuration incomplete, skipping email notification")
            return
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{notification['level'].upper()}] {notification['title']}"
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            
            # Plain text version
            text_body = f"""
{notification['title']}

{notification['message']}

Level: {notification['level']}
Time: {notification['timestamp']}

---
Agentic Project Management System
"""
            
            # HTML version
            html_body = f"""
<html>
<body>
<h2>{notification['title']}</h2>
<p>{notification['message'].replace(chr(10), '<br>')}</p>
<hr>
<p><strong>Level:</strong> {notification['level']}<br>
<strong>Time:</strong> {notification['timestamp']}</p>
<hr>
<p><em>Agentic Project Management System</em></p>
</body>
</html>
"""
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email notification sent to {len(self.to_emails)} recipient(s)")
            
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
    
    async def send_daily_briefing(self, briefing_report: str, filepath: str):
        """Send daily briefing notification"""
        await self.send_notification(
            title=f"Daily Briefing - {datetime.now().strftime('%Y-%m-%d')}",
            message=f"Daily briefing report has been generated.\n\nLocation: {filepath}\n\nSummary:\n{briefing_report[:500]}...",
            level=NotificationLevel.INFO,
            data={'filepath': filepath, 'type': 'daily_briefing'}
        )
    
    async def send_anomaly_alert(self, anomaly_type: str, description: str, severity: str):
        """Send anomaly alert"""
        level_map = {
            'low': NotificationLevel.INFO,
            'medium': NotificationLevel.WARNING,
            'high': NotificationLevel.ERROR,
            'critical': NotificationLevel.CRITICAL
        }
        
        await self.send_notification(
            title=f"Anomaly Detected: {anomaly_type}",
            message=description,
            level=level_map.get(severity, NotificationLevel.WARNING),
            data={'anomaly_type': anomaly_type, 'severity': severity}
        )
    
    async def send_agent_status_alert(self, agent_name: str, status: str, message: str):
        """Send agent status alert"""
        level = NotificationLevel.ERROR if status == 'error' else NotificationLevel.WARNING
        
        await self.send_notification(
            title=f"Agent Status: {agent_name}",
            message=f"Agent {agent_name} status changed to {status}.\n\n{message}",
            level=level,
            data={'agent': agent_name, 'status': status}
        )
    
    async def send_blocker_alert(self, project: str, blocker: str):
        """Send blocker detection alert"""
        await self.send_notification(
            title=f"Blocker Detected: {project}",
            message=f"A blocker has been detected in {project}:\n\n{blocker}",
            level=NotificationLevel.WARNING,
            data={'project': project, 'blocker': blocker}
        )
    
    def get_recent_notifications(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent notifications"""
        return self.notification_history[-count:]
    
    def get_notifications_by_level(self, level: str) -> List[Dict[str, Any]]:
        """Get notifications by level"""
        return [n for n in self.notification_history if n['level'] == level]
    
    async def test_notification(self):
        """Send a test notification"""
        await self.send_notification(
            title="Test Notification",
            message="This is a test notification from the Agentic Project Management System.",
            level=NotificationLevel.INFO,
            data={'test': True}
        )


async def main():
    """Test the notification system"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Notification System')
    parser.add_argument('--config', help='Config file path')
    parser.add_argument('--test', action='store_true', help='Send test notification')
    parser.add_argument('--email', help='Test email address')
    
    args = parser.parse_args()
    
    notifier = NotificationSystem(args.config)
    
    if args.test:
        print("Sending test notification...")
        
        # Override email for testing
        if args.email:
            notifier.email_enabled = True
            notifier.to_emails = [args.email]
            notifier.from_email = args.email
        
        await notifier.test_notification()
        
        print(f"\n✓ Test notification sent")
        print(f"  File saved to: {notifier.notifications_dir}")
        
        if notifier.email_enabled:
            print(f"  Email sent to: {', '.join(notifier.to_emails)}")
    
    else:
        print("Notification System")
        print(f"  Notifications directory: {notifier.notifications_dir}")
        print(f"  Email enabled: {notifier.email_enabled}")
        print(f"  Recent notifications: {len(notifier.notification_history)}")
        print("\nUse --test to send a test notification")


if __name__ == "__main__":
    asyncio.run(main())
