"""
Production Email Service with Automatic Failover
Supports SendGrid, AWS SES, and SMTP fallback
"""

import os
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class EmailService:
    """
    Multi-provider email service with automatic failover
    Priority: SendGrid > AWS SES > SMTP
    """

    def __init__(self):
        self.from_email = os.getenv("EMAIL_FROM", "noreply@catalyticcomputing.com")
        self.from_name = os.getenv("EMAIL_FROM_NAME", "Catalytic Computing")

        # Track provider availability
        self.sendgrid_available = self._check_sendgrid()
        self.aws_ses_available = self._check_aws_ses()
        self.smtp_available = self._check_smtp()

        logger.info(f"Email service initialized: SendGrid={self.sendgrid_available}, "
                   f"AWS SES={self.aws_ses_available}, SMTP={self.smtp_available}")

    def _check_sendgrid(self) -> bool:
        """Check if SendGrid is configured"""
        api_key = os.getenv("SENDGRID_API_KEY")
        return bool(api_key and api_key != "SG.YOUR_API_KEY_HERE")

    def _check_aws_ses(self) -> bool:
        """Check if AWS SES is configured"""
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        return bool(access_key and secret_key)

    def _check_smtp(self) -> bool:
        """Check if SMTP is configured"""
        host = os.getenv("SMTP_HOST")
        username = os.getenv("SMTP_USERNAME")
        password = os.getenv("SMTP_PASSWORD")
        return bool(host and username and password)

    def send_email(
        self,
        to_emails: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> bool:
        """
        Send email using first available provider with automatic failover

        Args:
            to_emails: List of recipient email addresses
            subject: Email subject line
            html_content: HTML email body
            text_content: Plain text fallback (optional)

        Returns:
            bool: True if email sent successfully, False otherwise
        """
        # Try SendGrid first
        if self.sendgrid_available:
            try:
                if self._send_via_sendgrid(to_emails, subject, html_content, text_content):
                    logger.info(f"Email sent successfully via SendGrid to {to_emails}")
                    return True
            except Exception as e:
                logger.warning(f"SendGrid failed: {e}, falling back to next provider")

        # Try AWS SES
        if self.aws_ses_available:
            try:
                if self._send_via_aws_ses(to_emails, subject, html_content, text_content):
                    logger.info(f"Email sent successfully via AWS SES to {to_emails}")
                    return True
            except Exception as e:
                logger.warning(f"AWS SES failed: {e}, falling back to SMTP")

        # Final fallback: SMTP
        if self.smtp_available:
            try:
                if self._send_via_smtp(to_emails, subject, html_content, text_content):
                    logger.info(f"Email sent successfully via SMTP to {to_emails}")
                    return True
            except Exception as e:
                logger.error(f"SMTP failed: {e}, all email providers exhausted")

        logger.error(f"Failed to send email to {to_emails}: No providers available")
        return False

    def _send_via_sendgrid(
        self,
        to_emails: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str]
    ) -> bool:
        """Send email via SendGrid"""
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail

            api_key = os.getenv("SENDGRID_API_KEY")

            message = Mail(
                from_email=(self.from_email, self.from_name),
                to_emails=to_emails,
                subject=subject,
                html_content=html_content
            )

            if text_content:
                message.plain_text_content = text_content

            sg = SendGridAPIClient(api_key)
            response = sg.send(message)

            return response.status_code in [200, 202]

        except ImportError:
            logger.error("SendGrid package not installed: pip install sendgrid")
            self.sendgrid_available = False
            raise

    def _send_via_aws_ses(
        self,
        to_emails: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str]
    ) -> bool:
        """Send email via AWS SES"""
        try:
            import boto3
            from botocore.exceptions import ClientError

            access_key = os.getenv("AWS_ACCESS_KEY_ID")
            secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
            region = os.getenv("AWS_REGION", "us-east-1")

            ses_client = boto3.client(
                'ses',
                region_name=region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )

            body_config = {
                'Html': {
                    'Data': html_content,
                    'Charset': 'UTF-8'
                }
            }

            if text_content:
                body_config['Text'] = {
                    'Data': text_content,
                    'Charset': 'UTF-8'
                }

            response = ses_client.send_email(
                Source=self.from_email,
                Destination={'ToAddresses': to_emails},
                Message={
                    'Subject': {
                        'Data': subject,
                        'Charset': 'UTF-8'
                    },
                    'Body': body_config
                }
            )

            return 'MessageId' in response

        except ImportError:
            logger.error("Boto3 package not installed: pip install boto3")
            self.aws_ses_available = False
            raise
        except ClientError as e:
            logger.error(f"AWS SES error: {e.response['Error']['Message']}")
            raise

    def _send_via_smtp(
        self,
        to_emails: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str]
    ) -> bool:
        """Send email via SMTP (Gmail, etc.)"""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        smtp_host = os.getenv("SMTP_HOST")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_username = os.getenv("SMTP_USERNAME")
        smtp_password = os.getenv("SMTP_PASSWORD")

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{self.from_name} <{self.from_email}>"
        msg['To'] = ", ".join(to_emails)

        if text_content:
            msg.attach(MIMEText(text_content, 'plain'))
        msg.attach(MIMEText(html_content, 'html'))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)

        return True

    def send_welcome_email(self, to_email: str, user_name: str) -> bool:
        """Send welcome email to new user"""
        subject = "Welcome to Catalytic Computing!"

        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2563eb;">Welcome {user_name}!</h2>
                <p>Thank you for joining Catalytic Computing SaaS platform.</p>

                <p>Your account has been successfully created and you can now:</p>
                <ul>
                    <li>Create and manage lattice computations</li>
                    <li>Access our powerful GPU-accelerated algorithms</li>
                    <li>Track your usage and billing</li>
                    <li>Generate API keys for programmatic access</li>
                </ul>

                <p>Get started by logging in to your dashboard.</p>

                <hr style="margin: 30px 0; border: none; border-top: 1px solid #e5e7eb;">
                <p style="color: #6b7280; font-size: 12px;">
                    This is an automated message from Catalytic Computing SaaS.
                </p>
            </div>
        </body>
        </html>
        """

        return self.send_email([to_email], subject, html_content)

    def send_password_reset_email(self, to_email: str, reset_token: str, reset_url: str) -> bool:
        """Send password reset email"""
        subject = "Password Reset Request"

        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2563eb;">Password Reset Request</h2>
                <p>We received a request to reset your password.</p>

                <p>Click the button below to reset your password:</p>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_url}?token={reset_token}"
                       style="background-color: #2563eb; color: white; padding: 12px 24px;
                              text-decoration: none; border-radius: 5px; display: inline-block;">
                        Reset Password
                    </a>
                </div>

                <p style="color: #6b7280; font-size: 14px;">
                    This link will expire in 1 hour. If you didn't request this, please ignore this email.
                </p>

                <hr style="margin: 30px 0; border: none; border-top: 1px solid #e5e7eb;">
                <p style="color: #6b7280; font-size: 12px;">
                    This is an automated message from Catalytic Computing SaaS.
                </p>
            </div>
        </body>
        </html>
        """

        return self.send_email([to_email], subject, html_content)


# Global instance
_email_service = None


def get_email_service() -> EmailService:
    """Get singleton email service instance"""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
