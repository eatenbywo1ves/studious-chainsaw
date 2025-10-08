#!/usr/bin/env python3
"""
Email Service Setup and Testing Script
Tests SendGrid, AWS SES, and SMTP email delivery
"""

import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment
load_dotenv()


def test_sendgrid():
    """Test SendGrid email service"""
    print("\n" + "="*70)
    print("TESTING SENDGRID")
    print("="*70 + "\n")

    api_key = os.getenv("SENDGRID_API_KEY")

    if not api_key or api_key == "SG.YOUR_API_KEY_HERE":
        print("[SKIP] SendGrid API key not configured")
        print("\nTo configure SendGrid:")
        print("1. Create account: https://signup.sendgrid.com/")
        print("2. Create API key: https://app.sendgrid.com/settings/api_keys")
        print("3. Add to .env:")
        print("   SENDGRID_API_KEY=SG.your_api_key_here")
        print("   EMAIL_FROM=noreply@yourdomain.com")
        print("   EMAIL_FROM_NAME=Your Company")
        return False

    try:
        from sendgrid import SendGridAPIClient
        from sendgrid.helpers.mail import Mail

        email_from = os.getenv("EMAIL_FROM", "noreply@catalyticcomputing.com")
        email_from_name = os.getenv("EMAIL_FROM_NAME", "Catalytic Computing")

        # Get test recipient
        test_email = input("Enter test email address (or press Enter to skip): ").strip()
        if not test_email:
            print("[SKIP] No test email provided")
            return False

        print(f"\nSending test email to: {test_email}")

        message = Mail(
            from_email=(email_from, email_from_name),
            to_emails=test_email,
            subject=f'Catalytic Computing SaaS - Email Test ({datetime.now().strftime("%Y-%m-%d %H:%M:%S")})',
            html_content=f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2563eb;">Email Service Test</h2>
                    <p>This is a test email from the Catalytic Computing SaaS platform.</p>

                    <div style="background-color: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <h3 style="margin-top: 0;">Test Details:</h3>
                        <ul>
                            <li><strong>Provider:</strong> SendGrid</li>
                            <li><strong>Timestamp:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</li>
                            <li><strong>From:</strong> {email_from}</li>
                            <li><strong>Environment:</strong> {os.getenv('APP_ENV', 'development')}</li>
                        </ul>
                    </div>

                    <p>If you received this email, the SendGrid integration is working correctly!</p>

                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #e5e7eb;">
                    <p style="color: #6b7280; font-size: 12px;">
                        This is an automated test email from Catalytic Computing SaaS.
                    </p>
                </div>
            </body>
            </html>
            """
        )

        sg = SendGridAPIClient(api_key)
        response = sg.send(message)

        if response.status_code in [200, 202]:
            print("[OK] Email sent successfully via SendGrid")
            print(f"  Status Code: {response.status_code}")
            print(f"  Message ID: {response.headers.get('X-Message-Id', 'N/A')}")
            return True
        else:
            print(f"[ERROR] SendGrid returned status {response.status_code}")
            return False

    except ImportError:
        print("[ERROR] sendgrid package not installed")
        print("Run: pip install sendgrid")
        return False
    except Exception as e:
        print(f"[ERROR] SendGrid test failed: {str(e)}")
        return False


def test_aws_ses():
    """Test AWS SES email service"""
    print("\n" + "="*70)
    print("TESTING AWS SES")
    print("="*70 + "\n")

    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region = os.getenv("AWS_REGION", "us-east-1")

    if not access_key or not secret_key:
        print("[SKIP] AWS credentials not configured")
        print("\nTo configure AWS SES:")
        print("1. Create AWS account or use existing")
        print("2. Create IAM user with SES permissions")
        print("3. Get access key and secret key")
        print("4. Verify email address in SES console")
        print("5. Add to .env:")
        print("   AWS_ACCESS_KEY_ID=your_access_key")
        print("   AWS_SECRET_ACCESS_KEY=your_secret_key")
        print("   AWS_REGION=us-east-1")
        print("   EMAIL_FROM=verified@yourdomain.com")
        return False

    try:
        import boto3
        from botocore.exceptions import ClientError

        email_from = os.getenv("EMAIL_FROM", "noreply@catalyticcomputing.com")

        # Get test recipient
        test_email = input("Enter test email address (or press Enter to skip): ").strip()
        if not test_email:
            print("[SKIP] No test email provided")
            return False

        print(f"\nSending test email to: {test_email}")

        ses_client = boto3.client(
            'ses',
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )

        response = ses_client.send_email(
            Source=email_from,
            Destination={'ToAddresses': [test_email]},
            Message={
                'Subject': {
                    'Data': f'Catalytic Computing SaaS - Email Test ({datetime.now().strftime("%Y-%m-%d %H:%M:%S")})',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': f"""
                        <html>
                        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                                <h2 style="color: #2563eb;">Email Service Test</h2>
                                <p>This is a test email from the Catalytic Computing SaaS platform.</p>

                                <div style="background-color: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                                    <h3 style="margin-top: 0;">Test Details:</h3>
                                    <ul>
                                        <li><strong>Provider:</strong> AWS SES</li>
                                        <li><strong>Region:</strong> {region}</li>
                                        <li><strong>Timestamp:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</li>
                                        <li><strong>From:</strong> {email_from}</li>
                                    </ul>
                                </div>

                                <p>If you received this email, the AWS SES integration is working correctly!</p>
                            </div>
                        </body>
                        </html>
                        """,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )

        print("[OK] Email sent successfully via AWS SES")
        print(f"  Message ID: {response['MessageId']}")
        return True

    except ImportError:
        print("[ERROR] boto3 package not installed")
        print("Run: pip install boto3")
        return False
    except ClientError as e:
        print(f"[ERROR] AWS SES test failed: {e.response['Error']['Message']}")
        return False
    except Exception as e:
        print(f"[ERROR] AWS SES test failed: {str(e)}")
        return False


def test_smtp():
    """Test SMTP email service"""
    print("\n" + "="*70)
    print("TESTING SMTP")
    print("="*70 + "\n")

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = os.getenv("SMTP_PORT", "587")
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")

    if not smtp_host or not smtp_username or not smtp_password:
        print("[SKIP] SMTP credentials not configured")
        print("\nTo configure SMTP (e.g., Gmail):")
        print("1. Enable 2-factor authentication on Gmail")
        print("2. Generate app password: https://myaccount.google.com/apppasswords")
        print("3. Add to .env:")
        print("   SMTP_HOST=smtp.gmail.com")
        print("   SMTP_PORT=587")
        print("   SMTP_USERNAME=your-email@gmail.com")
        print("   SMTP_PASSWORD=your-app-password")
        print("   EMAIL_FROM=your-email@gmail.com")
        return False

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        email_from = os.getenv("EMAIL_FROM", smtp_username)

        # Get test recipient
        test_email = input("Enter test email address (or press Enter to skip): ").strip()
        if not test_email:
            print("[SKIP] No test email provided")
            return False

        print(f"\nSending test email to: {test_email}")

        msg = MIMEMultipart('alternative')
        msg['Subject'] = f'Catalytic Computing SaaS - Email Test ({datetime.now().strftime("%Y-%m-%d %H:%M:%S")})'
        msg['From'] = email_from
        msg['To'] = test_email

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2563eb;">Email Service Test</h2>
                <p>This is a test email from the Catalytic Computing SaaS platform.</p>

                <div style="background-color: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <h3 style="margin-top: 0;">Test Details:</h3>
                    <ul>
                        <li><strong>Provider:</strong> SMTP ({smtp_host})</li>
                        <li><strong>Port:</strong> {smtp_port}</li>
                        <li><strong>Timestamp:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</li>
                        <li><strong>From:</strong> {email_from}</li>
                    </ul>
                </div>

                <p>If you received this email, the SMTP integration is working correctly!</p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(msg)

        print("[OK] Email sent successfully via SMTP")
        print(f"  Host: {smtp_host}:{smtp_port}")
        return True

    except Exception as e:
        print(f"[ERROR] SMTP test failed: {str(e)}")
        return False


def show_email_config():
    """Display current email configuration"""
    print("\n" + "="*70)
    print("CURRENT EMAIL CONFIGURATION")
    print("="*70 + "\n")

    configs = {
        "SendGrid": {
            "API Key": os.getenv("SENDGRID_API_KEY", "NOT SET"),
            "From Email": os.getenv("EMAIL_FROM", "NOT SET"),
            "From Name": os.getenv("EMAIL_FROM_NAME", "NOT SET")
        },
        "AWS SES": {
            "Access Key ID": os.getenv("AWS_ACCESS_KEY_ID", "NOT SET"),
            "Secret Key": "***" if os.getenv("AWS_SECRET_ACCESS_KEY") else "NOT SET",
            "Region": os.getenv("AWS_REGION", "NOT SET")
        },
        "SMTP": {
            "Host": os.getenv("SMTP_HOST", "NOT SET"),
            "Port": os.getenv("SMTP_PORT", "NOT SET"),
            "Username": os.getenv("SMTP_USERNAME", "NOT SET"),
            "Password": "***" if os.getenv("SMTP_PASSWORD") else "NOT SET"
        }
    }

    for provider, settings in configs.items():
        print(f"{provider}:")
        for key, value in settings.items():
            status = "[CONFIGURED]" if value not in ["NOT SET", "SG.YOUR_API_KEY_HERE"] else "[NOT SET]"
            display_value = value[:20] + "..." if len(value) > 20 and value != "NOT SET" else value
            print(f"  {key:.<30} {display_value:.<30} {status}")
        print()


def main():
    """Main testing function"""
    print("\n" + "="*70)
    print("CATALYTIC COMPUTING SAAS - EMAIL SERVICE SETUP")
    print("="*70)

    # Show current configuration
    show_email_config()

    # Test available providers
    print("\n" + "="*70)
    print("TESTING EMAIL PROVIDERS")
    print("="*70)

    results = {}
    results['sendgrid'] = test_sendgrid()
    results['aws_ses'] = test_aws_ses()
    results['smtp'] = test_smtp()

    # Summary
    print("\n" + "="*70)
    print("EMAIL SERVICE TEST SUMMARY")
    print("="*70 + "\n")

    for provider, success in results.items():
        status = "[OK] Working" if success else "[SKIP] Not configured or failed"
        print(f"{provider.upper():.<30} {status}")

    if any(results.values()):
        print("\n[OK] At least one email provider is configured and working!")
    else:
        print("\n[WARN] No email providers configured. Email notifications will not work.")

    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    main()
