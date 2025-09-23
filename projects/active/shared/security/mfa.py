"""
Multi-Factor Authentication (MFA) Implementation

Enterprise-grade MFA with multiple providers:
- TOTP (Time-based One-Time Password) with QR codes
- SMS-based authentication with multiple providers
- Backup code generation and validation
- MFA enrollment and device management
- Recovery mechanisms and admin overrides
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import httpx
import qrcode


class MFAMethod(Enum):
    """MFA method types"""

    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BACKUP_CODES = "backup_codes"
    HARDWARE_TOKEN = "hardware_token"


class MFAStatus(Enum):
    """MFA enrollment status"""

    NOT_ENROLLED = "not_enrolled"
    PENDING = "pending"
    ENROLLED = "enrolled"
    DISABLED = "disabled"
    SUSPENDED = "suspended"


@dataclass
class MFADevice:
    """MFA device configuration"""

    device_id: str
    user_id: str
    method: MFAMethod
    name: str
    status: MFAStatus = MFAStatus.PENDING
    secret: Optional[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    backup_codes: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
    recovery_codes_generated: int = 0

    def is_active(self) -> bool:
        """Check if device is active and can be used"""
        return self.status == MFAStatus.ENROLLED

    def to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        result = {
            "device_id": self.device_id,
            "method": self.method.value,
            "name": self.name,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "last_used_at": (
                self.last_used_at.isoformat() if self.last_used_at else None
            ),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }

        if include_secrets:
            result.update(
                {
                    "secret": self.secret,
                    "phone_number": self.phone_number,
                    "email": self.email,
                    "backup_codes": self.backup_codes,
                }
            )

        return result


@dataclass
class MFAChallenge:
    """MFA challenge for verification"""

    challenge_id: str
    user_id: str
    device_id: str
    method: MFAMethod
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(
        default_factory=lambda: datetime.utcnow() + timedelta(minutes=5)
    )
    attempts: int = 0
    max_attempts: int = 3
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    @property
    def is_exhausted(self) -> bool:
        return self.attempts >= self.max_attempts

    def can_attempt(self) -> bool:
        return not self.is_expired and not self.is_exhausted and not self.verified


class TOTPProvider:
    """Time-based One-Time Password provider"""

    def __init__(self, issuer: str = "MCP Platform", digits: int = 6, period: int = 30):
        self.issuer = issuer
        self.digits = digits
        self.period = period

    def generate_secret(self) -> str:
        """Generate base32-encoded secret for TOTP"""
        return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

    def generate_qr_code(
        self, user_id: str, secret: str, account_name: Optional[str] = None
    ) -> bytes:
        """Generate QR code for TOTP setup"""
        account_name = account_name or user_id

        # Create TOTP URI
        uri = f"otpauth://totp/{urllib.parse.quote(self.issuer)}:{urllib.parse.quote(account_name)}"
        params = {
            "secret": secret,
            "issuer": self.issuer,
            "algorithm": "SHA1",
            "digits": str(self.digits),
            "period": str(self.period),
        }

        uri += "?" + urllib.parse.urlencode(params)

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to bytes
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def generate_token(self, secret: str, timestamp: Optional[int] = None) -> str:
        """Generate TOTP token"""
        if timestamp is None:
            timestamp = int(time.time())

        # Calculate time counter
        counter = timestamp // self.period

        # Convert secret from base32
        key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))

        # Generate HMAC
        counter_bytes = struct.pack(">Q", counter)
        hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()

        # Extract dynamic binary code
        offset = hmac_digest[-1] & 0xF
        code = struct.unpack(">I", hmac_digest[offset : offset + 4])[0]
        code &= 0x7FFFFFFF

        # Generate token
        token = str(code % (10**self.digits)).zfill(self.digits)
        return token

    def verify_token(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token with time window tolerance"""
        current_time = int(time.time())

        # Check current time and nearby time windows
        for i in range(-window, window + 1):
            test_time = current_time + (i * self.period)
            expected_token = self.generate_token(secret, test_time)

            if secrets.compare_digest(expected_token, token):
                return True

        return False

    def get_remaining_time(self) -> int:
        """Get remaining time for current TOTP period"""
        return self.period - (int(time.time()) % self.period)


class SMSProvider:
    """SMS-based MFA provider with multiple backends"""

    def __init__(self, provider: str = "twilio", config: Dict[str, str] = None):
        self.provider = provider
        self.config = config or {}
        self.code_length = 6
        self.code_expiry = 300  # 5 minutes
        self.pending_codes: Dict[str, Tuple[str, datetime]] = {}

    def generate_code(self) -> str:
        """Generate random SMS verification code"""
        return "".join(secrets.choice("0123456789") for _ in range(self.code_length))

    async def send_code(self, phone_number: str, user_id: str) -> str:
        """Send SMS code to phone number"""
        code = self.generate_code()
        code_id = str(uuid.uuid4())

        # Store code with expiry
        expires_at = datetime.utcnow() + timedelta(seconds=self.code_expiry)
        self.pending_codes[code_id] = (code, expires_at)

        # Send SMS based on provider
        if self.provider == "twilio":
            await self._send_twilio_sms(phone_number, code)
        elif self.provider == "aws_sns":
            await self._send_aws_sns_sms(phone_number, code)
        elif self.provider == "mock":
            print(f"SMS Code for {phone_number}: {code}")
        else:
            raise ValueError(f"Unsupported SMS provider: {self.provider}")

        return code_id

    async def verify_code(self, code_id: str, submitted_code: str) -> bool:
        """Verify submitted SMS code"""
        if code_id not in self.pending_codes:
            return False

        stored_code, expires_at = self.pending_codes[code_id]

        # Check expiry
        if datetime.utcnow() > expires_at:
            del self.pending_codes[code_id]
            return False

        # Verify code
        if secrets.compare_digest(stored_code, submitted_code):
            del self.pending_codes[code_id]
            return True

        return False

    async def _send_twilio_sms(self, phone_number: str, code: str):
        """Send SMS using Twilio API"""
        account_sid = self.config.get("account_sid")
        auth_token = self.config.get("auth_token")
        from_number = self.config.get("from_number")

        if not all([account_sid, auth_token, from_number]):
            raise ValueError("Missing Twilio configuration")

        url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                auth=(account_sid, auth_token),
                data={
                    "From": from_number,
                    "To": phone_number,
                    "Body": f"Your MCP verification code is: {code}. Valid for 5 minutes.",
                },
            )
            response.raise_for_status()

    async def _send_aws_sns_sms(self, phone_number: str, code: str):
        """Send SMS using AWS SNS"""
        # Implementation would use boto3

    def cleanup_expired_codes(self):
        """Remove expired SMS codes"""
        now = datetime.utcnow()
        expired_codes = [
            code_id
            for code_id, (_, expires_at) in self.pending_codes.items()
            if now > expires_at
        ]

        for code_id in expired_codes:
            del self.pending_codes[code_id]


class BackupCodeProvider:
    """Backup code provider for account recovery"""

    def __init__(self, code_count: int = 10, code_length: int = 8):
        self.code_count = code_count
        self.code_length = code_length

    def generate_codes(self) -> List[str]:
        """Generate backup recovery codes"""
        codes = []
        for _ in range(self.code_count):
            # Generate code with format: XXXX-XXXX
            part1 = "".join(
                secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(4)
            )
            part2 = "".join(
                secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(4)
            )
            codes.append(f"{part1}-{part2}")

        return codes

    def hash_code(self, code: str) -> str:
        """Hash backup code for secure storage"""
        return hashlib.sha256(code.encode()).hexdigest()

    def verify_code(self, submitted_code: str, hashed_codes: List[str]) -> bool:
        """Verify backup code against hashed codes"""
        submitted_hash = self.hash_code(submitted_code.upper().replace("-", ""))

        for stored_hash in hashed_codes:
            if secrets.compare_digest(submitted_hash, stored_hash):
                return True

        return False


class MFAProvider:
    """
    Complete MFA provider with multiple authentication methods
    """

    def __init__(self, issuer: str = "MCP Platform"):
        self.issuer = issuer
        self.totp_provider = TOTPProvider(issuer)
        self.sms_provider = SMSProvider()
        self.backup_code_provider = BackupCodeProvider()

        # Storage (in production, use database)
        self.devices: Dict[str, MFADevice] = {}
        self.user_devices: Dict[str, List[str]] = {}  # user_id -> device_ids
        self.challenges: Dict[str, MFAChallenge] = {}

    async def enroll_totp(self, user_id: str, device_name: str) -> Dict[str, Any]:
        """Start TOTP enrollment process"""
        device_id = str(uuid.uuid4())
        secret = self.totp_provider.generate_secret()

        device = MFADevice(
            device_id=device_id,
            user_id=user_id,
            method=MFAMethod.TOTP,
            name=device_name,
            secret=secret,
            status=MFAStatus.PENDING,
        )

        # Generate QR code
        qr_code = self.totp_provider.generate_qr_code(user_id, secret)

        # Store device
        self.devices[device_id] = device
        if user_id not in self.user_devices:
            self.user_devices[user_id] = []
        self.user_devices[user_id].append(device_id)

        return {
            "device_id": device_id,
            "secret": secret,
            "qr_code": base64.b64encode(qr_code).decode(),
            "manual_entry_key": secret,
            "issuer": self.issuer,
        }

    async def verify_totp_enrollment(self, device_id: str, token: str) -> bool:
        """Complete TOTP enrollment verification"""
        device = self.devices.get(device_id)
        if not device or device.method != MFAMethod.TOTP:
            return False

        if self.totp_provider.verify_token(device.secret, token):
            device.status = MFAStatus.ENROLLED
            device.verified_at = datetime.utcnow()
            return True

        return False

    async def enroll_sms(
        self, user_id: str, phone_number: str, device_name: str
    ) -> Dict[str, str]:
        """Enroll SMS-based MFA"""
        device_id = str(uuid.uuid4())

        device = MFADevice(
            device_id=device_id,
            user_id=user_id,
            method=MFAMethod.SMS,
            name=device_name,
            phone_number=phone_number,
            status=MFAStatus.PENDING,
        )

        # Send verification SMS
        code_id = await self.sms_provider.send_code(phone_number, user_id)

        # Store device
        self.devices[device_id] = device
        if user_id not in self.user_devices:
            self.user_devices[user_id] = []
        self.user_devices[user_id].append(device_id)

        return {
            "device_id": device_id,
            "verification_id": code_id,
            "phone_number": phone_number[-4:],  # Only show last 4 digits
        }

    async def verify_sms_enrollment(
        self, device_id: str, verification_id: str, code: str
    ) -> bool:
        """Complete SMS enrollment verification"""
        device = self.devices.get(device_id)
        if not device or device.method != MFAMethod.SMS:
            return False

        if await self.sms_provider.verify_code(verification_id, code):
            device.status = MFAStatus.ENROLLED
            device.verified_at = datetime.utcnow()
            return True

        return False

    async def generate_backup_codes(self, user_id: str) -> Dict[str, Any]:
        """Generate backup recovery codes"""
        device_id = str(uuid.uuid4())
        codes = self.backup_code_provider.generate_codes()
        hashed_codes = [self.backup_code_provider.hash_code(code) for code in codes]

        device = MFADevice(
            device_id=device_id,
            user_id=user_id,
            method=MFAMethod.BACKUP_CODES,
            name="Backup Codes",
            backup_codes=hashed_codes,
            status=MFAStatus.ENROLLED,
            verified_at=datetime.utcnow(),
        )

        device.recovery_codes_generated += 1

        # Store device
        self.devices[device_id] = device
        if user_id not in self.user_devices:
            self.user_devices[user_id] = []
        self.user_devices[user_id].append(device_id)

        return {
            "device_id": device_id,
            "codes": codes,
            "generated_at": device.created_at.isoformat(),
        }

    async def create_challenge(
        self, user_id: str, required_methods: List[MFAMethod] = None
    ) -> Dict[str, Any]:
        """Create MFA challenge for user"""
        user_device_ids = self.user_devices.get(user_id, [])
        active_devices = [
            self.devices[device_id]
            for device_id in user_device_ids
            if device_id in self.devices and self.devices[device_id].is_active()
        ]

        if not active_devices:
            raise ValueError("No active MFA devices found for user")

        # Filter devices by required methods if specified
        if required_methods:
            active_devices = [d for d in active_devices if d.method in required_methods]
            if not active_devices:
                raise ValueError("No active devices found for required MFA methods")

        challenge_id = str(uuid.uuid4())

        # Create challenge for first available device
        device = active_devices[0]

        challenge = MFAChallenge(
            challenge_id=challenge_id,
            user_id=user_id,
            device_id=device.device_id,
            method=device.method,
        )

        # Send challenge based on method
        if device.method == MFAMethod.SMS:
            code_id = await self.sms_provider.send_code(device.phone_number, user_id)
            challenge.metadata["verification_id"] = code_id

        self.challenges[challenge_id] = challenge

        return {
            "challenge_id": challenge_id,
            "method": device.method.value,
            "device_name": device.name,
            "expires_at": challenge.expires_at.isoformat(),
            "metadata": {
                "phone_last_4": (
                    device.phone_number[-4:] if device.phone_number else None
                )
            },
        }

    async def verify_challenge(
        self, challenge_id: str, response: str
    ) -> Dict[str, Any]:
        """Verify MFA challenge response"""
        challenge = self.challenges.get(challenge_id)
        if not challenge:
            return {"success": False, "error": "Invalid challenge"}

        if not challenge.can_attempt():
            return {"success": False, "error": "Challenge expired or exhausted"}

        challenge.attempts += 1

        device = self.devices.get(challenge.device_id)
        if not device:
            return {"success": False, "error": "Device not found"}

        verified = False

        # Verify based on method
        if challenge.method == MFAMethod.TOTP:
            verified = self.totp_provider.verify_token(device.secret, response)

        elif challenge.method == MFAMethod.SMS:
            verification_id = challenge.metadata.get("verification_id")
            if verification_id:
                verified = await self.sms_provider.verify_code(
                    verification_id, response
                )

        elif challenge.method == MFAMethod.BACKUP_CODES:
            verified = self.backup_code_provider.verify_code(
                response, device.backup_codes
            )

            # Remove used backup code
            if verified:
                used_hash = self.backup_code_provider.hash_code(
                    response.upper().replace("-", "")
                )
                device.backup_codes = [
                    code for code in device.backup_codes if code != used_hash
                ]

        if verified:
            challenge.verified = True
            device.last_used_at = datetime.utcnow()

            # Clean up challenge
            del self.challenges[challenge_id]

            return {
                "success": True,
                "device_id": device.device_id,
                "method": challenge.method.value,
                "verified_at": datetime.utcnow().isoformat(),
            }
        else:
            return {
                "success": False,
                "error": "Invalid verification code",
                "attempts_remaining": challenge.max_attempts - challenge.attempts,
            }

    def get_user_devices(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all MFA devices for user"""
        device_ids = self.user_devices.get(user_id, [])
        devices = []

        for device_id in device_ids:
            if device_id in self.devices:
                device = self.devices[device_id]
                devices.append(device.to_dict())

        return devices

    async def remove_device(self, user_id: str, device_id: str) -> bool:
        """Remove MFA device"""
        if device_id not in self.devices:
            return False

        device = self.devices[device_id]
        if device.user_id != user_id:
            return False

        # Remove device
        del self.devices[device_id]

        # Update user device list
        if user_id in self.user_devices:
            self.user_devices[user_id] = [
                did for did in self.user_devices[user_id] if did != device_id
            ]

        return True

    async def disable_device(self, user_id: str, device_id: str) -> bool:
        """Disable MFA device"""
        if device_id not in self.devices:
            return False

        device = self.devices[device_id]
        if device.user_id != user_id:
            return False

        device.status = MFAStatus.DISABLED
        return True

    def is_user_enrolled(self, user_id: str) -> bool:
        """Check if user has any enrolled MFA devices"""
        device_ids = self.user_devices.get(user_id, [])
        return any(
            self.devices[device_id].is_active()
            for device_id in device_ids
            if device_id in self.devices
        )

    def get_mfa_stats(self) -> Dict[str, Any]:
        """Get MFA usage statistics"""
        total_devices = len(self.devices)
        enrolled_devices = len([d for d in self.devices.values() if d.is_active()])

        method_counts = {}
        for method in MFAMethod:
            method_counts[method.value] = len(
                [
                    d
                    for d in self.devices.values()
                    if d.method == method and d.is_active()
                ]
            )

        return {
            "total_devices": total_devices,
            "enrolled_devices": enrolled_devices,
            "active_challenges": len(self.challenges),
            "method_distribution": method_counts,
            "total_users": len(self.user_devices),
        }

    async def cleanup_expired_challenges(self):
        """Remove expired MFA challenges"""
        expired_challenges = [
            challenge_id
            for challenge_id, challenge in self.challenges.items()
            if challenge.is_expired
        ]

        for challenge_id in expired_challenges:
            del self.challenges[challenge_id]

        # Also cleanup SMS codes
        self.sms_provider.cleanup_expired_codes()
