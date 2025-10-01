"""
Enhanced JWT Security Implementation
Provides secure JWT token handling with RSA keys, proper validation, and security best practices
"""

import jwt
import time
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"
    RESET = "reset"

class SecurityLevel(Enum):
    BASIC = "basic"
    ENHANCED = "enhanced"
    STRICT = "strict"

class JWTSecurityManager:
    """
    Enhanced JWT Security Manager with RSA encryption and comprehensive validation
    """
    
    def __init__(
        self,
        private_key_path: str,
        public_key_path: str,
        algorithm: str = "RS256",
        access_token_expire_minutes: int = 15,
        refresh_token_expire_days: int = 7,
        security_level: SecurityLevel = SecurityLevel.ENHANCED
    ):
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days
        self.security_level = security_level
        
        # Load RSA keys
        self.private_key = self._load_private_key(private_key_path)
        self.public_key = self._load_public_key(public_key_path)
        
        # Token blacklist (in production, use Redis)
        self.blacklisted_tokens: set = set()
        
        # Rate limiting storage (in production, use Redis)
        self.failed_attempts: Dict[str, List[float]] = {}
        
        logger.info(f"JWT Security Manager initialized with {security_level.value} security level")

    def _load_private_key(self, key_path: str):
        """Load RSA private key from file"""
        try:
            with open(key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            return private_key
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise

    def _load_public_key(self, key_path: str):
        """Load RSA public key from file"""
        try:
            with open(key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            return public_key
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            raise

    def create_access_token(
        self,
        subject: str,
        user_id: str,
        roles: List[str],
        permissions: List[str],
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a secure access token with comprehensive claims
        """
        now = datetime.now(timezone.utc)
        expire = now + timedelta(minutes=self.access_token_expire_minutes)
        
        # Generate unique token ID
        jti = secrets.token_urlsafe(32)
        
        # Base claims
        claims = {
            "sub": subject,
            "user_id": user_id,
            "roles": roles,
            "permissions": permissions,
            "token_type": TokenType.ACCESS.value,
            "iat": now,
            "exp": expire,
            "nbf": now,  # Not before
            "jti": jti,  # JWT ID for revocation
            "iss": "catalytic-computing-api",  # Issuer
            "aud": ["catalytic-api", "saas-api"],  # Audience
        }
        
        # Add security metadata based on level
        if self.security_level in [SecurityLevel.ENHANCED, SecurityLevel.STRICT]:
            claims.update({
                "security_level": self.security_level.value,
                "token_version": "2.0",
                "created_at": now.isoformat(),
            })
        
        # Add additional claims if provided
        if additional_claims:
            claims.update(additional_claims)
        
        try:
            token = jwt.encode(claims, self.private_key, algorithm=self.algorithm)
            logger.info(f"Access token created for user {user_id} with JTI {jti}")
            return token
        except Exception as e:
            logger.error(f"Failed to create access token: {e}")
            raise

    def create_refresh_token(self, user_id: str, fingerprint: str) -> str:
        """
        Create a secure refresh token
        """
        now = datetime.now(timezone.utc)
        expire = now + timedelta(days=self.refresh_token_expire_days)
        
        # Generate unique token ID and hash the fingerprint
        jti = secrets.token_urlsafe(32)
        fingerprint_hash = hashlib.sha256(fingerprint.encode()).hexdigest()
        
        claims = {
            "user_id": user_id,
            "token_type": TokenType.REFRESH.value,
            "fingerprint": fingerprint_hash,
            "iat": now,
            "exp": expire,
            "nbf": now,
            "jti": jti,
            "iss": "catalytic-computing-api",
            "aud": ["catalytic-api"],
        }
        
        try:
            token = jwt.encode(claims, self.private_key, algorithm=self.algorithm)
            logger.info(f"Refresh token created for user {user_id} with JTI {jti}")
            return token
        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}")
            raise

    def create_api_key_token(
        self,
        user_id: str,
        api_key_name: str,
        scopes: List[str],
        expire_days: Optional[int] = None
    ) -> str:
        """
        Create a long-lived API key token
        """
        now = datetime.now(timezone.utc)
        
        # API keys can be long-lived or never expire
        if expire_days:
            expire = now + timedelta(days=expire_days)
        else:
            expire = now + timedelta(days=365 * 10)  # 10 years if no expiry
        
        jti = secrets.token_urlsafe(32)
        
        claims = {
            "user_id": user_id,
            "api_key_name": api_key_name,
            "scopes": scopes,
            "token_type": TokenType.API_KEY.value,
            "iat": now,
            "exp": expire,
            "nbf": now,
            "jti": jti,
            "iss": "catalytic-computing-api",
            "aud": ["catalytic-api", "saas-api"],
        }
        
        try:
            token = jwt.encode(claims, self.private_key, algorithm=self.algorithm)
            logger.info(f"API key token created for user {user_id}: {api_key_name}")
            return token
        except Exception as e:
            logger.error(f"Failed to create API key token: {e}")
            raise

    def verify_token(self, token: str, expected_type: TokenType = None) -> Dict[str, Any]:
        """
        Verify and decode JWT token with comprehensive validation
        """
        try:
            # Check if token is blacklisted
            if token in self.blacklisted_tokens:
                raise jwt.InvalidTokenError("Token has been revoked")
            
            # Decode and verify token
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require_exp": True,
                    "require_iat": True,
                    "require_nbf": True,
                }
            )
            
            # Validate token type if specified
            if expected_type and payload.get("token_type") != expected_type.value:
                raise jwt.InvalidTokenError(f"Expected {expected_type.value} token")
            
            # Additional security checks for enhanced/strict modes
            if self.security_level in [SecurityLevel.ENHANCED, SecurityLevel.STRICT]:
                self._perform_enhanced_validation(payload)
            
            logger.debug(f"Token verified successfully for user {payload.get('user_id')}")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            raise
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            raise jwt.InvalidTokenError("Token verification failed")

    def _perform_enhanced_validation(self, payload: Dict[str, Any]) -> None:
        """
        Perform additional validation for enhanced security levels
        """
        # Validate required claims
        required_claims = ["jti", "iss", "aud"]
        for claim in required_claims:
            if claim not in payload:
                raise jwt.InvalidTokenError(f"Missing required claim: {claim}")
        
        # Validate issuer
        if payload["iss"] != "catalytic-computing-api":
            raise jwt.InvalidTokenError("Invalid issuer")
        
        # Validate audience
        expected_audiences = ["catalytic-api", "saas-api"]
        if not any(aud in payload.get("aud", []) for aud in expected_audiences):
            raise jwt.InvalidTokenError("Invalid audience")
        
        # Check token age (additional security for strict mode)
        if self.security_level == SecurityLevel.STRICT:
            iat = payload.get("iat")
            if iat:
                token_age = datetime.now(timezone.utc) - datetime.fromtimestamp(iat, tz=timezone.utc)
                max_age = timedelta(hours=24)  # Maximum token age
                if token_age > max_age:
                    raise jwt.InvalidTokenError("Token is too old")

    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token by adding it to blacklist
        """
        try:
            # Decode token to get JTI
            payload = jwt.decode(token, self.public_key, algorithms=[self.algorithm], options={"verify_exp": False})
            jti = payload.get("jti")
            
            if jti:
                self.blacklisted_tokens.add(token)
                logger.info(f"Token revoked with JTI: {jti}")
                return True
            else:
                logger.warning("Token does not contain JTI, cannot revoke properly")
                return False
                
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False

    def refresh_access_token(
        self,
        refresh_token: str,
        fingerprint: str,
        user_roles: List[str],
        user_permissions: List[str]
    ) -> Optional[str]:
        """
        Create new access token from refresh token
        """
        try:
            # Verify refresh token
            payload = self.verify_token(refresh_token, TokenType.REFRESH)
            
            # Verify fingerprint
            fingerprint_hash = hashlib.sha256(fingerprint.encode()).hexdigest()
            if payload.get("fingerprint") != fingerprint_hash:
                raise jwt.InvalidTokenError("Invalid fingerprint")
            
            # Create new access token
            user_id = payload["user_id"]
            return self.create_access_token(
                subject=user_id,
                user_id=user_id,
                roles=user_roles,
                permissions=user_permissions
            )
            
        except Exception as e:
            logger.error(f"Failed to refresh access token: {e}")
            return None

    def check_rate_limit(self, identifier: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
        """
        Check if identifier is within rate limits
        """
        now = time.time()
        window_start = now - (window_minutes * 60)
        
        # Clean old attempts
        if identifier in self.failed_attempts:
            self.failed_attempts[identifier] = [
                timestamp for timestamp in self.failed_attempts[identifier]
                if timestamp > window_start
            ]
        
        # Check current attempts
        attempts = len(self.failed_attempts.get(identifier, []))
        
        if attempts >= max_attempts:
            logger.warning(f"Rate limit exceeded for {identifier}: {attempts} attempts")
            return False
        
        return True

    def record_failed_attempt(self, identifier: str) -> None:
        """
        Record a failed authentication attempt
        """
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        self.failed_attempts[identifier].append(time.time())
        logger.warning(f"Failed attempt recorded for {identifier}")

    def generate_key_pair(self, key_size: int = 2048) -> tuple:
        """
        Generate RSA key pair for JWT signing
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem

# Example usage and testing
if __name__ == "__main__":
    # This would typically be run during setup to generate keys
    jwt_manager = JWTSecurityManager(
        private_key_path="./security/secrets/jwt_private_key.pem",
        public_key_path="./security/secrets/jwt_public_key.pem",
        security_level=SecurityLevel.ENHANCED
    )
    
    # Example token creation
    access_token = jwt_manager.create_access_token(
        subject="user123",
        user_id="user123",
        roles=["user", "premium"],
        permissions=["read", "write", "api_access"],
        additional_claims={"plan": "premium", "region": "us-east-1"}
    )
    
    print(f"Generated access token: {access_token[:50]}...")
    
    # Verify token
    try:
        payload = jwt_manager.verify_token(access_token, TokenType.ACCESS)
        print(f"Token verified for user: {payload['user_id']}")
    except Exception as e:
        print(f"Token verification failed: {e}")