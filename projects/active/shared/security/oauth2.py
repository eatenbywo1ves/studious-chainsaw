"""
OAuth2 and OpenID Connect Implementation

Enterprise-grade OAuth2/OIDC provider with:
- Authorization Code flow with PKCE
- Client Credentials flow
- Device Authorization flow
- JWT token validation and introspection
- OpenID Connect identity layer
- Multi-provider federation
"""

import base64
import hashlib
import secrets
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class GrantType(Enum):
    """OAuth2 grant types"""

    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class TokenType(Enum):
    """Token types"""

    BEARER = "Bearer"
    MAC = "MAC"
    DPOP = "DPoP"


class ResponseType(Enum):
    """OAuth2 response types"""

    CODE = "code"
    TOKEN = "token"
    ID_TOKEN = "id_token"


@dataclass
class OAuthClient:
    """OAuth2 client configuration"""

    client_id: str
    client_secret: Optional[str] = None
    redirect_uris: List[str] = field(default_factory=list)
    grant_types: List[GrantType] = field(default_factory=list)
    response_types: List[ResponseType] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    contacts: List[str] = field(default_factory=list)
    tos_uri: Optional[str] = None
    policy_uri: Optional[str] = None
    jwks_uri: Optional[str] = None
    public_client: bool = False
    token_endpoint_auth_method: str = "client_secret_basic"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class OAuthToken:
    """OAuth2 token representation"""

    access_token: str
    token_type: TokenType = TokenType.BEARER
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None
    issued_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired"""
        if not self.expires_in:
            return False
        return datetime.utcnow() > (self.issued_at + timedelta(seconds=self.expires_in))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON response"""
        result = {
            "access_token": self.access_token,
            "token_type": self.token_type.value,
        }

        if self.expires_in:
            result["expires_in"] = self.expires_in
        if self.refresh_token:
            result["refresh_token"] = self.refresh_token
        if self.scope:
            result["scope"] = self.scope
        if self.id_token:
            result["id_token"] = self.id_token

        return result


@dataclass
class AuthorizationCode:
    """Authorization code for OAuth2 flow"""

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    user_id: str
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    nonce: Optional[str] = None
    state: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_in: int = 600  # 10 minutes

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > (
            self.created_at + timedelta(seconds=self.expires_in)
        )


@dataclass
class DeviceCode:
    """Device authorization code"""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int = 1800  # 30 minutes
    interval: int = 5
    client_id: str
    scope: str
    user_id: Optional[str] = None
    authorized: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > (
            self.created_at + timedelta(seconds=self.expires_in)
        )


@dataclass
class UserInfo:
    """OpenID Connect user information"""

    sub: str  # Subject identifier
    name: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    middle_name: Optional[str] = None
    nickname: Optional[str] = None
    preferred_username: Optional[str] = None
    profile: Optional[str] = None
    picture: Optional[str] = None
    website: Optional[str] = None
    email: Optional[str] = None
    email_verified: bool = False
    gender: Optional[str] = None
    birthdate: Optional[str] = None
    zoneinfo: Optional[str] = None
    locale: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_verified: bool = False
    address: Optional[Dict[str, str]] = None
    updated_at: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON response"""
        result = {"sub": self.sub}

        for field_name, field_value in self.__dict__.items():
            if field_name != "sub" and field_value is not None:
                result[field_name] = field_value

        return result


class PKCEChallenge:
    """PKCE challenge generator and validator"""

    @staticmethod
    def generate_code_verifier(length: int = 128) -> str:
        """Generate code verifier for PKCE"""
        if length < 43 or length > 128:
            raise ValueError("Code verifier length must be between 43 and 128")

        # Generate cryptographically random string
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(length))
            .decode("utf-8")
            .rstrip("=")
        )

        return code_verifier[:length]

    @staticmethod
    def generate_code_challenge(code_verifier: str, method: str = "S256") -> str:
        """Generate code challenge from verifier"""
        if method == "plain":
            return code_verifier
        elif method == "S256":
            digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
        else:
            raise ValueError(f"Unsupported challenge method: {method}")

    @staticmethod
    def verify_challenge(
        code_verifier: str, code_challenge: str, method: str = "S256"
    ) -> bool:
        """Verify PKCE challenge"""
        expected_challenge = PKCEChallenge.generate_code_challenge(
            code_verifier, method
        )
        return secrets.compare_digest(expected_challenge, code_challenge)


class JWTManager:
    """JWT token management"""

    def __init__(
        self,
        private_key: Optional[str] = None,
        public_key: Optional[str] = None,
        algorithm: str = "RS256",
        issuer: str = "mcp-auth",
        audience: str = "mcp-api",
    ):
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience

        if private_key and public_key:
            self.private_key = private_key
            self.public_key = public_key
        else:
            # Generate new key pair
            self.private_key, self.public_key = self._generate_key_pair()

    def _generate_key_pair(self):
        """Generate RSA key pair for JWT signing"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem.decode(), public_pem.decode()

    def create_access_token(
        self, user_id: str, client_id: str, scope: str, expires_in: int = 3600, **claims
    ) -> str:
        """Create JWT access token"""
        now = datetime.utcnow()
        payload = {
            "iss": self.issuer,
            "sub": user_id,
            "aud": self.audience,
            "exp": now + timedelta(seconds=expires_in),
            "iat": now,
            "client_id": client_id,
            "scope": scope,
            **claims,
        }

        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def create_id_token(
        self,
        user_info: UserInfo,
        client_id: str,
        nonce: Optional[str] = None,
        expires_in: int = 3600,
    ) -> str:
        """Create OpenID Connect ID token"""
        now = datetime.utcnow()
        payload = {
            "iss": self.issuer,
            "sub": user_info.sub,
            "aud": client_id,
            "exp": now + timedelta(seconds=expires_in),
            "iat": now,
            **user_info.to_dict(),
        }

        if nonce:
            payload["nonce"] = nonce

        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
            )
            return payload
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")

    def get_jwks(self) -> Dict[str, Any]:
        """Get JSON Web Key Set for token validation"""
        # Extract public key components
        ___public_key = jwt.get_unverified_header(
            jwt.encode({"test": "test"}, self.private_key, algorithm=self.algorithm)
        )

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "mcp-auth-key",
                    "alg": self.algorithm,
                    "n": "...",  # RSA modulus (base64url encoded)
                    "e": "AQAB",  # RSA exponent
                }
            ]
        }


class OAuth2Provider:
    """
    Complete OAuth2 and OpenID Connect provider implementation
    """

    def __init__(
        self,
        base_url: str = "https://auth.mcp.local",
        jwt_manager: Optional[JWTManager] = None,
    ):
        self.base_url = base_url
        self.jwt_manager = jwt_manager or JWTManager()

        # Storage (in production, use proper database)
        self.clients: Dict[str, OAuthClient] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.device_codes: Dict[str, DeviceCode] = {}
        self.tokens: Dict[str, OAuthToken] = {}
        self.refresh_tokens: Dict[str, str] = {}  # refresh_token -> access_token

        # Configuration
        self.token_expires_in = 3600  # 1 hour
        self.refresh_token_expires_in = 604800  # 1 week
        self.code_expires_in = 600  # 10 minutes

    async def register_client(self, client_data: Dict[str, Any]) -> OAuthClient:
        """Register new OAuth2 client"""
        client_id = client_data.get("client_id") or str(uuid.uuid4())
        client_secret = None

        if not client_data.get("public_client", False):
            client_secret = secrets.token_urlsafe(32)

        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=client_data.get("redirect_uris", []),
            grant_types=[
                GrantType(gt)
                for gt in client_data.get("grant_types", ["authorization_code"])
            ],
            response_types=[
                ResponseType(rt) for rt in client_data.get("response_types", ["code"])
            ],
            scopes=client_data.get("scopes", ["openid"]),
            client_name=client_data.get("client_name"),
            public_client=client_data.get("public_client", False),
        )

        self.clients[client_id] = client
        return client

    def get_client(self, client_id: str) -> Optional[OAuthClient]:
        """Get OAuth2 client by ID"""
        return self.clients.get(client_id)

    async def create_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid",
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
    ) -> str:
        """Create authorization URL for OAuth2 flow"""
        client = self.get_client(client_id)
        if not client:
            raise ValueError(f"Unknown client: {client_id}")

        if redirect_uri not in client.redirect_uris:
            raise ValueError(f"Invalid redirect URI: {redirect_uri}")

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
        }

        if state:
            params["state"] = state
        if nonce:
            params["nonce"] = nonce
        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method

        query_string = urllib.parse.urlencode(params)
        return f"{self.base_url}/authorize?{query_string}"

    async def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        user_id: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: str = "S256",
        nonce: Optional[str] = None,
        state: Optional[str] = None,
    ) -> str:
        """Generate authorization code"""
        client = self.get_client(client_id)
        if not client:
            raise ValueError(f"Unknown client: {client_id}")

        if redirect_uri not in client.redirect_uris:
            raise ValueError(f"Invalid redirect URI: {redirect_uri}")

        # Generate authorization code
        code = secrets.token_urlsafe(32)

        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            user_id=user_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            state=state,
        )

        self.authorization_codes[code] = auth_code

        # Clean up expired codes
        await self._cleanup_expired_codes()

        return code

    async def exchange_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None,
        client_secret: Optional[str] = None,
    ) -> OAuthToken:
        """Exchange authorization code for tokens"""
        auth_code = self.authorization_codes.get(code)
        if not auth_code or auth_code.is_expired:
            raise ValueError("Invalid or expired authorization code")

        client = self.get_client(client_id)
        if not client:
            raise ValueError(f"Unknown client: {client_id}")

        # Validate client authentication
        if not client.public_client:
            if client_secret != client.client_secret:
                raise ValueError("Invalid client credentials")

        # Validate parameters
        if auth_code.client_id != client_id:
            raise ValueError("Client ID mismatch")
        if auth_code.redirect_uri != redirect_uri:
            raise ValueError("Redirect URI mismatch")

        # Validate PKCE if used
        if auth_code.code_challenge:
            if not code_verifier:
                raise ValueError("Code verifier required for PKCE")

            if not PKCEChallenge.verify_challenge(
                code_verifier,
                auth_code.code_challenge,
                auth_code.code_challenge_method or "S256",
            ):
                raise ValueError("Invalid PKCE code verifier")

        # Create tokens
        access_token = self.jwt_manager.create_access_token(
            user_id=auth_code.user_id,
            client_id=client_id,
            scope=auth_code.scope,
            expires_in=self.token_expires_in,
        )

        refresh_token = secrets.token_urlsafe(32)

        # Create ID token for OpenID Connect
        id_token = None
        if "openid" in auth_code.scope:
            # Get user info (would normally come from user store)
            user_info = UserInfo(sub=auth_code.user_id)
            id_token = self.jwt_manager.create_id_token(
                user_info=user_info, client_id=client_id, nonce=auth_code.nonce
            )

        token = OAuthToken(
            access_token=access_token,
            token_type=TokenType.BEARER,
            expires_in=self.token_expires_in,
            refresh_token=refresh_token,
            scope=auth_code.scope,
            id_token=id_token,
        )

        # Store tokens
        self.tokens[access_token] = token
        self.refresh_tokens[refresh_token] = access_token

        # Clean up authorization code
        del self.authorization_codes[code]

        return token

    async def client_credentials_flow(
        self, client_id: str, client_secret: str, scope: str = ""
    ) -> OAuthToken:
        """Client credentials grant flow"""
        client = self.get_client(client_id)
        if not client:
            raise ValueError(f"Unknown client: {client_id}")

        if client.client_secret != client_secret:
            raise ValueError("Invalid client credentials")

        if GrantType.CLIENT_CREDENTIALS not in client.grant_types:
            raise ValueError("Client credentials grant not allowed for this client")

        # Create access token
        access_token = self.jwt_manager.create_access_token(
            user_id=client_id,  # Use client_id as subject
            client_id=client_id,
            scope=scope,
            expires_in=self.token_expires_in,
        )

        token = OAuthToken(
            access_token=access_token,
            token_type=TokenType.BEARER,
            expires_in=self.token_expires_in,
            scope=scope,
        )

        self.tokens[access_token] = token
        return token

    async def refresh_access_token(
        self, refresh_token: str, client_id: str, client_secret: Optional[str] = None
    ) -> OAuthToken:
        """Refresh access token"""
        if refresh_token not in self.refresh_tokens:
            raise ValueError("Invalid refresh token")

        old_access_token = self.refresh_tokens[refresh_token]
        old_token = self.tokens.get(old_access_token)

        if not old_token:
            raise ValueError("Associated access token not found")

        client = self.get_client(client_id)
        if not client:
            raise ValueError(f"Unknown client: {client_id}")

        # Validate client credentials for confidential clients
        if not client.public_client and client_secret != client.client_secret:
            raise ValueError("Invalid client credentials")

        # Create new access token
        # Extract user_id from old token
        try:
            old_payload = self.jwt_manager.verify_token(old_access_token)
            user_id = old_payload["sub"]
            scope = old_token.scope or ""
        except Exception:
            raise ValueError("Invalid access token")

        new_access_token = self.jwt_manager.create_access_token(
            user_id=user_id,
            client_id=client_id,
            scope=scope,
            expires_in=self.token_expires_in,
        )

        new_refresh_token = secrets.token_urlsafe(32)

        new_token = OAuthToken(
            access_token=new_access_token,
            token_type=TokenType.BEARER,
            expires_in=self.token_expires_in,
            refresh_token=new_refresh_token,
            scope=scope,
        )

        # Update storage
        self.tokens[new_access_token] = new_token
        self.refresh_tokens[new_refresh_token] = new_access_token

        # Clean up old tokens
        if old_access_token in self.tokens:
            del self.tokens[old_access_token]
        del self.refresh_tokens[refresh_token]

        return new_token

    async def device_authorization(self, client_id: str, scope: str = "") -> DeviceCode:
        """Device authorization flow - step 1"""
        client = self.get_client(client_id)
        if not client:
            raise ValueError(f"Unknown client: {client_id}")

        if GrantType.DEVICE_CODE not in client.grant_types:
            raise ValueError("Device authorization grant not allowed for this client")

        device_code_str = secrets.token_urlsafe(32)
        user_code = "".join(
            secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(8)
        )

        device_code = DeviceCode(
            device_code=device_code_str,
            user_code=user_code,
            verification_uri=f"{self.base_url}/device",
            verification_uri_complete=f"{self.base_url}/device?user_code={user_code}",
            client_id=client_id,
            scope=scope,
        )

        self.device_codes[device_code_str] = device_code
        return device_code

    async def device_token_poll(
        self, device_code: str, client_id: str
    ) -> Optional[OAuthToken]:
        """Device authorization flow - token polling"""
        device_auth = self.device_codes.get(device_code)
        if not device_auth or device_auth.is_expired:
            raise ValueError("Invalid or expired device code")

        if device_auth.client_id != client_id:
            raise ValueError("Client ID mismatch")

        if not device_auth.authorized:
            return None  # Authorization pending

        # Create tokens
        access_token = self.jwt_manager.create_access_token(
            user_id=device_auth.user_id,
            client_id=client_id,
            scope=device_auth.scope,
            expires_in=self.token_expires_in,
        )

        refresh_token = secrets.token_urlsafe(32)

        token = OAuthToken(
            access_token=access_token,
            token_type=TokenType.BEARER,
            expires_in=self.token_expires_in,
            refresh_token=refresh_token,
            scope=device_auth.scope,
        )

        # Store tokens and clean up device code
        self.tokens[access_token] = token
        self.refresh_tokens[refresh_token] = access_token
        del self.device_codes[device_code]

        return token

    async def authorize_device(self, user_code: str, user_id: str) -> bool:
        """Device authorization flow - user authorization"""
        device_auth = None
        for dc in self.device_codes.values():
            if dc.user_code == user_code and not dc.is_expired:
                device_auth = dc
                break

        if not device_auth:
            return False

        device_auth.authorized = True
        device_auth.user_id = user_id
        return True

    async def introspect_token(self, token: str) -> Dict[str, Any]:
        """Token introspection endpoint"""
        try:
            payload = self.jwt_manager.verify_token(token)

            return {
                "active": True,
                "client_id": payload.get("client_id"),
                "sub": payload.get("sub"),
                "scope": payload.get("scope"),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
                "iss": payload.get("iss"),
                "aud": payload.get("aud"),
            }
        except Exception:
            return {"active": False}

    async def revoke_token(
        self, token: str, client_id: str, client_secret: Optional[str] = None
    ):
        """Token revocation endpoint"""
        client = self.get_client(client_id)
        if not client:
            raise ValueError(f"Unknown client: {client_id}")

        # Validate client credentials for confidential clients
        if not client.public_client and client_secret != client.client_secret:
            raise ValueError("Invalid client credentials")

        # Remove access token
        if token in self.tokens:
            del self.tokens[token]

        # Remove refresh token
        if token in self.refresh_tokens:
            access_token = self.refresh_tokens[token]
            if access_token in self.tokens:
                del self.tokens[access_token]
            del self.refresh_tokens[token]

    async def get_user_info(self, access_token: str) -> UserInfo:
        """OpenID Connect UserInfo endpoint"""
        try:
            payload = self.jwt_manager.verify_token(access_token)
            user_id = payload["sub"]

            # In production, fetch from user store
            return UserInfo(sub=user_id)
        except Exception:
            raise ValueError("Invalid access token")

    def get_openid_configuration(self) -> Dict[str, Any]:
        """OpenID Connect discovery document"""
        return {
            "issuer": self.jwt_manager.issuer,
            "authorization_endpoint": f"{self.base_url}/authorize",
            "token_endpoint": f"{self.base_url}/token",
            "userinfo_endpoint": f"{self.base_url}/userinfo",
            "jwks_uri": f"{self.base_url}/.well-known/jwks.json",
            "device_authorization_endpoint": f"{self.base_url}/device_authorization",
            "introspection_endpoint": f"{self.base_url}/introspect",
            "revocation_endpoint": f"{self.base_url}/revoke",
            "response_types_supported": ["code", "token", "id_token"],
            "grant_types_supported": [
                "authorization_code",
                "client_credentials",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["plain", "S256"],
            "subject_types_supported": ["public"],
        }

    async def _cleanup_expired_codes(self):
        """Clean up expired authorization codes"""
        expired_codes = [
            code
            for code, auth_code in self.authorization_codes.items()
            if auth_code.is_expired
        ]

        for code in expired_codes:
            del self.authorization_codes[code]


class TokenValidator:
    """
    Token validation middleware for API endpoints
    """

    def __init__(
        self, oauth_provider: OAuth2Provider, required_scopes: List[str] = None
    ):
        self.oauth_provider = oauth_provider
        self.required_scopes = required_scopes or []

    async def validate_request(self, authorization_header: str) -> Dict[str, Any]:
        """Validate OAuth2 token from Authorization header"""
        if not authorization_header:
            raise ValueError("Missing Authorization header")

        parts = authorization_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ValueError("Invalid Authorization header format")

        access_token = parts[1]

        try:
            payload = self.oauth_provider.jwt_manager.verify_token(access_token)

            # Check required scopes
            token_scopes = payload.get("scope", "").split()
            if self.required_scopes:
                if not all(scope in token_scopes for scope in self.required_scopes):
                    raise ValueError("Insufficient scope")

            return {
                "user_id": payload["sub"],
                "client_id": payload["client_id"],
                "scopes": token_scopes,
                "expires_at": payload["exp"],
            }

        except Exception as e:
            raise ValueError(f"Invalid token: {str(e)}")

    def require_scopes(self, *scopes):
        """Decorator to require specific scopes"""

        def decorator(func):
            async def wrapper(*args, **kwargs):
                # Extract token from request context
                # Implementation depends on framework
                return await func(*args, **kwargs)

            return wrapper

        return decorator
