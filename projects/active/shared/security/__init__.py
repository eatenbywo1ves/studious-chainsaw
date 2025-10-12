"""
Advanced Security Framework for MCP Agent Architecture

Enterprise-grade security components including:
- OAuth2/OpenID Connect integration
- SAML 2.0 federation
- Multi-factor authentication (MFA)
- Role-based access control (RBAC)
- Zero-trust network architecture
- Advanced audit logging
- Certificate-based authentication
"""

# Import only available modules
try:
    from .audit import AuditLogger, AuditTrail, SecurityEvent
except (ImportError, Exception):
    AuditLogger = AuditTrail = SecurityEvent = None

try:
    from .certificates import CertificateManager, mTLSValidator
except (ImportError, Exception):
    CertificateManager = mTLSValidator = None

try:
    from .mfa import MFAProvider, SMSProvider, TOTPProvider
except (ImportError, Exception):
    MFAProvider = SMSProvider = TOTPProvider = None

try:
    from .oauth2 import OAuth2Provider, OAuthToken, TokenValidator
except (ImportError, Exception):
    OAuth2Provider = OAuthToken = TokenValidator = None

from .rbac import AccessPolicy, Permission, RBACManager, Role

try:
    from .saml import SAMLAssertion, SAMLProvider, SAMLResponse
except (ImportError, Exception):
    SAMLAssertion = SAMLProvider = SAMLResponse = None

try:
    from .zero_trust import TrustEvaluator, ZeroTrustGateway
except (ImportError, Exception):
    TrustEvaluator = ZeroTrustGateway = None

__all__ = [
    "OAuth2Provider",
    "OAuthToken",
    "TokenValidator",
    "SAMLProvider",
    "SAMLAssertion",
    "SAMLResponse",
    "MFAProvider",
    "TOTPProvider",
    "SMSProvider",
    "RBACManager",
    "Role",
    "Permission",
    "AccessPolicy",
    "AuditLogger",
    "SecurityEvent",
    "AuditTrail",
    "CertificateManager",
    "mTLSValidator",
    "ZeroTrustGateway",
    "TrustEvaluator",
]
