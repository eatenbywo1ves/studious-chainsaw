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

from .audit import AuditLogger, AuditTrail, SecurityEvent
from .certificates import CertificateManager, mTLSValidator
from .mfa import MFAProvider, SMSProvider, TOTPProvider
from .oauth2 import OAuth2Provider, OAuthToken, TokenValidator
from .rbac import AccessPolicy, Permission, RBACManager, Role
from .saml import SAMLAssertion, SAMLProvider, SAMLResponse
from .zero_trust import TrustEvaluator, ZeroTrustGateway

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
