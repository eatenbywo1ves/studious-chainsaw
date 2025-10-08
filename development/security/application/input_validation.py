"""
Comprehensive Input Validation and Sanitization
Provides robust input validation, sanitization, and security filtering
"""

import re
import html
import json
import bleach
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import logging
from urllib.parse import urlparse
import ipaddress

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ValidationRule:
    name: str
    validator: Callable
    sanitizer: Optional[Callable] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    description: str = ""

@dataclass
class ValidationResult:
    is_valid: bool
    sanitized_value: Any
    errors: List[str]
    warnings: List[str]
    severity: SeverityLevel = SeverityLevel.LOW

class SecurityInputValidator:
    """
    Comprehensive input validation and sanitization system
    """

    def __init__(self):
        # Common regex patterns
        self.patterns = {
            'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
            'phone': re.compile(r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'),
            'username': re.compile(r'^[a-zA-Z0-9_-]{3,20}$'),
            'password': re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'),
            'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
            'hex': re.compile(r'^[0-9a-fA-F]+$'),
            'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
            'slug': re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$'),
        }

        # SQL injection patterns
        self.sql_injection_patterns = [
            re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)", re.IGNORECASE),
            re.compile(r"(--|#|/\*|\*/)", re.IGNORECASE),
            re.compile(r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
            re.compile(r"('|(\\'))+.*(OR|AND)", re.IGNORECASE),
        ]

        # XSS patterns
        self.xss_patterns = [
            re.compile(r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"vbscript:", re.IGNORECASE),
            re.compile(r"onload\s*=", re.IGNORECASE),
            re.compile(r"onerror\s*=", re.IGNORECASE),
            re.compile(r"onclick\s*=", re.IGNORECASE),
        ]

        # Command injection patterns
        self.command_injection_patterns = [
            re.compile(r"[;&|`]", re.IGNORECASE),
            re.compile(r"\$\(", re.IGNORECASE),
            re.compile(r"\.\.\/", re.IGNORECASE),
            re.compile(r"(rm|cat|ls|ps|kill|chmod|chown)\s", re.IGNORECASE),
        ]

        # LDAP injection patterns
        self.ldap_injection_patterns = [
            re.compile(r"[()&|!]", re.IGNORECASE),
            re.compile(r"\\[0-9a-f]{2}", re.IGNORECASE),
        ]

        logger.info("Security input validator initialized")

    def validate_email(self, email: str) -> ValidationResult:
        """Validate and sanitize email address"""
        errors = []
        warnings = []

        if not email:
            errors.append("Email is required")
            return ValidationResult(False, "", errors, warnings, SeverityLevel.HIGH)

        # Sanitize
        sanitized = email.strip().lower()

        # Length check
        if len(sanitized) > 254:
            errors.append("Email too long (max 254 characters)")

        # Format validation
        if not self.patterns['email'].match(sanitized):
            errors.append("Invalid email format")

        # Check for suspicious patterns
        if any(pattern in sanitized for pattern in ['..', '@@', '++']):
            warnings.append("Suspicious email pattern detected")

        # Domain validation
        try:
            domain = sanitized.split('@')[1]
            if len(domain) > 253:
                errors.append("Domain name too long")
            if domain.startswith('.') or domain.endswith('.'):
                errors.append("Invalid domain format")
        except IndexError:
            errors.append("Invalid email format")

        is_valid = len(errors) == 0
        severity = SeverityLevel.HIGH if errors else SeverityLevel.LOW

        return ValidationResult(is_valid, sanitized, errors, warnings, severity)

    def validate_password(self, password: str) -> ValidationResult:
        """Validate password strength and security"""
        errors = []
        warnings = []

        if not password:
            errors.append("Password is required")
            return ValidationResult(False, "", errors, warnings, SeverityLevel.CRITICAL)

        # Length check
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        if len(password) > 128:
            errors.append("Password too long (max 128 characters)")

        # Complexity checks
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        if not re.search(r'[@$!%*?&]', password):
            errors.append("Password must contain at least one special character")

        # Common password checks
        common_passwords = ['password', '123456', 'qwerty', 'admin', 'root']
        if password.lower() in common_passwords:
            errors.append("Password is too common")

        # Sequential character check
        if self._has_sequential_chars(password):
            warnings.append("Password contains sequential characters")

        is_valid = len(errors) == 0
        severity = SeverityLevel.CRITICAL if errors else SeverityLevel.LOW

        # Don't return the actual password in sanitized_value for security
        return ValidationResult(is_valid, "***" if is_valid else "", errors, warnings, severity)

    def validate_username(self, username: str) -> ValidationResult:
        """Validate username format and security"""
        errors = []
        warnings = []

        if not username:
            errors.append("Username is required")
            return ValidationResult(False, "", errors, warnings, SeverityLevel.HIGH)

        # Sanitize
        sanitized = username.strip()

        # Length and format checks
        if len(sanitized) < 3:
            errors.append("Username must be at least 3 characters long")
        if len(sanitized) > 20:
            errors.append("Username too long (max 20 characters)")

        if not self.patterns['username'].match(sanitized):
            errors.append("Username can only contain letters, numbers, hyphens, and underscores")

        # Reserved words check
        reserved_words = ['admin', 'root', 'administrator', 'user', 'guest', 'api', 'system']
        if sanitized.lower() in reserved_words:
            errors.append("Username is reserved")

        # Sequential character check
        if sanitized.lower() in ['123456', 'abcdef', 'qwerty']:
            warnings.append("Username contains sequential characters")

        is_valid = len(errors) == 0
        severity = SeverityLevel.MEDIUM if errors else SeverityLevel.LOW

        return ValidationResult(is_valid, sanitized, errors, warnings, severity)

    def validate_and_sanitize_text(self, text: str, max_length: int = 1000, allow_html: bool = False) -> ValidationResult:
        """Validate and sanitize text input"""
        errors = []
        warnings = []

        if not text:
            return ValidationResult(True, "", errors, warnings, SeverityLevel.LOW)

        # Length check
        if len(text) > max_length:
            errors.append(f"Text too long (max {max_length} characters)")

        # Security checks
        if self._contains_sql_injection(text):
            errors.append("Potential SQL injection detected")

        if self._contains_xss(text):
            if allow_html:
                warnings.append("Potential XSS detected in HTML content")
            else:
                errors.append("Potential XSS detected")

        if self._contains_command_injection(text):
            errors.append("Potential command injection detected")

        # Sanitize based on HTML allowance
        if allow_html:
            sanitized = self._sanitize_html(text)
        else:
            sanitized = html.escape(text)

        # Additional sanitization
        sanitized = self._remove_null_bytes(sanitized)
        sanitized = self._normalize_whitespace(sanitized)

        is_valid = len(errors) == 0
        severity = SeverityLevel.HIGH if any("injection" in error for error in errors) else SeverityLevel.LOW

        return ValidationResult(is_valid, sanitized, errors, warnings, severity)

    def validate_url(self, url: str) -> ValidationResult:
        """Validate URL format and security"""
        errors = []
        warnings = []

        if not url:
            errors.append("URL is required")
            return ValidationResult(False, "", errors, warnings, SeverityLevel.MEDIUM)

        # Sanitize
        sanitized = url.strip()

        # Length check
        if len(sanitized) > 2048:
            errors.append("URL too long (max 2048 characters)")

        try:
            parsed = urlparse(sanitized)

            # Scheme validation
            if parsed.scheme not in ['http', 'https']:
                errors.append("Only HTTP and HTTPS URLs are allowed")

            # Hostname validation
            if not parsed.netloc:
                errors.append("Invalid URL format")

            # Check for suspicious patterns
            if any(pattern in sanitized.lower() for pattern in ['javascript:', 'vbscript:', 'data:']):
                errors.append("Potentially dangerous URL scheme")

            # Check for SSRF attempts
            if self._is_private_ip(parsed.netloc):
                warnings.append("URL points to private network")

        except Exception as e:
            errors.append(f"Invalid URL format: {str(e)}")

        is_valid = len(errors) == 0
        severity = SeverityLevel.HIGH if any("dangerous" in error for error in errors) else SeverityLevel.LOW

        return ValidationResult(is_valid, sanitized, errors, warnings, severity)

    def validate_json(self, json_str: str, max_depth: int = 10, max_size: int = 1000000) -> ValidationResult:
        """Validate JSON input"""
        errors = []
        warnings = []

        if not json_str:
            return ValidationResult(True, {}, errors, warnings, SeverityLevel.LOW)

        # Size check
        if len(json_str) > max_size:
            errors.append(f"JSON too large (max {max_size} bytes)")

        try:
            parsed_json = json.loads(json_str)

            # Depth check
            if self._get_json_depth(parsed_json) > max_depth:
                errors.append(f"JSON too deep (max depth {max_depth})")

            # Check for suspicious keys
            suspicious_keys = ['__proto__', 'constructor', 'prototype']
            if self._contains_suspicious_keys(parsed_json, suspicious_keys):
                warnings.append("JSON contains suspicious keys")

            sanitized = parsed_json

        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON format: {str(e)}")
            sanitized = {}

        is_valid = len(errors) == 0
        severity = SeverityLevel.MEDIUM if errors else SeverityLevel.LOW

        return ValidationResult(is_valid, sanitized, errors, warnings, severity)

    def validate_file_upload(self, filename: str, content_type: str, file_size: int) -> ValidationResult:
        """Validate file upload security"""
        errors = []
        warnings = []

        if not filename:
            errors.append("Filename is required")
            return ValidationResult(False, "", errors, warnings, SeverityLevel.HIGH)

        # Sanitize filename
        sanitized = self._sanitize_filename(filename)

        # Extension validation
        allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.csv', '.json']
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.jsp', '.php', '.asp']

        extension = '.' + filename.lower().split('.')[-1] if '.' in filename else ''

        if extension in dangerous_extensions:
            errors.append("File type not allowed")
        elif extension not in allowed_extensions:
            warnings.append("Unusual file type detected")

        # Size validation
        max_file_size = 10 * 1024 * 1024  # 10MB
        if file_size > max_file_size:
            errors.append("File too large (max 10MB)")

        # Content type validation
        expected_content_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.csv': 'text/csv',
            '.json': 'application/json'
        }

        if extension in expected_content_types:
            if content_type != expected_content_types[extension]:
                warnings.append("Content type doesn't match file extension")

        is_valid = len(errors) == 0
        severity = SeverityLevel.HIGH if any("not allowed" in error for error in errors) else SeverityLevel.LOW

        return ValidationResult(is_valid, sanitized, errors, warnings, severity)

    def _contains_sql_injection(self, text: str) -> bool:
        """Check for SQL injection patterns"""
        return any(pattern.search(text) for pattern in self.sql_injection_patterns)

    def _contains_xss(self, text: str) -> bool:
        """Check for XSS patterns"""
        return any(pattern.search(text) for pattern in self.xss_patterns)

    def _contains_command_injection(self, text: str) -> bool:
        """Check for command injection patterns"""
        return any(pattern.search(text) for pattern in self.command_injection_patterns)

    def _sanitize_html(self, html_content: str) -> str:
        """Sanitize HTML content"""
        allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
        allowed_attributes = {'a': ['href'], 'img': ['src', 'alt']}

        return bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attributes)

    def _remove_null_bytes(self, text: str) -> str:
        """Remove null bytes from text"""
        return text.replace('\x00', '')

    def _normalize_whitespace(self, text: str) -> str:
        """Normalize whitespace in text"""
        return ' '.join(text.split())

    def _has_sequential_chars(self, text: str) -> bool:
        """Check for sequential characters"""
        sequences = ['123456', 'abcdef', 'qwerty', '098765', 'fedcba']
        return any(seq in text.lower() for seq in sequences)

    def _is_private_ip(self, hostname: str) -> bool:
        """Check if hostname resolves to private IP"""
        try:
            # Extract hostname if port is included
            hostname = hostname.split(':')[0]
            ip = ipaddress.ip_address(hostname)
            return ip.is_private
        except (ValueError, ipaddress.AddressValueError):
            return False

    def _get_json_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate JSON object depth"""
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._get_json_depth(value, current_depth + 1) for value in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._get_json_depth(item, current_depth + 1) for item in obj)
        else:
            return current_depth

    def _contains_suspicious_keys(self, obj: Any, suspicious_keys: List[str]) -> bool:
        """Check for suspicious keys in JSON object"""
        if isinstance(obj, dict):
            for key in obj.keys():
                if key in suspicious_keys:
                    return True
                if self._contains_suspicious_keys(obj[key], suspicious_keys):
                    return True
        elif isinstance(obj, list):
            for item in obj:
                if self._contains_suspicious_keys(item, suspicious_keys):
                    return True
        return False

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage"""
        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        sanitized = re.sub(r'\.{2,}', '.', sanitized)  # Remove multiple dots
        sanitized = sanitized.strip('. ')  # Remove leading/trailing dots and spaces

        # Limit length
        if len(sanitized) > 255:
            name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
            max_name_length = 255 - len(ext) - 1 if ext else 255
            sanitized = name[:max_name_length] + ('.' + ext if ext else '')

        return sanitized

# Decorator for automatic validation
def validate_input(validation_rules: Dict[str, ValidationRule]):
    """Decorator for automatic input validation"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Validate kwargs based on rules
            for param_name, rule in validation_rules.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    result = rule.validator(value)

                    if not result.is_valid:
                        error_msg = f"Validation failed for {param_name}: {'; '.join(result.errors)}"
                        logger.error(error_msg)
                        raise ValidationError(error_msg)

                    # Use sanitized value
                    if rule.sanitizer:
                        kwargs[param_name] = rule.sanitizer(result.sanitized_value)
                    else:
                        kwargs[param_name] = result.sanitized_value

                    # Log warnings
                    for warning in result.warnings:
                        logger.warning(f"Validation warning for {param_name}: {warning}")

            return func(*args, **kwargs)
        return wrapper
    return decorator

# Example usage
if __name__ == "__main__":
    validator = SecurityInputValidator()

    # Test email validation
    email_result = validator.validate_email("user@example.com")
    print(f"Email validation: {email_result}")

    # Test password validation
    password_result = validator.validate_password("SecureP@ssw0rd!")
    print(f"Password validation: {password_result}")

    # Test text sanitization
    text_result = validator.validate_and_sanitize_text("<script>alert('xss')</script>Hello World!")
    print(f"Text validation: {text_result}")

    # Test URL validation
    url_result = validator.validate_url("https://example.com/path")
    print(f"URL validation: {url_result}")
