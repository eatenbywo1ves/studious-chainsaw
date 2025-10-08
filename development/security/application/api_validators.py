"""
API Input Validators for Catalytic Computing SaaS
Comprehensive validation for all API endpoints

Implements:
- PCI DSS Requirement 6.5.1 - Input validation
- OWASP Top 10 - Injection prevention
- SOC 2 CC6.8 - Input data quality
"""

from typing import Optional, Any, Dict
from pydantic import BaseModel, Field, validator, EmailStr, constr, conlist
import re


# ============================================================================
# AUTHENTICATION VALIDATORS
# ============================================================================

class LoginRequest(BaseModel):
    """
    Login request with comprehensive validation

    Security:
    - Email format validation
    - Password length validation (no max to support long passwords)
    - Tenant slug sanitization
    """
    email: EmailStr = Field(..., description="User email address")
    password: constr(min_length=8) = Field(..., description="User password (min 8 chars)")
    tenant_slug: Optional[constr(min_length=1, max_length=50, regex=r'^[a-z0-9-]+$')] = Field(
        None,
        description="Tenant slug (lowercase alphanumeric and hyphens only)"
    )

    @validator('email')
    def validate_email_format(cls, v):
        """Additional email validation"""
        if not v or len(v) > 254:  # RFC 5321
            raise ValueError('Invalid email address')
        return v.lower().strip()

    @validator('tenant_slug')
    def validate_tenant_slug(cls, v):
        """Sanitize tenant slug"""
        if v:
            v = v.lower().strip()
            if not re.match(r'^[a-z0-9-]+$', v):
                raise ValueError('Tenant slug must contain only lowercase letters, numbers, and hyphens')
        return v


class RefreshRequest(BaseModel):
    """
    Token refresh request validation

    Security:
    - JWT token format validation
    - Length constraints
    """
    refresh_token: constr(min_length=10, max_length=2000) = Field(
        ...,
        description="JWT refresh token"
    )

    @validator('refresh_token')
    def validate_token_format(cls, v):
        """Validate JWT token structure"""
        v = v.strip()
        # JWT format: header.payload.signature
        if v.count('.') != 2:
            raise ValueError('Invalid token format')
        return v


# ============================================================================
# LATTICE OPERATION VALIDATORS
# ============================================================================

class LatticeCreateRequest(BaseModel):
    """
    Lattice creation request with validation

    Security:
    - Name length and content validation
    - Dimension bounds checking
    - Size limits to prevent DoS
    """
    name: Optional[constr(min_length=1, max_length=100)] = Field(
        None,
        description="Lattice name (optional)"
    )
    dimensions: int = Field(
        ...,
        ge=1,
        le=10,
        description="Number of dimensions (1-10)"
    )
    size: int = Field(
        ...,
        ge=2,
        le=100,
        description="Lattice size per dimension (2-100)"
    )

    @validator('name')
    def validate_name(cls, v):
        """Validate and sanitize name"""
        if v:
            v = v.strip()
            if not v:
                raise ValueError('Name cannot be empty or whitespace only')
            # Remove control characters
            v = ''.join(char for char in v if char.isprintable())
            if len(v) > 100:
                raise ValueError('Name too long after sanitization')
        return v

    @validator('dimensions')
    def validate_dimensions(cls, v):
        """Validate dimension count"""
        if v < 1:
            raise ValueError('Dimensions must be at least 1')
        if v > 10:
            raise ValueError('Dimensions cannot exceed 10 (resource limit)')
        return v

    @validator('size')
    def validate_size(cls, v, values):
        """Validate size and check resource limits"""
        if v < 2:
            raise ValueError('Size must be at least 2')
        if v > 100:
            raise ValueError('Size cannot exceed 100 (resource limit)')

        # Check total vertex count to prevent memory exhaustion
        dimensions = values.get('dimensions', 1)
        total_vertices = v ** dimensions
        if total_vertices > 1_000_000:  # 1M vertex limit
            raise ValueError(f'Total vertices ({total_vertices:,}) exceeds limit of 1,000,000')

        return v


class PathFindRequest(BaseModel):
    """
    Pathfinding request validation

    Security:
    - Lattice ID format validation
    - Coordinate list validation
    - Bounds checking
    """
    lattice_id: constr(min_length=1, max_length=100) = Field(
        ...,
        description="Lattice identifier"
    )
    start: conlist(int, min_items=1, max_items=10) = Field(
        ...,
        description="Start coordinates (1-10 dimensions)"
    )
    end: conlist(int, min_items=1, max_items=10) = Field(
        ...,
        description="End coordinates (1-10 dimensions)"
    )

    @validator('lattice_id')
    def validate_lattice_id(cls, v):
        """Sanitize lattice ID"""
        v = v.strip()
        if not v:
            raise ValueError('Lattice ID cannot be empty')
        # Allow alphanumeric, hyphens, underscores only
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Lattice ID contains invalid characters')
        return v

    @validator('start', 'end')
    def validate_coordinates(cls, v):
        """Validate coordinate values"""
        for coord in v:
            if coord < 0:
                raise ValueError('Coordinates must be non-negative')
            if coord > 999:  # Reasonable upper bound
                raise ValueError('Coordinate value too large')
        return v

    @validator('end')
    def validate_dimensions_match(cls, v, values):
        """Ensure start and end have same dimensions"""
        start = values.get('start')
        if start and len(start) != len(v):
            raise ValueError(f'Start ({len(start)}D) and end ({len(v)}D) dimensions must match')
        return v


# ============================================================================
# TENANT MANAGEMENT VALIDATORS
# ============================================================================

class TenantCreateRequest(BaseModel):
    """
    Tenant creation request validation

    Security:
    - Company name validation
    - Slug format enforcement
    - Contact email validation
    """
    company_name: constr(min_length=1, max_length=200) = Field(
        ...,
        description="Company/organization name"
    )
    slug: constr(min_length=3, max_length=50, regex=r'^[a-z0-9-]+$') = Field(
        ...,
        description="Unique tenant slug (lowercase alphanumeric and hyphens)"
    )
    contact_email: EmailStr = Field(
        ...,
        description="Primary contact email"
    )
    subscription_plan: Optional[constr(min_length=1, max_length=50)] = Field(
        None,
        description="Subscription plan name"
    )

    @validator('company_name')
    def validate_company_name(cls, v):
        """Validate and sanitize company name"""
        v = v.strip()
        if not v:
            raise ValueError('Company name cannot be empty')
        # Remove control characters
        v = ''.join(char for char in v if char.isprintable())
        return v

    @validator('slug')
    def validate_slug_format(cls, v):
        """Validate slug format"""
        v = v.lower().strip()
        if not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
        if v.startswith('-') or v.endswith('-'):
            raise ValueError('Slug cannot start or end with hyphen')
        if '--' in v:
            raise ValueError('Slug cannot contain consecutive hyphens')
        return v

    @validator('contact_email')
    def validate_contact_email(cls, v):
        """Validate contact email"""
        return v.lower().strip()


class TenantUpdateRequest(BaseModel):
    """
    Tenant update request validation

    Security:
    - Optional field validation
    - Sanitization of all inputs
    """
    company_name: Optional[constr(min_length=1, max_length=200)] = None
    contact_email: Optional[EmailStr] = None
    is_active: Optional[bool] = None

    @validator('company_name')
    def validate_company_name(cls, v):
        """Validate company name if provided"""
        if v:
            v = v.strip()
            if not v:
                raise ValueError('Company name cannot be empty or whitespace')
            v = ''.join(char for char in v if char.isprintable())
        return v

    @validator('contact_email')
    def validate_contact_email(cls, v):
        """Validate contact email if provided"""
        if v:
            return v.lower().strip()
        return v


# ============================================================================
# USER MANAGEMENT VALIDATORS
# ============================================================================

class UserCreateRequest(BaseModel):
    """
    User creation request validation

    Security:
    - Email uniqueness (enforced at DB level)
    - Password strength requirements
    - Name validation and sanitization
    """
    email: EmailStr = Field(..., description="User email address")
    password: constr(min_length=12) = Field(
        ...,
        description="User password (min 12 chars for strong security)"
    )
    first_name: constr(min_length=1, max_length=100) = Field(
        ...,
        description="User first name"
    )
    last_name: constr(min_length=1, max_length=100) = Field(
        ...,
        description="User last name"
    )
    role: Optional[constr(regex=r'^(admin|user|viewer)$')] = Field(
        'user',
        description="User role: admin, user, or viewer"
    )

    @validator('email')
    def validate_email(cls, v):
        """Validate email format"""
        return v.lower().strip()

    @validator('password')
    def validate_password_strength(cls, v):
        """
        Validate password strength

        Requirements:
        - Min 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')

        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')

        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')

        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character')

        return v

    @validator('first_name', 'last_name')
    def validate_name(cls, v):
        """Validate and sanitize name fields"""
        v = v.strip()
        if not v:
            raise ValueError('Name cannot be empty or whitespace')
        # Remove control characters and special chars
        v = ''.join(char for char in v if char.isalnum() or char in ' -\'.')
        if len(v) > 100:
            raise ValueError('Name too long after sanitization')
        return v


# ============================================================================
# METADATA VALIDATORS
# ============================================================================

class MetadataValidator(BaseModel):
    """
    Generic metadata field validator

    Security:
    - Nested object validation
    - Key/value sanitization
    - Size limits to prevent DoS
    """
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional metadata dictionary"
    )

    @validator('metadata')
    def validate_metadata(cls, v):
        """
        Validate metadata structure

        Constraints:
        - Max 50 keys
        - Max 1000 chars per value
        - No deeply nested objects (max 2 levels)
        """
        if v is None:
            return v

        if not isinstance(v, dict):
            raise ValueError('Metadata must be a dictionary')

        if len(v) > 50:
            raise ValueError('Metadata cannot contain more than 50 keys')

        def check_value(value, depth=0):
            if depth > 2:
                raise ValueError('Metadata cannot be nested more than 2 levels deep')

            if isinstance(value, str):
                if len(value) > 1000:
                    raise ValueError('Metadata string values cannot exceed 1000 characters')
            elif isinstance(value, dict):
                for k, v2 in value.items():
                    if not isinstance(k, str) or len(k) > 100:
                        raise ValueError('Metadata keys must be strings < 100 chars')
                    check_value(v2, depth + 1)
            elif isinstance(value, list):
                if len(value) > 100:
                    raise ValueError('Metadata lists cannot contain more than 100 items')
                for item in value:
                    check_value(item, depth + 1)

        for key, value in v.items():
            if not isinstance(key, str):
                raise ValueError('Metadata keys must be strings')
            if len(key) > 100:
                raise ValueError('Metadata keys cannot exceed 100 characters')
            check_value(value)

        return v


# ============================================================================
# PAGINATION VALIDATORS
# ============================================================================

class PaginationParams(BaseModel):
    """
    Pagination parameter validation

    Security:
    - Limit bounds to prevent DoS
    - Offset validation
    """
    limit: int = Field(
        20,
        ge=1,
        le=100,
        description="Number of items per page (1-100)"
    )
    offset: int = Field(
        0,
        ge=0,
        description="Number of items to skip"
    )

    @validator('offset')
    def validate_offset(cls, v):
        """Validate offset is reasonable"""
        if v > 1_000_000:  # Arbitrary large limit
            raise ValueError('Offset too large')
        return v


# ============================================================================
# FILTER VALIDATORS
# ============================================================================

class FilterParams(BaseModel):
    """
    Generic filter parameter validation

    Security:
    - SQL injection prevention
    - Field name validation
    """
    field: Optional[constr(min_length=1, max_length=50, regex=r'^[a-zA-Z_][a-zA-Z0-9_]*$')] = None
    value: Optional[str] = None
    operator: Optional[constr(regex=r'^(eq|ne|gt|lt|gte|lte|like)$')] = 'eq'

    @validator('field')
    def validate_field_name(cls, v):
        """Validate field name is safe"""
        if v and not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', v):
            raise ValueError('Invalid field name')
        return v

    @validator('value')
    def validate_value(cls, v):
        """Sanitize filter value"""
        if v:
            v = v.strip()
            if len(v) > 1000:
                raise ValueError('Filter value too long')
        return v


# ============================================================================
# EXPORT VALIDATORS
# ============================================================================

class ExportRequest(BaseModel):
    """
    Data export request validation

    Security:
    - Format validation
    - Field selection validation
    """
    format: constr(regex=r'^(json|csv|excel)$') = Field(
        'json',
        description="Export format: json, csv, or excel"
    )
    fields: Optional[conlist(str, min_items=1, max_items=50)] = Field(
        None,
        description="Fields to export (optional, defaults to all)"
    )

    @validator('fields')
    def validate_fields(cls, v):
        """Validate field names"""
        if v:
            for field in v:
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', field):
                    raise ValueError(f'Invalid field name: {field}')
        return v


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Sanitize string input

    Args:
        value: Input string
        max_length: Maximum allowed length

    Returns:
        Sanitized string

    Raises:
        ValueError: If string is too long or contains invalid characters
    """
    value = value.strip()

    # Remove control characters
    value = ''.join(char for char in value if char.isprintable())

    # Check length
    if len(value) > max_length:
        raise ValueError(f'String too long (max {max_length} characters)')

    return value


def validate_uuid(value: str) -> str:
    """
    Validate UUID format

    Args:
        value: UUID string

    Returns:
        Validated UUID string

    Raises:
        ValueError: If UUID is invalid
    """
    import uuid
    try:
        uuid.UUID(value)
        return value
    except ValueError:
        raise ValueError('Invalid UUID format')


def validate_json_structure(data: Dict[str, Any], max_depth: int = 3, max_keys: int = 100) -> bool:
    """
    Validate JSON structure for safety

    Args:
        data: JSON data to validate
        max_depth: Maximum nesting depth
        max_keys: Maximum number of keys at any level

    Returns:
        True if valid

    Raises:
        ValueError: If structure is invalid
    """
    def check_depth(obj, depth=0):
        if depth > max_depth:
            raise ValueError(f'JSON nested too deeply (max {max_depth} levels)')

        if isinstance(obj, dict):
            if len(obj) > max_keys:
                raise ValueError(f'Too many keys (max {max_keys})')
            for value in obj.values():
                check_depth(value, depth + 1)
        elif isinstance(obj, list):
            if len(obj) > max_keys:
                raise ValueError(f'List too long (max {max_keys} items)')
            for item in obj:
                check_depth(item, depth + 1)

    check_depth(data)
    return True
