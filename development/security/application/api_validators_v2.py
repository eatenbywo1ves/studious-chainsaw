"""
API Input Validators for Catalytic Computing SaaS (Pydantic v2)
Comprehensive validation for all API endpoints

Implements:
- PCI DSS Requirement 6.5.1 - Input validation
- OWASP Top 10 - Injection prevention
- SOC 2 CC6.8 - Input data quality
"""

from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, field_validator, EmailStr, ConfigDict
import re


# ============================================================================
# AUTHENTICATION VALIDATORS
# ============================================================================

class LoginRequest(BaseModel):
    """Login request with comprehensive validation"""
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password (min 8 chars)")
    tenant_slug: Optional[str] = Field(
        None,
        min_length=1,
        max_length=50,
        pattern=r'^[a-z0-9-]+$',
        description="Tenant slug (lowercase alphanumeric and hyphens only)"
    )

    @field_validator('email')
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Additional email validation"""
        if not v or len(v) > 254:  # RFC 5321
            raise ValueError('Invalid email address')
        return v.lower()

    @field_validator('tenant_slug')
    @classmethod
    def validate_tenant_slug(cls, v: Optional[str]) -> Optional[str]:
        """Sanitize tenant slug"""
        if v:
            v = v.lower()
            if not re.match(r'^[a-z0-9-]+$', v):
                raise ValueError('Tenant slug must contain only lowercase letters, numbers, and hyphens')
        return v


class RefreshRequest(BaseModel):
    """Token refresh request validation"""
    model_config = ConfigDict(str_strip_whitespace=True)

    refresh_token: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description="JWT refresh token"
    )

    @field_validator('refresh_token')
    @classmethod
    def validate_token_format(cls, v: str) -> str:
        """Validate JWT token structure"""
        if v.count('.') != 2:
            raise ValueError('Invalid token format')
        return v


# ============================================================================
# LATTICE OPERATION VALIDATORS
# ============================================================================

class LatticeCreateRequest(BaseModel):
    """Lattice creation request with validation"""
    model_config = ConfigDict(str_strip_whitespace=True)

    name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=100,
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

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        """Validate and sanitize name"""
        if v:
            if not v:
                raise ValueError('Name cannot be empty or whitespace only')
            # Remove control characters
            v = ''.join(char for char in v if char.isprintable())
            if len(v) > 100:
                raise ValueError('Name too long after sanitization')
        return v

    @field_validator('size')
    @classmethod
    def validate_size(cls, v: int, info) -> int:
        """Validate size and check resource limits"""
        # Check total vertex count to prevent memory exhaustion
        dimensions = info.data.get('dimensions', 1)
        total_vertices = v ** dimensions
        if total_vertices > 1_000_000:  # 1M vertex limit
            raise ValueError(f'Total vertices ({total_vertices:,}) exceeds limit of 1,000,000')
        return v


class PathFindRequest(BaseModel):
    """Pathfinding request validation"""
    model_config = ConfigDict(str_strip_whitespace=True)

    lattice_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Lattice identifier"
    )
    start: List[int] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="Start coordinates (1-10 dimensions)"
    )
    end: List[int] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="End coordinates (1-10 dimensions)"
    )

    @field_validator('lattice_id')
    @classmethod
    def validate_lattice_id(cls, v: str) -> str:
        """Sanitize lattice ID"""
        if not v:
            raise ValueError('Lattice ID cannot be empty')
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Lattice ID contains invalid characters')
        return v

    @field_validator('start', 'end')
    @classmethod
    def validate_coordinates(cls, v: List[int]) -> List[int]:
        """Validate coordinate values"""
        for coord in v:
            if coord < 0:
                raise ValueError('Coordinates must be non-negative')
            if coord > 999:
                raise ValueError('Coordinate value too large')
        return v

    @field_validator('end')
    @classmethod
    def validate_dimensions_match(cls, v: List[int], info) -> List[int]:
        """Ensure start and end have same dimensions"""
        start = info.data.get('start')
        if start and len(start) != len(v):
            raise ValueError(f'Start ({len(start)}D) and end ({len(v)}D) dimensions must match')
        return v


# ============================================================================
# TENANT MANAGEMENT VALIDATORS
# ============================================================================

class TenantCreateRequest(BaseModel):
    """Tenant creation request validation"""
    model_config = ConfigDict(str_strip_whitespace=True)

    company_name: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Company/organization name"
    )
    slug: str = Field(
        ...,
        min_length=3,
        max_length=50,
        pattern=r'^[a-z0-9-]+$',
        description="Unique tenant slug"
    )
    contact_email: EmailStr = Field(
        ...,
        description="Primary contact email"
    )
    subscription_plan: Optional[str] = Field(
        None,
        min_length=1,
        max_length=50,
        description="Subscription plan name"
    )

    @field_validator('company_name')
    @classmethod
    def validate_company_name(cls, v: str) -> str:
        """Validate and sanitize company name"""
        if not v:
            raise ValueError('Company name cannot be empty')
        v = ''.join(char for char in v if char.isprintable())
        return v

    @field_validator('slug')
    @classmethod
    def validate_slug_format(cls, v: str) -> str:
        """Validate slug format"""
        v = v.lower()
        if not re.match(r'^[a-z0-9-]+$', v):
            raise ValueError('Slug must contain only lowercase letters, numbers, and hyphens')
        if v.startswith('-') or v.endswith('-'):
            raise ValueError('Slug cannot start or end with hyphen')
        if '--' in v:
            raise ValueError('Slug cannot contain consecutive hyphens')
        return v


class TenantUpdateRequest(BaseModel):
    """Tenant update request validation"""
    model_config = ConfigDict(str_strip_whitespace=True)

    company_name: Optional[str] = Field(None, min_length=1, max_length=200)
    contact_email: Optional[EmailStr] = None
    is_active: Optional[bool] = None

    @field_validator('company_name')
    @classmethod
    def validate_company_name(cls, v: Optional[str]) -> Optional[str]:
        """Validate company name if provided"""
        if v:
            if not v:
                raise ValueError('Company name cannot be empty or whitespace')
            v = ''.join(char for char in v if char.isprintable())
        return v


# ============================================================================
# USER MANAGEMENT VALIDATORS
# ============================================================================

class UserCreateRequest(BaseModel):
    """User creation request validation"""
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=12,
        description="User password (min 12 chars)"
    )
    first_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="User first name"
    )
    last_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="User last name"
    )
    role: Optional[str] = Field(
        'user',
        pattern=r'^(admin|user|viewer)$',
        description="User role"
    )

    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Validate email format"""
        return v.lower()

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength"""
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

    @field_validator('first_name', 'last_name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate and sanitize name fields"""
        if not v:
            raise ValueError('Name cannot be empty or whitespace')
        v = ''.join(char for char in v if char.isalnum() or char in ' -\'.')
        if len(v) > 100:
            raise ValueError('Name too long after sanitization')
        return v


# ============================================================================
# METADATA VALIDATORS
# ============================================================================

class MetadataValidator(BaseModel):
    """Generic metadata field validator"""
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional metadata dictionary"
    )

    @field_validator('metadata')
    @classmethod
    def validate_metadata(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate metadata structure"""
        if v is None:
            return v

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
    """Pagination parameter validation"""
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

    @field_validator('offset')
    @classmethod
    def validate_offset(cls, v: int) -> int:
        """Validate offset is reasonable"""
        if v > 1_000_000:
            raise ValueError('Offset too large')
        return v


# ============================================================================
# FILTER VALIDATORS
# ============================================================================

class FilterParams(BaseModel):
    """Generic filter parameter validation"""
    model_config = ConfigDict(str_strip_whitespace=True)

    field: Optional[str] = Field(None, pattern=r'^[a-zA-Z_][a-zA-Z0-9_]*$')
    value: Optional[str] = None
    operator: Optional[str] = Field('eq', pattern=r'^(eq|ne|gt|lt|gte|lte|like)$')

    @field_validator('value')
    @classmethod
    def validate_value(cls, v: Optional[str]) -> Optional[str]:
        """Sanitize filter value"""
        if v and len(v) > 1000:
            raise ValueError('Filter value too long')
        return v


# ============================================================================
# EXPORT VALIDATORS
# ============================================================================

class ExportRequest(BaseModel):
    """Data export request validation"""
    format: str = Field(
        'json',
        pattern=r'^(json|csv|excel)$',
        description="Export format"
    )
    fields: Optional[List[str]] = Field(
        None,
        min_length=1,
        max_length=50,
        description="Fields to export"
    )

    @field_validator('fields')
    @classmethod
    def validate_fields(cls, v: Optional[List[str]]) -> Optional[List[str]]:
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
    """Sanitize string input"""
    value = value.strip()
    value = ''.join(char for char in value if char.isprintable())
    if len(value) > max_length:
        raise ValueError(f'String too long (max {max_length} characters)')
    return value


def validate_uuid(value: str) -> str:
    """Validate UUID format"""
    import uuid
    try:
        uuid.UUID(value)
        return value
    except ValueError:
        raise ValueError('Invalid UUID format')


def validate_json_structure(data: Dict[str, Any], max_depth: int = 3, max_keys: int = 100) -> bool:
    """Validate JSON structure for safety"""
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
