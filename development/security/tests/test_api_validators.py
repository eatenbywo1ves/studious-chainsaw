"""
Test Suite for API Input Validators

Tests all validation logic for security and correctness
"""

import pytest
from pydantic import ValidationError
from security.application.api_validators_v2 import (
    LoginRequest,
    RefreshRequest,
    LatticeCreateRequest,
    PathFindRequest,
    TenantCreateRequest,
    UserCreateRequest,
    MetadataValidator,
    PaginationParams,
    sanitize_string,
    validate_uuid,
    validate_json_structure
)


# ============================================================================
# AUTHENTICATION VALIDATOR TESTS
# ============================================================================

class TestLoginRequest:
    """Test LoginRequest validator"""

    def test_valid_login(self):
        """Test valid login request"""
        req = LoginRequest(
            email="user@example.com",
            password="SecurePass123!",
            tenant_slug="acme-corp"
        )
        assert req.email == "user@example.com"
        assert req.password == "SecurePass123!"
        assert req.tenant_slug == "acme-corp"

    def test_email_normalization(self):
        """Test email is lowercased and trimmed"""
        req = LoginRequest(
            email="  USER@EXAMPLE.COM  ",
            password="SecurePass123!"
        )
        assert req.email == "user@example.com"

    def test_invalid_email(self):
        """Test invalid email format"""
        with pytest.raises(ValidationError):
            LoginRequest(
                email="not-an-email",
                password="SecurePass123!"
            )

    def test_password_too_short(self):
        """Test password minimum length"""
        with pytest.raises(ValidationError):
            LoginRequest(
                email="user@example.com",
                password="short"
            )

    def test_invalid_tenant_slug(self):
        """Test invalid tenant slug format"""
        with pytest.raises(ValidationError):
            LoginRequest(
                email="user@example.com",
                password="SecurePass123!",
                tenant_slug="INVALID_SLUG!"
            )

    def test_tenant_slug_normalization(self):
        """Test tenant slug is lowercased"""
        req = LoginRequest(
            email="user@example.com",
            password="SecurePass123!",
            tenant_slug="Acme-Corp"
        )
        assert req.tenant_slug == "acme-corp"


class TestRefreshRequest:
    """Test RefreshRequest validator"""

    def test_valid_refresh_token(self):
        """Test valid refresh token"""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        req = RefreshRequest(refresh_token=token)
        assert req.refresh_token == token

    def test_invalid_token_format(self):
        """Test invalid JWT format"""
        with pytest.raises(ValidationError):
            RefreshRequest(refresh_token="invalid-token")

    def test_token_too_short(self):
        """Test token minimum length"""
        with pytest.raises(ValidationError):
            RefreshRequest(refresh_token="a.b.c")


# ============================================================================
# LATTICE VALIDATOR TESTS
# ============================================================================

class TestLatticeCreateRequest:
    """Test LatticeCreateRequest validator"""

    def test_valid_lattice(self):
        """Test valid lattice creation"""
        req = LatticeCreateRequest(
            name="Test Lattice",
            dimensions=3,
            size=10
        )
        assert req.name == "Test Lattice"
        assert req.dimensions == 3
        assert req.size == 10

    def test_name_sanitization(self):
        """Test name is trimmed and sanitized"""
        req = LatticeCreateRequest(
            name="  Test  Lattice  ",
            dimensions=2,
            size=5
        )
        assert req.name == "Test  Lattice"

    def test_empty_name_rejected(self):
        """Test empty name is rejected"""
        with pytest.raises(ValidationError):
            LatticeCreateRequest(
                name="   ",
                dimensions=2,
                size=5
            )

    def test_dimensions_too_low(self):
        """Test dimensions minimum"""
        with pytest.raises(ValidationError):
            LatticeCreateRequest(
                dimensions=0,
                size=5
            )

    def test_dimensions_too_high(self):
        """Test dimensions maximum"""
        with pytest.raises(ValidationError):
            LatticeCreateRequest(
                dimensions=11,
                size=5
            )

    def test_size_too_low(self):
        """Test size minimum"""
        with pytest.raises(ValidationError):
            LatticeCreateRequest(
                dimensions=2,
                size=1
            )

    def test_size_too_high(self):
        """Test size maximum"""
        with pytest.raises(ValidationError):
            LatticeCreateRequest(
                dimensions=2,
                size=101
            )

    def test_vertex_limit_exceeded(self):
        """Test total vertex limit"""
        with pytest.raises(ValidationError):
            # 100^5 = 10B vertices (exceeds 1M limit)
            LatticeCreateRequest(
                dimensions=5,
                size=100
            )

    def test_vertex_limit_ok(self):
        """Test acceptable vertex count"""
        req = LatticeCreateRequest(
            dimensions=3,
            size=100
        )
        # 100^3 = 1M vertices (exactly at limit)
        assert req.dimensions == 3
        assert req.size == 100


class TestPathFindRequest:
    """Test PathFindRequest validator"""

    def test_valid_pathfind(self):
        """Test valid pathfinding request"""
        req = PathFindRequest(
            lattice_id="lattice-123",
            start=[0, 0, 0],
            end=[5, 5, 5]
        )
        assert req.lattice_id == "lattice-123"
        assert req.start == [0, 0, 0]
        assert req.end == [5, 5, 5]

    def test_lattice_id_sanitization(self):
        """Test lattice ID is trimmed"""
        req = PathFindRequest(
            lattice_id="  lattice-123  ",
            start=[0],
            end=[1]
        )
        assert req.lattice_id == "lattice-123"

    def test_invalid_lattice_id(self):
        """Test invalid lattice ID characters"""
        with pytest.raises(ValidationError):
            PathFindRequest(
                lattice_id="lattice/123",
                start=[0],
                end=[1]
            )

    def test_negative_coordinates(self):
        """Test negative coordinates rejected"""
        with pytest.raises(ValidationError):
            PathFindRequest(
                lattice_id="lattice-123",
                start=[-1, 0],
                end=[1, 1]
            )

    def test_coordinate_too_large(self):
        """Test coordinate maximum"""
        with pytest.raises(ValidationError):
            PathFindRequest(
                lattice_id="lattice-123",
                start=[0, 0],
                end=[1000, 1000]
            )

    def test_dimension_mismatch(self):
        """Test start/end dimension mismatch"""
        with pytest.raises(ValidationError):
            PathFindRequest(
                lattice_id="lattice-123",
                start=[0, 0],
                end=[1, 1, 1]
            )


# ============================================================================
# TENANT VALIDATOR TESTS
# ============================================================================

class TestTenantCreateRequest:
    """Test TenantCreateRequest validator"""

    def test_valid_tenant(self):
        """Test valid tenant creation"""
        req = TenantCreateRequest(
            company_name="Acme Corporation",
            slug="acme-corp",
            contact_email="admin@acme.com",
            subscription_plan="pro"
        )
        assert req.company_name == "Acme Corporation"
        assert req.slug == "acme-corp"
        assert req.contact_email == "admin@acme.com"

    def test_slug_normalization(self):
        """Test slug is lowercased"""
        req = TenantCreateRequest(
            company_name="Acme Corporation",
            slug="Acme-Corp",
            contact_email="admin@acme.com"
        )
        assert req.slug == "acme-corp"

    def test_slug_too_short(self):
        """Test slug minimum length"""
        with pytest.raises(ValidationError):
            TenantCreateRequest(
                company_name="Acme Corporation",
                slug="ab",
                contact_email="admin@acme.com"
            )

    def test_invalid_slug_characters(self):
        """Test invalid slug characters"""
        with pytest.raises(ValidationError):
            TenantCreateRequest(
                company_name="Acme Corporation",
                slug="acme_corp!",
                contact_email="admin@acme.com"
            )

    def test_slug_consecutive_hyphens(self):
        """Test slug cannot have consecutive hyphens"""
        with pytest.raises(ValidationError):
            TenantCreateRequest(
                company_name="Acme Corporation",
                slug="acme--corp",
                contact_email="admin@acme.com"
            )

    def test_company_name_sanitization(self):
        """Test company name is trimmed"""
        req = TenantCreateRequest(
            company_name="  Acme Corp  ",
            slug="acme-corp",
            contact_email="admin@acme.com"
        )
        assert req.company_name == "Acme Corp"


# ============================================================================
# USER VALIDATOR TESTS
# ============================================================================

class TestUserCreateRequest:
    """Test UserCreateRequest validator"""

    def test_valid_user(self):
        """Test valid user creation"""
        req = UserCreateRequest(
            email="user@example.com",
            password="SecurePass123!",
            first_name="John",
            last_name="Doe",
            role="user"
        )
        assert req.email == "user@example.com"
        assert req.first_name == "John"
        assert req.last_name == "Doe"

    def test_password_strength_validation(self):
        """Test password strength requirements"""
        # Missing uppercase
        with pytest.raises(ValidationError) as exc:
            UserCreateRequest(
                email="user@example.com",
                password="securepass123!",
                first_name="John",
                last_name="Doe"
            )
        assert "uppercase" in str(exc.value).lower()

        # Missing lowercase
        with pytest.raises(ValidationError) as exc:
            UserCreateRequest(
                email="user@example.com",
                password="SECUREPASS123!",
                first_name="John",
                last_name="Doe"
            )
        assert "lowercase" in str(exc.value).lower()

        # Missing digit
        with pytest.raises(ValidationError) as exc:
            UserCreateRequest(
                email="user@example.com",
                password="SecurePass!",
                first_name="John",
                last_name="Doe"
            )
        assert "digit" in str(exc.value).lower()

        # Missing special character
        with pytest.raises(ValidationError) as exc:
            UserCreateRequest(
                email="user@example.com",
                password="SecurePass123",
                first_name="John",
                last_name="Doe"
            )
        assert "special" in str(exc.value).lower()

    def test_name_sanitization(self):
        """Test name sanitization"""
        req = UserCreateRequest(
            email="user@example.com",
            password="SecurePass123!",
            first_name="  John  ",
            last_name="O'Brien"
        )
        assert req.first_name == "John"
        assert req.last_name == "O'Brien"

    def test_invalid_role(self):
        """Test invalid role rejected"""
        with pytest.raises(ValidationError):
            UserCreateRequest(
                email="user@example.com",
                password="SecurePass123!",
                first_name="John",
                last_name="Doe",
                role="superuser"
            )


# ============================================================================
# METADATA VALIDATOR TESTS
# ============================================================================

class TestMetadataValidator:
    """Test MetadataValidator"""

    def test_valid_metadata(self):
        """Test valid metadata"""
        req = MetadataValidator(metadata={
            "key1": "value1",
            "key2": 123,
            "key3": {"nested": "value"}
        })
        assert req.metadata["key1"] == "value1"

    def test_too_many_keys(self):
        """Test metadata key limit"""
        metadata = {f"key{i}": i for i in range(51)}
        with pytest.raises(ValidationError):
            MetadataValidator(metadata=metadata)

    def test_value_too_long(self):
        """Test metadata value length limit"""
        with pytest.raises(ValidationError):
            MetadataValidator(metadata={
                "key": "x" * 1001
            })

    def test_nested_too_deep(self):
        """Test nesting depth limit"""
        with pytest.raises(ValidationError):
            MetadataValidator(metadata={
                "level1": {
                    "level2": {
                        "level3": {
                            "level4": "too deep"
                        }
                    }
                }
            })

    def test_list_too_long(self):
        """Test list length limit"""
        with pytest.raises(ValidationError):
            MetadataValidator(metadata={
                "list": list(range(101))
            })


# ============================================================================
# PAGINATION VALIDATOR TESTS
# ============================================================================

class TestPaginationParams:
    """Test PaginationParams validator"""

    def test_valid_pagination(self):
        """Test valid pagination params"""
        req = PaginationParams(limit=20, offset=0)
        assert req.limit == 20
        assert req.offset == 0

    def test_defaults(self):
        """Test default values"""
        req = PaginationParams()
        assert req.limit == 20
        assert req.offset == 0

    def test_limit_too_low(self):
        """Test limit minimum"""
        with pytest.raises(ValidationError):
            PaginationParams(limit=0)

    def test_limit_too_high(self):
        """Test limit maximum"""
        with pytest.raises(ValidationError):
            PaginationParams(limit=101)

    def test_offset_negative(self):
        """Test offset must be non-negative"""
        with pytest.raises(ValidationError):
            PaginationParams(offset=-1)

    def test_offset_too_large(self):
        """Test offset maximum"""
        with pytest.raises(ValidationError):
            PaginationParams(offset=1_000_001)


# ============================================================================
# UTILITY FUNCTION TESTS
# ============================================================================

class TestUtilityFunctions:
    """Test utility validation functions"""

    def test_sanitize_string(self):
        """Test string sanitization"""
        result = sanitize_string("  test  ")
        assert result == "test"

    def test_sanitize_string_too_long(self):
        """Test string length limit"""
        with pytest.raises(ValueError):
            sanitize_string("x" * 1001)

    def test_validate_uuid_valid(self):
        """Test valid UUID"""
        uuid_str = "123e4567-e89b-12d3-a456-426614174000"
        result = validate_uuid(uuid_str)
        assert result == uuid_str

    def test_validate_uuid_invalid(self):
        """Test invalid UUID"""
        with pytest.raises(ValueError):
            validate_uuid("not-a-uuid")

    def test_validate_json_structure_valid(self):
        """Test valid JSON structure"""
        data = {
            "level1": {
                "level2": {
                    "level3": "value"
                }
            }
        }
        assert validate_json_structure(data) is True

    def test_validate_json_structure_too_deep(self):
        """Test JSON nesting limit"""
        data = {
            "l1": {
                "l2": {
                    "l3": {
                        "l4": "too deep"
                    }
                }
            }
        }
        with pytest.raises(ValueError):
            validate_json_structure(data)

    def test_validate_json_structure_too_many_keys(self):
        """Test JSON key limit"""
        data = {f"key{i}": i for i in range(101)}
        with pytest.raises(ValueError):
            validate_json_structure(data)


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
