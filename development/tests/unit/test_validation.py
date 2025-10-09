"""
Unit Tests for Validation Module
Tests all validation functions and Pydantic models
"""

import pytest

from libs.utils.validation import (
    # Models
    LatticeParameters,
    WebhookConfig,
    PaginationParams,
    # Functions
    validate_dimensions,
    validate_lattice_size,
    validate_coordinates,
    validate_port,
    validate_url,
    validate_email,
    validate_json,
    validate_file_path,
    validate_memory_size,
    validate_percentage,
    validate_batch,
    # Decorators
    validate_input,
    validate_type,
)
from libs.utils.exceptions import ValidationError as CustomValidationError
from libs.constants.constants import (
    MIN_DIMENSIONS,
    MAX_DIMENSIONS,
    MIN_LATTICE_SIZE,
    MAX_LATTICE_SIZE,
    MAX_AUX_MEMORY_MB,
)


class TestLatticeParametersModel:
    """Test LatticeParameters Pydantic model"""

    def test_valid_lattice_parameters(self, sample_lattice_params):
        """Test valid lattice parameter creation"""
        params = LatticeParameters(**sample_lattice_params)

        assert params.dimensions == sample_lattice_params["dimensions"]
        assert params.size == sample_lattice_params["size"]
        assert params.auxiliary_memory == sample_lattice_params["auxiliary_memory"]
        assert params.algorithm == sample_lattice_params["algorithm"]

    def test_dimensions_boundaries(self):
        """Test dimension boundary values"""
        # Minimum valid
        params_min = LatticeParameters(dimensions=MIN_DIMENSIONS, size=10)
        assert params_min.dimensions == MIN_DIMENSIONS

        # Maximum valid
        params_max = LatticeParameters(dimensions=MAX_DIMENSIONS, size=2)
        assert params_max.dimensions == MAX_DIMENSIONS

        # Below minimum - should raise
        with pytest.raises(ValueError):
            LatticeParameters(dimensions=MIN_DIMENSIONS - 1, size=10)

        # Above maximum - should raise
        with pytest.raises(ValueError):
            LatticeParameters(dimensions=MAX_DIMENSIONS + 1, size=10)

    def test_size_boundaries(self):
        """Test size boundary values"""
        # Minimum valid
        params_min = LatticeParameters(dimensions=3, size=MIN_LATTICE_SIZE)
        assert params_min.size == MIN_LATTICE_SIZE

        # Maximum valid
        params_max = LatticeParameters(dimensions=2, size=MAX_LATTICE_SIZE)
        assert params_max.size == MAX_LATTICE_SIZE

        # Below minimum - should raise
        with pytest.raises(ValueError):
            LatticeParameters(dimensions=3, size=MIN_LATTICE_SIZE - 1)

        # Above maximum - should raise
        with pytest.raises(ValueError):
            LatticeParameters(dimensions=3, size=MAX_LATTICE_SIZE + 1)

    def test_total_points_validation(self):
        """Test that total points validation works"""
        # This should be fine - 10^3 = 1000 points
        params = LatticeParameters(dimensions=3, size=10)
        assert params.dimensions == 3

        # This should fail - 100^10 > 1,000,000 points
        with pytest.raises(ValueError) as exc_info:
            LatticeParameters(dimensions=10, size=100)
        assert "Lattice too large" in str(exc_info.value)

    def test_optional_fields(self):
        """Test optional field defaults"""
        params = LatticeParameters(dimensions=3, size=5)

        # Check defaults
        assert params.auxiliary_memory == 10.0
        assert params.algorithm == "dijkstra"

    @pytest.mark.parametrize(
        "invalid_data,expected_error",
        [
            ({"dimensions": "three", "size": 10}, ValueError),
            ({"dimensions": 3.5, "size": 10}, ValueError),
            ({"dimensions": 3, "size": "ten"}, ValueError),
            ({"dimensions": None, "size": 10}, ValueError),
            ({}, ValueError),  # Missing required fields
        ],
    )
    def test_invalid_lattice_parameters(self, invalid_data, expected_error):
        """Test invalid lattice parameter inputs"""
        with pytest.raises(expected_error):
            LatticeParameters(**invalid_data)


class TestWebhookConfigModel:
    """Test WebhookConfig Pydantic model"""

    def test_valid_webhook_config(self, sample_webhook_config):
        """Test valid webhook configuration"""
        config = WebhookConfig(**sample_webhook_config)

        assert config.url == sample_webhook_config["url"]
        assert config.events == sample_webhook_config["events"]
        assert config.secret == sample_webhook_config["secret"]
        assert config.active == sample_webhook_config["active"]

    def test_url_validation(self):
        """Test URL format validation"""
        # Valid URLs
        valid_urls = [
            "https://example.com/webhook",
            "http://api.service.com/hook",
            "https://webhook.io/v1/events",
        ]

        for url in valid_urls:
            config = WebhookConfig(url=url, events=["test.event"])
            assert config.url == url

        # Invalid URLs
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "https://",
            "",
        ]

        for url in invalid_urls:
            with pytest.raises(ValueError):
                WebhookConfig(url=url, events=["test.event"])

    def test_localhost_warning(self):
        """Test that localhost URLs trigger warning"""
        # Should work but with warning
        config = WebhookConfig(url="http://localhost:8080/webhook", events=["test.event"])
        assert "localhost" in config.url

    def test_secret_validation(self):
        """Test secret length requirements"""
        # Valid secret (16+ chars)
        config = WebhookConfig(
            url="https://example.com", events=["test"], secret="this_is_16_chars"
        )
        assert config.secret == "this_is_16_chars"

        # Too short secret
        with pytest.raises(ValueError):
            WebhookConfig(url="https://example.com", events=["test"], secret="short")

    def test_retry_and_timeout_bounds(self):
        """Test retry count and timeout boundaries"""
        # Valid values
        config = WebhookConfig(
            url="https://example.com", events=["test"], retry_count=5, timeout=150
        )
        assert config.retry_count == 5
        assert config.timeout == 150

        # Invalid retry count
        with pytest.raises(ValueError):
            WebhookConfig(
                url="https://example.com",
                events=["test"],
                retry_count=11,  # Max is 10
            )

        # Invalid timeout
        with pytest.raises(ValueError):
            WebhookConfig(
                url="https://example.com",
                events=["test"],
                timeout=301,  # Max is 300
            )


class TestPaginationParamsModel:
    """Test PaginationParams Pydantic model"""

    def test_default_pagination(self):
        """Test default pagination values"""
        params = PaginationParams()

        assert params.page == 1
        assert params.page_size == 100
        assert params.sort_order == "asc"
        assert params.sort_by is None

    def test_offset_calculation(self):
        """Test offset property calculation"""
        params = PaginationParams(page=1, page_size=20)
        assert params.offset == 0

        params = PaginationParams(page=2, page_size=20)
        assert params.offset == 20

        params = PaginationParams(page=5, page_size=50)
        assert params.offset == 200

    def test_page_size_limits(self):
        """Test page size boundaries"""
        # Maximum page size
        params = PaginationParams(page_size=1000)
        assert params.page_size == 1000

        # Exceeds maximum
        with pytest.raises(ValueError):
            PaginationParams(page_size=1001)

        # Below minimum
        with pytest.raises(ValueError):
            PaginationParams(page_size=0)

    def test_sort_order_validation(self):
        """Test sort order validation"""
        params_asc = PaginationParams(sort_order="asc")
        assert params_asc.sort_order == "asc"

        params_desc = PaginationParams(sort_order="desc")
        assert params_desc.sort_order == "desc"

        # Invalid sort order
        with pytest.raises(ValueError):
            PaginationParams(sort_order="invalid")


class TestValidationFunctions:
    """Test individual validation functions"""

    def test_validate_dimensions(self):
        """Test dimension validation function"""
        # Valid dimensions
        assert validate_dimensions(5) == 5
        assert validate_dimensions("3") == 3

        # Invalid dimensions
        with pytest.raises(CustomValidationError) as exc_info:
            validate_dimensions(0)
        assert "dimensions" in exc_info.value.details.get("field", "")

        with pytest.raises(CustomValidationError):
            validate_dimensions(11)

        with pytest.raises(CustomValidationError):
            validate_dimensions("invalid")

    def test_validate_lattice_size(self):
        """Test lattice size validation"""
        # Valid sizes
        assert validate_lattice_size(10) == 10
        assert validate_lattice_size("50", dimensions=3) == 50

        # Invalid sizes
        with pytest.raises(CustomValidationError):
            validate_lattice_size(1)  # Too small

        with pytest.raises(CustomValidationError):
            validate_lattice_size(101)  # Too large

        # Total points check
        with pytest.raises(CustomValidationError) as exc_info:
            validate_lattice_size(100, dimensions=10)  # 100^10 > 1M
        assert "Total points" in str(exc_info.value.message)

    def test_validate_coordinates(self):
        """Test coordinate validation"""
        # Valid coordinates
        coords = validate_coordinates([0, 5, 9], dimensions=3, lattice_size=10)
        assert coords == [0, 5, 9]

        # Wrong number of dimensions
        with pytest.raises(CustomValidationError) as exc_info:
            validate_coordinates([1, 2], dimensions=3, lattice_size=10)
        assert "Expected 3 coordinates" in str(exc_info.value.message)

        # Out of bounds
        with pytest.raises(CustomValidationError):
            validate_coordinates([0, 10, 5], dimensions=3, lattice_size=10)

        # Non-integer coordinates
        with pytest.raises(CustomValidationError):
            validate_coordinates([1.5, 2, 3], dimensions=3, lattice_size=10)

    def test_validate_port(self):
        """Test port number validation"""
        # Valid ports
        assert validate_port(8080) == 8080
        assert validate_port("3000") == 3000

        # Invalid ports
        with pytest.raises(CustomValidationError):
            validate_port(0)

        with pytest.raises(CustomValidationError):
            validate_port(65536)

        with pytest.raises(CustomValidationError):
            validate_port("not_a_port")

    def test_validate_url(self):
        """Test URL validation"""
        # Valid URLs
        assert validate_url("https://example.com") == "https://example.com"
        assert validate_url("http://api.service.io/v1") == "http://api.service.io/v1"

        # Invalid URLs
        with pytest.raises(CustomValidationError):
            validate_url("not a url")

        with pytest.raises(CustomValidationError):
            validate_url("ftp://example.com")

        # HTTPS requirement
        with pytest.raises(CustomValidationError):
            validate_url("http://example.com", require_https=True)

        # URL too long
        long_url = "https://example.com/" + "a" * 2048
        with pytest.raises(CustomValidationError):
            validate_url(long_url)

    def test_validate_email(self):
        """Test email validation"""
        # Valid emails
        assert validate_email("user@example.com") == "user@example.com"
        assert validate_email("Test.User@Company.co.uk") == "test.user@company.co.uk"

        # Invalid emails
        invalid_emails = [
            "not-an-email",
            "@example.com",
            "user@",
            "user@.com",
            "user space@example.com",
        ]

        for email in invalid_emails:
            with pytest.raises(CustomValidationError):
                validate_email(email)

    def test_validate_json(self):
        """Test JSON validation"""
        # Valid JSON string
        json_str = '{"key": "value", "number": 42}'
        result = validate_json(json_str)
        assert result["key"] == "value"
        assert result["number"] == 42

        # Already a dict
        data = {"test": True}
        result = validate_json(data)
        assert result == data

        # Invalid JSON
        with pytest.raises(CustomValidationError):
            validate_json("not json")

        with pytest.raises(CustomValidationError):
            validate_json('{"incomplete": ')

    def test_validate_file_path(self, tmp_path):
        """Test file path validation"""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # Valid existing file
        result = validate_file_path(str(test_file), must_exist=True, must_be_file=True)
        assert result == test_file

        # Valid directory
        result = validate_file_path(str(tmp_path), must_exist=True, must_be_directory=True)
        assert result == tmp_path

        # Non-existent path
        with pytest.raises(CustomValidationError):
            validate_file_path(str(tmp_path / "nonexistent.txt"), must_exist=True)

        # Wrong type (file vs directory)
        with pytest.raises(CustomValidationError):
            validate_file_path(str(test_file), must_be_directory=True)

        # Extension check
        with pytest.raises(CustomValidationError):
            validate_file_path(str(test_file), allowed_extensions=[".json", ".yaml"])

    def test_validate_memory_size(self):
        """Test memory size validation"""
        # Valid sizes
        assert validate_memory_size(10.5) == 10.5
        assert validate_memory_size("100") == 100.0

        # Invalid sizes
        with pytest.raises(CustomValidationError):
            validate_memory_size(-10)

        with pytest.raises(CustomValidationError):
            validate_memory_size(0)

        # Exceeds maximum
        with pytest.raises(CustomValidationError):
            validate_memory_size(MAX_AUX_MEMORY_MB + 1)

        # Custom maximum
        assert validate_memory_size(50, max_mb=100) == 50.0
        with pytest.raises(CustomValidationError):
            validate_memory_size(101, max_mb=100)

    def test_validate_percentage(self):
        """Test percentage validation"""
        # Valid percentages
        assert validate_percentage(0) == 0.0
        assert validate_percentage(50.5) == 50.5
        assert validate_percentage(100) == 100.0

        # Invalid percentages
        with pytest.raises(CustomValidationError):
            validate_percentage(-1)

        with pytest.raises(CustomValidationError):
            validate_percentage(101)

        with pytest.raises(CustomValidationError):
            validate_percentage("not a number")

        # Custom field name
        with pytest.raises(CustomValidationError) as exc_info:
            validate_percentage(150, field_name="cpu_usage")
        assert "cpu_usage" in str(exc_info.value)


class TestValidationDecorators:
    """Test validation decorator functions"""

    def test_validate_input_decorator(self):
        """Test input validation decorator"""

        @validate_input(x=lambda v: v > 0, y=lambda v: v < 100)
        def test_func(x: int, y: int) -> int:
            return x + y

        # Valid inputs
        result = test_func(10, 20)
        assert result == 30

        # Invalid x
        with pytest.raises(CustomValidationError):
            test_func(-1, 20)

        # Invalid y
        with pytest.raises(CustomValidationError):
            test_func(10, 100)

    def test_validate_type_decorator(self):
        """Test type validation decorator"""

        @validate_type(int, str, float)
        def test_func(a: int, b: str, c: float) -> str:
            return f"{a}-{b}-{c}"

        # Valid types
        result = test_func(42, "test", 3.14)
        assert result == "42-test-3.14"

        # Invalid type for first argument
        with pytest.raises(TypeError) as exc_info:
            test_func("42", "test", 3.14)
        assert "expected int" in str(exc_info.value)

        # Invalid type for third argument
        with pytest.raises(TypeError):
            test_func(42, "test", "3.14")


class TestBatchValidation:
    """Test batch validation functionality"""

    def test_validate_batch_success(self):
        """Test successful batch validation"""
        items = [
            {"dimensions": 3, "size": 10},
            {"dimensions": 4, "size": 8},
            {"dimensions": 5, "size": 5},
        ]

        valid_items, errors = validate_batch(items, LatticeParameters)

        assert len(valid_items) == 3
        assert len(errors) == 0
        assert all(isinstance(item, LatticeParameters) for item in valid_items)

    def test_validate_batch_with_errors(self):
        """Test batch validation with some errors"""
        items = [
            {"dimensions": 3, "size": 10},  # Valid
            {"dimensions": 0, "size": 10},  # Invalid dimensions
            {"dimensions": 4, "size": 8},  # Valid
            {"dimensions": 3, "size": 200},  # Invalid size
        ]

        valid_items, errors = validate_batch(items, LatticeParameters)

        assert len(valid_items) == 2
        assert len(errors) == 2

        # Check error structure
        assert errors[0]["index"] == 1
        assert errors[1]["index"] == 3
        assert "errors" in errors[0]

    def test_validate_batch_size_limit(self):
        """Test batch size limit"""
        items = [{"dimensions": 3, "size": 10}] * 1001  # Exceeds default max of 1000

        with pytest.raises(CustomValidationError) as exc_info:
            validate_batch(items, LatticeParameters)

        assert "Batch size exceeds maximum" in str(exc_info.value.message)

    def test_validate_batch_custom_limit(self):
        """Test batch validation with custom limit"""
        items = [{"dimensions": 3, "size": 10}] * 5

        # Should work with custom limit of 10
        valid_items, errors = validate_batch(items, LatticeParameters, max_items=10)
        assert len(valid_items) == 5

        # Should fail with custom limit of 3
        with pytest.raises(CustomValidationError):
            validate_batch(items, LatticeParameters, max_items=3)


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_none_inputs(self):
        """Test None input handling"""
        with pytest.raises(CustomValidationError):
            validate_dimensions(None)

        with pytest.raises(CustomValidationError):
            validate_port(None)

        with pytest.raises(CustomValidationError):
            validate_url(None)

    def test_empty_strings(self):
        """Test empty string handling"""
        with pytest.raises(CustomValidationError):
            validate_url("")

        with pytest.raises(CustomValidationError):
            validate_email("")

        with pytest.raises(CustomValidationError):
            validate_json("")

    def test_special_characters(self):
        """Test special character handling"""
        # URLs with special characters
        url = "https://example.com/path?query=value&other=123#fragment"
        result = validate_url(url)
        assert result == url

        # Email with dots and dashes
        email = "first.last-name+tag@sub.domain.com"
        result = validate_email(email)
        assert result == email.lower()

    def test_unicode_handling(self):
        """Test Unicode string handling"""
        # Unicode in JSON
        json_str = '{"name": "Tést Üsér", "emoji": "🚀"}'
        result = validate_json(json_str)
        assert result["name"] == "Tést Üsér"
        assert result["emoji"] == "🚀"

    def test_large_values(self):
        """Test handling of large values"""
        # Large but valid port
        assert validate_port(65535) == 65535

        # Large memory size at boundary
        assert validate_memory_size(MAX_AUX_MEMORY_MB) == MAX_AUX_MEMORY_MB

        # Large dimension with small size (should work)
        params = LatticeParameters(dimensions=10, size=2)  # 2^10 = 1024 points
        assert params.dimensions == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=validation"])
