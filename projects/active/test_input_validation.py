"""
Comprehensive test cases for input validation system
Tests string and floating point validation with various error scenarios
"""

from libraries.validation_errors import ValidationErrorHandler
from libraries.input_validation import (
    StringValidator,
    FloatValidator,
    TMUXConfigValidator,
    ValidationErrorType,
    ValidationError,
    validate_input,
    batch_validate,
)
import pytest
from pathlib import Path
import sys

# Add shared directory to path for testing
sys.path.insert(0, str(Path(__file__).parent / "shared"))


class TestStringValidator:
    """Test cases for string validation"""

    def test_valid_session_names(self):
        """Test valid session name inputs"""
        valid_names = [
            "dev-workflow",
            "test_session",
            "monitoring01",
            "my-dev-env",
            "workflow_engine_test",
        ]

        for name in valid_names:
            result = StringValidator.validate_session_name(name)
            assert result.is_valid, f"Failed for valid name: {name}"
            assert result.value == name
            assert result.sanitized_value == name

    def test_invalid_session_names(self):
        """Test invalid session name inputs"""
        invalid_cases = [
            ("", ValidationErrorType.EMPTY_VALUE),
            ("  ", ValidationErrorType.EMPTY_VALUE),
            ("a", ValidationErrorType.TOO_SHORT),
            ("x" * 51, ValidationErrorType.TOO_LONG),
            ("session with spaces", ValidationErrorType.INVALID_CHARACTERS),
            ("session@special", ValidationErrorType.INVALID_CHARACTERS),
            ("session.dot", ValidationErrorType.INVALID_CHARACTERS),
            (123, ValidationErrorType.INVALID_TYPE),
            (None, ValidationErrorType.INVALID_TYPE),
            ([], ValidationErrorType.INVALID_TYPE),
        ]

        for invalid_input, expected_error in invalid_cases:
            result = StringValidator.validate_session_name(invalid_input)
            assert not result.is_valid, f"Should fail for: {invalid_input}"
            assert result.error_type == expected_error

    def test_valid_commands(self):
        """Test valid command string inputs"""
        valid_commands = [
            "ls -la",
            "ps aux | grep python",
            "docker ps -a",
            "kubectl get pods",
            "tail -f /var/log/app.log",
            "python -m pytest tests/",
        ]

        for cmd in valid_commands:
            result = StringValidator.validate_command_string(cmd)
            assert result.is_valid, f"Failed for valid command: {cmd}"

    def test_dangerous_commands(self):
        """Test detection of dangerous commands"""
        dangerous_commands = [
            "rm -rf /",
            "sudo rm -rf /home",
            "format c:",
            "del /q /f c:\\*",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
        ]

        for cmd in dangerous_commands:
            result = StringValidator.validate_command_string(cmd)
            assert not result.is_valid, f"Should block dangerous command: {cmd}"
            assert result.error_type == ValidationErrorType.INVALID_CHARACTERS

    def test_valid_file_paths(self):
        """Test valid file path inputs"""
        valid_paths = [
            "/home/user/file.txt",
            "C:\\Users\\User\\Documents\\file.doc",
            "./relative/path.py",
            "../parent/file.json",
            "/var/log/application.log",
        ]

        for path in valid_paths:
            result = StringValidator.validate_file_path(path, must_exist=False)
            assert result.is_valid, f"Failed for valid path: {path}"
            assert result.sanitized_value is not None

    def test_invalid_file_paths(self):
        """Test invalid file path inputs"""
        invalid_paths = [
            "file<invalid>.txt",
            "file>invalid.txt",
            'file"invalid.txt',
            "file|invalid.txt",
            "file?invalid.txt",
            "file*invalid.txt",
            "",
            "   ",
        ]

        for path in invalid_paths:
            result = StringValidator.validate_file_path(path)
            assert not result.is_valid, f"Should fail for invalid path: {path}"


class TestFloatValidator:
    """Test cases for floating point validation"""

    def test_valid_timeout_values(self):
        """Test valid timeout value inputs"""
        valid_timeouts = [0.1, 1.0, 5.5, 30.0, 300.0, 3600.0, "0.5", "10", "60.0"]

        for timeout in valid_timeouts:
            result = FloatValidator.validate_timeout_value(timeout)
            assert result.is_valid, f"Failed for valid timeout: {timeout}"
            assert isinstance(result.value, float)
            assert 0.1 <= result.value <= 3600.0

    def test_invalid_timeout_values(self):
        """Test invalid timeout value inputs"""
        invalid_timeouts = [
            (-1.0, ValidationErrorType.OUT_OF_RANGE),
            (0.05, ValidationErrorType.OUT_OF_RANGE),
            (4000.0, ValidationErrorType.OUT_OF_RANGE),
            ("invalid", ValidationErrorType.INVALID_FORMAT),
            (None, ValidationErrorType.INVALID_TYPE),
            ([], ValidationErrorType.INVALID_TYPE),
            (float("nan"), ValidationErrorType.SPECIAL_VALUE),
            (float("inf"), ValidationErrorType.SPECIAL_VALUE),
            ("", ValidationErrorType.EMPTY_VALUE),
        ]

        for invalid_input, expected_error in invalid_timeouts:
            result = FloatValidator.validate_timeout_value(invalid_input)
            assert not result.is_valid, f"Should fail for: {invalid_input}"
            assert result.error_type == expected_error

    def test_valid_percentages(self):
        """Test valid percentage inputs"""
        valid_percentages = [0.0, 25.5, 50.0, 75.75, 100.0, "50", "0.1"]

        for percentage in valid_percentages:
            result = FloatValidator.validate_percentage(percentage)
            assert result.is_valid, f"Failed for valid percentage: {percentage}"
            assert 0.0 <= result.value <= 100.0

    def test_valid_scale_factors(self):
        """Test valid scaling factor inputs"""
        valid_factors = [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, "1.5", "3"]

        for factor in valid_factors:
            result = FloatValidator.validate_scale_factor(factor)
            assert result.is_valid, f"Failed for valid scale factor: {factor}"
            assert 0.1 <= result.value <= 10.0

    def test_memory_size_validation(self):
        """Test memory size validation"""
        valid_sizes = [0.1, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0]

        for size in valid_sizes:
            result = FloatValidator.validate_memory_size_gb(size)
            assert result.is_valid, f"Failed for valid memory size: {size}"

        # Test invalid sizes
        invalid_sizes = [0.05, 2000.0]
        for size in invalid_sizes:
            result = FloatValidator.validate_memory_size_gb(size)
            assert not result.is_valid, f"Should fail for invalid memory size: {size}"

    def test_cpu_cores_validation(self):
        """Test CPU cores validation"""
        valid_cores = [0.1, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0]

        for cores in valid_cores:
            result = FloatValidator.validate_cpu_cores(cores)
            assert result.is_valid, f"Failed for valid CPU cores: {cores}"

    def test_floating_point_precision(self):
        """Test floating point precision handling"""
        # Test that precision is handled correctly
        result = FloatValidator.validate_timeout_value(1.123456789)
        assert result.is_valid
        assert result.sanitized_value == round(1.123456789, 6)


class TestTMUXConfigValidator:
    """Test cases for TMUX configuration validation"""

    def test_valid_window_sizes(self):
        """Test valid window size inputs"""
        valid_sizes = [
            (80, 24),  # Standard terminal
            (120, 40),  # Larger terminal
            (100, 50),  # Square-ish
            ("80", "24"),  # String inputs
        ]

        for width, height in valid_sizes:
            result = TMUXConfigValidator.validate_window_size(width, height)
            assert result.is_valid, f"Failed for valid size: {width}x{height}"
            assert isinstance(result.value, tuple)
            assert len(result.value) == 2

    def test_invalid_window_sizes(self):
        """Test invalid window size inputs"""
        invalid_sizes = [
            (10, 24),  # Width too small
            (80, 2),  # Height too small
            (600, 24),  # Width too large
            (80, 300),  # Height too large
            ("invalid", 24),  # Invalid width
            (80, "invalid"),  # Invalid height
        ]

        for width, height in invalid_sizes:
            result = TMUXConfigValidator.validate_window_size(width, height)
            assert (
                not result.is_valid
            ), f"Should fail for invalid size: {width}x{height}"

    def test_valid_key_bindings(self):
        """Test valid key binding inputs"""
        valid_bindings = [
            "C-a",  # Ctrl+a
            "M-x",  # Alt+x
            "S-F",  # Shift+F
            "w",  # Single letter
            "F1",  # Function key
            "F12",  # Function key
        ]

        for binding in valid_bindings:
            result = TMUXConfigValidator.validate_key_binding(binding)
            assert result.is_valid, f"Failed for valid binding: {binding}"

    def test_invalid_key_bindings(self):
        """Test invalid key binding inputs"""
        invalid_bindings = [
            "Ctrl-a",  # Wrong format
            "Alt-x",  # Wrong format
            "C-",  # Missing key
            "C-aa",  # Too long
            "F13",  # Invalid function key
            "",  # Empty
            123,  # Wrong type
            "C-@",  # Invalid character
        ]

        for binding in invalid_bindings:
            result = TMUXConfigValidator.validate_key_binding(binding)
            assert not result.is_valid, f"Should fail for invalid binding: {binding}"


class TestValidationErrorHandler:
    """Test cases for validation error handling"""

    def test_error_handling(self):
        """Test error message generation"""
        handler = ValidationErrorHandler()

        # Test invalid session name
        result = StringValidator.validate_session_name("")
        error_response = handler.handle_validation_error(result, "session_name")

        assert not error_response["success"]
        assert error_response["field"] == "session_name"
        assert "suggestions" in error_response
        assert isinstance(error_response["suggestions"], list)

    def test_multiple_error_formatting(self):
        """Test formatting of multiple validation errors"""
        handler = ValidationErrorHandler()

        errors = {
            "session": StringValidator.validate_session_name(""),
            "timeout": FloatValidator.validate_timeout_value(-1.0),
            "memory": FloatValidator.validate_memory_size_gb(2000.0),
        }

        formatted = handler.format_multiple_errors(errors, "TMUX Configuration")

        assert not formatted["success"]
        assert formatted["total_errors"] == 3
        assert len(formatted["errors"]) == 3

    def test_success_handling(self):
        """Test handling of successful validations"""
        handler = ValidationErrorHandler()

        result = StringValidator.validate_session_name("valid-session")
        response = handler.handle_validation_error(result, "session_name")

        assert response["success"]
        assert "value" in response

    def test_validation_tips(self):
        """Test validation tips generation"""
        handler = ValidationErrorHandler()

        tips = handler.get_validation_tips("session_name")
        assert isinstance(tips, list)
        assert len(tips) > 0

        tips = handler.get_validation_tips("unknown_type")
        assert isinstance(tips, list)
        assert len(tips) > 0


class TestBatchValidation:
    """Test cases for batch validation functionality"""

    def test_batch_validation_success(self):
        """Test successful batch validation"""
        validations = [
            ("valid-session", StringValidator.validate_session_name),
            (30.0, FloatValidator.validate_timeout_value),
            (2.0, FloatValidator.validate_memory_size_gb),
        ]

        results = batch_validate(validations)

        assert len(results) == 3
        for result in results.values():
            assert result.is_valid

    def test_batch_validation_mixed_results(self):
        """Test batch validation with mixed success/failure"""
        validations = [
            ("", StringValidator.validate_session_name),  # Invalid
            (30.0, FloatValidator.validate_timeout_value),  # Valid
            (-1.0, FloatValidator.validate_memory_size_gb),  # Invalid
        ]

        results = batch_validate(validations)

        assert len(results) == 3
        assert not results["field_0"].is_valid  # Empty session name
        assert results["field_1"].is_valid  # Valid timeout
        assert not results["field_2"].is_valid  # Invalid memory


class TestValidationError:
    """Test cases for ValidationError exception"""

    def test_validation_error_creation(self):
        """Test ValidationError exception creation"""
        result = StringValidator.validate_session_name("")

        with pytest.raises(ValidationError) as exc_info:
            validate_input(
                StringValidator.validate_session_name, "", raise_on_error=True
            )

        assert exc_info.value.result == result

    def test_validation_no_error_on_success(self):
        """Test that no error is raised for valid inputs"""
        result = validate_input(
            StringValidator.validate_session_name, "valid-session", raise_on_error=True
        )

        assert result.is_valid


def run_validation_performance_test():
    """Performance test for validation functions"""
    import time

    print("Running validation performance tests...")

    # Test string validation performance
    start_time = time.time()
    for i in range(1000):
        StringValidator.validate_session_name(f"session-{i}")
    string_time = time.time() - start_time

    # Test float validation performance
    start_time = time.time()
    for i in range(1000):
        FloatValidator.validate_timeout_value(float(i % 100))
    float_time = time.time() - start_time

    print(f"String validation: {string_time:.4f}s for 1000 iterations")
    print(f"Float validation: {float_time:.4f}s for 1000 iterations")
    print(f"Total validation time: {string_time + float_time:.4f}s")


if __name__ == "__main__":
    # Run basic test verification
    print("Running input validation tests...")

    # Test string validation
    print("Testing string validation...")
    test_string = TestStringValidator()
    test_string.test_valid_session_names()
    test_string.test_invalid_session_names()
    print("[OK] String validation tests passed")

    # Test float validation
    print("Testing float validation...")
    test_float = TestFloatValidator()
    test_float.test_valid_timeout_values()
    test_float.test_invalid_timeout_values()
    print("[OK] Float validation tests passed")

    # Test TMUX config validation
    print("Testing TMUX config validation...")
    test_tmux = TestTMUXConfigValidator()
    test_tmux.test_valid_window_sizes()
    test_tmux.test_valid_key_bindings()
    print("[OK] TMUX config validation tests passed")

    # Test error handling
    print("Testing error handling...")
    test_errors = TestValidationErrorHandler()
    test_errors.test_error_handling()
    test_errors.test_multiple_error_formatting()
    print("[OK] Error handling tests passed")

    # Run performance test
    run_validation_performance_test()

    print("\nAll validation tests completed successfully!")
    print("\nTo run with pytest:")
    print("pytest test_input_validation.py -v")
