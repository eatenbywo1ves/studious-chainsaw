"""
Input validation utilities for TMUX integration system
Provides comprehensive validation for string and floating point inputs
"""

import re
import math
from typing import Any, Optional, Tuple, List, Dict
from dataclasses import dataclass
from enum import Enum


class ValidationErrorType(Enum):
    """Types of validation errors"""

    INVALID_TYPE = "invalid_type"
    OUT_OF_RANGE = "out_of_range"
    INVALID_FORMAT = "invalid_format"
    EMPTY_VALUE = "empty_value"
    TOO_LONG = "too_long"
    TOO_SHORT = "too_short"
    INVALID_CHARACTERS = "invalid_characters"
    SPECIAL_VALUE = "special_value"


@dataclass
class ValidationResult:
    """Result of input validation"""

    is_valid: bool
    value: Any = None
    error_type: Optional[ValidationErrorType] = None
    error_message: Optional[str] = None
    sanitized_value: Any = None


class StringValidator:
    """Validates and sanitizes string inputs"""

    @staticmethod
    def validate_session_name(value: Any) -> ValidationResult:
        """Validate TMUX session name"""
        if not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.INVALID_TYPE,
                error_message=f"Session name must be a string, got {type(value).__name__}",
            )

        if not value or value.isspace():
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.EMPTY_VALUE,
                error_message="Session name cannot be empty or whitespace",
            )

        if len(value) > 50:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.TOO_LONG,
                error_message="Session name cannot exceed 50 characters",
            )

        if len(value) < 2:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.TOO_SHORT,
                error_message="Session name must be at least 2 characters",
            )

        # TMUX session names should only contain alphanumeric, dash, underscore
        pattern = r"^[a-zA-Z0-9_-]+$"
        if not re.match(pattern, value):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.INVALID_CHARACTERS,
                error_message="Session name can only contain letters, numbers, dashes, and underscores",
            )

        # Sanitize by removing any potentially problematic characters
        sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", value)

        return ValidationResult(is_valid=True, value=value, sanitized_value=sanitized)

    @staticmethod
    def validate_command_string(value: Any, max_length: int = 1000) -> ValidationResult:
        """Validate shell command string"""
        if not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.INVALID_TYPE,
                error_message=f"Command must be a string, got {type(value).__name__}",
            )

        if not value or value.isspace():
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.EMPTY_VALUE,
                error_message="Command cannot be empty",
            )

        if len(value) > max_length:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.TOO_LONG,
                error_message=f"Command cannot exceed {max_length} characters",
            )

        # Check for potentially dangerous command patterns
        dangerous_patterns = [
            r"rm\s+-rf\s+/",
            r"sudo\s+rm",
            r"format\s+c:",
            r"del\s+/[qsf]",
            r"mkfs\.",
            r"dd\s+if=/dev/zero",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return ValidationResult(
                    is_valid=False,
                    error_type=ValidationErrorType.INVALID_CHARACTERS,
                    error_message="Command contains potentially dangerous operations",
                )

        # Basic sanitization - escape special shell characters
        sanitized = value.replace(";", "\\;").replace("&", "\\&").replace("|", "\\|")

        return ValidationResult(is_valid=True, value=value, sanitized_value=sanitized)

    @staticmethod
    def validate_file_path(value: Any, must_exist: bool = False) -> ValidationResult:
        """Validate file path string"""
        if not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.INVALID_TYPE,
                error_message=f"File path must be a string, got {type(value).__name__}",
            )

        if not value or value.isspace():
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.EMPTY_VALUE,
                error_message="File path cannot be empty",
            )

        # Check for invalid path characters
        invalid_chars = ["<", ">", ":", '"', "|", "?", "*"]
        for char in invalid_chars:
            if char in value:
                return ValidationResult(
                    is_valid=False,
                    error_type=ValidationErrorType.INVALID_CHARACTERS,
                    error_message=f"File path contains invalid character: {char}",
                )

        if must_exist:
            from pathlib import Path

            if not Path(value).exists():
                return ValidationResult(
                    is_valid=False,
                    error_type=ValidationErrorType.INVALID_FORMAT,
                    error_message=f"File path does not exist: {value}",
                )

        # Normalize path separators
        import os

        sanitized = os.path.normpath(value)

        return ValidationResult(is_valid=True, value=value, sanitized_value=sanitized)


class FloatValidator:
    """Validates and sanitizes floating point inputs"""

    @staticmethod
    def validate_timeout_value(value: Any) -> ValidationResult:
        """Validate timeout value in seconds"""
        return FloatValidator._validate_float_range(
            value=value,
            min_value=0.1,
            max_value=3600.0,
            field_name="timeout",  # 1 hour max
        )

    @staticmethod
    def validate_percentage(value: Any) -> ValidationResult:
        """Validate percentage value (0.0 to 100.0)"""
        return FloatValidator._validate_float_range(
            value=value, min_value=0.0, max_value=100.0, field_name="percentage"
        )

    @staticmethod
    def validate_scale_factor(value: Any) -> ValidationResult:
        """Validate scaling factor (0.1 to 10.0)"""
        return FloatValidator._validate_float_range(
            value=value, min_value=0.1, max_value=10.0, field_name="scale_factor"
        )

    @staticmethod
    def validate_memory_size_gb(value: Any) -> ValidationResult:
        """Validate memory size in GB"""
        return FloatValidator._validate_float_range(
            value=value,
            min_value=0.1,
            max_value=1024.0,
            field_name="memory_size_gb",  # 1TB max
        )

    @staticmethod
    def validate_cpu_cores(value: Any) -> ValidationResult:
        """Validate CPU cores (can be fractional for containers)"""
        return FloatValidator._validate_float_range(
            value=value, min_value=0.1, max_value=128.0, field_name="cpu_cores"
        )

    @staticmethod
    def _validate_float_range(
        value: Any, min_value: float, max_value: float, field_name: str
    ) -> ValidationResult:
        """Generic float range validation"""

        # Try to convert to float
        try:
            if isinstance(value, str):
                # Handle common string representations
                value = value.strip()
                if not value:
                    return ValidationResult(
                        is_valid=False,
                        error_type=ValidationErrorType.EMPTY_VALUE,
                        error_message=f"{field_name} cannot be empty",
                    )

                float_value = float(value)
            elif isinstance(value, (int, float)):
                float_value = float(value)
            else:
                return ValidationResult(
                    is_valid=False,
                    error_type=ValidationErrorType.INVALID_TYPE,
                    error_message=f"{field_name} must be a number, got {type(value).__name__}",
                )

        except (ValueError, TypeError):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.INVALID_FORMAT,
                error_message=f"{field_name} must be a valid number",
            )

        # Check for special float values
        if math.isnan(float_value):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.SPECIAL_VALUE,
                error_message=f"{field_name} cannot be NaN",
            )

        if math.isinf(float_value):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.SPECIAL_VALUE,
                error_message=f"{field_name} cannot be infinite",
            )

        # Check range
        if float_value < min_value:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.OUT_OF_RANGE,
                error_message=f"{field_name} must be at least {min_value}, got {float_value}",
            )

        if float_value > max_value:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.OUT_OF_RANGE,
                error_message=f"{field_name} cannot exceed {max_value}, got {float_value}",
            )

        # Round to reasonable precision (avoid floating point precision issues)
        sanitized_value = round(float_value, 6)

        return ValidationResult(
            is_valid=True, value=float_value, sanitized_value=sanitized_value
        )


class TMUXConfigValidator:
    """Validates TMUX-specific configuration parameters"""

    @staticmethod
    def validate_window_size(width: Any, height: Any) -> ValidationResult:
        """Validate TMUX window dimensions"""
        width_result = FloatValidator._validate_float_range(
            width, 20, 500, "window_width"
        )
        if not width_result.is_valid:
            return width_result

        height_result = FloatValidator._validate_float_range(
            height, 5, 200, "window_height"
        )
        if not height_result.is_valid:
            return height_result

        return ValidationResult(
            is_valid=True,
            value=(int(width_result.value), int(height_result.value)),
            sanitized_value=(
                int(width_result.sanitized_value),
                int(height_result.sanitized_value),
            ),
        )

    @staticmethod
    def validate_key_binding(value: Any) -> ValidationResult:
        """Validate TMUX key binding string"""
        if not isinstance(value, str):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.INVALID_TYPE,
                error_message=f"Key binding must be a string, got {type(value).__name__}",
            )

        if not value or value.isspace():
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.EMPTY_VALUE,
                error_message="Key binding cannot be empty",
            )

        # Valid key binding patterns for TMUX
        valid_patterns = [
            r"^C-[a-zA-Z]$",  # Ctrl+letter
            r"^M-[a-zA-Z]$",  # Alt+letter
            r"^S-[a-zA-Z]$",  # Shift+letter
            r"^[a-zA-Z]$",  # Single letter
            r"^F[1-9][0-2]?$",  # Function keys F1-F12
        ]

        is_valid_pattern = any(re.match(pattern, value) for pattern in valid_patterns)
        if not is_valid_pattern:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.INVALID_FORMAT,
                error_message=f"Invalid key binding format: {value}",
            )

        return ValidationResult(
            is_valid=True, value=value, sanitized_value=value.upper()
        )


class ValidationError(Exception):
    """Custom exception for validation errors"""

    def __init__(self, result: ValidationResult):
        self.result = result
        super().__init__(result.error_message)


def validate_input(
    validator_func, value: Any, raise_on_error: bool = False
) -> ValidationResult:
    """Generic validation wrapper with error handling"""
    try:
        result = validator_func(value)

        if not result.is_valid and raise_on_error:
            raise ValidationError(result)

        return result

    except Exception as e:
        if isinstance(e, ValidationError):
            raise

        error_result = ValidationResult(
            is_valid=False,
            error_type=ValidationErrorType.INVALID_TYPE,
            error_message=f"Validation failed with error: {str(e)}",
        )

        if raise_on_error:
            raise ValidationError(error_result)

        return error_result


def batch_validate(
    validations: List[Tuple[Any, callable]],
) -> Dict[str, ValidationResult]:
    """Validate multiple inputs in batch"""
    results = {}

    for i, (value, validator) in enumerate(validations):
        field_name = f"field_{i}"
        results[field_name] = validate_input(validator, value)

    return results
