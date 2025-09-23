"""
Error handling and user feedback for validation failures
Provides user-friendly error messages and recovery suggestions
"""

from typing import Dict, List, Optional, Any
from .input_validation import ValidationResult, ValidationErrorType
import logging


class ValidationErrorHandler:
    """Handles validation errors and provides user feedback"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.error_counts = {}

    def handle_validation_error(
        self, result: ValidationResult, field_name: str, user_context: str = ""
    ) -> Dict[str, Any]:
        """Handle validation error and provide user feedback"""

        if result.is_valid:
            return {"success": True, "value": result.sanitized_value or result.value}

        # Track error frequency
        error_key = f"{field_name}:{result.error_type.value}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1

        # Log the error
        self.logger.warning(
            f"Validation failed for {field_name}: {result.error_message}"
        )

        # Generate user-friendly message with suggestions
        user_message = self._generate_user_message(result, field_name)
        suggestions = self._get_recovery_suggestions(result, field_name)

        error_response = {
            "success": False,
            "field": field_name,
            "error_type": result.error_type.value,
            "message": user_message,
            "suggestions": suggestions,
            "context": user_context,
        }

        # Add frequency warning if this error occurs often
        if self.error_counts[error_key] > 3:
            error_response["frequency_warning"] = (
                f"This error has occurred {self.error_counts[error_key]} times. "
                "Consider reviewing the input requirements."
            )

        return error_response

    def _generate_user_message(self, result: ValidationResult, field_name: str) -> str:
        """Generate user-friendly error message"""

        base_messages = {
            ValidationErrorType.INVALID_TYPE: f"The {field_name} must be a valid data type.",
            ValidationErrorType.OUT_OF_RANGE: f"The {field_name} value is outside the allowed range.",
            ValidationErrorType.INVALID_FORMAT: f"The {field_name} format is not recognized.",
            ValidationErrorType.EMPTY_VALUE: f"The {field_name} cannot be empty.",
            ValidationErrorType.TOO_LONG: f"The {field_name} is too long.",
            ValidationErrorType.TOO_SHORT: f"The {field_name} is too short.",
            ValidationErrorType.INVALID_CHARACTERS: f"The {field_name} contains invalid characters.",
            ValidationErrorType.SPECIAL_VALUE: f"The {field_name} contains a special value that's not allowed.",
        }

        base_message = base_messages.get(
            result.error_type, f"There was a problem with the {field_name}."
        )

        # Add specific details from the validation result
        if result.error_message:
            return f"{base_message} {result.error_message}"

        return base_message

    def _get_recovery_suggestions(
        self, result: ValidationResult, field_name: str
    ) -> List[str]:
        """Get suggestions for fixing the validation error"""

        suggestions = []

        if result.error_type == ValidationErrorType.INVALID_TYPE:
            if "string" in str(result.error_message).lower():
                suggestions.append(
                    "Ensure the input is provided as text, not a number or other data type"
                )
            elif "float" in str(result.error_message).lower():
                suggestions.append(
                    "Ensure the input is a decimal number (e.g., 1.5, 3.14)"
                )
            elif "int" in str(result.error_message).lower():
                suggestions.append(
                    "Ensure the input is a whole number (e.g., 1, 42, 100)"
                )

        elif result.error_type == ValidationErrorType.OUT_OF_RANGE:
            suggestions.append(
                "Check the allowed range and adjust your input accordingly"
            )
            if "timeout" in field_name.lower():
                suggestions.append(
                    "Timeout values should be between 0.1 and 3600 seconds"
                )
            elif "percentage" in field_name.lower():
                suggestions.append("Percentage values should be between 0 and 100")
            elif "memory" in field_name.lower():
                suggestions.append("Memory sizes should be between 0.1 GB and 1024 GB")

        elif result.error_type == ValidationErrorType.INVALID_FORMAT:
            if "session" in field_name.lower():
                suggestions.append(
                    "Session names should only contain letters, numbers, dashes, and underscores"
                )
                suggestions.append("Examples: 'my-session', 'workflow_001', 'dev-env'")
            elif "path" in field_name.lower():
                suggestions.append("Use forward slashes (/) for path separators")
                suggestions.append('Avoid special characters like <, >, :, ", |, ?, *')
            elif "command" in field_name.lower():
                suggestions.append("Ensure the command is a valid shell command")
                suggestions.append("Avoid potentially dangerous operations")

        elif result.error_type == ValidationErrorType.EMPTY_VALUE:
            suggestions.append("Provide a non-empty value for this field")
            if "session" in field_name.lower():
                suggestions.append("Session names should be at least 2 characters long")

        elif result.error_type == ValidationErrorType.TOO_LONG:
            suggestions.append(
                "Shorten the input to meet the maximum length requirement"
            )
            if "session" in field_name.lower():
                suggestions.append("Session names should be 50 characters or less")
            elif "command" in field_name.lower():
                suggestions.append("Commands should be 1000 characters or less")

        elif result.error_type == ValidationErrorType.TOO_SHORT:
            suggestions.append(
                "Provide a longer input to meet the minimum length requirement"
            )
            if "session" in field_name.lower():
                suggestions.append("Session names should be at least 2 characters")

        elif result.error_type == ValidationErrorType.INVALID_CHARACTERS:
            if "session" in field_name.lower():
                suggestions.append(
                    "Use only letters (a-z, A-Z), numbers (0-9), dashes (-), and underscores (_)"
                )
            elif "command" in field_name.lower():
                suggestions.append(
                    "The command contains potentially dangerous operations"
                )
                suggestions.append("Review the command for safety before proceeding")
            else:
                suggestions.append("Remove or replace invalid characters")

        elif result.error_type == ValidationErrorType.SPECIAL_VALUE:
            suggestions.append(
                "The input contains a special mathematical value (NaN or infinity)"
            )
            suggestions.append("Provide a regular numeric value instead")

        # Add generic recovery suggestions
        if not suggestions:
            suggestions.append("Check the input format and try again")
            suggestions.append("Refer to the documentation for valid input examples")

        return suggestions

    def format_multiple_errors(
        self, errors: Dict[str, ValidationResult], context: str = ""
    ) -> Dict[str, Any]:
        """Format multiple validation errors for user display"""

        error_details = []
        total_errors = 0

        for field_name, result in errors.items():
            if not result.is_valid:
                total_errors += 1
                error_info = self.handle_validation_error(result, field_name, context)
                error_details.append(error_info)

        if total_errors == 0:
            return {"success": True, "message": "All validations passed successfully"}

        summary_message = (
            f"Found {total_errors} validation error{'s' if total_errors > 1 else ''}"
        )
        if context:
            summary_message += f" in {context}"

        return {
            "success": False,
            "summary": summary_message,
            "total_errors": total_errors,
            "errors": error_details,
            "context": context,
        }

    def get_validation_tips(self, field_type: str) -> List[str]:
        """Get general validation tips for different field types"""

        tips = {
            "session_name": [
                "Use descriptive but concise names",
                "Stick to alphanumeric characters, dashes, and underscores",
                "Examples: 'dev-workflow', 'monitoring_01', 'test-env'",
            ],
            "timeout": [
                "Use decimal numbers for sub-second timeouts (e.g., 0.5)",
                "Common values: 1.0 (1 second), 30.0 (30 seconds), 300.0 (5 minutes)",
                "Maximum timeout is 1 hour (3600 seconds)",
            ],
            "memory_size": [
                "Specify memory in GB (e.g., 2.5 for 2.5 GB)",
                "Common values: 0.5, 1.0, 2.0, 4.0, 8.0",
                "Consider your system's available memory",
            ],
            "cpu_cores": [
                "Can use fractional values for containers (e.g., 0.5, 1.5)",
                "Common values: 0.5, 1.0, 2.0, 4.0",
                "Don't exceed your system's CPU count",
            ],
            "file_path": [
                "Use absolute paths when possible",
                "Use forward slashes (/) as separators",
                "Avoid spaces in paths or use quotes",
            ],
            "command": [
                "Test commands manually before using in automation",
                "Avoid destructive operations like 'rm -rf'",
                "Use full paths for executables when possible",
            ],
        }

        return tips.get(
            field_type,
            [
                "Follow the field's specific format requirements",
                "Check for typos and extra spaces",
                "Refer to examples in the documentation",
            ],
        )

    def reset_error_counts(self):
        """Reset error frequency tracking"""
        self.error_counts.clear()
        self.logger.info("Validation error counts reset")
