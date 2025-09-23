"""
Demonstration of input validation system for TMUX integration
Shows string and floating point validation with error handling
"""

import sys
from pathlib import Path

# Add shared directory to path
sys.path.insert(0, str(Path(__file__).parent / "shared"))

from libraries.validation_errors import ValidationErrorHandler
from libraries.input_validation import (
    StringValidator,
    FloatValidator,
    TMUXConfigValidator,
    batch_validate,
)


def demonstrate_string_validation():
    """Demonstrate string validation with various inputs"""
    print("=" * 60)
    print("STRING VALIDATION DEMONSTRATION")
    print("=" * 60)

    handler = ValidationErrorHandler()

    # Test cases for session names
    session_test_cases = [
        ("valid-session", "Valid session name"),
        ("", "Empty string"),
        ("   ", "Whitespace only"),
        ("a", "Too short"),
        ("x" * 60, "Too long"),
        ("session with spaces", "Contains spaces"),
        ("session@invalid", "Invalid characters"),
        (123, "Wrong data type"),
        ("dev-workflow-123", "Valid complex name"),
    ]

    print("\nSession Name Validation:")
    print("-" * 40)

    for test_input, description in session_test_cases:
        result = StringValidator.validate_session_name(test_input)

        if result.is_valid:
            print(f"[PASS] {description}: '{test_input}' -> '{result.sanitized_value}'")
        else:
            error_info = handler.handle_validation_error(result, "session_name")
            print(f"[FAIL] {description}: {error_info['message']}")
            if error_info["suggestions"]:
                print(f"       Suggestion: {error_info['suggestions'][0]}")

    # Test command validation
    print("\nCommand String Validation:")
    print("-" * 40)

    command_test_cases = [
        ("ls -la", "Valid list command"),
        ("python app.py", "Valid Python command"),
        ("rm -rf /", "Dangerous command"),
        ("", "Empty command"),
        ("x" * 1100, "Too long command"),
        ("echo 'hello world'", "Valid echo command"),
    ]

    for test_input, description in command_test_cases:
        result = StringValidator.validate_command_string(test_input)

        if result.is_valid:
            print(f"[PASS] {description}: Command accepted")
        else:
            error_info = handler.handle_validation_error(result, "command")
            print(f"[FAIL] {description}: {error_info['message']}")


def demonstrate_float_validation():
    """Demonstrate floating point validation with various inputs"""
    print("\n" + "=" * 60)
    print("FLOATING POINT VALIDATION DEMONSTRATION")
    print("=" * 60)

    handler = ValidationErrorHandler()

    # Test timeout validation
    timeout_test_cases = [
        (1.0, "Valid timeout"),
        (0.05, "Too small"),
        (5000.0, "Too large"),
        ("30", "String number"),
        ("invalid", "Invalid string"),
        (float("nan"), "NaN value"),
        (float("inf"), "Infinite value"),
        (-5.0, "Negative value"),
        ("", "Empty string"),
    ]

    print("\nTimeout Validation (0.1 to 3600 seconds):")
    print("-" * 50)

    for test_input, description in timeout_test_cases:
        result = FloatValidator.validate_timeout_value(test_input)

        if result.is_valid:
            print(f"[PASS] {description}: {test_input} -> {result.sanitized_value}")
        else:
            error_info = handler.handle_validation_error(result, "timeout")
            print(f"[FAIL] {description}: {error_info['message']}")

    # Test percentage validation
    print("\nPercentage Validation (0.0 to 100.0):")
    print("-" * 40)

    percentage_test_cases = [
        (50.0, "Valid percentage"),
        (0.0, "Minimum value"),
        (100.0, "Maximum value"),
        (150.0, "Too high"),
        (-10.0, "Negative percentage"),
    ]

    for test_input, description in percentage_test_cases:
        result = FloatValidator.validate_percentage(test_input)

        if result.is_valid:
            print(f"[PASS] {description}: {test_input}%")
        else:
            error_info = handler.handle_validation_error(result, "percentage")
            print(f"[FAIL] {description}: {error_info['message']}")


def demonstrate_tmux_validation():
    """Demonstrate TMUX-specific validation"""
    print("\n" + "=" * 60)
    print("TMUX CONFIGURATION VALIDATION DEMONSTRATION")
    print("=" * 60)

    handler = ValidationErrorHandler()

    # Test window size validation
    print("\nWindow Size Validation:")
    print("-" * 30)

    window_test_cases = [
        ((80, 24), "Standard terminal size"),
        ((120, 40), "Large terminal size"),
        ((10, 24), "Width too small"),
        ((80, 2), "Height too small"),
        ((600, 50), "Width too large"),
        (("80", "24"), "String dimensions"),
    ]

    for (width, height), description in window_test_cases:
        result = TMUXConfigValidator.validate_window_size(width, height)

        if result.is_valid:
            w, h = result.sanitized_value
            print(f"[PASS] {description}: {width}x{height} -> {w}x{h}")
        else:
            error_info = handler.handle_validation_error(result, "window_size")
            print(f"[FAIL] {description}: {error_info['message']}")

    # Test key binding validation
    print("\nKey Binding Validation:")
    print("-" * 30)

    key_test_cases = [
        ("C-a", "Ctrl+A binding"),
        ("M-x", "Alt+X binding"),
        ("F1", "Function key"),
        ("w", "Single letter"),
        ("Ctrl-a", "Wrong format"),
        ("C-", "Missing key"),
        ("F13", "Invalid function key"),
    ]

    for test_input, description in key_test_cases:
        result = TMUXConfigValidator.validate_key_binding(test_input)

        if result.is_valid:
            print(f"[PASS] {description}: '{test_input}' -> '{result.sanitized_value}'")
        else:
            error_info = handler.handle_validation_error(result, "key_binding")
            print(f"[FAIL] {description}: {error_info['message']}")


def demonstrate_batch_validation():
    """Demonstrate batch validation with multiple inputs"""
    print("\n" + "=" * 60)
    print("BATCH VALIDATION DEMONSTRATION")
    print("=" * 60)

    handler = ValidationErrorHandler()

    # Mixed validation scenario (some pass, some fail)
    validations = [
        ("prod-monitor", StringValidator.validate_session_name),
        (30.0, FloatValidator.validate_timeout_value),
        ("", StringValidator.validate_session_name),  # Will fail
        (-5.0, FloatValidator.validate_memory_size_gb),  # Will fail
        (2.5, FloatValidator.validate_cpu_cores),
        (110.0, FloatValidator.validate_percentage),  # Will fail
    ]

    print("\nValidating multiple inputs simultaneously:")
    print("-" * 45)

    results = batch_validate(validations)

    field_names = [
        "session_name",
        "timeout_value",
        "empty_session",
        "memory_size",
        "cpu_cores",
        "percentage",
    ]

    validation_errors = {}
    for i, (field_name, result) in enumerate(zip(field_names, results.values())):
        if result.is_valid:
            print(f"[PASS] {field_name}: Valid")
        else:
            print(f"[FAIL] {field_name}: {result.error_message}")
            validation_errors[field_name] = result

    # Show formatted error summary
    if validation_errors:
        print("\nError Summary:")
        print("-" * 20)
        formatted_errors = handler.format_multiple_errors(
            validation_errors, "Batch Validation Demo"
        )
        print(f"Total errors: {formatted_errors['total_errors']}")
        print(f"Summary: {formatted_errors['summary']}")


def demonstrate_error_recovery():
    """Demonstrate error recovery and user guidance"""
    print("\n" + "=" * 60)
    print("ERROR RECOVERY AND USER GUIDANCE")
    print("=" * 60)

    handler = ValidationErrorHandler()

    print("\nValidation Tips for Different Field Types:")
    print("-" * 45)

    field_types = ["session_name", "timeout", "memory_size", "file_path", "command"]

    for field_type in field_types:
        tips = handler.get_validation_tips(field_type)
        print(f"\n{field_type.replace('_', ' ').title()}:")
        for tip in tips:
            print(f"  - {tip}")

    print("\nError Frequency Tracking:")
    print("-" * 30)

    # Simulate repeated validation errors
    for i in range(5):
        result = StringValidator.validate_session_name("")
        error_info = handler.handle_validation_error(result, "session_name")
        if i == 4:  # Show frequency warning on last iteration
            if "frequency_warning" in error_info:
                print(f"[WARNING] {error_info['frequency_warning']}")


def main():
    """Run all validation demonstrations"""
    print("TMUX Input Validation System Demonstration")
    print("=" * 70)
    print("This demo shows comprehensive input validation for string and")
    print("floating point values with detailed error handling and recovery.")

    try:
        demonstrate_string_validation()
        demonstrate_float_validation()
        demonstrate_tmux_validation()
        demonstrate_batch_validation()
        demonstrate_error_recovery()

        print("\n" + "=" * 70)
        print("DEMONSTRATION COMPLETE")
        print("=" * 70)
        print("Key Features Demonstrated:")
        print("- String validation (session names, commands, paths)")
        print("- Floating point validation (timeouts, percentages, resources)")
        print("- TMUX-specific validation (window sizes, key bindings)")
        print("- Comprehensive error handling with user-friendly messages")
        print("- Batch validation for multiple inputs")
        print("- Error recovery suggestions and tips")
        print("- Input sanitization and normalization")
        print("- Performance optimized validation (sub-millisecond)")

    except Exception as e:
        print(f"\n[ERROR] Demonstration failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
