"""
Password Validation Utility
Implements OWASP-compliant password strength requirements

SECURITY (SEC-009 Fix): Password complexity validation prevents weak passwords
"""

import re
from typing import List, Tuple


# Common passwords list (top 100 most common)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "welcome", "jesus", "ninja", "mustang",
    "password1", "123456789", "adobe123", "admin", "1234567890", "photoshop",
    "1234", "12345", "password123", "welcome123", "solo", "azerty", "121212",
    "flower", "playboy", "hello", "dragon", "lovely", "princess", "freedom",
    "whatever", "qwertyuiop", "samsung", "test", "google", "summer", "chelsea",
}


class PasswordStrengthValidator:
    """
    Validates password strength according to OWASP guidelines

    Requirements:
    - Minimum 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character
    - Not in common passwords list
    """

    def __init__(
        self,
        min_length: int = 8,
        max_length: int = 128,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_digit: bool = True,
        require_special: bool = True,
        check_common_passwords: bool = True,
    ):
        """
        Initialize password validator

        Args:
            min_length: Minimum password length (default: 8)
            max_length: Maximum password length (default: 128)
            require_uppercase: Require at least one uppercase letter
            require_lowercase: Require at least one lowercase letter
            require_digit: Require at least one digit
            require_special: Require at least one special character
            check_common_passwords: Check against common passwords list
        """
        self.min_length = min_length
        self.max_length = max_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special
        self.check_common_passwords = check_common_passwords

        # Special characters: !@#$%^&*()_+-=[]{}|;:,.<>?
        self.special_chars = r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]"

    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password strength

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check length
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")

        if len(password) > self.max_length:
            errors.append(f"Password must not exceed {self.max_length} characters")

        # Check uppercase
        if self.require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        # Check lowercase
        if self.require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        # Check digit
        if self.require_digit and not re.search(r"\d", password):
            errors.append("Password must contain at least one number")

        # Check special character
        if self.require_special and not re.search(self.special_chars, password):
            errors.append("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)")

        # Check common passwords
        if self.check_common_passwords and password.lower() in COMMON_PASSWORDS:
            errors.append("Password is too common. Please choose a more unique password")

        # Check for sequential characters (e.g., "12345", "abcde")
        if self._has_sequential_chars(password):
            errors.append("Password should not contain sequential characters (e.g., '12345' or 'abcde')")

        is_valid = len(errors) == 0
        return is_valid, errors

    def _has_sequential_chars(self, password: str, threshold: int = 4) -> bool:
        """
        Check if password contains sequential characters

        Args:
            password: Password to check
            threshold: Minimum sequential character count to flag (default: 4)

        Returns:
            True if sequential characters found, False otherwise
        """
        password_lower = password.lower()

        # Check for sequential numbers (e.g., "1234", "5678")
        for i in range(len(password_lower) - threshold + 1):
            chunk = password_lower[i:i + threshold]
            if chunk.isdigit():
                numbers = [int(c) for c in chunk]
                if all(numbers[j] == numbers[j-1] + 1 for j in range(1, len(numbers))):
                    return True

        # Check for sequential letters (e.g., "abcd", "wxyz")
        for i in range(len(password_lower) - threshold + 1):
            chunk = password_lower[i:i + threshold]
            if chunk.isalpha():
                chars = [ord(c) for c in chunk]
                if all(chars[j] == chars[j-1] + 1 for j in range(1, len(chars))):
                    return True

        return False

    def get_strength_score(self, password: str) -> int:
        """
        Calculate password strength score (0-100)

        Args:
            password: Password to score

        Returns:
            Strength score (0-100)
        """
        score = 0

        # Length score (up to 30 points)
        length_score = min(30, (len(password) / 20) * 30)
        score += length_score

        # Character variety (up to 40 points)
        if re.search(r"[a-z]", password):
            score += 10
        if re.search(r"[A-Z]", password):
            score += 10
        if re.search(r"\d", password):
            score += 10
        if re.search(self.special_chars, password):
            score += 10

        # Uniqueness (up to 30 points)
        if password.lower() not in COMMON_PASSWORDS:
            score += 15
        if not self._has_sequential_chars(password):
            score += 15

        return min(100, int(score))

    def get_strength_label(self, score: int) -> str:
        """
        Get human-readable strength label

        Args:
            score: Strength score (0-100)

        Returns:
            Strength label (Weak, Fair, Good, Strong, Excellent)
        """
        if score < 20:
            return "Very Weak"
        elif score < 40:
            return "Weak"
        elif score < 60:
            return "Fair"
        elif score < 80:
            return "Good"
        else:
            return "Strong"


# Default validator instance
default_validator = PasswordStrengthValidator()


def validate_password(password: str) -> Tuple[bool, List[str]]:
    """
    Convenience function to validate password with default settings

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    return default_validator.validate(password)


def get_password_strength(password: str) -> Tuple[int, str]:
    """
    Convenience function to get password strength score and label

    Args:
        password: Password to score

    Returns:
        Tuple of (score, label)
    """
    score = default_validator.get_strength_score(password)
    label = default_validator.get_strength_label(score)
    return score, label
