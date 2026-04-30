"""
Validation Applicative - Accumulating Error Validation

Based on Category Theory for Programmers.
Unlike Result which short-circuits on first error, Validation
accumulates all errors using the Applicative functor.

Type: Validation[E, A] = Valid[A] | Invalid[List[E]]

Perfect for form validation, configuration validation, etc.
where you want to show ALL errors to the user, not just the first.

Laws:
    1. Functor Identity: map(id) = id
    2. Functor Composition: map(g ∘ f) = map(g) ∘ map(f)
    3. Applicative Identity: pure(id) <*> v = v
    4. Applicative Composition: pure(∘) <*> u <*> v <*> w = u <*> (v <*> w)
    5. Applicative Homomorphism: pure(f) <*> pure(x) = pure(f(x))
    6. Applicative Interchange: u <*> pure(y) = pure(λf → f(y)) <*> u
"""

from __future__ import annotations
from typing import TypeVar, Generic, Callable, Union, Any
from dataclasses import dataclass

__all__ = [
    'Validation', 'Valid', 'Invalid',
    'is_valid', 'is_invalid',
    'validate_all', 'validator'
]

E = TypeVar('E')
A = TypeVar('A')
B = TypeVar('B')
C = TypeVar('C')
D = TypeVar('D')


@dataclass(frozen=True)
class Valid(Generic[A]):
    """
    Valid case of Validation applicative

    Represents successful validation with value of type A
    """
    value: A

    def __repr__(self) -> str:
        return f"Valid({self.value!r})"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Valid) and self.value == other.value

    def __hash__(self) -> int:
        return hash(('Valid', self.value))


@dataclass(frozen=True)
class Invalid(Generic[E]):
    """
    Invalid case of Validation applicative

    Represents failed validation with list of errors of type E
    """
    errors: list[E]

    def __repr__(self) -> str:
        return f"Invalid({self.errors!r})"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Invalid) and self.errors == other.errors

    def __hash__(self) -> int:
        return hash(('Invalid', tuple(self.errors)))


# Union type for Validation
Validation = Union[Valid[A], Invalid[E]]


# ============================================================================
# TYPE GUARDS
# ============================================================================

def is_valid(validation: Validation[E, A]) -> bool:
    """Check if Validation is Valid"""
    return isinstance(validation, Valid)


def is_invalid(validation: Validation[E, A]) -> bool:
    """Check if Validation is Invalid"""
    return isinstance(validation, Invalid)


# ============================================================================
# FUNCTOR INSTANCE
# ============================================================================

def map(validation: Validation[E, A], f: Callable[[A], B]) -> Validation[E, B]:
    """
    Functor map - Transform the value inside Valid

    Type signature: (A → B) → Validation[E, A] → Validation[E, B]

    Examples:
        >>> map(Valid(5), lambda x: x * 2)
        Valid(10)

        >>> map(Invalid(["error"]), lambda x: x * 2)
        Invalid(["error"])
    """
    if isinstance(validation, Valid):
        return Valid(f(validation.value))
    else:
        return validation  # type: ignore


# ============================================================================
# APPLICATIVE INSTANCE (Key difference from Result!)
# ============================================================================

def pure(value: A) -> Validation[E, A]:
    """
    Applicative pure - Lift a value into Validation context

    Type signature: A → Validation[E, A]
    """
    return Valid(value)


def ap(validation_f: Validation[E, Callable[[A], B]], validation: Validation[E, A]) -> Validation[E, B]:
    """
    Applicative apply - ACCUMULATES ERRORS

    Type signature: Validation[E, A → B] → Validation[E, A] → Validation[E, B]

    This is the KEY feature: when both are Invalid, errors are combined!

    Examples:
        >>> ap(Valid(lambda x: x * 2), Valid(5))
        Valid(10)

        >>> ap(Invalid(["error1"]), Invalid(["error2"]))
        Invalid(["error1", "error2"])  # Both errors accumulated!

        >>> ap(Invalid(["error1"]), Valid(5))
        Invalid(["error1"])

        >>> ap(Valid(lambda x: x * 2), Invalid(["error2"]))
        Invalid(["error2"])
    """
    if isinstance(validation_f, Valid) and isinstance(validation, Valid):
        return Valid(validation_f.value(validation.value))
    elif isinstance(validation_f, Invalid) and isinstance(validation, Invalid):
        # KEY: Accumulate errors from both!
        return Invalid(validation_f.errors + validation.errors)
    elif isinstance(validation_f, Invalid):
        return validation_f  # type: ignore
    else:
        return validation  # type: ignore


# ============================================================================
# MONAD INSTANCE (Note: Validation is NOT a monad!)
# ============================================================================

# Validation does NOT have a proper monad instance because
# it cannot maintain error accumulation semantics with bind.
# This is by design - use Applicative for validation!

def flat_map(validation: Validation[E, A], f: Callable[[A], Validation[E, B]]) -> Validation[E, B]:
    """
    Limited bind operation

    WARNING: This short-circuits on first error (like Result),
    defeating the purpose of Validation. Prefer using Applicative!

    Type signature: Validation[E, A] → (A → Validation[E, B]) → Validation[E, B]
    """
    if isinstance(validation, Valid):
        return f(validation.value)
    else:
        return validation  # type: ignore


# ============================================================================
# VALIDATION-SPECIFIC OPERATIONS
# ============================================================================

def validate_all(*validations: Validation[E, Any]) -> Validation[E, tuple]:
    """
    Combine multiple validations, accumulating all errors

    Type signature: Validation[E, A]* → Validation[E, (A, ...)]

    This uses Applicative to accumulate errors from all validations.

    Examples:
        >>> validate_all(
        ...     Valid(1),
        ...     Valid(2),
        ...     Valid(3)
        ... )
        Valid((1, 2, 3))

        >>> validate_all(
        ...     Invalid(["error1"]),
        ...     Valid(2),
        ...     Invalid(["error3"])
        ... )
        Invalid(["error1", "error3"])  # All errors!
    """
    if not validations:
        return Valid(())

    # Accumulate using applicative
    result: Validation[E, tuple] = map(validations[0], lambda x: (x,))

    for validation in validations[1:]:
        # Lift tuple append function
        def append_to_tuple(tup):
            return lambda x: tup + (x,)

        # Apply with error accumulation
        lifted = map(result, append_to_tuple)
        result = ap(lifted, validation)

    return result


def validator(f: Callable[[A], bool], error: E) -> Callable[[A], Validation[E, A]]:
    """
    Create validator function from predicate

    Type signature: (A → Bool) → E → (A → Validation[E, A])

    Examples:
        >>> is_positive = validator(lambda x: x > 0, "Must be positive")
        >>> is_positive(5)
        Valid(5)
        >>> is_positive(-5)
        Invalid(["Must be positive"])

        >>> is_even = validator(lambda x: x % 2 == 0, "Must be even")
        >>> is_short = validator(lambda s: len(s) < 10, "Must be short")
    """
    def validate(value: A) -> Validation[E, A]:
        if f(value):
            return Valid(value)
        else:
            return Invalid([error])
    return validate


# ============================================================================
# CONVERSION UTILITIES
# ============================================================================

def from_result(result: 'Result[A, E]') -> Validation[E, A]:
    """
    Convert Result to Validation

    Examples:
        >>> from_result(Success(5))
        Valid(5)

        >>> from_result(Failure("error"))
        Invalid(["error"])
    """
    from ..core.result import Success
    if isinstance(result, Success):
        return Valid(result.value)
    else:
        return Invalid([result.error])


def to_result(validation: Validation[E, A]) -> 'Result[A, list[E]]':
    """
    Convert Validation to Result

    Examples:
        >>> to_result(Valid(5))
        Success(5)

        >>> to_result(Invalid(["error1", "error2"]))
        Failure(["error1", "error2"])
    """
    from ..core.result import Success, Failure
    if isinstance(validation, Valid):
        return Success(validation.value)
    else:
        return Failure(validation.errors)


# ============================================================================
# COLLECTION OPERATIONS
# ============================================================================

def collect(validations: list[Validation[E, A]]) -> Validation[E, list[A]]:
    """
    Collect list of validations, accumulating ALL errors

    Type signature: [Validation[E, A]] → Validation[E, [A]]

    Examples:
        >>> collect([Valid(1), Valid(2), Valid(3)])
        Valid([1, 2, 3])

        >>> collect([Valid(1), Invalid(["e1"]), Invalid(["e2"])])
        Invalid(["e1", "e2"])
    """
    values: list[A] = []
    errors: list[E] = []

    for validation in validations:
        if isinstance(validation, Valid):
            values.append(validation.value)
        else:
            errors.extend(validation.errors)

    if errors:
        return Invalid(errors)
    else:
        return Valid(values)


def traverse(items: list[A], f: Callable[[A], Validation[E, B]]) -> Validation[E, list[B]]:
    """
    Map validation function and collect results

    Type signature: [A] → (A → Validation[E, B]) → Validation[E, [B]]
    """
    return collect([f(item) for item in items])


# ============================================================================
# PRACTICAL FORM VALIDATION EXAMPLE
# ============================================================================

"""
Example: Form Validation with Error Accumulation

```python
from dataclasses import dataclass
from functional.validation import Valid, Invalid, validate_all, validator

@dataclass
class UserForm:
    username: str
    email: str
    age: int

# Define validators
username_not_empty = validator(lambda s: len(s) > 0, "Username cannot be empty")
username_min_length = validator(lambda s: len(s) >= 3, "Username must be at least 3 chars")
username_max_length = validator(lambda s: len(s) <= 20, "Username must be at most 20 chars")

email_valid = validator(lambda s: "@" in s, "Email must contain @")
email_domain = validator(lambda s: "." in s.split("@")[1] if "@" in s else False, "Email must have valid domain")

age_positive = validator(lambda n: n > 0, "Age must be positive")
age_reasonable = validator(lambda n: n < 150, "Age must be less than 150")

def validate_username(username: str) -> Validation[str, str]:
    '''Accumulate all username errors'''
    return validate_all(
        username_not_empty(username),
        username_min_length(username),
        username_max_length(username)
    ).map(lambda _: username)  # Return original if all pass

def validate_email(email: str) -> Validation[str, str]:
    return validate_all(
        email_valid(email),
        email_domain(email)
    ).map(lambda _: email)

def validate_age(age: int) -> Validation[str, int]:
    return validate_all(
        age_positive(age),
        age_reasonable(age)
    ).map(lambda _: age)

def validate_user_form(username: str, email: str, age: int) -> Validation[str, UserForm]:
    '''Validate entire form, accumulating ALL errors'''
    # Use applicative to accumulate errors across all fields
    username_val = validate_username(username)
    email_val = validate_email(email)
    age_val = validate_age(age)

    # Lift constructor into Validation
    result = validate_all(username_val, email_val, age_val)

    # Map to UserForm
    return result.map(lambda vals: UserForm(vals[0], vals[1], vals[2]))

# Usage
result = validate_user_form("ab", "invalid-email", -5)
# Invalid([
#     "Username must be at least 3 chars",
#     "Email must contain @",
#     "Age must be positive"
# ])

# All errors shown at once! Much better UX than Result.
```

Benefits:
- ✅ Shows ALL validation errors, not just first
- ✅ Better user experience for forms
- ✅ Composable validators
- ✅ Type-safe error accumulation
- ✅ Declarative validation logic
"""


# ============================================================================
# ADVANCED APPLICATIVE COMBINATORS
# ============================================================================

def lift2(
    f: Callable[[A, B], C]
) -> Callable[[Validation[E, A], Validation[E, B]], Validation[E, C]]:
    """
    Lift binary function into Validation applicative

    Type signature: (A → B → C) → Validation[E, A] → Validation[E, B] → Validation[E, C]

    Examples:
        >>> add = lambda x, y: x + y
        >>> lifted_add = lift2(add)
        >>> lifted_add(Valid(5), Valid(10))
        Valid(15)

        >>> lifted_add(Invalid(["e1"]), Invalid(["e2"]))
        Invalid(["e1", "e2"])
    """
    def lifted(va: Validation[E, A], vb: Validation[E, B]) -> Validation[E, C]:
        # Curry the function
        curried = map(va, lambda a: lambda b: f(a, b))
        # Apply to second validation
        return ap(curried, vb)
    return lifted


def lift3(
    f: Callable[[A, B, C], D]
) -> Callable[[Validation[E, A], Validation[E, B], Validation[E, C]], Validation[E, D]]:
    """
    Lift ternary function into Validation applicative

    Type signature: (A → B → C → D) → Validation[E, A] → Validation[E, B] → Validation[E, C] → Validation[E, D]
    """
    def lifted(va: Validation[E, A], vb: Validation[E, B], vc: Validation[E, C]) -> Validation[E, D]:
        # Curry the function
        curried = map(va, lambda a: lambda b: lambda c: f(a, b, c))
        # Apply to second and third validations
        applied_b = ap(curried, vb)
        return ap(applied_b, vc)
    return lifted


def apply_to(validation: Validation[E, A], validation_f: Validation[E, Callable[[A], B]]) -> Validation[E, B]:
    """
    Flipped version of ap - more convenient for chaining

    Type signature: Validation[E, A] → Validation[E, A → B] → Validation[E, B]
    """
    return ap(validation_f, validation)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def unwrap(validation: Validation[E, A], default: A) -> A:
    """
    Extract value from Validation, using default if Invalid

    Examples:
        >>> unwrap(Valid(5), 0)
        5

        >>> unwrap(Invalid(["error"]), 0)
        0
    """
    if isinstance(validation, Valid):
        return validation.value
    else:
        return default


def unwrap_or_else(validation: Validation[E, A], f: Callable[[list[E]], A]) -> A:
    """
    Extract value from Validation, computing default from errors if Invalid
    """
    if isinstance(validation, Valid):
        return validation.value
    else:
        return f(validation.errors)


def expect(validation: Validation[E, A], message: str) -> A:
    """
    Extract value from Validation, raising exception if Invalid
    """
    if isinstance(validation, Valid):
        return validation.value
    else:
        raise Exception(f"{message}: {validation.errors}")


def or_else(validation: Validation[E, A], default: Validation[E, A]) -> Validation[E, A]:
    """
    Return validation if Valid, otherwise return default
    """
    if isinstance(validation, Valid):
        return validation
    else:
        return default


def tap(validation: Validation[E, A], f: Callable[[A], None]) -> Validation[E, A]:
    """
    Execute side effect on Valid, return unchanged validation
    """
    if isinstance(validation, Valid):
        f(validation.value)
    return validation


def tap_errors(validation: Validation[E, A], f: Callable[[list[E]], None]) -> Validation[E, A]:
    """
    Execute side effect on Invalid, return unchanged validation
    """
    if isinstance(validation, Invalid):
        f(validation.errors)
    return validation
