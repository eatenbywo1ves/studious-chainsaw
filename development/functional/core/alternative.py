"""
Alternative Functor - Composable Choice

Based on Category Theory for Programmers.
The Alternative type class provides a way to combine computations
that may fail, trying alternatives until one succeeds.

This is perfect for fallback strategies (email providers, API endpoints, etc.)

Laws:
    1. Associativity: (a <|> b) <|> c = a <|> (b <|> c)
    2. Left Identity: empty <|> a = a
    3. Right Identity: a <|> empty = a
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Callable, Generic, Protocol, TypeVar

if TYPE_CHECKING:
    from ..core.maybe import Maybe
    from ..core.result import Result

__all__ = [
    'Alternative', 'or_else', 'first_success',
    'try_alternatives', 'fallback_chain'
]

T = TypeVar('T')
E = TypeVar('E')


class Alternative(Protocol[T]):
    """
    Type class for Alternative functor

    Provides <|> (or_else) operator for combining computations
    that may fail, choosing the first success.
    """

    @staticmethod
    def empty() -> Alternative[T]:
        """Identity element for <|> operator"""
        ...

    def or_else(self, other: Alternative[T]) -> Alternative[T]:
        """
        Alternative operator (<|>)

        Try this computation, if it fails try other.
        """
        ...


# ============================================================================
# ALTERNATIVE FOR RESULT
# ============================================================================

def or_else_result(first: 'Result[T, E]', second: 'Result[T, E]') -> 'Result[T, E]':
    """
    Alternative for Result type

    Type signature: Result[T, E] → Result[T, E] → Result[T, E]

    Returns first if Success, otherwise returns second.

    Examples:
        >>> or_else_result(Success(5), Success(10))
        Success(5)

        >>> or_else_result(Failure("error"), Success(10))
        Success(10)

        >>> or_else_result(Failure("error1"), Failure("error2"))
        Failure("error2")
    """
    from ..core.result import Success

    if isinstance(first, Success):
        return first
    else:
        return second


# ============================================================================
# ALTERNATIVE FOR MAYBE
# ============================================================================

def or_else_maybe(first: 'Maybe[T]', second: 'Maybe[T]') -> 'Maybe[T]':
    """
    Alternative for Maybe type

    Type signature: Maybe[T] → Maybe[T] → Maybe[T]

    Returns first if Just, otherwise returns second.

    Examples:
        >>> or_else_maybe(Just(5), Just(10))
        Just(5)

        >>> or_else_maybe(NOTHING, Just(10))
        Just(10)

        >>> or_else_maybe(NOTHING, NOTHING)
        Nothing
    """
    from ..core.maybe import Just

    if isinstance(first, Just):
        return first
    else:
        return second


# ============================================================================
# GENERIC ALTERNATIVE OPERATIONS
# ============================================================================

def or_else(first: T, second: T, is_success: Callable[[T], bool]) -> T:
    """
    Generic alternative operator

    Type signature: T → T → (T → Bool) → T

    Examples:
        >>> or_else(None, 5, lambda x: x is not None)
        5

        >>> or_else(10, 5, lambda x: x is not None)
        10
    """
    if is_success(first):
        return first
    else:
        return second


def first_success(options: list[Callable[[], T]], is_success: Callable[[T], bool]) -> T | None:
    """
    Try each option until one succeeds

    Type signature: [() → T] → (T → Bool) → T?

    Examples:
        >>> def provider1(): raise Exception("Failed")
        >>> def provider2(): return "Success!"
        >>> def provider3(): return "Backup"
        >>>
        >>> first_success([provider1, provider2, provider3], lambda x: x is not None)
        "Success!"
    """
    for option in options:
        try:
            result = option()
            if is_success(result):
                return result
        except Exception:
            continue
    return None


# ============================================================================
# RESULT-SPECIFIC ALTERNATIVES
# ============================================================================

def try_alternatives(
    alternatives: list[Callable[[], 'Result[T, E]']]
) -> 'Result[T, list[E]]':
    """
    Try each alternative until one succeeds, collecting errors

    Type signature: [() → Result[T, E]] → Result[T, [E]]

    Perfect for fallback strategies with error tracking.

    Examples:
        >>> def sendgrid(): return Failure("SendGrid down")
        >>> def aws_ses(): return Success("Sent via SES")
        >>> def smtp(): return Failure("SMTP timeout")
        >>>
        >>> try_alternatives([sendgrid, aws_ses, smtp])
        Success("Sent via SES")
    """
    from ..core.result import Success, Failure

    errors: list[E] = []

    for alternative in alternatives:
        try:
            result = alternative()
            if isinstance(result, Success):
                return result
            else:
                errors.append(result.error)
        except Exception as e:
            errors.append(e)  # type: ignore

    return Failure(errors)


def fallback_chain(
    *alternatives: Callable[[], 'Result[T, E]']
) -> 'Result[T, list[E]]':
    """
    Convenient syntax for fallback chain

    Type signature: (() → Result[T, E])* → Result[T, [E]]

    Examples:
        >>> result = fallback_chain(
        ...     lambda: send_via_sendgrid(email),
        ...     lambda: send_via_ses(email),
        ...     lambda: send_via_smtp(email)
        ... )
    """
    return try_alternatives(list(alternatives))


# ============================================================================
# MAYBE-SPECIFIC ALTERNATIVES
# ============================================================================

def maybe_alternatives(
    alternatives: list[Callable[[], 'Maybe[T]']]
) -> 'Maybe[T]':
    """
    Try each alternative until one produces Just

    Type signature: [() → Maybe[T]] → Maybe[T]

    Examples:
        >>> def cache(): return NOTHING
        >>> def database(): return Just("Found in DB")
        >>> def api(): return NOTHING
        >>>
        >>> maybe_alternatives([cache, database, api])
        Just("Found in DB")
    """
    from ..core.maybe import Just, NOTHING

    for alternative in alternatives:
        try:
            result = alternative()
            if isinstance(result, Just):
                return result
        except Exception:
            continue

    return NOTHING


# ============================================================================
# LAZY EVALUATION ALTERNATIVE
# ============================================================================

class LazyAlternative(Generic[T]):
    """
    Lazy alternative that doesn't evaluate until needed

    Useful for expensive operations or operations with side effects.
    """

    def __init__(self, thunk: Callable[[], T]):
        self._thunk = thunk
        self._evaluated = False
        self._value: T | None = None

    def get(self) -> T:
        """Evaluate and return value (memoized)"""
        if not self._evaluated:
            self._value = self._thunk()
            self._evaluated = True
        return self._value  # type: ignore

    def or_else(self, other: LazyAlternative[T]) -> LazyAlternative[T]:
        """Try this alternative, if None/Failure try other"""
        def combined():
            first = self.get()
            if first is not None:
                return first
            return other.get()
        return LazyAlternative(combined)


def lazy(thunk: Callable[[], T]) -> LazyAlternative[T]:
    """Create lazy alternative"""
    return LazyAlternative(thunk)


# ============================================================================
# PRACTICAL EMAIL EXAMPLE
# ============================================================================

"""
Example: Composable Email Provider Fallback

BEFORE (Imperative):
```python
def send_email(to, subject, body):
    if sendgrid_available:
        try:
            return send_via_sendgrid(to, subject, body)
        except:
            pass

    if aws_ses_available:
        try:
            return send_via_ses(to, subject, body)
        except:
            pass

    if smtp_available:
        try:
            return send_via_smtp(to, subject, body)
        except:
            pass

    return False
```

AFTER (Alternative):
```python
def send_email(to: str, subject: str, body: str) -> Result[bool, list[str]]:
    return fallback_chain(
        lambda: send_via_sendgrid(to, subject, body),
        lambda: send_via_ses(to, subject, body),
        lambda: send_via_smtp(to, subject, body)
    )

# Or with explicit alternatives list
def send_email_v2(to: str, subject: str, body: str) -> Result[bool, list[str]]:
    providers = [
        lambda: send_via_sendgrid(to, subject, body),
        lambda: send_via_ses(to, subject, body),
        lambda: send_via_smtp(to, subject, body)
    ]
    return try_alternatives(providers)
```

Benefits:
- ✅ Declarative list of alternatives
- ✅ Automatic error collection
- ✅ Easy to add/remove providers
- ✅ Composable with other Result operations
- ✅ Type-safe error handling
"""


# ============================================================================
# REDUCTION COMBINATORS
# ============================================================================

def reduce_alternatives(
    alternatives: list['Result[T, E]']
) -> 'Result[T, list[E]]':
    """
    Reduce list of Results using Alternative combinator

    Type signature: [Result[T, E]] → Result[T, [E]]

    Examples:
        >>> reduce_alternatives([Failure("a"), Success(5), Failure("b")])
        Success(5)

        >>> reduce_alternatives([Failure("a"), Failure("b"), Failure("c")])
        Failure(["a", "b", "c"])
    """
    from ..core.result import Success, Failure

    errors: list[E] = []

    for result in alternatives:
        if isinstance(result, Success):
            return result
        else:
            errors.append(result.error)

    return Failure(errors)


def any_success(
    operations: list[Callable[[], 'Result[T, E]']]
) -> 'Result[list[T], list[E]]':
    """
    Execute all operations, return all successes or all errors

    Type signature: [() → Result[T, E]] → Result[[T], [E]]

    Unlike try_alternatives, this executes ALL operations.

    Examples:
        >>> ops = [
        ...     lambda: Success(1),
        ...     lambda: Failure("error"),
        ...     lambda: Success(3)
        ... ]
        >>> any_success(ops)
        Success([1, 3])
    """
    from ..core.result import Success, Failure, partition

    results = [op() for op in operations]
    successes, errors = partition(results)

    if successes:
        return Success(successes)
    else:
        return Failure(errors)


# ============================================================================
# CHAINING WITH ALTERNATIVE
# ============================================================================

def chain_with_alternative(
    primary: Callable[[], 'Result[T, E]'],
    fallback: Callable[[], 'Result[T, E]']
) -> 'Result[T, tuple[E, E]]':
    """
    Try primary, if fails try fallback, collect both errors

    Examples:
        >>> chain_with_alternative(
        ...     lambda: Failure("primary failed"),
        ...     lambda: Success("fallback success")
        ... )
        Success("fallback success")
    """
    from ..core.result import Success, Failure

    primary_result = primary()
    if isinstance(primary_result, Success):
        return primary_result

    fallback_result = fallback()
    if isinstance(fallback_result, Success):
        return fallback_result

    return Failure((primary_result.error, fallback_result.error))


def retry_with_alternative(
    operation: Callable[[], 'Result[T, E]'],
    max_retries: int = 3
) -> 'Result[T, list[E]]':
    """
    Retry operation using Alternative pattern

    Examples:
        >>> attempts = 0
        >>> def flaky_op():
        ...     nonlocal attempts
        ...     attempts += 1
        ...     if attempts < 3:
        ...         return Failure(f"Attempt {attempts} failed")
        ...     return Success("Success!")
        >>>
        >>> retry_with_alternative(flaky_op, max_retries=3)
        Success("Success!")
    """
    return try_alternatives([operation for _ in range(max_retries)])
