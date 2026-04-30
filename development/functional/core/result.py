"""
Result/Either Monad - Composable Error Handling

Based on Category Theory for Programmers.
The Result type represents computations that may fail, providing
composable error handling without exceptions.

Type: Result[T, E] = Success[T] | Failure[E]

Laws:
    1. Functor Identity: map(id) = id
    2. Functor Composition: map(g ∘ f) = map(g) ∘ map(f)
    3. Monad Left Identity: pure(a) >>= f = f(a)
    4. Monad Right Identity: m >>= pure = m
    5. Monad Associativity: (m >>= f) >>= g = m >>= (λx → f(x) >>= g)
"""

from __future__ import annotations
from typing import TypeVar, Generic, Callable, Union, cast, Any
from dataclasses import dataclass

__all__ = [
    'Result', 'Success', 'Failure',
    'is_success', 'is_failure',
    'from_optional', 'from_exception',
    'collect', 'sequence'
]

T = TypeVar('T')
U = TypeVar('U')
V = TypeVar('V')
E = TypeVar('E')
F = TypeVar('F')


@dataclass(frozen=True)
class Success(Generic[T]):
    """
    Success case of Result monad

    Represents a successful computation with value of type T
    """
    value: T

    def __repr__(self) -> str:
        return f"Success({self.value!r})"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Success) and self.value == other.value

    def __hash__(self) -> int:
        return hash(('Success', self.value))


@dataclass(frozen=True)
class Failure(Generic[E]):
    """
    Failure case of Result monad

    Represents a failed computation with error of type E
    """
    error: E

    def __repr__(self) -> str:
        return f"Failure({self.error!r})"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Failure) and self.error == other.error

    def __hash__(self) -> int:
        return hash(('Failure', self.error))


# Union type for Result
Result = Union[Success[T], Failure[E]]


# ============================================================================
# TYPE GUARDS
# ============================================================================

def is_success(result: Result[T, E]) -> bool:
    """Check if Result is Success"""
    return isinstance(result, Success)


def is_failure(result: Result[T, E]) -> bool:
    """Check if Result is Failure"""
    return isinstance(result, Failure)


# ============================================================================
# FUNCTOR INSTANCE
# ============================================================================

def map(result: Result[T, E], f: Callable[[T], U]) -> Result[U, E]:
    """
    Functor map - Transform the value inside Success

    Type signature: (T → U) → Result[T, E] → Result[U, E]

    Laws:
        map(id) = id
        map(g ∘ f) = map(g) ∘ map(f)

    Examples:
        >>> map(Success(5), lambda x: x * 2)
        Success(10)

        >>> map(Failure("error"), lambda x: x * 2)
        Failure("error")
    """
    if isinstance(result, Success):
        return Success(f(result.value))
    else:
        return cast(Result[U, E], result)


def map_error(result: Result[T, E], f: Callable[[E], F]) -> Result[T, F]:
    """
    Map over the error type

    Type signature: (E → F) → Result[T, E] → Result[T, F]
    """
    if isinstance(result, Failure):
        return Failure(f(result.error))
    else:
        return cast(Result[T, F], result)


# ============================================================================
# APPLICATIVE INSTANCE
# ============================================================================

def pure(value: T) -> Result[T, E]:
    """
    Applicative pure - Lift a value into Result context

    Type signature: T → Result[T, E]

    This is the identity morphism for the Result monad.
    """
    return Success(value)


def ap(result_f: Result[Callable[[T], U], E], result: Result[T, E]) -> Result[U, E]:
    """
    Applicative apply - Apply a function in Result context

    Type signature: Result[T → U, E] → Result[T, E] → Result[U, E]

    Examples:
        >>> ap(Success(lambda x: x * 2), Success(5))
        Success(10)

        >>> ap(Failure("error"), Success(5))
        Failure("error")
    """
    if isinstance(result_f, Success) and isinstance(result, Success):
        return Success(result_f.value(result.value))
    elif isinstance(result_f, Failure):
        return cast(Result[U, E], result_f)
    else:
        return cast(Result[U, E], result)


# ============================================================================
# MONAD INSTANCE
# ============================================================================

def flat_map(result: Result[T, E], f: Callable[[T], Result[U, E]]) -> Result[U, E]:
    """
    Monad bind (>>=) - Kleisli composition

    Type signature: Result[T, E] → (T → Result[U, E]) → Result[U, E]

    This enables chaining operations that may fail.

    Laws:
        Left Identity:  pure(a) >>= f = f(a)
        Right Identity: m >>= pure = m
        Associativity:  (m >>= f) >>= g = m >>= (λx → f(x) >>= g)

    Examples:
        >>> flat_map(Success(5), lambda x: Success(x * 2))
        Success(10)

        >>> flat_map(Success(5), lambda x: Failure("error"))
        Failure("error")

        >>> flat_map(Failure("error"), lambda x: Success(x * 2))
        Failure("error")
    """
    if isinstance(result, Success):
        return f(result.value)
    else:
        return cast(Result[U, E], result)


# Aliases for convenience
bind = flat_map
chain = flat_map


def flatten(result: Result[Result[T, E], E]) -> Result[T, E]:
    """
    Flatten nested Results (monadic join)

    Type signature: Result[Result[T, E], E] → Result[T, E]
    """
    return flat_map(result, lambda x: x)


# ============================================================================
# COMPOSITION OPERATORS
# ============================================================================

def compose_kleisli(
    f: Callable[[T], Result[U, E]],
    g: Callable[[U], Result[V, E]]
) -> Callable[[T], Result[V, E]]:
    """
    Kleisli composition (>=>)

    Compose two functions that return Results.

    Type signature: (T → Result[U, E]) → (U → Result[V, E]) → (T → Result[V, E])

    Examples:
        >>> f = lambda x: Success(x + 1)
        >>> g = lambda x: Success(x * 2)
        >>> h = compose_kleisli(f, g)
        >>> h(5)
        Success(12)
    """
    return lambda x: flat_map(f(x), g)


# Operator alias
kleisli = compose_kleisli


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def from_optional(value: T | None, error: E) -> Result[T, E]:
    """
    Convert Optional/None to Result

    Examples:
        >>> from_optional(5, "not found")
        Success(5)

        >>> from_optional(None, "not found")
        Failure("not found")
    """
    if value is not None:
        return Success(value)
    else:
        return Failure(error)


def from_exception(f: Callable[[], T], error_mapper: Callable[[Exception], E] | None = None) -> Result[T, E]:
    """
    Execute function and catch exceptions as Result

    Args:
        f: Function that may raise exceptions
        error_mapper: Optional function to transform exception to error type

    Examples:
        >>> from_exception(lambda: 10 / 2)
        Success(5.0)

        >>> from_exception(lambda: 10 / 0, lambda e: str(e))
        Failure("division by zero")
    """
    try:
        return Success(f())
    except Exception as e:
        if error_mapper:
            return Failure(error_mapper(e))
        else:
            return Failure(cast(E, str(e)))


def unwrap(result: Result[T, E], default: T) -> T:
    """
    Extract value from Result, using default if Failure

    Examples:
        >>> unwrap(Success(5), 0)
        5

        >>> unwrap(Failure("error"), 0)
        0
    """
    if isinstance(result, Success):
        return result.value
    else:
        return default


def unwrap_or_else(result: Result[T, E], f: Callable[[E], T]) -> T:
    """
    Extract value from Result, computing default from error if Failure

    Examples:
        >>> unwrap_or_else(Success(5), lambda e: 0)
        5

        >>> unwrap_or_else(Failure("error"), lambda e: len(e))
        5
    """
    if isinstance(result, Success):
        return result.value
    else:
        return f(result.error)


def expect(result: Result[T, E], message: str) -> T:
    """
    Extract value from Result, raising exception if Failure

    Use sparingly - defeats purpose of Result monad!
    Only use at program boundaries.

    Examples:
        >>> expect(Success(5), "should have value")
        5

        >>> expect(Failure("error"), "should have value")
        Traceback (most recent call last):
        ...
        Exception: should have value: error
    """
    if isinstance(result, Success):
        return result.value
    else:
        raise Exception(f"{message}: {result.error}")


# ============================================================================
# COLLECTION OPERATIONS
# ============================================================================

def collect(results: list[Result[T, E]]) -> Result[list[T], E]:
    """
    Collect list of Results into Result of list

    Short-circuits on first Failure.

    Type signature: [Result[T, E]] → Result[[T], E]

    Examples:
        >>> collect([Success(1), Success(2), Success(3)])
        Success([1, 2, 3])

        >>> collect([Success(1), Failure("error"), Success(3)])
        Failure("error")
    """
    values: list[T] = []
    for result in results:
        if isinstance(result, Success):
            values.append(result.value)
        else:
            return cast(Result[list[T], E], result)
    return Success(values)


# Alias
sequence = collect


def traverse(items: list[T], f: Callable[[T], Result[U, E]]) -> Result[list[U], E]:
    """
    Map function over list and collect results

    Type signature: [T] → (T → Result[U, E]) → Result[[U], E]

    Examples:
        >>> traverse([1, 2, 3], lambda x: Success(x * 2))
        Success([2, 4, 6])

        >>> traverse([1, 2, 3], lambda x: Failure("error") if x == 2 else Success(x * 2))
        Failure("error")
    """
    return collect([f(item) for item in items])


def partition(results: list[Result[T, E]]) -> tuple[list[T], list[E]]:
    """
    Partition list of Results into successes and failures

    Examples:
        >>> partition([Success(1), Failure("a"), Success(2), Failure("b")])
        ([1, 2], ["a", "b"])
    """
    successes: list[T] = []
    failures: list[E] = []

    for result in results:
        if isinstance(result, Success):
            successes.append(result.value)
        else:
            failures.append(result.error)

    return successes, failures


# ============================================================================
# BIMAP (BIFUNCTOR)
# ============================================================================

def bimap(result: Result[T, E], f: Callable[[T], U], g: Callable[[E], F]) -> Result[U, F]:
    """
    Map over both Success and Failure

    Type signature: (T → U) → (E → F) → Result[T, E] → Result[U, F]

    Examples:
        >>> bimap(Success(5), lambda x: x * 2, lambda e: e.upper())
        Success(10)

        >>> bimap(Failure("error"), lambda x: x * 2, lambda e: e.upper())
        Failure("ERROR")
    """
    if isinstance(result, Success):
        return Success(f(result.value))
    else:
        return Failure(g(result.error))


# ============================================================================
# COMBINATORS
# ============================================================================

def or_else(result: Result[T, E], default: Result[T, E]) -> Result[T, E]:
    """
    Return result if Success, otherwise return default

    Examples:
        >>> or_else(Success(5), Success(10))
        Success(5)

        >>> or_else(Failure("error"), Success(10))
        Success(10)
    """
    if isinstance(result, Success):
        return result
    else:
        return default


def and_then(result: Result[T, E], f: Callable[[T], Result[U, E]]) -> Result[U, E]:
    """
    Alias for flat_map (more readable in chains)
    """
    return flat_map(result, f)


def tap(result: Result[T, E], f: Callable[[T], None]) -> Result[T, E]:
    """
    Execute side effect on Success, return unchanged result

    Use for logging, debugging, etc.

    Examples:
        >>> result = Success(5)
        >>> tap(result, lambda x: print(f"Value: {x}"))
        Value: 5
        Success(5)
    """
    if isinstance(result, Success):
        f(result.value)
    return result


def tap_error(result: Result[T, E], f: Callable[[E], None]) -> Result[T, E]:
    """
    Execute side effect on Failure, return unchanged result
    """
    if isinstance(result, Failure):
        f(result.error)
    return result
