"""
Maybe/Option Monad - Composable Null Handling

Based on Category Theory for Programmers.
The Maybe type represents computations that may produce no value,
providing composable null handling without None checks.

Type: Maybe[T] = Just[T] | Nothing

Laws:
    1. Functor Identity: map(id) = id
    2. Functor Composition: map(g ∘ f) = map(g) ∘ map(f)
    3. Monad Left Identity: pure(a) >>= f = f(a)
    4. Monad Right Identity: m >>= pure = m
    5. Monad Associativity: (m >>= f) >>= g = m >>= (λx → f(x) >>= g)
"""

from __future__ import annotations
from typing import TypeVar, Generic, Callable, Union, Any
from dataclasses import dataclass

__all__ = [
    'Maybe', 'Just', 'Nothing',
    'is_just', 'is_nothing',
    'from_optional', 'from_predicate',
    'collect', 'sequence', 'first_just'
]

T = TypeVar('T')
U = TypeVar('U')
V = TypeVar('V')


@dataclass(frozen=True)
class Just(Generic[T]):
    """
    Just case of Maybe monad

    Represents a computation that produced a value
    """
    value: T

    def __repr__(self) -> str:
        return f"Just({self.value!r})"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Just) and self.value == other.value

    def __hash__(self) -> int:
        return hash(('Just', self.value))


@dataclass(frozen=True)
class Nothing:
    """
    Nothing case of Maybe monad

    Represents a computation that produced no value
    Singleton pattern - all Nothing instances are equal
    """

    def __repr__(self) -> str:
        return "Nothing"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Nothing)

    def __hash__(self) -> int:
        return hash('Nothing')


# Singleton instance
NOTHING = Nothing()

# Union type for Maybe
Maybe = Union[Just[T], Nothing]


# ============================================================================
# TYPE GUARDS
# ============================================================================

def is_just(maybe: Maybe[T]) -> bool:
    """Check if Maybe is Just"""
    return isinstance(maybe, Just)


def is_nothing(maybe: Maybe[T]) -> bool:
    """Check if Maybe is Nothing"""
    return isinstance(maybe, Nothing)


# ============================================================================
# FUNCTOR INSTANCE
# ============================================================================

def map(maybe: Maybe[T], f: Callable[[T], U]) -> Maybe[U]:
    """
    Functor map - Transform the value inside Just

    Type signature: (T → U) → Maybe[T] → Maybe[U]

    Laws:
        map(id) = id
        map(g ∘ f) = map(g) ∘ map(f)

    Examples:
        >>> map(Just(5), lambda x: x * 2)
        Just(10)

        >>> map(NOTHING, lambda x: x * 2)
        Nothing
    """
    if isinstance(maybe, Just):
        return Just(f(maybe.value))
    else:
        return NOTHING


# ============================================================================
# APPLICATIVE INSTANCE
# ============================================================================

def pure(value: T) -> Maybe[T]:
    """
    Applicative pure - Lift a value into Maybe context

    Type signature: T → Maybe[T]

    This is the identity morphism for the Maybe monad.
    """
    return Just(value)


def ap(maybe_f: Maybe[Callable[[T], U]], maybe: Maybe[T]) -> Maybe[U]:
    """
    Applicative apply - Apply a function in Maybe context

    Type signature: Maybe[T → U] → Maybe[T] → Maybe[U]

    Examples:
        >>> ap(Just(lambda x: x * 2), Just(5))
        Just(10)

        >>> ap(NOTHING, Just(5))
        Nothing

        >>> ap(Just(lambda x: x * 2), NOTHING)
        Nothing
    """
    if isinstance(maybe_f, Just) and isinstance(maybe, Just):
        return Just(maybe_f.value(maybe.value))
    else:
        return NOTHING


# ============================================================================
# MONAD INSTANCE
# ============================================================================

def flat_map(maybe: Maybe[T], f: Callable[[T], Maybe[U]]) -> Maybe[U]:
    """
    Monad bind (>>=) - Kleisli composition

    Type signature: Maybe[T] → (T → Maybe[U]) → Maybe[U]

    This enables chaining operations that may produce no value.

    Laws:
        Left Identity:  pure(a) >>= f = f(a)
        Right Identity: m >>= pure = m
        Associativity:  (m >>= f) >>= g = m >>= (λx → f(x) >>= g)

    Examples:
        >>> flat_map(Just(5), lambda x: Just(x * 2))
        Just(10)

        >>> flat_map(Just(5), lambda x: NOTHING)
        Nothing

        >>> flat_map(NOTHING, lambda x: Just(x * 2))
        Nothing
    """
    if isinstance(maybe, Just):
        return f(maybe.value)
    else:
        return NOTHING


# Aliases for convenience
bind = flat_map
chain = flat_map


def flatten(maybe: Maybe[Maybe[T]]) -> Maybe[T]:
    """
    Flatten nested Maybes (monadic join)

    Type signature: Maybe[Maybe[T]] → Maybe[T]
    """
    return flat_map(maybe, lambda x: x)


# ============================================================================
# COMPOSITION OPERATORS
# ============================================================================

def compose_kleisli(
    f: Callable[[T], Maybe[U]],
    g: Callable[[U], Maybe[V]]
) -> Callable[[T], Maybe[V]]:
    """
    Kleisli composition (>=>)

    Compose two functions that return Maybes.

    Type signature: (T → Maybe[U]) → (U → Maybe[V]) → (T → Maybe[V])

    Examples:
        >>> f = lambda x: Just(x + 1)
        >>> g = lambda x: Just(x * 2)
        >>> h = compose_kleisli(f, g)
        >>> h(5)
        Just(12)
    """
    return lambda x: flat_map(f(x), g)


# Operator alias
kleisli = compose_kleisli


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def from_optional(value: T | None) -> Maybe[T]:
    """
    Convert Optional/None to Maybe

    Examples:
        >>> from_optional(5)
        Just(5)

        >>> from_optional(None)
        Nothing
    """
    if value is not None:
        return Just(value)
    else:
        return NOTHING


def from_predicate(value: T, predicate: Callable[[T], bool]) -> Maybe[T]:
    """
    Create Maybe based on predicate

    Examples:
        >>> from_predicate(5, lambda x: x > 0)
        Just(5)

        >>> from_predicate(-5, lambda x: x > 0)
        Nothing
    """
    if predicate(value):
        return Just(value)
    else:
        return NOTHING


def to_optional(maybe: Maybe[T]) -> T | None:
    """
    Convert Maybe to Optional/None

    Examples:
        >>> to_optional(Just(5))
        5

        >>> to_optional(NOTHING)
        None
    """
    if isinstance(maybe, Just):
        return maybe.value
    else:
        return None


def unwrap(maybe: Maybe[T], default: T) -> T:
    """
    Extract value from Maybe, using default if Nothing

    Examples:
        >>> unwrap(Just(5), 0)
        5

        >>> unwrap(NOTHING, 0)
        0
    """
    if isinstance(maybe, Just):
        return maybe.value
    else:
        return default


def unwrap_or_else(maybe: Maybe[T], f: Callable[[], T]) -> T:
    """
    Extract value from Maybe, computing default if Nothing

    Examples:
        >>> unwrap_or_else(Just(5), lambda: 0)
        5

        >>> unwrap_or_else(NOTHING, lambda: 0)
        0
    """
    if isinstance(maybe, Just):
        return maybe.value
    else:
        return f()


def expect(maybe: Maybe[T], message: str) -> T:
    """
    Extract value from Maybe, raising exception if Nothing

    Use sparingly - defeats purpose of Maybe monad!
    Only use at program boundaries.

    Examples:
        >>> expect(Just(5), "should have value")
        5

        >>> expect(NOTHING, "should have value")
        Traceback (most recent call last):
        ...
        Exception: should have value
    """
    if isinstance(maybe, Just):
        return maybe.value
    else:
        raise Exception(message)


# ============================================================================
# COLLECTION OPERATIONS
# ============================================================================

def collect(maybes: list[Maybe[T]]) -> Maybe[list[T]]:
    """
    Collect list of Maybes into Maybe of list

    Short-circuits on first Nothing.

    Type signature: [Maybe[T]] → Maybe[[T]]

    Examples:
        >>> collect([Just(1), Just(2), Just(3)])
        Just([1, 2, 3])

        >>> collect([Just(1), NOTHING, Just(3)])
        Nothing
    """
    values: list[T] = []
    for maybe in maybes:
        if isinstance(maybe, Just):
            values.append(maybe.value)
        else:
            return NOTHING
    return Just(values)


# Alias
sequence = collect


def traverse(items: list[T], f: Callable[[T], Maybe[U]]) -> Maybe[list[U]]:
    """
    Map function over list and collect Maybes

    Type signature: [T] → (T → Maybe[U]) → Maybe[[U]]

    Examples:
        >>> traverse([1, 2, 3], lambda x: Just(x * 2))
        Just([2, 4, 6])

        >>> traverse([1, 2, 3], lambda x: NOTHING if x == 2 else Just(x * 2))
        Nothing
    """
    return collect([f(item) for item in items])


def cat_maybes(maybes: list[Maybe[T]]) -> list[T]:
    """
    Extract all Just values from list, discarding Nothings

    Examples:
        >>> cat_maybes([Just(1), NOTHING, Just(2), NOTHING, Just(3)])
        [1, 2, 3]
    """
    values: list[T] = []
    for maybe in maybes:
        if isinstance(maybe, Just):
            values.append(maybe.value)
    return values


def map_maybe(items: list[T], f: Callable[[T], Maybe[U]]) -> list[U]:
    """
    Map function and extract Just values

    Type signature: [T] → (T → Maybe[U]) → [U]

    Examples:
        >>> map_maybe([1, 2, 3, 4], lambda x: Just(x * 2) if x % 2 == 0 else NOTHING)
        [4, 8]
    """
    return cat_maybes([f(item) for item in items])


def first_just(maybes: list[Maybe[T]]) -> Maybe[T]:
    """
    Return first Just value, or Nothing if all are Nothing

    Examples:
        >>> first_just([NOTHING, Just(5), Just(10)])
        Just(5)

        >>> first_just([NOTHING, NOTHING])
        Nothing
    """
    for maybe in maybes:
        if isinstance(maybe, Just):
            return maybe
    return NOTHING


# ============================================================================
# COMBINATORS
# ============================================================================

def or_else(maybe: Maybe[T], default: Maybe[T]) -> Maybe[T]:
    """
    Return maybe if Just, otherwise return default

    Examples:
        >>> or_else(Just(5), Just(10))
        Just(5)

        >>> or_else(NOTHING, Just(10))
        Just(10)
    """
    if isinstance(maybe, Just):
        return maybe
    else:
        return default


def and_then(maybe: Maybe[T], f: Callable[[T], Maybe[U]]) -> Maybe[U]:
    """
    Alias for flat_map (more readable in chains)
    """
    return flat_map(maybe, f)


def filter(maybe: Maybe[T], predicate: Callable[[T], bool]) -> Maybe[T]:
    """
    Filter Maybe by predicate

    Examples:
        >>> filter(Just(5), lambda x: x > 0)
        Just(5)

        >>> filter(Just(-5), lambda x: x > 0)
        Nothing

        >>> filter(NOTHING, lambda x: x > 0)
        Nothing
    """
    if isinstance(maybe, Just) and predicate(maybe.value):
        return maybe
    else:
        return NOTHING


def tap(maybe: Maybe[T], f: Callable[[T], None]) -> Maybe[T]:
    """
    Execute side effect on Just, return unchanged maybe

    Use for logging, debugging, etc.

    Examples:
        >>> maybe = Just(5)
        >>> tap(maybe, lambda x: print(f"Value: {x}"))
        Value: 5
        Just(5)
    """
    if isinstance(maybe, Just):
        f(maybe.value)
    return maybe


# ============================================================================
# CONVERSIONS
# ============================================================================

def to_result(maybe: Maybe[T], error: E) -> 'Result[T, E]':
    """
    Convert Maybe to Result

    Examples:
        >>> to_result(Just(5), "not found")
        Success(5)

        >>> to_result(NOTHING, "not found")
        Failure("not found")
    """
    from .result import Success, Failure
    if isinstance(maybe, Just):
        return Success(maybe.value)
    else:
        return Failure(error)


def from_result(result: 'Result[T, E]') -> Maybe[T]:
    """
    Convert Result to Maybe (discards error)

    Examples:
        >>> from_result(Success(5))
        Just(5)

        >>> from_result(Failure("error"))
        Nothing
    """
    from .result import Success
    if isinstance(result, Success):
        return Just(result.value)
    else:
        return NOTHING
