"""
Composition Operators - Morphism Composition

Based on Category Theory for Programmers.
Function composition is the essence of category theory.

Key operators:
- compose: Mathematical composition (g ∘ f)
- pipe: Left-to-right composition (f |> g)
- identity: Identity morphism

Laws:
    1. Associativity: (h ∘ g) ∘ f = h ∘ (g ∘ f)
    2. Left Identity: id ∘ f = f
    3. Right Identity: f ∘ id = f
"""

from typing import TypeVar, Callable, overload
from functools import reduce

__all__ = [
    'identity', 'compose', 'pipe', 'compose_many',
    'pipe_many', 'curry', 'partial', 'flip'
]

A = TypeVar('A')
B = TypeVar('B')
C = TypeVar('C')
D = TypeVar('D')
E = TypeVar('E')


# ============================================================================
# IDENTITY MORPHISM
# ============================================================================

def identity(x: A) -> A:
    """
    Identity morphism - Returns input unchanged

    Type signature: A → A

    This is the neutral element for composition:
        compose(identity, f) = f
        compose(f, identity) = f

    Examples:
        >>> identity(5)
        5

        >>> identity("hello")
        "hello"

        >>> compose(identity, lambda x: x * 2)(5)
        10
    """
    return x


# Alias
id = identity


# ============================================================================
# FUNCTION COMPOSITION
# ============================================================================

@overload
def compose(
    f: Callable[[A], B],
    g: Callable[[B], C]
) -> Callable[[A], C]: ...


@overload
def compose(
    f: Callable[[A], B],
    g: Callable[[B], C],
    h: Callable[[C], D]
) -> Callable[[A], D]: ...


@overload
def compose(
    f: Callable[[A], B],
    g: Callable[[B], C],
    h: Callable[[C], D],
    i: Callable[[D], E]
) -> Callable[[A], E]: ...


def compose(*functions: Callable) -> Callable:
    """
    Function composition (right-to-left)

    Mathematical notation: (g ∘ f)(x) = g(f(x))

    Type signature: (B → C) → (A → B) → (A → C)

    Functions are applied right-to-left (mathematical order).

    Laws:
        Associativity: compose(h, g, f) = compose(h, compose(g, f))
        Identity: compose(f, identity) = compose(identity, f) = f

    Examples:
        >>> f = lambda x: x + 1
        >>> g = lambda x: x * 2
        >>> h = compose(g, f)
        >>> h(5)
        12  # g(f(5)) = g(6) = 12

        >>> # Multiple functions
        >>> add_one = lambda x: x + 1
        >>> double = lambda x: x * 2
        >>> square = lambda x: x ** 2
        >>> composed = compose(square, double, add_one)
        >>> composed(5)
        144  # square(double(add_one(5))) = square(double(6)) = square(12) = 144
    """
    if len(functions) == 0:
        return identity
    elif len(functions) == 1:
        return functions[0]
    else:
        def composed(x):
            # Apply functions right-to-left
            return reduce(lambda acc, f: f(acc), reversed(functions), x)
        return composed


# ============================================================================
# PIPE (LEFT-TO-RIGHT COMPOSITION)
# ============================================================================

@overload
def pipe(
    f: Callable[[A], B],
    g: Callable[[B], C]
) -> Callable[[A], C]: ...


@overload
def pipe(
    f: Callable[[A], B],
    g: Callable[[B], C],
    h: Callable[[C], D]
) -> Callable[[A], D]: ...


@overload
def pipe(
    f: Callable[[A], B],
    g: Callable[[B], C],
    h: Callable[[C], D],
    i: Callable[[D], E]
) -> Callable[[A], E]: ...


def pipe(*functions: Callable) -> Callable:
    """
    Function composition (left-to-right)

    Type signature: (A → B) → (B → C) → (A → C)

    Functions are applied left-to-right (data flow order).
    More intuitive for imperative programmers.

    Examples:
        >>> f = lambda x: x + 1
        >>> g = lambda x: x * 2
        >>> h = pipe(f, g)
        >>> h(5)
        12  # g(f(5)) = g(6) = 12

        >>> # Multiple functions - easier to read
        >>> pipeline = pipe(
        ...     lambda x: x + 1,     # step 1
        ...     lambda x: x * 2,     # step 2
        ...     lambda x: x ** 2     # step 3
        ... )
        >>> pipeline(5)
        144  # ((5 + 1) * 2) ** 2 = 144
    """
    if len(functions) == 0:
        return identity
    elif len(functions) == 1:
        return functions[0]
    else:
        def piped(x):
            # Apply functions left-to-right
            return reduce(lambda acc, f: f(acc), functions, x)
        return piped


# ============================================================================
# MANY-FUNCTION COMPOSITION
# ============================================================================

def compose_many(functions: list[Callable]) -> Callable:
    """
    Compose a list of functions (right-to-left)

    Examples:
        >>> functions = [
        ...     lambda x: x + 1,
        ...     lambda x: x * 2,
        ...     lambda x: x ** 2
        ... ]
        >>> f = compose_many(functions)
        >>> f(5)
        144
    """
    return compose(*functions)


def pipe_many(functions: list[Callable]) -> Callable:
    """
    Pipe a list of functions (left-to-right)

    Examples:
        >>> functions = [
        ...     lambda x: x + 1,
        ...     lambda x: x * 2,
        ...     lambda x: x ** 2
        ... ]
        >>> f = pipe_many(functions)
        >>> f(5)
        144
    """
    return pipe(*functions)


# ============================================================================
# CURRYING AND PARTIAL APPLICATION
# ============================================================================

def curry(f: Callable) -> Callable:
    """
    Convert a function of multiple arguments to nested single-argument functions

    Type signature: (A → B → C) → (A → (B → C))

    Examples:
        >>> def add(x, y):
        ...     return x + y
        >>> add_curried = curry(add)
        >>> add_5 = add_curried(5)
        >>> add_5(10)
        15
    """
    from functools import wraps
    import inspect

    sig = inspect.signature(f)
    num_params = len(sig.parameters)

    if num_params <= 1:
        return f

    @wraps(f)
    def curried(*args, **kwargs):
        if len(args) + len(kwargs) >= num_params:
            return f(*args, **kwargs)
        else:
            @wraps(f)
            def partial_f(*more_args, **more_kwargs):
                return curried(*(args + more_args), **{**kwargs, **more_kwargs})
            return partial_f

    return curried


def partial(f: Callable, *args, **kwargs) -> Callable:
    """
    Partial application of function arguments

    Type signature: (A → B → C) → A → (B → C)

    Examples:
        >>> def add(x, y):
        ...     return x + y
        >>> add_5 = partial(add, 5)
        >>> add_5(10)
        15
    """
    from functools import partial as functools_partial
    return functools_partial(f, *args, **kwargs)


def flip(f: Callable[[A, B], C]) -> Callable[[B, A], C]:
    """
    Flip the order of two arguments

    Type signature: (A → B → C) → (B → A → C)

    Examples:
        >>> def divide(x, y):
        ...     return x / y
        >>> divide(10, 2)
        5.0
        >>> flip(divide)(2, 10)
        5.0
    """
    def flipped(b: B, a: A) -> C:
        return f(a, b)
    return flipped


# ============================================================================
# PRACTICAL COMPOSITION PATTERNS
# ============================================================================

def tap_log(message: str = "") -> Callable[[A], A]:
    """
    Create a tap function that logs and returns value unchanged

    Useful for debugging composition chains.

    Examples:
        >>> pipeline = pipe(
        ...     lambda x: x + 1,
        ...     tap_log("After add 1"),
        ...     lambda x: x * 2,
        ...     tap_log("After multiply")
        ... )
        >>> pipeline(5)
        After add 1: 6
        After multiply: 12
        12
    """
    def tap(x: A) -> A:
        print(f"{message}: {x}" if message else str(x))
        return x
    return tap


def trace(label: str) -> Callable[[A], A]:
    """
    Trace function execution in composition

    Examples:
        >>> pipeline = pipe(
        ...     trace("input"),
        ...     lambda x: x + 1,
        ...     trace("after +1"),
        ...     lambda x: x * 2,
        ...     trace("after *2")
        ... )
        >>> pipeline(5)
        input: 5
        after +1: 6
        after *2: 12
        12
    """
    def traced(x: A) -> A:
        print(f"{label}: {x!r}")
        return x
    return traced


def constant(value: B) -> Callable[[A], B]:
    """
    Create a function that always returns the same value

    Type signature: B → (A → B)

    Examples:
        >>> always_5 = constant(5)
        >>> always_5(10)
        5
        >>> always_5("anything")
        5
    """
    return lambda _: value


# ============================================================================
# COMPOSITION WITH EFFECTS
# ============================================================================

def compose_with_result(*functions: Callable) -> Callable:
    """
    Compose functions that return Result, using Kleisli composition

    Type signature: (B → Result[C, E]) → (A → Result[B, E]) → (A → Result[C, E])

    Examples:
        >>> from ..core.result import Success, Failure, flat_map
        >>> f = lambda x: Success(x + 1) if x > 0 else Failure("negative")
        >>> g = lambda x: Success(x * 2) if x < 100 else Failure("too large")
        >>> h = compose_with_result(g, f)
        >>> h(5)
        Success(12)
        >>> h(-5)
        Failure("negative")
    """
    from ..core.result import flat_map

    def composed(x):
        result = functions[-1](x) if functions else x
        for f in reversed(functions[:-1]):
            result = flat_map(result, f)
        return result

    return composed


def pipe_with_result(*functions: Callable) -> Callable:
    """
    Pipe functions that return Result (left-to-right Kleisli)

    Examples:
        >>> from ..core.result import Success
        >>> pipeline = pipe_with_result(
        ...     lambda x: Success(x + 1),
        ...     lambda x: Success(x * 2),
        ...     lambda x: Success(x ** 2)
        ... )
        >>> pipeline(5)
        Success(144)
    """
    from ..core.result import flat_map

    def piped(x):
        result = functions[0](x) if functions else x
        for f in functions[1:]:
            result = flat_map(result, f)
        return result

    return piped


# ============================================================================
# FUNCTION LIFTING
# ============================================================================

def lift1(f: Callable[[A], B]) -> Callable[['F[A]'], 'F[B]']:
    """
    Lift unary function into functor context

    This is just map, but expressed as lifting.
    """
    from ..core.result import map as result_map
    from ..core.maybe import map as maybe_map

    def lifted(fa):
        # Duck typing - works with any type that has map
        if hasattr(fa, '__class__'):
            class_name = fa.__class__.__name__
            if class_name in ('Success', 'Failure'):
                return result_map(fa, f)
            elif class_name in ('Just', 'Nothing'):
                return maybe_map(fa, f)
        return fa  # fallback

    return lifted


def lift2(f: Callable[[A, B], C]) -> Callable[['F[A]', 'F[B]'], 'F[C]']:
    """
    Lift binary function into applicative context

    Examples:
        >>> from ..core.result import Success
        >>> add = lambda x, y: x + y
        >>> lifted_add = lift2(add)
        >>> lifted_add(Success(5), Success(10))
        Success(15)
    """
    from ..core.result import ap, map as result_map

    def lifted(fa, fb):
        # First map over first argument
        f_in_context = result_map(fa, lambda a: lambda b: f(a, b))
        # Then apply to second argument
        return ap(f_in_context, fb)

    return lifted


# ============================================================================
# PRACTICAL EXAMPLES
# ============================================================================

"""
Example: Data Processing Pipeline

BEFORE (Imperative):
```python
def process_data(data):
    validated = validate(data)
    if not validated:
        return None

    transformed = transform(validated)
    enriched = enrich(transformed)
    formatted = format(enriched)

    return formatted
```

AFTER (Compositional):
```python
process_data = pipe(
    validate,
    transform,
    enrich,
    format
)

# With logging
process_data_debug = pipe(
    validate,
    trace("after validation"),
    transform,
    trace("after transform"),
    enrich,
    trace("after enrich"),
    format
)

# With error handling
from ..core.result import Success, Failure

def validate_safe(data):
    return Success(data) if is_valid(data) else Failure("Invalid data")

def transform_safe(data):
    return Success(transform(data))

process_data_safe = pipe_with_result(
    validate_safe,
    transform_safe,
    lambda d: Success(enrich(d)),
    lambda d: Success(format(d))
)
```
"""
