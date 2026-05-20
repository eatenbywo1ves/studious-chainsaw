"""
Functional Programming Library for Python

A comprehensive category theory-based functional programming library
providing composable abstractions for building maintainable systems.

Based on "Category Theory for Programmers" by Bartosz Milewski.

## Core Types

- **Result[T, E]**: Composable error handling without exceptions
- **Maybe[T]**: Composable null handling without None checks
- **Reader[R, A]**: Composable dependency injection without global state
- **IO[A]**: Pure effect tracking with explicit side effects

## Key Concepts

### Functors
Types that can be mapped over while preserving structure.

### Monads
Types that support flat_map (bind) for chaining dependent computations.

### Alternative
Types that support choice/fallback operations.

## Quick Start

```python
from functional import Result, Success, Failure, pipe

# Composable error handling
def divide(x: float, y: float) -> Result[float, str]:
    if y == 0:
        return Failure("Division by zero")
    return Success(x / y)

result = divide(10, 2)  # Success(5.0)
error = divide(10, 0)   # Failure("Division by zero")

# Function composition
from functional import pipe

process = pipe(
    lambda x: x + 1,
    lambda x: x * 2,
    lambda x: x ** 2
)
process(5)  # 144

# Dependency injection with Reader
from functional import Reader, ask, run_reader

def get_config() -> Reader[Config, str]:
    return ask().map(lambda c: c.database_url)

config = Config(database_url="postgresql://...")
url = run_reader(get_config(), config)
```

## Installation

Add to your project:
```
from functional import Result, Maybe, Reader, IO, pipe, compose
```

## Documentation

See individual modules for detailed documentation:
- `functional.core.result`: Result/Either monad
- `functional.core.maybe`: Maybe/Option monad
- `functional.monads.reader`: Reader monad
- `functional.monads.io`: IO monad
- `functional.operators.compose`: Composition utilities
"""

__version__ = '1.0.0'
__author__ = 'Catalytic Computing'

# ============================================================================
# CORE TYPES
# ============================================================================

# Result/Either monad
from .core.result import (
    Result, Success, Failure,
    is_success, is_failure,
    from_optional as result_from_optional,
    from_exception,
    collect as result_collect,
    sequence as result_sequence,
)

# Maybe/Option monad
from .core.maybe import (
    Maybe, Just, Nothing, NOTHING,
    is_just, is_nothing,
    from_optional as maybe_from_optional,
    from_predicate,
    collect as maybe_collect,
    sequence as maybe_sequence,
    first_just,
)

# Alternative functor
from .core.alternative import (
    or_else_result,
    or_else_maybe,
    try_alternatives,
    fallback_chain,
    retry_with_alternative,
)

# ============================================================================
# MONADS
# ============================================================================

# Reader monad
from .monads.reader import (
    Reader,
    pure as reader_pure,
    ask,
    asks,
    run_reader,
)

# IO monad
from .monads.io import (
    IO,
    pure as io_pure,
    from_effect,
    unsafe_perform,
    print_line,
    read_line,
    read_file,
    write_file,
)

# ============================================================================
# OPERATORS
# ============================================================================

from .operators.compose import (
    identity, id,
    compose, pipe,
    compose_many, pipe_many,
    curry, partial, flip,
    tap_log, trace, constant,
)

# ============================================================================
# PUBLIC API
# ============================================================================

__all__ = [
    # Version
    '__version__',

    # Result
    'Result', 'Success', 'Failure',
    'is_success', 'is_failure',
    'from_exception',
    'result_from_optional', 'result_collect', 'result_sequence',

    # Maybe
    'Maybe', 'Just', 'Nothing', 'NOTHING',
    'is_just', 'is_nothing',
    'maybe_from_optional', 'from_predicate',
    'maybe_collect', 'maybe_sequence', 'first_just',

    # Alternative
    'or_else_result', 'or_else_maybe',
    'try_alternatives', 'fallback_chain',
    'retry_with_alternative',

    # Reader
    'Reader', 'reader_pure', 'ask', 'asks', 'run_reader',

    # IO
    'IO', 'io_pure', 'from_effect', 'unsafe_perform',
    'print_line', 'read_line', 'read_file', 'write_file',

    # Composition
    'identity', 'id',
    'compose', 'pipe',
    'compose_many', 'pipe_many',
    'curry', 'partial', 'flip',
    'tap_log', 'trace', 'constant',
]


# ============================================================================
# CONVENIENCE EXPORTS
# ============================================================================

# Make common operations available at top level
def ok(value):
    """Alias for Success"""
    return Success(value)


def err(error):
    """Alias for Failure"""
    return Failure(error)


def some(value):
    """Alias for Just"""
    return Just(value)


def none():
    """Alias for NOTHING"""
    return NOTHING


__all__ += ['ok', 'err', 'some', 'none']


# ============================================================================
# LIBRARY INFO
# ============================================================================

def version():
    """Get library version"""
    return __version__


def info():
    """Print library information"""
    print(f"""
Functional Programming Library v{__version__}
================================================

A category theory-based functional programming library for Python.

Core Types:
  - Result[T, E]: Composable error handling
  - Maybe[T]: Composable null handling
  - Reader[R, A]: Composable dependency injection
  - IO[A]: Pure effect tracking

Features:
  - Functor/Applicative/Monad type classes
  - Kleisli composition for monads
  - Alternative for composable choice
  - Pipe and compose operators
  - Category law tests

Documentation: See module docstrings
Repository: https://github.com/catalytic-computing
License: MIT
""")


__all__ += ['version', 'info']
