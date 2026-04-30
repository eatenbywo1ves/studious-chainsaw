"""
IO Monad - Pure Effect Tracking

Based on Category Theory for Programmers.
The IO monad encapsulates side effects, making them visible in type signatures
while keeping core logic pure.

Type: IO[A] = () → A

This separates:
- Pure computation (building the IO action)
- Impure execution (running the IO action)

The "edge of the world" pattern - effects only execute at program boundaries.
"""

from __future__ import annotations
from typing import TypeVar, Generic, Callable
from dataclasses import dataclass

__all__ = ['IO', 'pure', 'from_effect', 'unsafe_perform']

A = TypeVar('A')
B = TypeVar('B')
C = TypeVar('C')


@dataclass(frozen=True)
class IO(Generic[A]):
    """
    IO monad for effect tracking

    Wraps an effectful computation () → A, making side effects
    explicit in the type system.

    The computation doesn't execute until explicitly run.
    """
    unsafe_run: Callable[[], A]

    def __repr__(self) -> str:
        return "IO(<effect>)"

    # ========================================================================
    # FUNCTOR INSTANCE
    # ========================================================================

    def map(self, f: Callable[[A], B]) -> IO[B]:
        """
        Functor map - Transform the result of IO action

        Type signature: (A → B) → IO[A] → IO[B]

        Creates a new IO action without executing the original.

        Examples:
            >>> read_line = IO(lambda: input("Enter name: "))
            >>> upper_line = read_line.map(str.upper)
            >>> # Nothing executed yet! Pure composition.
        """
        return IO(lambda: f(self.unsafe_run()))

    # ========================================================================
    # APPLICATIVE INSTANCE
    # ========================================================================

    def ap(self, io_f: IO[Callable[[A], B]]) -> IO[B]:
        """
        Applicative apply

        Type signature: IO[A → B] → IO[A] → IO[B]
        """
        return IO(lambda: io_f.unsafe_run()(self.unsafe_run()))

    # ========================================================================
    # MONAD INSTANCE
    # ========================================================================

    def flat_map(self, f: Callable[[A], IO[B]]) -> IO[B]:
        """
        Monad bind (>>=) - Chain IO actions

        Type signature: IO[A] → (A → IO[B]) → IO[B]

        Sequences effects - the second effect depends on the
        result of the first.

        Examples:
            >>> def greet_user():
            ...     return (
            ...         IO(lambda: input("Name: "))
            ...         .flat_map(lambda name:
            ...             IO(lambda: print(f"Hello, {name}!")))
            ...     )
            >>> # Pure! Nothing executed until:
            >>> greet_user().unsafe_run()
        """
        return IO(lambda: f(self.unsafe_run()).unsafe_run())

    # Aliases
    def bind(self, f: Callable[[A], IO[B]]) -> IO[B]:
        return self.flat_map(f)

    def chain(self, f: Callable[[A], IO[B]]) -> IO[B]:
        return self.flat_map(f)

    def and_then(self, f: Callable[[A], IO[B]]) -> IO[B]:
        """More readable alias"""
        return self.flat_map(f)

    # ========================================================================
    # IO-SPECIFIC OPERATIONS
    # ========================================================================

    def then(self, io_next: IO[B]) -> IO[B]:
        """
        Execute this IO, discard result, then execute next IO

        Type signature: IO[A] → IO[B] → IO[B]

        Examples:
            >>> print_hello = IO(lambda: print("Hello"))
            >>> print_world = IO(lambda: print("World"))
            >>> program = print_hello.then(print_world)
        """
        return self.flat_map(lambda _: io_next)

    def tap(self, f: Callable[[A], None]) -> IO[A]:
        """
        Execute side effect with result, return original result

        Useful for logging without changing the computation.

        Examples:
            >>> compute = IO(lambda: 42)
            >>> logged = compute.tap(lambda x: print(f"Result: {x}"))
        """
        return self.map(lambda x: (f(x), x)[1])


# ============================================================================
# CONSTRUCTORS
# ============================================================================

def pure(value: A) -> IO[A]:
    """
    Lift a pure value into IO context

    Type signature: A → IO[A]

    No effects, just wraps the value.

    Examples:
        >>> pure(42)
        IO(<effect>)
        >>> pure(42).unsafe_run()
        42
    """
    return IO(lambda: value)


def from_effect(effect: Callable[[], A]) -> IO[A]:
    """
    Create IO from effectful computation

    Type signature: (() → A) → IO[A]

    Examples:
        >>> read_file = from_effect(lambda: open("data.txt").read())
        >>> # File not opened yet!
        >>> content = read_file.unsafe_run()  # Now it executes
    """
    return IO(effect)


def defer(f: Callable[[], A]) -> IO[A]:
    """Alias for from_effect"""
    return from_effect(f)


# ============================================================================
# EXECUTION
# ============================================================================

def unsafe_perform(io: IO[A]) -> A:
    """
    Execute IO action (!!!)

    Type signature: IO[A] → A

    WARNING: This is the "edge of the world"!
    Only call this at program entry point (main function).

    Everywhere else, keep building IO actions.

    Examples:
        >>> io = IO(lambda: print("Hello!"))
        >>> unsafe_perform(io)  # NOW it executes
        Hello!
    """
    return io.unsafe_run()


# Alias
run = unsafe_perform


# ============================================================================
# COMPOSITION
# ============================================================================

def sequence(ios: list[IO[A]]) -> IO[list[A]]:
    """
    Execute list of IO actions, collect results

    Type signature: [IO[A]] → IO[[A]]

    Examples:
        >>> ios = [
        ...     IO(lambda: print("Line 1")),
        ...     IO(lambda: print("Line 2")),
        ...     IO(lambda: print("Line 3"))
        ... ]
        >>> program = sequence(ios)
        >>> program.unsafe_run()
        Line 1
        Line 2
        Line 3
    """
    def run_all():
        return [io.unsafe_run() for io in ios]
    return IO(run_all)


def traverse(items: list[A], f: Callable[[A], IO[B]]) -> IO[list[B]]:
    """
    Map IO-returning function and sequence results

    Type signature: [A] → (A → IO[B]) → IO[[B]]
    """
    return sequence([f(item) for item in items])


def foreach(items: list[A], f: Callable[[A], IO[None]]) -> IO[None]:
    """
    Execute IO action for each item, discard results

    Type signature: [A] → (A → IO[()]) → IO[()]

    Examples:
        >>> names = ["Alice", "Bob", "Carol"]
        >>> foreach(names, lambda name: IO(lambda: print(f"Hello, {name}")))
    """
    return traverse(items, f).map(lambda _: None)


# ============================================================================
# COMMON IO OPERATIONS
# ============================================================================

def print_line(text: str) -> IO[None]:
    """Print text with newline"""
    return IO(lambda: print(text))


def read_line(prompt: str = "") -> IO[str]:
    """Read line from stdin"""
    return IO(lambda: input(prompt))


def read_file(path: str) -> IO[str]:
    """Read entire file"""
    return IO(lambda: open(path).read())


def write_file(path: str, content: str) -> IO[None]:
    """Write content to file"""
    return IO(lambda: open(path, 'w').write(content) and None)


# ============================================================================
# LIFTING AND CONVERSION
# ============================================================================

def lift_pure(f: Callable[[A], B]) -> Callable[[A], IO[B]]:
    """
    Lift pure function into IO

    Type signature: (A → B) → (A → IO[B])

    Examples:
        >>> double = lambda x: x * 2
        >>> io_double = lift_pure(double)
        >>> io_double(5).unsafe_run()
        10
    """
    return lambda a: pure(f(a))


def to_result(io: IO[A]) -> IO['Result[A, Exception]']:
    """
    Convert IO to IO[Result], catching exceptions

    Type signature: IO[A] → IO[Result[A, Exception]]

    Examples:
        >>> risky = IO(lambda: 10 / 0)
        >>> safe = to_result(risky)
        >>> safe.unsafe_run()
        Failure(ZeroDivisionError(...))
    """
    from ..core.result import Success, Failure

    def run_safe():
        try:
            return Success(io.unsafe_run())
        except Exception as e:
            return Failure(e)

    return IO(run_safe)


# ============================================================================
# PRACTICAL EXAMPLE
# ============================================================================

"""
Example: Pure Program with IO

BEFORE (Impure):
```python
def main():
    print("Enter your name:")
    name = input()

    print(f"Hello, {name}!")

    with open("greeting.txt", "w") as f:
        f.write(f"Hello, {name}!")

    print("Greeting saved!")
```

AFTER (Pure with IO):
```python
def get_name() -> IO[str]:
    return (
        print_line("Enter your name:")
        .then(read_line())
    )

def greet(name: str) -> IO[None]:
    return print_line(f"Hello, {name}!")

def save_greeting(name: str) -> IO[None]:
    return write_file("greeting.txt", f"Hello, {name}!")

def main_program() -> IO[None]:
    '''Pure composition of IO actions'''
    return (
        get_name()
        .flat_map(lambda name:
            greet(name)
            .then(save_greeting(name))
            .then(print_line("Greeting saved!"))
        )
    )

# Execute at entry point
if __name__ == "__main__":
    unsafe_perform(main_program())
```

Benefits:
- ✅ Pure functions everywhere except main
- ✅ Effects visible in type signatures
- ✅ Easy to test (just check IO structure)
- ✅ Composable without executing
- ✅ Referentially transparent
"""


# ============================================================================
# COMBINATORS
# ============================================================================

def when(condition: bool, action: IO[None]) -> IO[None]:
    """
    Conditionally execute IO action

    Examples:
        >>> when(user.is_admin, print_line("Welcome, admin!"))
    """
    if condition:
        return action
    else:
        return pure(None)


def unless(condition: bool, action: IO[None]) -> IO[None]:
    """Execute IO action unless condition is true"""
    return when(not condition, action)


def forever(action: IO[A]) -> IO[None]:
    """
    Repeat IO action forever

    WARNING: Infinite loop!

    Examples:
        >>> server = forever(handle_request())
    """
    def loop():
        action.unsafe_run()
        return loop()

    return IO(loop)


def repeat(n: int, action: IO[A]) -> IO[list[A]]:
    """
    Repeat IO action n times

    Examples:
        >>> repeat(3, print_line("Hello"))
    """
    return sequence([action for _ in range(n)])


def retry(n: int, action: IO[A]) -> IO[A]:
    """
    Retry IO action up to n times on exception

    Examples:
        >>> flaky_api = IO(lambda: requests.get("..."))
        >>> reliable = retry(3, flaky_api)
    """
    def attempt():
        for i in range(n):
            try:
                return action.unsafe_run()
            except Exception:
                if i == n - 1:
                    raise
                continue
        raise RuntimeError("Unreachable")

    return IO(attempt)


# ============================================================================
# MEMOIZATION
# ============================================================================

def memoize(io: IO[A]) -> IO[A]:
    """
    Memoize IO action - execute once, cache result

    Examples:
        >>> expensive = IO(lambda: compute_large_dataset())
        >>> cached = memoize(expensive)
        >>> # First call executes
        >>> cached.unsafe_run()
        >>> # Subsequent calls return cached value
        >>> cached.unsafe_run()
    """
    cache: dict[str, A] = {}

    def run_once():
        if 'value' not in cache:
            cache['value'] = io.unsafe_run()
        return cache['value']

    return IO(run_once)
