"""
Reader Monad - Composable Dependency Injection

Based on Category Theory for Programmers.
The Reader monad represents computations that depend on a shared environment,
providing composable dependency injection without global state.

Type: Reader[R, A] = R → A

This solves the global singleton problem by making dependencies explicit.

Laws:
    1. Functor Identity: map(id) = id
    2. Functor Composition: map(g ∘ f) = map(g) ∘ map(f)
    3. Monad Left Identity: pure(a) >>= f = f(a)
    4. Monad Right Identity: m >>= pure = m
    5. Monad Associativity: (m >>= f) >>= g = m >>= (λx → f(x) >>= g)
"""

from __future__ import annotations
from typing import TypeVar, Generic, Callable
from dataclasses import dataclass

__all__ = [
    'Reader', 'pure', 'ask', 'asks',
    'local', 'run_reader'
]

R = TypeVar('R')  # Environment/Config type
A = TypeVar('A')  # Value type
B = TypeVar('B')
C = TypeVar('C')


@dataclass(frozen=True)
class Reader(Generic[R, A]):
    """
    Reader monad for dependency injection

    Wraps a function R → A, representing a computation
    that reads from environment R and produces value A.

    This eliminates the need for global singletons by
    making dependencies explicit in the type signature.
    """
    run: Callable[[R], A]

    def __repr__(self) -> str:
        return "Reader(<function>)"

    # ========================================================================
    # FUNCTOR INSTANCE
    # ========================================================================

    def map(self, f: Callable[[A], B]) -> Reader[R, B]:
        """
        Functor map - Transform the result value

        Type signature: (A → B) → Reader[R, A] → Reader[R, B]

        Examples:
            >>> reader = Reader(lambda config: config.value)
            >>> mapped = reader.map(lambda x: x * 2)
            >>> mapped.run(Config(value=5))
            10
        """
        return Reader(lambda r: f(self.run(r)))

    # ========================================================================
    # APPLICATIVE INSTANCE
    # ========================================================================

    def ap(self, reader_f: Reader[R, Callable[[A], B]]) -> Reader[R, B]:
        """
        Applicative apply

        Type signature: Reader[R, A → B] → Reader[R, A] → Reader[R, B]
        """
        return Reader(lambda r: reader_f.run(r)(self.run(r)))

    # ========================================================================
    # MONAD INSTANCE
    # ========================================================================

    def flat_map(self, f: Callable[[A], Reader[R, B]]) -> Reader[R, B]:
        """
        Monad bind (>>=) - Kleisli composition

        Type signature: Reader[R, A] → (A → Reader[R, B]) → Reader[R, B]

        This enables chaining computations that depend on the same environment.

        Examples:
            >>> def get_user(config):
            ...     return Reader(lambda env: env.db.get_user(config.user_id))
            >>>
            >>> def get_posts(user):
            ...     return Reader(lambda env: env.db.get_posts(user.id))
            >>>
            >>> reader = Reader(lambda env: env.config)
            >>> result = reader.flat_map(get_user).flat_map(get_posts)
        """
        return Reader(lambda r: f(self.run(r)).run(r))

    # Aliases
    def bind(self, f: Callable[[A], Reader[R, B]]) -> Reader[R, B]:
        return self.flat_map(f)

    def chain(self, f: Callable[[A], Reader[R, B]]) -> Reader[R, B]:
        return self.flat_map(f)

    def and_then(self, f: Callable[[A], Reader[R, B]]) -> Reader[R, B]:
        """More readable alias for flat_map"""
        return self.flat_map(f)

    # ========================================================================
    # READER-SPECIFIC OPERATIONS
    # ========================================================================

    def local(self, f: Callable[[R], R]) -> Reader[R, A]:
        """
        Execute computation with modified environment

        Type signature: (R → R) → Reader[R, A] → Reader[R, A]

        Examples:
            >>> reader = Reader(lambda config: config.timeout)
            >>> with_longer_timeout = reader.local(lambda c: c.with_timeout(60))
        """
        return Reader(lambda r: self.run(f(r)))

    def with_env(self, env: R) -> A:
        """
        Execute reader with given environment (alias for run)
        """
        return self.run(env)


# ============================================================================
# CONSTRUCTORS
# ============================================================================

def pure(value: A) -> Reader[R, A]:
    """
    Applicative pure - Lift a value into Reader context

    Type signature: A → Reader[R, A]

    Ignores the environment and returns the value.
    This is the identity morphism for the Reader monad.

    Examples:
        >>> reader = pure(42)
        >>> reader.run(any_config)
        42
    """
    return Reader(lambda r: value)


def ask() -> Reader[R, R]:
    """
    Get the current environment

    Type signature: Reader[R, R]

    Examples:
        >>> reader = ask()
        >>> reader.run(config)
        config
    """
    return Reader(lambda r: r)


def asks(f: Callable[[R], A]) -> Reader[R, A]:
    """
    Get a value derived from the environment

    Type signature: (R → A) → Reader[R, A]

    Examples:
        >>> get_db_url = asks(lambda config: config.database_url)
        >>> get_db_url.run(config)
        "postgresql://..."
    """
    return Reader(f)


def local(f: Callable[[R], R], reader: Reader[R, A]) -> Reader[R, A]:
    """
    Execute reader with modified environment

    Type signature: (R → R) → Reader[R, A] → Reader[R, A]

    Examples:
        >>> reader = Reader(lambda config: config.timeout)
        >>> longer_timeout = local(lambda c: c.with_timeout(60), reader)
    """
    return reader.local(f)


# ============================================================================
# EXECUTION
# ============================================================================

def run_reader(reader: Reader[R, A], env: R) -> A:
    """
    Execute a Reader computation with given environment

    Type signature: Reader[R, A] → R → A

    This is the "edge of the world" - where pure computations
    meet the real environment. Should be called at program entry point.

    Examples:
        >>> config = Config(timeout=30, db_url="...")
        >>> result = run_reader(my_computation, config)
    """
    return reader.run(env)


# ============================================================================
# COMPOSITION UTILITIES
# ============================================================================

def compose_kleisli(
    f: Callable[[A], Reader[R, B]],
    g: Callable[[B], Reader[R, C]]
) -> Callable[[A], Reader[R, C]]:
    """
    Kleisli composition for Reader (>=>)

    Type signature: (A → Reader[R, B]) → (B → Reader[R, C]) → (A → Reader[R, C])

    Examples:
        >>> f = lambda x: pure(x + 1)
        >>> g = lambda x: pure(x * 2)
        >>> h = compose_kleisli(f, g)
        >>> h(5).run(config)
        12
    """
    return lambda a: f(a).flat_map(g)


def sequence(readers: list[Reader[R, A]]) -> Reader[R, list[A]]:
    """
    Execute list of readers with same environment

    Type signature: [Reader[R, A]] → Reader[R, [A]]

    Examples:
        >>> readers = [
        ...     asks(lambda c: c.db_url),
        ...     asks(lambda c: c.redis_url),
        ...     asks(lambda c: c.api_key)
        ... ]
        >>> result = sequence(readers).run(config)
        ["postgresql://...", "redis://...", "sk-..."]
    """
    def run_all(env: R) -> list[A]:
        return [reader.run(env) for reader in readers]
    return Reader(run_all)


def traverse(items: list[A], f: Callable[[A], Reader[R, B]]) -> Reader[R, list[B]]:
    """
    Map function over list and sequence readers

    Type signature: [A] → (A → Reader[R, B]) → Reader[R, [B]]
    """
    return sequence([f(item) for item in items])


# ============================================================================
# PRACTICAL EXAMPLES
# ============================================================================

"""
Example: Replace global singleton cache service

BEFORE (Global Singleton):
```python
_cache_service = None

def get_cache_service():
    global _cache_service
    if _cache_service is None:
        redis_url = os.getenv("REDIS_URL")
        _cache_service = CacheService(redis_url)
    return _cache_service

def get_user(user_id: str):
    cache = get_cache_service()  # Hidden dependency!
    return cache.get(f"user:{user_id}")
```

AFTER (Reader Monad):
```python
@dataclass(frozen=True)
class AppConfig:
    cache_service: CacheService
    db_client: DatabaseClient
    email_service: EmailService

def get_user(user_id: str) -> Reader[AppConfig, Optional[User]]:
    '''Explicit dependency on AppConfig'''
    def fetch(config: AppConfig) -> Optional[User]:
        return config.cache_service.get(f"user:{user_id}")
    return Reader(fetch)

def get_posts(user: User) -> Reader[AppConfig, list[Post]]:
    '''Chain operations with same dependencies'''
    def fetch(config: AppConfig) -> list[Post]:
        return config.db_client.get_posts(user.id)
    return Reader(fetch)

# Compose operations
def get_user_posts(user_id: str) -> Reader[AppConfig, list[Post]]:
    return (
        get_user(user_id)
        .flat_map(lambda user: get_posts(user) if user else pure([]))
    )

# Run at program entry point
config = AppConfig(
    cache_service=CacheService("redis://..."),
    db_client=DatabaseClient("postgresql://..."),
    email_service=EmailService()
)
posts = run_reader(get_user_posts("user-123"), config)
```

Benefits:
- ✅ No global mutable state
- ✅ Dependencies are explicit in types
- ✅ Easy to test (inject mock config)
- ✅ Composable - operations share environment
- ✅ Type-safe - compiler checks dependencies
"""


# ============================================================================
# HELPER FUNCTIONS FOR COMMON PATTERNS
# ============================================================================

def lift(f: Callable[[A], B]) -> Callable[[A], Reader[R, B]]:
    """
    Lift a pure function into Reader context

    Type signature: (A → B) → (A → Reader[R, B])
    """
    return lambda a: pure(f(a))


def lift2(
    f: Callable[[A, B], C]
) -> Callable[[Reader[R, A], Reader[R, B]], Reader[R, C]]:
    """
    Lift a binary function into Reader context

    Type signature: (A → B → C) → Reader[R, A] → Reader[R, B] → Reader[R, C]
    """
    def lifted(ra: Reader[R, A], rb: Reader[R, B]) -> Reader[R, C]:
        return Reader(lambda r: f(ra.run(r), rb.run(r)))
    return lifted


def when(condition: bool, action: Reader[R, A]) -> Reader[R, A | None]:
    """
    Conditionally execute reader

    Examples:
        >>> reader = when(user.is_admin, asks(lambda c: c.admin_panel))
    """
    if condition:
        return action.map(lambda x: x)
    else:
        return pure(None)


def unless(condition: bool, action: Reader[R, A]) -> Reader[R, A | None]:
    """
    Execute reader unless condition is true
    """
    return when(not condition, action)
