# Functional Programming Library

A comprehensive category theory-based functional programming library for Python, providing composable abstractions for building maintainable systems.

**Based on "Category Theory for Programmers" by Bartosz Milewski.**

---

## 🎯 Why This Library?

Your codebase analysis revealed critical **composition breaks**:

1. **Exceptions breaking composition chains** → Use `Result` monad
2. **Global mutable singletons** → Use `Reader` monad
3. **Imperative fallback logic** → Use `Alternative` functor
4. **Hidden side effects** → Use `IO` monad
5. **Short-circuit validation** → Use `Validation` applicative

This library fixes all of these by providing proper categorical abstractions.

---

## 📦 Installation

```python
# Add to your project
from functional import Result, Maybe, Reader, IO, pipe, compose
```

---

## 🚀 Quick Start

```python
from functional import Result, Success, Failure, pipe

# Composable error handling
def divide(x: float, y: float) -> Result[float, str]:
    if y == 0:
        return Failure("Division by zero")
    return Success(x / y)

# Chain operations
result = (
    divide(10, 2)
    .map(lambda x: x * 2)
    .flat_map(lambda x: divide(x, 3))
)
# Success(3.333...)

# Function composition
process = pipe(
    lambda x: x + 1,
    lambda x: x * 2,
    lambda x: x ** 2
)
process(5)  # 144
```

---

## 🏗️ Core Types

### Result[T, E] - Composable Error Handling

Replace exceptions with composable error handling.

```python
from functional import Result, Success, Failure

def parse_int(s: str) -> Result[int, str]:
    try:
        return Success(int(s))
    except ValueError:
        return Failure(f"'{s}' is not a valid integer")

# Compose operations that may fail
result = (
    parse_int("42")
    .map(lambda x: x * 2)
    .flat_map(lambda x: divide(x, 3))
)
# Success(28)
```

**Laws:** Functor, Applicative, Monad

---

### Maybe[T] - Composable Null Handling

Replace `None` checks with composable null handling.

```python
from functional import Maybe, Just, Nothing

def find_user(user_id: str) -> Maybe[User]:
    user = db.get(user_id)
    return Just(user) if user else Nothing

# Chain operations without None checks
email = (
    find_user("user-123")
    .map(lambda user: user.email)
    .filter(lambda email: email.endswith("@example.com"))
    .unwrap("noreply@default.com")
)
```

**Laws:** Functor, Applicative, Monad

---

### Reader[R, A] - Composable Dependency Injection

Replace global singletons with explicit dependencies.

```python
from functional import Reader, ask, run_reader
from dataclasses import dataclass

@dataclass(frozen=True)
class AppConfig:
    cache: CacheService
    db: DatabaseClient
    email: EmailService

def get_user(user_id: str) -> Reader[AppConfig, User]:
    """Dependency explicit in type signature"""
    def fetch(config: AppConfig) -> User:
        return config.cache.get(f"user:{user_id}")
    return Reader(fetch)

def get_posts(user: User) -> Reader[AppConfig, list[Post]]:
    def fetch(config: AppConfig) -> list[Post]:
        return config.db.get_posts(user.id)
    return Reader(fetch)

# Compose operations with same dependencies
def get_user_posts(user_id: str) -> Reader[AppConfig, list[Post]]:
    return get_user(user_id).flat_map(get_posts)

# Run at entry point
config = AppConfig(cache=..., db=..., email=...)
posts = run_reader(get_user_posts("user-123"), config)
```

**Laws:** Functor, Applicative, Monad

---

### IO[A] - Pure Effect Tracking

Make side effects explicit in type signatures.

```python
from functional import IO, print_line, read_line, unsafe_perform

def greet_user() -> IO[None]:
    """Pure function returning IO action"""
    return (
        print_line("What's your name?")
        .then(read_line())
        .flat_map(lambda name: print_line(f"Hello, {name}!"))
    )

# Nothing executes until:
unsafe_perform(greet_user())  # Now it runs!
```

**Laws:** Functor, Applicative, Monad

---

### Validation[E, A] - Error-Accumulating Validation

Show ALL validation errors, not just the first.

```python
from functional.validation import Valid, Invalid, validate_all, validator

# Define validators
username_min = validator(lambda s: len(s) >= 3, "Username too short")
email_valid = validator(lambda s: "@" in s, "Email invalid")
age_positive = validator(lambda n: n > 0, "Age must be positive")

# Validate form - accumulates ALL errors
result = validate_all(
    username_min("ab"),      # Invalid
    email_valid("invalid"),   # Invalid
    age_positive(-5)          # Invalid
)
# Invalid(["Username too short", "Email invalid", "Age must be positive"])
# Shows all errors at once!
```

**Laws:** Functor, Applicative (**NOT** Monad - by design!)

---

### Alternative - Composable Choice

Try alternatives until one succeeds.

```python
from functional import fallback_chain

def send_email(to: str, subject: str, body: str) -> Result[bool, list[str]]:
    """Try each provider, accumulate errors"""
    return fallback_chain(
        lambda: send_via_sendgrid(to, subject, body),
        lambda: send_via_aws_ses(to, subject, body),
        lambda: send_via_smtp(to, subject, body)
    )

result = send_email("user@example.com", "Hello", "World")
# Success(True) if any provider works
# Failure([...all errors...]) if all fail
```

**Laws:** Associativity, Identity

---

## 🔧 Composition Operators

### pipe - Left-to-Right Composition

```python
from functional import pipe

# Data flows left to right
process = pipe(
    lambda x: x + 1,
    lambda x: x * 2,
    lambda x: x ** 2
)
process(5)  # ((5 + 1) * 2) ** 2 = 144
```

### compose - Mathematical Composition

```python
from functional import compose

# Functions applied right to left (math notation)
process = compose(
    lambda x: x ** 2,  # Last
    lambda x: x * 2,   # Second
    lambda x: x + 1    # First
)
process(5)  # 144
```

### identity - Identity Morphism

```python
from functional import identity

# The neutral element for composition
compose(identity, f) == f
compose(f, identity) == f
```

---

## 📚 Category Laws

All implementations follow category theory laws. Run tests:

```bash
pytest functional/tests/test_category_laws.py -v
```

### Functor Laws
1. **Identity**: `map(id) = id`
2. **Composition**: `map(g ∘ f) = map(g) ∘ map(f)`

### Monad Laws
1. **Left Identity**: `pure(a) >>= f = f(a)`
2. **Right Identity**: `m >>= pure = m`
3. **Associativity**: `(m >>= f) >>= g = m >>= (λx → f(x) >>= g)`

### Composition Laws
1. **Associativity**: `(h ∘ g) ∘ f = h ∘ (g ∘ f)`
2. **Left Identity**: `id ∘ f = f`
3. **Right Identity**: `f ∘ id = f`

---

## 🎓 Migration Guide

See [MIGRATION_GUIDE.md](./docs/MIGRATION_GUIDE.md) for:

- Step-by-step migration from imperative code
- Before/after examples from your codebase
- Complete refactoring patterns
- Testing strategies

Key migrations:
1. Replace exceptions → `Result`
2. Replace `None` checks → `Maybe`
3. Replace global singletons → `Reader`
4. Replace try-catch chains → `Alternative`
5. Make effects explicit → `IO`

---

## 📁 Library Structure

```
functional/
├── __init__.py           # Main exports
├── core/
│   ├── result.py         # Result/Either monad
│   ├── maybe.py          # Maybe/Option monad
│   └── alternative.py    # Alternative functor
├── monads/
│   ├── reader.py         # Reader monad
│   └── io.py             # IO monad
├── operators/
│   └── compose.py        # Composition utilities
├── validation/
│   └── validation.py     # Validation applicative
├── tests/
│   └── test_category_laws.py
├── docs/
│   └── MIGRATION_GUIDE.md  # Migration guide
└── README.md               # This file
```

---

## 🧪 Testing

```bash
# Run all tests
pytest functional/tests/ -v

# Run specific test file
pytest functional/tests/test_category_laws.py -v

# Run with coverage
pytest functional/tests/ --cov=functional --cov-report=html
```

---

## 📖 Examples

### Example 1: Email Service with Fallback

```python
from functional import fallback_chain, Success, Failure

def send_via_sendgrid(email: str) -> Result[bool, str]:
    try:
        # SendGrid logic
        return Success(True)
    except Exception as e:
        return Failure(f"SendGrid: {e}")

def send_email(email: str) -> Result[bool, list[str]]:
    return fallback_chain(
        lambda: send_via_sendgrid(email),
        lambda: send_via_aws_ses(email),
        lambda: send_via_smtp(email)
    )
```

### Example 2: User Profile Pipeline

```python
from functional import pipe_with_result

def get_user_profile(user_id: str) -> Result[Profile, str]:
    return pipe_with_result(
        lambda id: fetch_user(id),
        lambda user: validate_user(user),
        lambda user: enrich_user_data(user),
        lambda user: format_profile(user)
    )(user_id)
```

### Example 3: Configuration Validation

```python
from functional.validation import validate_all, validator

# Validators
port_valid = validator(lambda n: 1 <= n <= 65535, "Port must be 1-65535")
url_valid = validator(lambda s: s.startswith("http"), "URL must start with http")

def validate_config(port: int, url: str) -> Validation[str, Config]:
    return validate_all(
        port_valid(port),
        url_valid(url)
    ).map(lambda vals: Config(vals[0], vals[1]))

# Shows all errors if invalid
result = validate_config(0, "invalid")
# Invalid(["Port must be 1-65535", "URL must start with http"])
```

---

## 🎯 Benefits

### Type Safety
- Errors visible in types: `Result[T, E]`
- Nulls visible in types: `Maybe[T]`
- Dependencies visible in types: `Reader[R, A]`
- Effects visible in types: `IO[A]`

### Composability
- Chain operations: `op1.flat_map(op2).flat_map(op3)`
- Compose functions: `pipe(f, g, h)`
- No nested try-catch or if-None

### Testability
- Pure functions (except IO boundaries)
- Easy to mock (inject config via Reader)
- No global state to reset

### Maintainability
- Explicit data flow
- Referentially transparent
- Mathematical guarantees via laws

---

## 🔗 Resources

- [Category Theory for Programmers](https://bartoszmilewski.com/2014/10/28/category-theory-for-programmers-the-preface/) - Bartosz Milewski
- [Functors, Applicatives, and Monads in Pictures](http://adit.io/posts/2013-04-17-functors,_applicatives,_and_monads_in_pictures.html)
- [Railway Oriented Programming](https://fsharpforfunandprofit.com/rop/) - Scott Wlaschin

---

## 📝 License

MIT License

---

## 🤝 Contributing

Contributions welcome! Please ensure:

1. All category law tests pass
2. New features have tests
3. Documentation is updated
4. Code follows existing patterns

---

## ✨ Version

**v1.0.0** - Initial release

### Features
- ✅ Result/Either monad
- ✅ Maybe/Option monad
- ✅ Reader monad
- ✅ IO monad
- ✅ Validation applicative
- ✅ Alternative functor
- ✅ Composition operators
- ✅ Category law tests
- ✅ Migration guide

---

## 🎉 Summary

This library provides mathematically sound, composable abstractions that fix the composition breaks in your codebase:

| Problem | Solution | Benefit |
|---------|----------|---------|
| Exceptions break composition | `Result` monad | Composable error handling |
| `None` checks everywhere | `Maybe` monad | Composable null handling |
| Global singletons | `Reader` monad | Explicit dependencies |
| Imperative fallback chains | `Alternative` functor | Composable choice |
| Hidden side effects | `IO` monad | Explicit effects |
| Short-circuit validation | `Validation` applicative | Show all errors |

**Welcome to compositional programming!** 🚀
