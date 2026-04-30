# Quick Reference Card

## Core Types

```python
from functional import *

# Result[T, E] - Error handling
Success(42)              # Success case
Failure("error")         # Failure case

# Maybe[T] - Null handling
Just(42)                 # Has value
NOTHING                  # No value

# Reader[R, A] - Dependency injection
Reader(lambda config: config.db)

# IO[A] - Effect tracking
IO(lambda: print("Hello"))

# Validation[E, A] - Error accumulation
Valid(42)                # Valid case
Invalid(["error"])       # Invalid case (list!)
```

---

## Common Operations

### Result

```python
# Map - transform value
Success(5).map(lambda x: x * 2)  # Success(10)

# FlatMap - chain operations
Success(5).flat_map(lambda x: divide(x, 2))  # Success(2.5)

# Collect errors or values
result_collect([Success(1), Success(2)])  # Success([1, 2])
```

### Maybe

```python
# Map
Just(5).map(lambda x: x * 2)  # Just(10)

# FlatMap
Just(5).flat_map(lambda x: find_user(x))

# Filter
Just(5).filter(lambda x: x > 0)  # Just(5)

# Unwrap with default
Just(5).unwrap(0)  # 5
NOTHING.unwrap(0)  # 0
```

### Reader

```python
# Create
reader = ask().map(lambda config: config.db_url)

# Compose
def get_user(id) -> Reader[Config, User]:
    return ask().map(lambda c: c.db.get(id))

# Run
run_reader(get_user("123"), config)
```

### IO

```python
# Create
io = IO(lambda: print("Hello"))

# Map
io.map(lambda _: "Done")

# Chain
io1.then(io2)  # Execute io1, then io2

# Run (at entry point only!)
unsafe_perform(io)
```

---

## Composition

```python
# Pipe (left to right)
pipe(f, g, h)(x)  # h(g(f(x)))

# Compose (right to left - math notation)
compose(h, g, f)(x)  # h(g(f(x)))

# Identity
identity(x)  # x
```

---

## Pattern Matching

```python
# Result
match result:
    case Success(value):
        print(f"Got: {value}")
    case Failure(error):
        print(f"Error: {error}")

# Maybe
match maybe:
    case Just(value):
        print(f"Got: {value}")
    case Nothing():
        print("No value")
```

---

## Common Patterns

### Error Handling

```python
def divide(x, y) -> Result[float, str]:
    if y == 0:
        return Failure("Division by zero")
    return Success(x / y)

# Chain operations
result = (
    divide(10, 2)
    .flat_map(lambda x: divide(x, 3))
    .map(lambda x: x * 2)
)
```

### Null Handling

```python
def find_user(id) -> Maybe[User]:
    user = db.get(id)
    return Just(user) if user else NOTHING

# Chain operations
email = (
    find_user("123")
    .map(lambda u: u.email)
    .unwrap("noreply@default.com")
)
```

### Dependency Injection

```python
@dataclass
class Config:
    db: DatabaseClient
    cache: CacheService

def get_user(id) -> Reader[Config, User]:
    return ask().map(lambda c: c.db.get(id))

# Run at entry
config = Config(db=..., cache=...)
user = run_reader(get_user("123"), config)
```

### Effect Tracking

```python
def greet() -> IO[None]:
    return (
        print_line("What's your name?")
        .then(read_line())
        .flat_map(lambda name: print_line(f"Hello, {name}!"))
    )

# Run at entry
unsafe_perform(greet())
```

### Validation

```python
username_valid = validator(lambda s: len(s) >= 3, "Too short")
email_valid = validator(lambda s: "@" in s, "Invalid email")

result = validate_all(
    username_valid("ab"),
    email_valid("invalid")
)
# Invalid(["Too short", "Invalid email"])
```

### Fallback

```python
def send_email(to, subject, body) -> Result[bool, list[str]]:
    return fallback_chain(
        lambda: send_via_sendgrid(to, subject, body),
        lambda: send_via_ses(to, subject, body),
        lambda: send_via_smtp(to, subject, body)
    )
```

---

## Method Chaining

```python
# Result
result.map(f).flat_map(g).unwrap(default)

# Maybe
maybe.map(f).filter(pred).flat_map(g).unwrap(default)

# Reader
reader.map(f).flat_map(g).run(config)

# IO
io.map(f).then(io2).tap(log).unsafe_run()
```

---

## Type Signatures

```python
# Functions that may fail
def parse_int(s: str) -> Result[int, str]: ...

# Functions that may return nothing
def find_user(id: str) -> Maybe[User]: ...

# Functions with dependencies
def get_config() -> Reader[Env, Config]: ...

# Functions with effects
def print_msg(msg: str) -> IO[None]: ...

# Validation functions
def validate_form(data) -> Validation[str, Form]: ...
```

---

## Laws to Remember

### Functor
- `map(id) = id`
- `map(g ∘ f) = map(g) ∘ map(f)`

### Monad
- `pure(a) >>= f = f(a)`
- `m >>= pure = m`
- `(m >>= f) >>= g = m >>= (λx → f(x) >>= g)`

### Composition
- `(h ∘ g) ∘ f = h ∘ (g ∘ f)`
- `id ∘ f = f ∘ id = f`

---

## Import Shortcuts

```python
# Common imports
from functional import (
    Result, Success, Failure,
    Maybe, Just, Nothing, NOTHING,
    Reader, ask, run_reader,
    IO, print_line, unsafe_perform,
    pipe, compose, identity
)

# Validation
from functional.validation import (
    Valid, Invalid,
    validate_all, validator
)

# Alternative
from functional import (
    fallback_chain,
    try_alternatives
)
```

---

## Testing

```python
# Run law tests
pytest functional/tests/test_category_laws.py -v

# Test your implementation
def test_my_function():
    result = my_function(input)
    assert isinstance(result, Success)
    assert result.value == expected
```

---

## Migration Checklist

- [ ] Replace `try/except` with `Result`
- [ ] Replace `if x is None` with `Maybe`
- [ ] Replace global singletons with `Reader`
- [ ] Replace nested try-catch with `Alternative`
- [ ] Wrap side effects in `IO`
- [ ] Use `Validation` for forms
- [ ] Run law tests
- [ ] Update type signatures

---

## Quick Tips

1. **Use Result for errors**: Never throw exceptions in composable code
2. **Use Maybe for nulls**: Never return None from composable code
3. **Use Reader for config**: Never use global singletons
4. **Use IO for effects**: Make side effects explicit
5. **Use pipe for readability**: Left-to-right is easier to read
6. **Run at the edge**: Only call `unsafe_perform` at program entry
7. **Test the laws**: Ensure your code follows category theory

---

## Help

- Full docs: See `README.md`
- Migration guide: See `docs/MIGRATION_GUIDE.md`
- Examples: See `tests/` directory
- Laws: Run `pytest tests/test_category_laws.py`
