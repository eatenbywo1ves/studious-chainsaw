# Migration Guide: From Imperative to Compositional

This guide shows how to migrate your existing Python codebase to use the functional programming library, fixing composition breaks identified in your system.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Replace Exceptions with Result](#replace-exceptions-with-result)
3. [Replace None Checks with Maybe](#replace-none-checks-with-maybe)
4. [Replace Global Singletons with Reader](#replace-global-singletons-with-reader)
5. [Replace Try-Except Chains with Alternative](#replace-try-except-chains-with-alternative)
6. [Make Effects Explicit with IO](#make-effects-explicit-with-io)
7. [Form Validation with Validation](#form-validation-with-validation)
8. [Complete Examples](#complete-examples)

---

## Quick Start

```python
# Install (add to your project)
from functional import Result, Success, Failure, Maybe, Just, Nothing, pipe

# Basic usage
def divide(x: float, y: float) -> Result[float, str]:
    if y == 0:
        return Failure("Division by zero")
    return Success(x / y)

result = divide(10, 2)  # Success(5.0)
error = divide(10, 0)   # Failure("Division by zero")
```

---

## 1. Replace Exceptions with Result

### Before: Exception-Based Error Handling

```python
# account_lockout.py (Lines 287-295)
def execute_lockout_script(self, attempts_key, lockout_key, current_time):
    try:
        result = self.redis_client.evalsha(...)
        return result
    except redis.exceptions.NoScriptError as e:
        raise  # Breaks composition!
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error: {e}")
        raise  # Can't compose operations that throw
```

### After: Composable Result

```python
from functional import Result, Success, Failure, flat_map

def execute_lockout_script(
    self, attempts_key: str, lockout_key: str, current_time: float
) -> Result[tuple[int, int], str]:
    """
    Returns Result instead of throwing exceptions.
    Now composable with other Result-returning operations!
    """
    try:
        if self._script_sha:
            result = self.redis_client.evalsha(...)
            return Success(result)
    except redis.exceptions.NoScriptError:
        try:
            self._script_sha = self.redis_client.script_load(...)
            result = self.redis_client.evalsha(...)
            return Success(result)
        except Exception as e:
            return Failure(f"Script reload failed: {e}")
    except redis.exceptions.RedisError as e:
        return Failure(f"Redis error: {e}")

    # Unreachable, but type checker happy
    return Failure("Unexpected error")


# Now compose multiple operations that may fail:
def record_and_notify(identifier: str) -> Result[bool, str]:
    """Compose lockout checking with notification"""
    return (
        execute_lockout_script(...)
        .flat_map(lambda result: process_lockout_result(result))
        .flat_map(lambda processed: send_notification(processed))
    )

# Or using pipe_with_result
from functional.operators.compose import pipe_with_result

def record_and_notify_v2(identifier: str) -> Result[bool, str]:
    return pipe_with_result(
        lambda id: check_attempts(id),
        lambda attempts: apply_lockout(attempts),
        lambda lockout: notify_user(lockout)
    )(identifier)
```

### Benefits

- ✅ No exceptions breaking composition
- ✅ Type-safe error handling
- ✅ Can chain operations: `op1 >>= op2 >>= op3`
- ✅ Compiler enforces error handling
- ✅ Easy to test (no exception mocking)

---

## 2. Replace None Checks with Maybe

### Before: Null Checks Everywhere

```python
def get_user(user_id: str) -> User | None:
    user = cache.get(f"user:{user_id}")
    if user is None:
        user = db.get_user(user_id)
        if user is None:
            return None
    return user

def get_user_email(user_id: str) -> str | None:
    user = get_user(user_id)
    if user is None:
        return None
    return user.email
```

### After: Composable Maybe

```python
from functional import Maybe, Just, Nothing, flat_map

def get_user(user_id: str) -> Maybe[User]:
    """Returns Just(user) or Nothing"""
    cached = cache.get(f"user:{user_id}")
    if cached:
        return Just(cached)

    db_user = db.get_user(user_id)
    return Just(db_user) if db_user else Nothing

def get_user_email(user_id: str) -> Maybe[str]:
    """Compose operations on Maybe"""
    return get_user(user_id).map(lambda user: user.email)

# Or chain multiple operations
def get_user_verified_email(user_id: str) -> Maybe[str]:
    return (
        get_user(user_id)
        .filter(lambda user: user.is_verified)
        .map(lambda user: user.email)
    )
```

### Benefits

- ✅ No null checks
- ✅ Composable with map/flat_map
- ✅ Type-safe (compiler knows it might be Nothing)
- ✅ Chain operations without nested ifs

---

## 3. Replace Global Singletons with Reader

### Before: Global Mutable State

```python
# cache_service.py (Lines 493-510)
_cache_service_instance: Optional[CacheService] = None

def get_cache_service() -> CacheService:
    global _cache_service_instance
    if _cache_service_instance is None:
        redis_url = os.getenv("REDIS_URL")
        _cache_service_instance = CacheService(redis_url)
    return _cache_service_instance

# Hidden dependency - not visible in type signature!
def get_user(user_id: str) -> Optional[User]:
    cache = get_cache_service()  # Spooky action at a distance
    return cache.get(f"user:{user_id}")
```

### After: Explicit Dependencies with Reader

```python
from functional import Reader, ask, run_reader
from dataclasses import dataclass

@dataclass(frozen=True)
class AppConfig:
    """All dependencies in one place"""
    cache_service: CacheService
    db_client: DatabaseClient
    email_service: EmailService

def get_user(user_id: str) -> Reader[AppConfig, Optional[User]]:
    """Dependency on AppConfig is explicit in type signature"""
    def fetch(config: AppConfig) -> Optional[User]:
        return config.cache_service.get(f"user:{user_id}")
    return Reader(fetch)

def get_posts(user: User) -> Reader[AppConfig, list[Post]]:
    """All operations share the same environment"""
    def fetch(config: AppConfig) -> list[Post]:
        return config.db_client.get_posts(user.id)
    return Reader(fetch)

# Compose operations with same dependencies
def get_user_posts(user_id: str) -> Reader[AppConfig, list[Post]]:
    return (
        get_user(user_id)
        .flat_map(lambda user: get_posts(user) if user else Reader.pure([]))
    )

# Run at program entry point only
config = AppConfig(
    cache_service=CacheService("redis://..."),
    db_client=DatabaseClient("postgresql://..."),
    email_service=EmailService()
)
posts = run_reader(get_user_posts("user-123"), config)
```

### Benefits

- ✅ No global mutable state
- ✅ Dependencies explicit in types
- ✅ Easy to test (inject mock config)
- ✅ Composable - operations share environment
- ✅ Referentially transparent

---

## 4. Replace Try-Except Chains with Alternative

### Before: Imperative Fallback Chain

```python
# email_service.py (Lines 78-106)
def send_email(to, subject, body) -> bool:
    if self.sendgrid_available:
        try:
            if self._send_via_sendgrid(to, subject, body):
                return True
        except Exception as e:
            logger.warning(f"SendGrid failed: {e}")

    if self.aws_ses_available:
        try:
            if self._send_via_aws_ses(to, subject, body):
                return True
        except Exception as e:
            logger.warning(f"AWS SES failed: {e}")

    if self.smtp_available:
        try:
            if self._send_via_smtp(to, subject, body):
                return True
        except Exception as e:
            logger.error(f"SMTP failed: {e}")

    return False
```

### After: Compositional Alternative

```python
from functional import Result, Success, Failure, fallback_chain

def send_via_sendgrid(to: str, subject: str, body: str) -> Result[bool, str]:
    """Pure function returning Result"""
    try:
        # SendGrid logic
        return Success(True)
    except Exception as e:
        return Failure(f"SendGrid error: {e}")

def send_via_aws_ses(to: str, subject: str, body: str) -> Result[bool, str]:
    try:
        # AWS SES logic
        return Success(True)
    except Exception as e:
        return Failure(f"AWS SES error: {e}")

def send_via_smtp(to: str, subject: str, body: str) -> Result[bool, str]:
    try:
        # SMTP logic
        return Success(True)
    except Exception as e:
        return Failure(f"SMTP error: {e}")

def send_email(to: str, subject: str, body: str) -> Result[bool, list[str]]:
    """
    Try each provider, accumulate errors.
    Returns Success on first success, or Failure with all errors.
    """
    return fallback_chain(
        lambda: send_via_sendgrid(to, subject, body),
        lambda: send_via_aws_ses(to, subject, body),
        lambda: send_via_smtp(to, subject, body)
    )

# Usage
result = send_email("user@example.com", "Hello", "World")
match result:
    case Success(value):
        print("Email sent!")
    case Failure(errors):
        print(f"All providers failed: {errors}")
```

### Benefits

- ✅ Declarative provider list
- ✅ Automatic error collection
- ✅ Easy to add/remove providers
- ✅ Type-safe
- ✅ Composable with other Result operations

---

## 5. Make Effects Explicit with IO

### Before: Impure Functions

```python
def main():
    """Hidden side effects everywhere"""
    print("Enter your name:")
    name = input()  # Hidden IO!

    print(f"Hello, {name}!")  # Hidden IO!

    with open("greeting.txt", "w") as f:  # Hidden IO!
        f.write(f"Hello, {name}!")

    print("Greeting saved!")  # Hidden IO!
```

### After: Pure Functions with IO

```python
from functional import IO, print_line, read_line, write_file, unsafe_perform

def get_name() -> IO[str]:
    """Returns IO action, doesn't execute yet"""
    return (
        print_line("Enter your name:")
        .then(read_line())
    )

def greet(name: str) -> IO[None]:
    """Pure function returning IO action"""
    return print_line(f"Hello, {name}!")

def save_greeting(name: str) -> IO[None]:
    """Pure function returning IO action"""
    return write_file("greeting.txt", f"Hello, {name}!")

def main_program() -> IO[None]:
    """
    Pure composition of IO actions.
    Nothing executes until run!
    """
    return (
        get_name()
        .flat_map(lambda name:
            greet(name)
            .then(save_greeting(name))
            .then(print_line("Greeting saved!"))
        )
    )

# Execute at entry point only
if __name__ == "__main__":
    unsafe_perform(main_program())  # Now it runs!
```

### Benefits

- ✅ Effects visible in type signatures
- ✅ Pure functions everywhere except main
- ✅ Easy to test (just check IO structure)
- ✅ Composable without executing
- ✅ Referentially transparent

---

## 6. Form Validation with Validation

### Before: Short-Circuit Validation

```python
def validate_user_form(username: str, email: str, age: int) -> Result[UserForm, str]:
    """Shows only FIRST error"""
    if len(username) < 3:
        return Failure("Username too short")
    if "@" not in email:
        return Failure("Invalid email")  # User never sees this if username fails
    if age < 0:
        return Failure("Invalid age")  # User never sees this if email fails

    return Success(UserForm(username, email, age))
```

### After: Error-Accumulating Validation

```python
from functional.validation import Valid, Invalid, validate_all, validator

# Define validators
username_min = validator(lambda s: len(s) >= 3, "Username must be at least 3 chars")
username_max = validator(lambda s: len(s) <= 20, "Username must be at most 20 chars")
email_has_at = validator(lambda s: "@" in s, "Email must contain @")
age_positive = validator(lambda n: n > 0, "Age must be positive")

def validate_username(username: str) -> Validation[str, str]:
    """Accumulate all username errors"""
    return validate_all(
        username_min(username),
        username_max(username)
    ).map(lambda _: username)

def validate_email(email: str) -> Validation[str, str]:
    return email_has_at(email).map(lambda _: email)

def validate_age(age: int) -> Validation[str, int]:
    return age_positive(age).map(lambda _: age)

def validate_user_form(username: str, email: str, age: int) -> Validation[str, UserForm]:
    """Shows ALL errors at once!"""
    username_val = validate_username(username)
    email_val = validate_email(email)
    age_val = validate_age(age)

    result = validate_all(username_val, email_val, age_val)
    return result.map(lambda vals: UserForm(vals[0], vals[1], vals[2]))

# Usage
result = validate_user_form("ab", "invalid", -5)
# Invalid([
#     "Username must be at least 3 chars",
#     "Email must contain @",
#     "Age must be positive"
# ])
# All errors shown at once - much better UX!
```

### Benefits

- ✅ Shows ALL errors, not just first
- ✅ Better user experience
- ✅ Composable validators
- ✅ Type-safe error accumulation

---

## 7. Complete Examples

### Example 1: Refactor account_lockout.py

```python
# Before
class AccountLockoutManager:
    def record_failed_attempt(self, identifier: str) -> None:
        if self.redis_client:
            self._record_failed_attempt_redis(identifier)
        else:
            self._record_failed_attempt_memory(identifier)

# After
from functional import Reader, Result, Success, Failure

class AccountLockoutManager:
    def record_failed_attempt(self, identifier: str) -> Reader[Config, Result[LockoutResult, str]]:
        """
        Pure function with explicit dependencies and error handling.
        Returns Reader[Config, Result[...]] - composable!
        """
        def operation(config: Config) -> Result[LockoutResult, str]:
            if config.use_redis:
                return self._record_redis(identifier, config.redis_client)
            else:
                return self._record_memory(identifier)

        return Reader(operation)

    def _record_redis(self, identifier: str, redis: RedisClient) -> Result[LockoutResult, str]:
        """Returns Result instead of throwing"""
        try:
            result = redis.evalsha(...)
            return Success(LockoutResult(result[0], result[1]))
        except Exception as e:
            return Failure(f"Redis error: {e}")
```

### Example 2: Refactor cache_service.py Decorator

```python
# Before (hides effects)
@cached("tenant:config", ttl=600)
def get_tenant_config(tenant_id: str):
    return db.query(...).first()

# After (explicit composition)
from functional import pipe

# Pure business logic
def fetch_tenant_config(tenant_id: str) -> Dict:
    return db.query(...).first()

# Explicit caching combinator
def with_cache(key_fn, fetch_fn, ttl):
    def composed(arg):
        cache = get_cache_service()
        key = key_fn(arg)

        cached = cache.get(key)
        if cached:
            return cached

        result = fetch_fn(arg)
        cache.set(key, result, ttl)
        return result

    return composed

# Explicit composition - caching is visible!
get_tenant_config = pipe(
    with_cache(
        key_fn=lambda id: f"tenant:config:{id}",
        fetch_fn=fetch_tenant_config,
        ttl=600
    )
)
```

---

## Migration Checklist

### Phase 1: Add Library
- [ ] Add functional library to your project
- [ ] Run tests to ensure library works
- [ ] Read this migration guide

### Phase 2: Replace Exceptions (High Priority)
- [ ] Identify functions that throw exceptions
- [ ] Refactor to return `Result[T, E]`
- [ ] Update callers to use `flat_map` for chaining
- [ ] Remove try-except blocks

### Phase 3: Remove Global State (High Priority)
- [ ] Identify global singletons
- [ ] Create config/environment dataclass
- [ ] Refactor to use `Reader[Config, A]`
- [ ] Update main to inject config

### Phase 4: Replace None Checks (Medium Priority)
- [ ] Identify functions returning `Optional[T]`
- [ ] Refactor to return `Maybe[T]`
- [ ] Replace if-None checks with `map`/`flat_map`

### Phase 5: Add Effect Tracking (Low Priority)
- [ ] Identify impure functions
- [ ] Refactor to return `IO[A]`
- [ ] Compose IO actions
- [ ] Execute only at entry points

### Phase 6: Improve Validation (Low Priority)
- [ ] Identify validation code
- [ ] Use `Validation` for forms/config
- [ ] Show all errors to users

---

## Testing Your Migration

Run the category law tests to ensure your implementations are correct:

```bash
cd development/functional
pytest tests/test_category_laws.py -v
```

All laws should pass! If they don't, your implementation violates category theory principles.

---

## Getting Help

- Read module docstrings for detailed API docs
- Check `tests/` for examples
- Review `functional/` source code (it's well-documented)

---

## Summary

The key insight from category theory: **Composition is everything**.

By making:
- Errors explicit (Result)
- Nulls explicit (Maybe)
- Dependencies explicit (Reader)
- Effects explicit (IO)
- Validation accumulating (Validation)

Your code becomes:
- ✅ More composable
- ✅ Type-safe
- ✅ Testable
- ✅ Maintainable
- ✅ Referentially transparent

Welcome to compositional programming! 🎉
