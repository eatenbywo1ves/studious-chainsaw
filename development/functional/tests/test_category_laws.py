"""
Category Laws Tests

Tests that verify our implementations follow the mathematical laws
from category theory. These laws MUST hold for correct implementations.

Run with: pytest test_category_laws.py -v
"""

import pytest

# Import modules to test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from functional.core.result import (
    Success, Failure,
    map as result_map,
    pure as result_pure,
    flat_map as result_flat_map
)
from functional.core.maybe import (
    Just, NOTHING,
    map as maybe_map,
    pure as maybe_pure,
    flat_map as maybe_flat_map
)
from functional.operators.compose import identity, compose


# ============================================================================
# TEST UTILITIES
# ============================================================================

def test_functions():
    """Helper functions for testing"""
    f = lambda x: x + 1
    g = lambda x: x * 2
    h = lambda x: x ** 2
    return f, g, h


# ============================================================================
# FUNCTOR LAWS - RESULT
# ============================================================================

class TestResultFunctorLaws:
    """Test that Result follows Functor laws"""

    def test_functor_identity_law(self):
        """
        Functor Identity: map(id) = id

        Mapping the identity function should not change the structure.
        """
        # Success case
        result = Success(42)
        assert result_map(result, identity) == result

        # Failure case
        result = Failure("error")
        assert result_map(result, identity) == result

    def test_functor_composition_law(self):
        """
        Functor Composition: map(g ∘ f) = map(g) ∘ map(f)

        Mapping composed functions should equal composing the maps.
        """
        f, g, _ = test_functions()
        result = Success(5)

        # Left side: map(g ∘ f)
        composed_fn = compose(g, f)
        left = result_map(result, composed_fn)

        # Right side: map(g) ∘ map(f)
        right = result_map(result_map(result, f), g)

        assert left == right


# ============================================================================
# MONAD LAWS - RESULT
# ============================================================================

class TestResultMonadLaws:
    """Test that Result follows Monad laws"""

    def test_monad_left_identity(self):
        """
        Left Identity: pure(a) >>= f = f(a)

        Wrapping a value and binding should equal applying the function directly.
        """
        a = 42
        f = lambda x: Success(x * 2)

        # Left side: pure(a) >>= f
        left = result_flat_map(result_pure(a), f)

        # Right side: f(a)
        right = f(a)

        assert left == right

    def test_monad_right_identity(self):
        """
        Right Identity: m >>= pure = m

        Binding with pure should not change the value.
        """
        m = Success(42)

        # Left side: m >>= pure
        left = result_flat_map(m, result_pure)

        # Right side: m
        right = m

        assert left == right

    def test_monad_associativity(self):
        """
        Associativity: (m >>= f) >>= g = m >>= (λx → f(x) >>= g)

        The order of binding operations shouldn't matter.
        """
        m = Success(5)
        f = lambda x: Success(x + 1)
        g = lambda x: Success(x * 2)

        # Left side: (m >>= f) >>= g
        left = result_flat_map(result_flat_map(m, f), g)

        # Right side: m >>= (λx → f(x) >>= g)
        right = result_flat_map(m, lambda x: result_flat_map(f(x), g))

        assert left == right


# ============================================================================
# FUNCTOR LAWS - MAYBE
# ============================================================================

class TestMaybeFunctorLaws:
    """Test that Maybe follows Functor laws"""

    def test_functor_identity_law(self):
        """Functor Identity: map(id) = id"""
        # Just case
        maybe = Just(42)
        assert maybe_map(maybe, identity) == maybe

        # Nothing case
        maybe = NOTHING
        assert maybe_map(maybe, identity) == maybe

    def test_functor_composition_law(self):
        """Functor Composition: map(g ∘ f) = map(g) ∘ map(f)"""
        f, g, _ = test_functions()
        maybe = Just(5)

        # Left side: map(g ∘ f)
        composed_fn = compose(g, f)
        left = maybe_map(maybe, composed_fn)

        # Right side: map(g) ∘ map(f)
        right = maybe_map(maybe_map(maybe, f), g)

        assert left == right


# ============================================================================
# MONAD LAWS - MAYBE
# ============================================================================

class TestMaybeMonadLaws:
    """Test that Maybe follows Monad laws"""

    def test_monad_left_identity(self):
        """Left Identity: pure(a) >>= f = f(a)"""
        a = 42
        f = lambda x: Just(x * 2)

        # Left side: pure(a) >>= f
        left = maybe_flat_map(maybe_pure(a), f)

        # Right side: f(a)
        right = f(a)

        assert left == right

    def test_monad_right_identity(self):
        """Right Identity: m >>= pure = m"""
        m = Just(42)

        # Left side: m >>= pure
        left = maybe_flat_map(m, maybe_pure)

        # Right side: m
        right = m

        assert left == right

    def test_monad_associativity(self):
        """Associativity: (m >>= f) >>= g = m >>= (λx → f(x) >>= g)"""
        m = Just(5)
        f = lambda x: Just(x + 1)
        g = lambda x: Just(x * 2)

        # Left side: (m >>= f) >>= g
        left = maybe_flat_map(maybe_flat_map(m, f), g)

        # Right side: m >>= (λx → f(x) >>= g)
        right = maybe_flat_map(m, lambda x: maybe_flat_map(f(x), g))

        assert left == right


# ============================================================================
# COMPOSITION LAWS
# ============================================================================

class TestCompositionLaws:
    """Test function composition laws"""

    def test_associativity(self):
        """
        Associativity: (h ∘ g) ∘ f = h ∘ (g ∘ f)

        Composition order should not matter.
        """
        f, g, h = test_functions()
        x = 5

        # Left side: (h ∘ g) ∘ f
        left = compose(compose(h, g), f)(x)

        # Right side: h ∘ (g ∘ f)
        right = compose(h, compose(g, f))(x)

        assert left == right

    def test_left_identity(self):
        """
        Left Identity: id ∘ f = f

        Composing with identity on the left should not change the function.
        """
        f, _, _ = test_functions()
        x = 5

        # Left side: id ∘ f
        left = compose(identity, f)(x)

        # Right side: f
        right = f(x)

        assert left == right

    def test_right_identity(self):
        """
        Right Identity: f ∘ id = f

        Composing with identity on the right should not change the function.
        """
        f, _, _ = test_functions()
        x = 5

        # Left side: f ∘ id
        left = compose(f, identity)(x)

        # Right side: f
        right = f(x)

        assert left == right


# ============================================================================
# VALIDATION APPLICATIVE LAWS
# ============================================================================

class TestValidationApplicativeLaws:
    """Test that Validation follows Applicative laws"""

    def setup_method(self):
        """Setup for validation tests"""
        from functional.validation.validation import Valid, Invalid, pure, ap, map

        self.Valid = Valid
        self.Invalid = Invalid
        self.pure = pure
        self.ap = ap
        self.map = map

    def test_applicative_identity(self):
        """
        Applicative Identity: pure(id) <*> v = v

        Applying the identity function in context should not change the value.
        """
        v = self.Valid(42)

        # Left side: pure(id) <*> v
        left = self.ap(self.pure(identity), v)

        # Right side: v
        right = v

        assert left == right

    def test_applicative_homomorphism(self):
        """
        Homomorphism: pure(f) <*> pure(x) = pure(f(x))

        Applying a pure function to a pure value should equal the pure result.
        """
        f = lambda x: x * 2
        x = 5

        # Left side: pure(f) <*> pure(x)
        left = self.ap(self.pure(f), self.pure(x))

        # Right side: pure(f(x))
        right = self.pure(f(x))

        assert left == right

    def test_error_accumulation(self):
        """
        Validation-specific: Errors should accumulate

        This is the key feature that distinguishes Validation from Result.
        """
        v1 = self.Invalid(["error1"])
        v2 = self.Invalid(["error2"])

        # When both are invalid, errors should combine
        result = self.ap(v1, v2)

        assert isinstance(result, self.Invalid)
        assert result.errors == ["error1", "error2"]


# ============================================================================
# READER MONAD LAWS
# ============================================================================

class TestReaderMonadLaws:
    """Test that Reader follows Monad laws"""

    def setup_method(self):
        """Setup for reader tests"""
        from functional.monads.reader import Reader, pure, run_reader

        self.Reader = Reader
        self.pure = pure
        self.run_reader = run_reader

    def test_reader_left_identity(self):
        """Left Identity: pure(a) >>= f = f(a)"""
        a = 42
        f = lambda x: self.pure(x * 2)
        env = {}  # Dummy environment

        # Left side: pure(a) >>= f
        left = self.pure(a).flat_map(f)

        # Right side: f(a)
        right = f(a)

        assert self.run_reader(left, env) == self.run_reader(right, env)

    def test_reader_right_identity(self):
        """Right Identity: m >>= pure = m"""
        m = self.pure(42)
        env = {}

        # Left side: m >>= pure
        left = m.flat_map(self.pure)

        # Right side: m
        right = m

        assert self.run_reader(left, env) == self.run_reader(right, env)

    def test_reader_associativity(self):
        """Associativity: (m >>= f) >>= g = m >>= (λx → f(x) >>= g)"""
        m = self.pure(5)
        f = lambda x: self.pure(x + 1)
        g = lambda x: self.pure(x * 2)
        env = {}

        # Left side: (m >>= f) >>= g
        left = m.flat_map(f).flat_map(g)

        # Right side: m >>= (λx → f(x) >>= g)
        right = m.flat_map(lambda x: f(x).flat_map(g))

        assert self.run_reader(left, env) == self.run_reader(right, env)


# ============================================================================
# IO MONAD LAWS
# ============================================================================

class TestIOMonadLaws:
    """Test that IO follows Monad laws"""

    def setup_method(self):
        """Setup for IO tests"""
        from functional.monads.io import IO, pure, unsafe_perform

        self.IO = IO
        self.pure = pure
        self.unsafe_perform = unsafe_perform

    def test_io_left_identity(self):
        """Left Identity: pure(a) >>= f = f(a)"""
        a = 42
        f = lambda x: self.pure(x * 2)

        # Left side: pure(a) >>= f
        left = self.pure(a).flat_map(f)

        # Right side: f(a)
        right = f(a)

        assert self.unsafe_perform(left) == self.unsafe_perform(right)

    def test_io_right_identity(self):
        """Right Identity: m >>= pure = m"""
        m = self.pure(42)

        # Left side: m >>= pure
        left = m.flat_map(self.pure)

        # Right side: m
        right = m

        assert self.unsafe_perform(left) == self.unsafe_perform(right)

    def test_io_associativity(self):
        """Associativity: (m >>= f) >>= g = m >>= (λx → f(x) >>= g)"""
        m = self.pure(5)
        f = lambda x: self.pure(x + 1)
        g = lambda x: self.pure(x * 2)

        # Left side: (m >>= f) >>= g
        left = m.flat_map(f).flat_map(g)

        # Right side: m >>= (λx → f(x) >>= g)
        right = m.flat_map(lambda x: f(x).flat_map(g))

        assert self.unsafe_perform(left) == self.unsafe_perform(right)


# ============================================================================
# PROPERTY-BASED TESTING
# ============================================================================

class TestPropertyBased:
    """Property-based tests using multiple values"""

    @pytest.mark.parametrize("value", [0, 1, -1, 42, 1000])
    def test_result_functor_identity_property(self, value):
        """Test functor identity with multiple values"""
        result = Success(value)
        assert result_map(result, identity) == result

    @pytest.mark.parametrize("value", [0, 1, -1, 42, 1000])
    def test_result_monad_left_identity_property(self, value):
        """Test monad left identity with multiple values"""
        f = lambda x: Success(x * 2)
        left = result_flat_map(result_pure(value), f)
        right = f(value)
        assert left == right

    @pytest.mark.parametrize("x", [1, 5, 10])
    @pytest.mark.parametrize("y", [2, 3, 4])
    def test_composition_associativity_property(self, x, y):
        """Test composition associativity with multiple values"""
        f = lambda n: n + x
        g = lambda n: n * y
        h = lambda n: n ** 2

        value = 5
        left = compose(compose(h, g), f)(value)
        right = compose(h, compose(g, f))(value)

        assert left == right


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
