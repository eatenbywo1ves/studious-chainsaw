#!/usr/bin/env python3
"""
Retry Handler - Exponential backoff retry logic for service startup

Provides decorators and utilities for retrying operations with configurable backoff strategies.
"""

import time
import functools
import logging
from typing import Callable, Type, Tuple, Optional
from datetime import datetime


logger = logging.getLogger('workspace_manager.retry')


def retry_with_backoff(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    backoff_factor: float = 2.0,
    max_delay: float = 60.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable] = None
):
    """
    Decorator to retry a function with exponential backoff

    Args:
        max_retries: Maximum number of retry attempts (default: 3)
        initial_delay: Initial delay in seconds before first retry (default: 1.0)
        backoff_factor: Multiplier for delay between retries (default: 2.0)
        max_delay: Maximum delay between retries in seconds (default: 60.0)
        exceptions: Tuple of exception types to catch and retry (default: all exceptions)
        on_retry: Optional callback function called on each retry with (attempt, error, delay)

    Example:
        @retry_with_backoff(max_retries=5, initial_delay=2.0, backoff_factor=2.0)
        def start_service(service_name):
            # Service startup code that may fail
            pass
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None

            for attempt in range(max_retries):
                try:
                    # Attempt the operation
                    result = func(*args, **kwargs)
                    return result

                except exceptions as e:
                    last_exception = e

                    # Check if this was the last attempt
                    if attempt == max_retries - 1:
                        logger.error(
                            f"Function {func.__name__} failed after {max_retries} attempts: {e}",
                            extra={
                                'function': func.__name__,
                                'max_retries': max_retries,
                                'error': str(e),
                                'error_type': type(e).__name__
                            }
                        )
                        raise

                    # Calculate next delay
                    current_delay = min(delay, max_delay)

                    # Log retry attempt
                    logger.warning(
                        f"Attempt {attempt + 1}/{max_retries} failed for {func.__name__}: {e}. "
                        f"Retrying in {current_delay:.1f}s...",
                        extra={
                            'function': func.__name__,
                            'attempt': attempt + 1,
                            'max_retries': max_retries,
                            'retry_delay_seconds': current_delay,
                            'error': str(e),
                            'error_type': type(e).__name__
                        }
                    )

                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(attempt + 1, e, current_delay)
                        except Exception as callback_error:
                            logger.warning(f"Retry callback failed: {callback_error}")

                    # Wait before next retry
                    time.sleep(current_delay)

                    # Increase delay for next attempt (exponential backoff)
                    delay *= backoff_factor

            # Should never reach here, but just in case
            if last_exception:
                raise last_exception

        return wrapper
    return decorator


class RetryStrategy:
    """Base class for retry strategies"""

    def should_retry(self, attempt: int, error: Exception) -> bool:
        """Determine if operation should be retried"""
        raise NotImplementedError

    def get_delay(self, attempt: int) -> float:
        """Calculate delay before next retry"""
        raise NotImplementedError


class ExponentialBackoff(RetryStrategy):
    """Exponential backoff retry strategy"""

    def __init__(self,
                 max_retries: int = 3,
                 initial_delay: float = 1.0,
                 backoff_factor: float = 2.0,
                 max_delay: float = 60.0):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.backoff_factor = backoff_factor
        self.max_delay = max_delay

    def should_retry(self, attempt: int, error: Exception) -> bool:
        return attempt < self.max_retries

    def get_delay(self, attempt: int) -> float:
        delay = self.initial_delay * (self.backoff_factor ** attempt)
        return min(delay, self.max_delay)


class LinearBackoff(RetryStrategy):
    """Linear backoff retry strategy (constant delay increase)"""

    def __init__(self,
                 max_retries: int = 3,
                 initial_delay: float = 1.0,
                 delay_increment: float = 1.0,
                 max_delay: float = 30.0):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.delay_increment = delay_increment
        self.max_delay = max_delay

    def should_retry(self, attempt: int, error: Exception) -> bool:
        return attempt < self.max_retries

    def get_delay(self, attempt: int) -> float:
        delay = self.initial_delay + (attempt * self.delay_increment)
        return min(delay, self.max_delay)


class RetryHandler:
    """Flexible retry handler with configurable strategies"""

    def __init__(self, strategy: RetryStrategy):
        self.strategy = strategy
        self.retry_history = []

    def execute(self,
                func: Callable,
                *args,
                exceptions: Tuple[Type[Exception], ...] = (Exception,),
                on_retry: Optional[Callable] = None,
                **kwargs):
        """
        Execute a function with retry logic

        Args:
            func: Function to execute
            *args: Positional arguments for function
            exceptions: Tuple of exception types to catch and retry
            on_retry: Optional callback called on each retry
            **kwargs: Keyword arguments for function

        Returns:
            Result of successful function execution

        Raises:
            Last exception if all retries are exhausted
        """
        attempt = 0
        start_time = time.time()

        while True:
            try:
                # Attempt the operation
                result = func(*args, **kwargs)

                # Record successful execution
                duration = time.time() - start_time
                self.retry_history.append({
                    'function': func.__name__,
                    'attempts': attempt + 1,
                    'success': True,
                    'duration_seconds': duration,
                    'timestamp': datetime.now().isoformat()
                })

                logger.info(
                    f"Function {func.__name__} succeeded on attempt {attempt + 1}",
                    extra={
                        'function': func.__name__,
                        'attempts': attempt + 1,
                        'duration_seconds': round(duration, 3)
                    }
                )

                return result

            except exceptions as e:
                attempt += 1

                # Check if we should retry
                if not self.strategy.should_retry(attempt, e):
                    duration = time.time() - start_time
                    self.retry_history.append({
                        'function': func.__name__,
                        'attempts': attempt,
                        'success': False,
                        'error': str(e),
                        'error_type': type(e).__name__,
                        'duration_seconds': duration,
                        'timestamp': datetime.now().isoformat()
                    })

                    logger.error(
                        f"Function {func.__name__} failed after {attempt} attempts: {e}",
                        extra={
                            'function': func.__name__,
                            'attempts': attempt,
                            'duration_seconds': round(duration, 3),
                            'error': str(e),
                            'error_type': type(e).__name__
                        }
                    )
                    raise

                # Calculate delay
                delay = self.strategy.get_delay(attempt - 1)

                logger.warning(
                    f"Attempt {attempt} failed for {func.__name__}: {e}. Retrying in {delay:.1f}s...",
                    extra={
                        'function': func.__name__,
                        'attempt': attempt,
                        'retry_delay_seconds': delay,
                        'error': str(e),
                        'error_type': type(e).__name__
                    }
                )

                # Call retry callback if provided
                if on_retry:
                    try:
                        on_retry(attempt, e, delay)
                    except Exception as callback_error:
                        logger.warning(f"Retry callback failed: {callback_error}")

                # Wait before next retry
                time.sleep(delay)

    def get_stats(self):
        """Get retry statistics"""
        if not self.retry_history:
            return {
                'total_operations': 0,
                'successful': 0,
                'failed': 0,
                'success_rate': 0.0,
                'avg_attempts': 0.0,
                'avg_duration_seconds': 0.0
            }

        total = len(self.retry_history)
        successful = sum(1 for h in self.retry_history if h['success'])
        failed = total - successful

        return {
            'total_operations': total,
            'successful': successful,
            'failed': failed,
            'success_rate': round(successful / total * 100, 2) if total > 0 else 0.0,
            'avg_attempts': round(sum(h['attempts'] for h in self.retry_history) / total, 2),
            'avg_duration_seconds': round(sum(h['duration_seconds'] for h in self.retry_history) / total, 3)
        }


# Example usage and testing
if __name__ == '__main__':
    import random

    # Configure logging for testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Test 1: Decorator with exponential backoff
    print("\n=== Test 1: Exponential Backoff Decorator ===")

    @retry_with_backoff(max_retries=3, initial_delay=0.5, backoff_factor=2.0)
    def unreliable_function(fail_count=2):
        """Function that fails fail_count times before succeeding"""
        if not hasattr(unreliable_function, 'attempts'):
            unreliable_function.attempts = 0
        unreliable_function.attempts += 1

        if unreliable_function.attempts <= fail_count:
            raise ConnectionError(f"Simulated failure (attempt {unreliable_function.attempts})")

        return f"Success on attempt {unreliable_function.attempts}!"

    try:
        result = unreliable_function(fail_count=2)
        print(f"Result: {result}")
    finally:
        delattr(unreliable_function, 'attempts')

    # Test 2: RetryHandler with exponential backoff
    print("\n=== Test 2: RetryHandler with Exponential Backoff ===")

    strategy = ExponentialBackoff(max_retries=4, initial_delay=0.5, backoff_factor=1.5)
    handler = RetryHandler(strategy)

    def flaky_service():
        """Randomly failing service simulation"""
        if random.random() < 0.6:  # 60% failure rate
            raise TimeoutError("Service timeout")
        return "Service response"

    try:
        result = handler.execute(flaky_service, exceptions=(TimeoutError,))
        print(f"Result: {result}")
    except Exception as e:
        print(f"Failed: {e}")

    # Test 3: Linear backoff
    print("\n=== Test 3: Linear Backoff ===")

    linear_strategy = LinearBackoff(max_retries=3, initial_delay=0.5, delay_increment=0.5)
    linear_handler = RetryHandler(linear_strategy)

    def linear_test():
        """Test with linear backoff"""
        if random.random() < 0.8:
            raise ValueError("Random error")
        return "Success with linear backoff"

    try:
        result = linear_handler.execute(linear_test, exceptions=(ValueError,))
        print(f"Result: {result}")
    except Exception as e:
        print(f"Failed: {e}")

    # Print statistics
    print("\n=== Retry Statistics ===")
    print(f"Exponential: {handler.get_stats()}")
    print(f"Linear: {linear_handler.get_stats()}")

    print("\n✓ Retry handler tests complete")
