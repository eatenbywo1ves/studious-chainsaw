"""
Unified HTTP Client for Security Testing
=========================================
Centralized HTTP request handling with consistent error handling, retries,
logging, and metrics collection.

This module eliminates ~80 duplicate requests.post() calls across agent files.
"""

from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field
from enum import Enum
import requests
from requests.adapters import HTTPAdapter, Retry
import logging
import time


class HTTPMethod(Enum):
    """Supported HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


@dataclass
class HTTPResponse:
    """Standardized HTTP response wrapper."""
    status_code: int
    text: str
    json_data: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    success: bool = False
    error: Optional[str] = None


@dataclass
class HTTPClientConfig:
    """Configuration for HTTP client behavior."""
    timeout_seconds: float = 10.0
    max_retries: int = 3
    retry_backoff: float = 0.5
    retry_on_statuses: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])
    user_agent: str = "MLSecTest/1.0 (Security Testing Framework)"
    verify_ssl: bool = True
    log_requests: bool = True
    log_responses: bool = True


class UnifiedHTTPClient:
    """
    Unified HTTP client for all security testing agents.

    Features:
    - Automatic retry logic with exponential backoff
    - Consistent error handling across all request types
    - Request/response logging for debugging
    - Metrics collection (request count, latency, errors)
    - Session management with connection pooling
    - SSL verification control

    Usage:
        client = UnifiedHTTPClient()
        response = client.post(
            url="http://target.com/api",
            json_data={"input": "test payload"}
        )

        if response.success:
            print(f"Response: {response.text}")
        else:
            print(f"Error: {response.error}")
    """

    def __init__(self, config: Optional[HTTPClientConfig] = None):
        """
        Initialize HTTP client with optional configuration.

        Args:
            config: Client configuration (uses defaults if not provided)
        """
        self.config = config or HTTPClientConfig()
        self.logger = self._setup_logger()
        self.session = self._create_session()

        # Metrics tracking
        self.metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_latency_ms": 0.0,
            "errors_by_type": {}
        }

    def _setup_logger(self) -> logging.Logger:
        """Configure HTTP client logging."""
        logger = logging.getLogger("MLSecTest.HTTPClient")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            console_handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '[%(asctime)s] [HTTP] %(levelname)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        return logger

    def _create_session(self) -> requests.Session:
        """
        Create requests session with retry logic and connection pooling.

        Returns:
            Configured requests.Session instance
        """
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_backoff,
            status_forcelist=self.config.retry_on_statuses,
            allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
        )

        # Mount adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json"
        })

        return session

    def post(
        self,
        url: str,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> HTTPResponse:
        """
        Execute POST request with unified error handling.

        Args:
            url: Target URL
            json_data: JSON payload (will be serialized automatically)
            data: Raw data payload (string or bytes)
            headers: Additional headers to send
            timeout: Request timeout (uses config default if not specified)

        Returns:
            HTTPResponse with standardized result data
        """
        return self._execute_request(
            method=HTTPMethod.POST,
            url=url,
            json_data=json_data,
            data=data,
            headers=headers,
            timeout=timeout
        )

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> HTTPResponse:
        """
        Execute GET request with unified error handling.

        Args:
            url: Target URL
            params: Query parameters
            headers: Additional headers to send
            timeout: Request timeout (uses config default if not specified)

        Returns:
            HTTPResponse with standardized result data
        """
        return self._execute_request(
            method=HTTPMethod.GET,
            url=url,
            params=params,
            headers=headers,
            timeout=timeout
        )

    def _execute_request(
        self,
        method: HTTPMethod,
        url: str,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Union[str, bytes]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None
    ) -> HTTPResponse:
        """
        Internal method to execute HTTP requests with comprehensive error handling.

        Args:
            method: HTTP method to use
            url: Target URL
            json_data: JSON payload
            data: Raw data payload
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout

        Returns:
            HTTPResponse with results or error information
        """
        timeout = timeout or self.config.timeout_seconds
        start_time = time.time()

        # Update metrics
        self.metrics["total_requests"] += 1

        # Log request if enabled
        if self.config.log_requests:
            self.logger.debug(f"{method.value} {url}")
            if json_data:
                self.logger.debug(f"  Payload: {json_data}")

        try:
            # Execute request
            response = self.session.request(
                method=method.value,
                url=url,
                json=json_data,
                data=data,
                params=params,
                headers=headers,
                timeout=timeout,
                verify=self.config.verify_ssl
            )

            # Calculate elapsed time
            elapsed_ms = (time.time() - start_time) * 1000
            self.metrics["total_latency_ms"] += elapsed_ms

            # Parse response
            json_response = None
            try:
                if response.headers.get('Content-Type', '').startswith('application/json'):
                    json_response = response.json()
            except ValueError:
                pass  # Not JSON, that's okay

            # Determine success
            success = 200 <= response.status_code < 300

            if success:
                self.metrics["successful_requests"] += 1
            else:
                self.metrics["failed_requests"] += 1

            # Log response if enabled
            if self.config.log_responses:
                self.logger.debug(
                    f"  Response: {response.status_code} ({elapsed_ms:.1f}ms)"
                )

            return HTTPResponse(
                status_code=response.status_code,
                text=response.text,
                json_data=json_response,
                headers=dict(response.headers),
                elapsed_ms=elapsed_ms,
                success=success,
                error=None if success else f"HTTP {response.status_code}"
            )

        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - start_time) * 1000
            self.metrics["failed_requests"] += 1
            self._track_error("timeout")

            self.logger.warning(f"Request timeout after {timeout}s: {url}")

            return HTTPResponse(
                status_code=0,
                text="",
                elapsed_ms=elapsed_ms,
                success=False,
                error=f"Request timeout after {timeout}s"
            )

        except requests.exceptions.ConnectionError as conn_error:
            elapsed_ms = (time.time() - start_time) * 1000
            self.metrics["failed_requests"] += 1
            self._track_error("connection_error")

            self.logger.warning(f"Connection error: {url} - {str(conn_error)}")

            return HTTPResponse(
                status_code=0,
                text="",
                elapsed_ms=elapsed_ms,
                success=False,
                error=f"Connection error: {str(conn_error)}"
            )

        except requests.exceptions.RequestException as request_error:
            elapsed_ms = (time.time() - start_time) * 1000
            self.metrics["failed_requests"] += 1
            self._track_error("request_exception")

            self.logger.error(f"Request failed: {url} - {str(request_error)}")

            return HTTPResponse(
                status_code=0,
                text="",
                elapsed_ms=elapsed_ms,
                success=False,
                error=f"Request error: {str(request_error)}"
            )

        except Exception as unexpected_error:
            elapsed_ms = (time.time() - start_time) * 1000
            self.metrics["failed_requests"] += 1
            self._track_error("unexpected_error")

            self.logger.error(
                f"Unexpected error during request: {url} - {str(unexpected_error)}"
            )

            return HTTPResponse(
                status_code=0,
                text="",
                elapsed_ms=elapsed_ms,
                success=False,
                error=f"Unexpected error: {str(unexpected_error)}"
            )

    def _track_error(self, error_type: str) -> None:
        """Track error by type for metrics."""
        if error_type not in self.metrics["errors_by_type"]:
            self.metrics["errors_by_type"][error_type] = 0
        self.metrics["errors_by_type"][error_type] += 1

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get HTTP client metrics.

        Returns:
            Dictionary with request statistics
        """
        total_requests = self.metrics["total_requests"]

        return {
            "total_requests": total_requests,
            "successful_requests": self.metrics["successful_requests"],
            "failed_requests": self.metrics["failed_requests"],
            "success_rate": (
                (self.metrics["successful_requests"] / total_requests * 100)
                if total_requests > 0 else 0.0
            ),
            "average_latency_ms": (
                (self.metrics["total_latency_ms"] / total_requests)
                if total_requests > 0 else 0.0
            ),
            "errors_by_type": self.metrics["errors_by_type"]
        }

    def reset_metrics(self) -> None:
        """Reset all metrics to zero."""
        self.metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_latency_ms": 0.0,
            "errors_by_type": {}
        }

    def close(self) -> None:
        """Close the HTTP session and release resources."""
        self.session.close()
        self.logger.info("HTTP client session closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - auto-close session."""
        self.close()
