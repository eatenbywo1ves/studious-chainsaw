"""
Input Validation Utilities for Catalytic Computing System
Provides comprehensive validation functions with type hints and error handling
"""

import re
from typing import Any, List, Optional, TypeVar, Callable, Annotated
from functools import wraps

from pydantic import BaseModel, Field, validator
from pydantic.types import conint, confloat

from libs.constants.constants import (
    MIN_DIMENSIONS, MAX_DIMENSIONS,
    MIN_LATTICE_SIZE, MAX_LATTICE_SIZE,
    MIN_AUX_MEMORY_MB, MAX_AUX_MEMORY_MB,
    MIN_PORT, MAX_PORT,
    ValidationRange,
    WebhookEvent,
    LatticeAlgorithm
)
from libs.utils.exceptions import ValidationError as CustomValidationError

T = TypeVar('T')


# === Pydantic Models for Validation ===

class LatticeParameters(BaseModel):
    """Validated parameters for lattice creation"""

    dimensions: conint(ge=MIN_DIMENSIONS, le=MAX_DIMENSIONS) = Field(
        description="Number of dimensions for the lattice"
    )
    size: conint(ge=MIN_LATTICE_SIZE, le=MAX_LATTICE_SIZE) = Field(
        description="Size in each dimension"
    )
    auxiliary_memory: Optional[confloat(ge=MIN_AUX_MEMORY_MB, le=MAX_AUX_MEMORY_MB)] = Field(
        default=10.0,
        description="Auxiliary memory in MB"
    )
    algorithm: Optional[LatticeAlgorithm] = Field(
        default=LatticeAlgorithm.DIJKSTRA,
        description="Algorithm to use for pathfinding"
    )

    @validator('dimensions')
    def validate_dimensions_for_size(cls, v: int, values: dict) -> int:
        """Ensure dimensions and size create manageable lattice"""
        if 'size' in values:
            total_points = values['size'] ** v
            if total_points > 1_000_000:
                raise ValueError(
                    f"Lattice too large: {total_points} points. "
                    f"Maximum 1,000,000 points allowed."
                )
        return v

    class Config:
        use_enum_values = True
        schema_extra = {
            "example": {
                "dimensions": 4,
                "size": 10,
                "auxiliary_memory": 20.0,
                "algorithm": "dijkstra"
            }
        }


class CoordinateList(BaseModel):
    """Validated list of coordinates"""

    coordinates: List[int] = Field(
        min_items=1,
        max_items=MAX_DIMENSIONS,
        description="List of coordinate values"
    )

    @validator('coordinates', each_item=True)
    def validate_coordinate_range(cls, v: int) -> int:
        """Ensure each coordinate is within valid range"""
        if not 0 <= v < MAX_LATTICE_SIZE ** MAX_DIMENSIONS:
            raise ValueError(f"Coordinate {v} out of range")
        return v


class WebhookConfig(BaseModel):
    """Validated webhook configuration"""

    url: Annotated[str, Field(pattern=r'^https?://[^\s]+$', max_length=2048)] = Field(
        description="Webhook URL"
    )
    events: List[WebhookEvent] = Field(
        min_items=1,
        description="Events to subscribe to"
    )
    secret: Optional[Annotated[str, Field(min_length=16, max_length=256)]] = Field(
        default=None,
        description="Webhook secret for signature validation"
    )
    active: bool = Field(default=True, description="Whether webhook is active")
    retry_count: conint(ge=0, le=10) = Field(default=3, description="Number of retries")
    timeout: conint(ge=5, le=300) = Field(default=30, description="Request timeout in seconds")

    @validator('url')
    def validate_url_accessibility(cls, v: str) -> str:
        """Basic URL validation"""
        if 'localhost' in v.lower() or '127.0.0.1' in v:
            import warnings
            warnings.warn("Using localhost URL for webhook", UserWarning)
        return v


class PaginationParams(BaseModel):
    """Validated pagination parameters"""

    page: conint(ge=1) = Field(default=1, description="Page number")
    page_size: conint(ge=1, le=1000) = Field(default=100, description="Items per page")
    sort_by: Optional[str] = Field(default=None, description="Field to sort by")
    sort_order: Optional[Annotated[str, Field(pattern="^(asc|desc)$")]] = Field(default="asc")

    @property
    def offset(self) -> int:
        """Calculate offset for database queries"""
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        """Get limit for database queries"""
        return self.page_size


# === Validation Decorators ===

def validate_input(**validators: Callable) -> Callable:
    """
    Decorator to validate function inputs

    Example:
        @validate_input(
            dimensions=lambda x: 1 <= x <= 10,
            size=lambda x: x > 0
        )
        def create_lattice(dimensions: int, size: int):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get function signature
            import inspect
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            # Validate each parameter
            for param_name, validator_func in validators.items():
                if param_name in bound.arguments:
                    value = bound.arguments[param_name]
                    if not validator_func(value):
                        raise CustomValidationError(
                            field=param_name,
                            value=value,
                            reason=f"Validation failed for {param_name}"
                        )

            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_type(*expected_types: type) -> Callable:
    """
    Decorator to validate parameter types

    Example:
        @validate_type(int, str, float)
        def process(a: int, b: str, c: float):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            import inspect
            sig = inspect.signature(func)
            params = list(sig.parameters.values())

            # Check positional arguments
            for i, (arg, expected_type) in enumerate(zip(args, expected_types)):
                if not isinstance(arg, expected_type):
                    param_name = params[i].name if i < len(params) else f"arg_{i}"
                    raise TypeError(
                        f"Parameter '{param_name}' expected {expected_type.__name__}, "
                        f"got {type(arg).__name__}"
                    )

            return func(*args, **kwargs)
        return wrapper
    return decorator


# === Core Validation Functions ===

def validate_dimensions(dimensions: Any) -> int:
    """
    Validate lattice dimensions

    Args:
        dimensions: Dimension value to validate

    Returns:
        Validated dimension value

    Raises:
        CustomValidationError: If validation fails
    """
    try:
        dims = int(dimensions)
    except (TypeError, ValueError):
        raise CustomValidationError(
            field="dimensions",
            value=dimensions,
            reason="Dimensions must be an integer"
        )

    if dims not in ValidationRange.DIMENSIONS:
        raise CustomValidationError(
            field="dimensions",
            value=dims,
            reason=f"Dimensions must be between {MIN_DIMENSIONS} and {MAX_DIMENSIONS}"
        )

    return dims


def validate_lattice_size(size: Any, dimensions: Optional[int] = None) -> int:
    """
    Validate lattice size

    Args:
        size: Size value to validate
        dimensions: Optional dimensions for total size validation

    Returns:
        Validated size value

    Raises:
        CustomValidationError: If validation fails
    """
    try:
        lattice_size = int(size)
    except (TypeError, ValueError):
        raise CustomValidationError(
            field="size",
            value=size,
            reason="Size must be an integer"
        )

    if lattice_size not in ValidationRange.LATTICE_SIZE:
        raise CustomValidationError(
            field="size",
            value=lattice_size,
            reason=f"Size must be between {MIN_LATTICE_SIZE} and {MAX_LATTICE_SIZE}"
        )

    # Check total points if dimensions provided
    if dimensions is not None:
        total_points = lattice_size ** dimensions
        if total_points > 1_000_000:
            raise CustomValidationError(
                field="size",
                value=lattice_size,
                reason=f"Total points ({total_points}) exceeds maximum of 1,000,000"
            )

    return lattice_size


def validate_coordinates(
    coordinates: List[Any],
    dimensions: int,
    lattice_size: int
) -> List[int]:
    """
    Validate coordinate list

    Args:
        coordinates: List of coordinates
        dimensions: Expected number of dimensions
        lattice_size: Size of lattice in each dimension

    Returns:
        Validated coordinate list

    Raises:
        CustomValidationError: If validation fails
    """
    if not isinstance(coordinates, list):
        raise CustomValidationError(
            field="coordinates",
            value=coordinates,
            reason="Coordinates must be a list"
        )

    if len(coordinates) != dimensions:
        raise CustomValidationError(
            field="coordinates",
            value=coordinates,
            reason=f"Expected {dimensions} coordinates, got {len(coordinates)}"
        )

    validated = []
    for i, coord in enumerate(coordinates):
        try:
            c = int(coord)
        except (TypeError, ValueError):
            raise CustomValidationError(
                field=f"coordinates[{i}]",
                value=coord,
                reason="Coordinate must be an integer"
            )

        if not 0 <= c < lattice_size:
            raise CustomValidationError(
                field=f"coordinates[{i}]",
                value=c,
                reason=f"Coordinate must be between 0 and {lattice_size - 1}"
            )

        validated.append(c)

    return validated


def validate_port(port: Any) -> int:
    """
    Validate network port

    Args:
        port: Port value to validate

    Returns:
        Validated port number

    Raises:
        CustomValidationError: If validation fails
    """
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        raise CustomValidationError(
            field="port",
            value=port,
            reason="Port must be an integer"
        )

    if port_num not in ValidationRange.PORT:
        raise CustomValidationError(
            field="port",
            value=port_num,
            reason=f"Port must be between {MIN_PORT} and {MAX_PORT}"
        )

    return port_num


def validate_url(url: Any, require_https: bool = False) -> str:
    """
    Validate URL format

    Args:
        url: URL to validate
        require_https: Whether to require HTTPS

    Returns:
        Validated URL string

    Raises:
        CustomValidationError: If validation fails
    """
    if not isinstance(url, str):
        raise CustomValidationError(
            field="url",
            value=url,
            reason="URL must be a string"
        )

    # Basic URL pattern
    url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    if not re.match(url_pattern, url):
        raise CustomValidationError(
            field="url",
            value=url,
            reason="Invalid URL format"
        )

    if require_https and not url.startswith('https://'):
        raise CustomValidationError(
            field="url",
            value=url,
            reason="HTTPS is required"
        )

    if len(url) > 2048:
        raise CustomValidationError(
            field="url",
            value=url,
            reason="URL exceeds maximum length of 2048 characters"
        )

    return url


def validate_email(email: Any) -> str:
    """
    Validate email address

    Args:
        email: Email to validate

    Returns:
        Validated email string

    Raises:
        CustomValidationError: If validation fails
    """
    if not isinstance(email, str):
        raise CustomValidationError(
            field="email",
            value=email,
            reason="Email must be a string"
        )

    # Basic email pattern
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise CustomValidationError(
            field="email",
            value=email,
            reason="Invalid email format"
        )

    return email.lower()


# === Export all validation utilities ===

__all__ = [
    # Models
    'LatticeParameters',
    'CoordinateList',
    'WebhookConfig',
    'PaginationParams',

    # Decorators
    'validate_input',
    'validate_type',

    # Functions
    'validate_dimensions',
    'validate_lattice_size',
    'validate_coordinates',
    'validate_port',
    'validate_url',
    'validate_email',
]
