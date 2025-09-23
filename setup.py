"""
Setup script for Catalytic Lattice Computing
Production-ready package configuration
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="catalytic-lattice",
    version="1.0.0",
    author="Catalytic Computing Team",
    author_email="team@catalytic-lattice.ai",
    description="High-dimensional lattice computing using catalytic memory principles",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/catalytic-lattice",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Mathematics",
        "Topic :: Scientific/Engineering :: Physics",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.9",
    
    # Core dependencies
    install_requires=[
        "numpy>=2.0.0",
        "numba>=0.60.0",
        "scipy>=1.10.0",
        "networkx>=3.0",
        "plotly>=6.0.0",
        "pandas>=2.0.0",
    ],
    
    # Optional dependencies for different use cases
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "gpu": [
            "cupy-cuda12x>=12.0.0",
            "jax[cuda12]>=0.4.0",
            # Note: PyTorch needs special installation
        ],
        "distributed": [
            "ray[default]>=2.0.0",
            "dask[complete]>=2023.0.0",
            "mpi4py>=3.1.0",
        ],
        "api": [
            "fastapi>=0.100.0",
            "uvicorn>=0.23.0",
            "pydantic>=2.0.0",
            "python-multipart>=0.0.6",
        ],
        "monitoring": [
            "prometheus-client>=0.17.0",
            "opentelemetry-api>=1.20.0",
            "opentelemetry-sdk>=1.20.0",
            "psutil>=5.9.0",
        ],
        "production": [
            "pyyaml>=6.0",
            "python-dotenv>=1.0.0",
            "structlog>=23.0.0",
            "tenacity>=8.0.0",  # For retry logic
            "cachetools>=5.0.0",  # For caching
            "aiofiles>=23.0.0",  # For async file operations
        ],
        "visualization": [
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
            "pyvista>=0.40.0",
            "holoviews>=1.16.0",
            "datashader>=0.15.0",
        ],
    },
    
    # CLI scripts
    entry_points={
        "console_scripts": [
            "catalytic-lattice=catalytic_lattice.cli:main",
            "catalytic-server=catalytic_lattice.api.server:run",
        ],
    },
    
    # Include non-Python files
    package_data={
        "catalytic_lattice": [
            "configs/*.yaml",
            "configs/*.json",
        ],
    },
    
    # Additional metadata
    project_urls={
        "Bug Reports": "https://github.com/yourusername/catalytic-lattice/issues",
        "Documentation": "https://catalytic-lattice.readthedocs.io/",
        "Source": "https://github.com/yourusername/catalytic-lattice/",
    },
)