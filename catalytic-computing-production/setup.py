"""
Catalytic Computing Production Package
Revolutionary memory-efficient lattice computation using catalytic algorithms
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="catalytic-computing",
    version="1.0.0",
    author="Catalytic Computing Team",
    author_email="admin@catalytic-computing.io",
    description="High-performance catalytic computing for memory-efficient lattice operations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/catalytic-computing/catalytic-computing",
    project_urls={
        "Documentation": "https://catalytic-computing.readthedocs.io",
        "Bug Tracker": "https://github.com/catalytic-computing/catalytic-computing/issues",
        "Source Code": "https://github.com/catalytic-computing/catalytic-computing",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Scientific/Engineering :: Mathematics",
        "Topic :: System :: Distributed Computing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "numpy>=1.24.0",
        "scipy>=1.11.0",
        "networkx>=3.0",
        "pandas>=2.0.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.20.0",
        "pydantic>=2.0.0",
        "structlog>=23.0.0",
        "prometheus-client>=0.15.0",
    ],
    extras_require={
        "gpu": [
            "cupy-cuda12x>=12.0.0",
            "numba>=0.58.0",
        ],
        "visualization": [
            "plotly>=5.0.0",
            "matplotlib>=3.5.0",
            "seaborn>=0.12.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
            "pytest-cov>=4.0.0",
            "pytest-benchmark>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "pylint>=3.0.0",
            "pre-commit>=3.0.0",
        ],
        "monitoring": [
            "opentelemetry-api>=1.20.0",
            "opentelemetry-sdk>=1.20.0",
            "opentelemetry-instrumentation-fastapi>=0.40b0",
        ],
    },
    entry_points={
        "console_scripts": [
            "catalytic-server=catalytic_computing.api.server:main",
            "catalytic-benchmark=catalytic_computing.utils.benchmark:main",
            "catalytic-viz=catalytic_computing.visualization.dashboard:main",
        ],
    },
    include_package_data=True,
    package_data={
        "catalytic_computing": [
            "config/*.yaml",
            "config/*.json",
            "visualization/templates/*.html",
            "visualization/static/*",
        ],
    },
    zip_safe=False,
)