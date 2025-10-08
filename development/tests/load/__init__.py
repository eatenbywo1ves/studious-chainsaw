"""
Load Testing Framework for Catalytic Computing SaaS Platform

This package contains comprehensive load testing scenarios using Locust
to validate performance, scalability, and stability.

Test Scenarios:
    - BaselineTest: Normal operations (100 users, 10 min)
    - StressTest: High load capacity (500 users, 5 min)
    - SpikeTest: Traffic surge handling (1000 users, 5 min)
    - SoakTest: Stability testing (50 users, 4 hours)
    - MixedWorkloadTest: Realistic production (200 users, 15 min)

Usage:
    python run_load_tests.py --scenario baseline

For detailed documentation, see README.md
"""

__version__ = "1.0.0"
__author__ = "Catalytic Computing Team"
