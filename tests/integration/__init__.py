#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Integration Tests Package for NGINX Security Monitor

This package contains comprehensive integration tests for verifying
component interactions and end-to-end functionality.

Test Organization:
- test_framework.py: Base classes and utilities
- test_phase1_core.py: Core component integration tests
- test_phase2_security.py: Security response integration tests (planned)
- test_phase3_advanced.py: Advanced integration scenarios (planned)

Usage:
    # Run all integration tests
    python -m pytest tests/integration/ -v

    # Run specific phase
    python -m pytest tests/integration/test_phase1_core.py -v

    # Run with integration test markers
    python -m pytest -m integration tests/
"""

__version__ = "1.0.0"
__author__ = "NGINX Security Monitor Team"

# Import base classes for easy access
from .test_framework import BaseIntegrationTest, IntegrationTestDataFactory

__all__ = ["BaseIntegrationTest", "IntegrationTestDataFactory"]
