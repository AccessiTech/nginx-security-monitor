# NGINX Security Monitor - Integration Test Framework

This directory contains the integration test framework for testing interactions between components of the NGINX Security Monitor system.

## Overview

The integration tests are designed to verify that all components work together as expected. Tests are organized into phases, following the structure outlined in the integration test plan:

1. **Phase 1: Core Component Integration**

   - Threat Detection Pipeline
   - Configuration System
   - Alert System

1. **Phase 2: Security Response Integration**

   - Threat Response
   - Security Integrations Flow
   - Service Protection

1. **Phase 3: Advanced Integration Scenarios**

   - Plugin System
   - Network Security
   - Crypto Integration

## Running Integration Tests

### All Integration Tests

To run all integration tests:

```bash
make test-integration
```

### Specific Phase

To run tests for a specific phase:

```bash
make test-integration-phase1
make test-integration-phase2
make test-integration-phase3
```

### Using the Runner Directly

You can also run the integration test runner directly with more options:

```bash
# Run all tests
python -m tests.integration.run_integration_tests

# Run specific phase
python -m tests.integration.run_integration_tests --phase phase1

# Run with increased verbosity
python -m tests.integration.run_integration_tests -v
```

## Integration Test Framework Components

The integration test framework consists of the following key components:

1. **BaseIntegrationTest** - Base class for all integration tests with setup and teardown methods
1. **IntegrationTestDataFactory** - Factory for creating realistic test data
1. **run_integration_tests.py** - Script for running tests and generating reports

## Adding New Integration Tests

To add new integration tests:

1. Create a new test file in the appropriate phase directory
1. Extend the `BaseIntegrationTest` class for access to the shared framework
1. Import components needed for the test
1. Define test methods following the naming convention `test_*`

Example:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
New Integration Test
"""

import unittest
from tests.integration.test_framework import BaseIntegrationTest

class TestNewIntegration(BaseIntegrationTest):
    """Test new integration scenario"""
    
    def test_new_integration_scenario(self):
        """Test a new integration scenario"""
        # Get components
        component1 = self.components['component1']
        component2 = self.components['component2']
        
        # Connect components
        component1.set_component2(component2)
        
        # Test scenario
        result = component1.process_with_component2(test_data)
        
        # Assert expected outcomes
        self.assertIsNotNone(result)
        self.assertEqual(result['expected_key'], 'expected_value')
```

## Best Practices

1. **Component Isolation**: Reset component state after each test
1. **Mock External Dependencies**: Use the mock_external_services context manager
1. **Clean Up Resources**: Ensure all test resources are cleaned up in tearDown
1. **Performance Measurement**: Use measure_integration_performance for critical paths
1. **Error Handling Tests**: Include tests for failure scenarios

## Debugging Integration Tests

The test framework includes helpful debug information. To see more details:

```bash
# Run with verbose output
python -m tests.integration.run_integration_tests -vv
```

Integration test reports are generated in the project root directory.

## Understanding Integration Test Output

The integration test runner provides the following information:

- Test phase and module being executed
- Pass/fail status of each test
- Duration of test execution
- Summary of results by phase and overall
- Detailed failure information
- Performance metrics for critical paths

## Metrics and Success Criteria

Integration test success is measured by:

- All tests passing
- Performance within acceptable limits
- Error handling working as expected
- No component state leakage between tests

## Documentation

For more details on the integration test plan, see:

- `copilot-session-summaries/integration_test_plan.md` - Comprehensive test plan
- `docs/TESTING.md` - General testing documentation
