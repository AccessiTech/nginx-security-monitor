# Testing Guide

This document provides comprehensive information about testing the NGINX Security Monitor, including running tests, understanding coverage, and contributing new tests.

## Prerequisites

### Virtual Environment Setup (Recommended)

It's strongly recommended to use a virtual environment to avoid dependency conflicts:

#### Using venv (Built-in, Recommended)

```bash
# Navigate to project directory
cd /path/to/nginx-security-monitor

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or on Windows: .venv\Scripts\activate

# Upgrade pip (recommended)
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Install testing dependencies
pip install -r dev-requirements.txt

# Install in development mode (for easier testing)
pip install -e .
```

#### Alternative: Using virtualenv

```bash
# Install virtualenv if not already installed
pip install virtualenv

# Create virtual environment
virtualenv .venv

# Activate and install dependencies
source .venv/bin/activate
pip install -r requirements.txt
pip install -r dev-requirements.txt
pip install -e .
```

#### Alternative: Using conda

```bash
# Create conda environment
conda create -n nginx-security-monitor python=3.8

# Activate environment
conda activate nginx-security-monitor

# Install dependencies
pip install -r requirements.txt
pip install -r dev-requirements.txt
pip install -e .
```

**Important**: Always activate your virtual environment before running tests:

```bash
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows
```

**To deactivate** when you're done:

```bash
deactivate
```

### Requirements Files

The project uses separate requirements files for better dependency management:

- **`requirements.txt`**: Core application dependencies (Flask, cryptography, etc.)
- **`dev-requirements.txt`**: Testing and development tools (pytest, coverage, linters)

For testing, install both. For production deployment, only `requirements.txt` is needed.

## Quick Start

```bash
# Ensure virtual environment is activated
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows

# Install dependencies (if not already done)
pip install -r requirements.txt
pip install -r dev-requirements.txt

# Run all tests
pytest

# Run tests with coverage report
pytest --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_pattern_detector.py

# Run specific test
pytest tests/test_pattern_detector.py::TestPatternDetector::test_sql_injection_detection
```

## Test Suite Overview

The project includes comprehensive test coverage across all major components:

### Test Statistics

- **Total Tests**: 394
- **Test Coverage**: 82%
- **Test Files**: 14
- **All Tests Passing**: ✅

### Current Coverage Breakdown

- **🟢 Perfect Coverage (100%)**: alert_manager, service_protection, threat_processor, plugin_system, log_parser
- **🟢 Excellent (95%+)**: security_integrations (99%), pattern_detector (97%), monitor_service (96%), network_security (96%)
- **🟢 High (90%+)**: crypto_utils (90%), mitigation (89%)
- **🟡 Good (80%+)**: email_alert (82%)
- **🔴 Needs Improvement**: config_manager (55%), security_coordinator (28%), sms_alert (15%), config_schema (42%)

**📈 Coverage Improvement Plan**: See [ELITE_TEST_COVERAGE_PLAN.md](../ELITE_TEST_COVERAGE_PLAN.md) for detailed roadmap to 95%+ coverage.

### Test Files Structure

```
tests/
├── __init__.py
├── test_alerts.py              # Email and SMS alerting (3 tests)
├── test_crypto_utils.py        # Encryption and obfuscation (12 tests)
├── test_log_parser.py          # Log parsing functionality (10 tests)
├── test_mitigation.py          # Threat mitigation strategies (22 tests)
├── test_monitor_service.py     # Main service orchestration (23 tests)
├── test_network_security.py    # Network-level security features (43 tests)
├── test_pattern_detector.py    # Attack pattern detection (16 tests)
├── test_plugin_system.py       # Plugin architecture (23 tests)
├── test_security_integrations.py # External security tools (13 tests)
└── test_service_protection.py  # Service self-protection (21 tests)
```

## Component Coverage

### 🟢 High Coverage Components (70%+)

- **Log Parser**: 100% coverage - Core log parsing functionality
- **Pattern Detector**: 95% coverage - Attack pattern detection algorithms
- **Plugin System**: 95% coverage - Plugin architecture and management
- **Mitigation**: 100% coverage - Threat mitigation strategies
- **Network Security**: 100% coverage - Network-level security features
- **Service Protection**: 80% coverage - Self-protection mechanisms
- **Crypto Utils**: 76% coverage - Encryption, decryption, and obfuscation
- **SMS Alerts**: 100% coverage - SMS notification system

### � Medium Coverage Components (50-70%)

- **Email Alerts**: 68% coverage - Email notification system
- **Security Integrations**: 61% coverage - External tool integrations
- **Monitor Service**: 55% coverage - Main service orchestration

### 🔴 Low Coverage Components (\<50%)

- None remaining! All components now have good test coverage.

## Running Tests

### Basic Test Execution

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run tests in parallel (faster)
pytest -n auto
```

### Coverage Reports

```bash
# Terminal coverage report
pytest --cov=src --cov-report=term-missing

# HTML coverage report (opens in browser)
pytest --cov=src --cov-report=html
open htmlcov/index.html  # macOS
# or navigate to htmlcov/index.html in your browser

# Generate coverage badge
coverage-badge -o coverage.svg
```

### Filtering Tests

```bash
# Run tests by pattern
pytest -k "test_sql_injection"
pytest -k "pattern_detector"

# Run tests by marker
pytest -m "slow"
pytest -m "integration"

# Run specific test categories
pytest tests/test_pattern_detector.py  # Pattern detection tests
pytest tests/test_alerts.py           # Alert system tests
pytest tests/test_crypto_utils.py     # Cryptography tests
```

### Test Output Options

```bash
# Quiet mode (minimal output)
pytest -q

# Show local variables on failure
pytest -l

# Stop on first failure
pytest -x

# Show test durations
pytest --durations=10
```

## Test Architecture

### Mocking Strategy

Our tests use extensive mocking to ensure:

- **Independence**: Tests don't depend on external services
- **Reliability**: Consistent results across environments
- **Speed**: Fast execution without network calls
- **Safety**: No side effects on the system

```python
# Example: Mocking external commands
@patch('subprocess.run')
def test_fail2ban_integration(self, mock_run):
    mock_run.return_value = Mock(returncode=0, stdout="pong")
    # Test implementation
```

### Test Categories

#### Unit Tests

- Test individual functions and methods
- Use mocks for external dependencies
- Fast execution (< 1 second each)

#### Integration Tests

- Test component interactions
- Mock external services but test internal integration
- Medium execution time (1-5 seconds each)

#### Configuration Tests

- Test various configuration scenarios
- Ensure proper error handling
- Test edge cases and invalid inputs

## Adding New Tests

### Test File Structure

```python
import unittest
from unittest.mock import Mock, patch
from src.your_module import YourClass

class TestYourClass(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method."""
        self.instance = YourClass()
    
    def test_basic_functionality(self):
        """Test description following conventions."""
        # Arrange
        input_data = "test_input"
        expected = "expected_output"
        
        # Act
        result = self.instance.method(input_data)
        
        # Assert
        self.assertEqual(result, expected)
    
    @patch('external.dependency')
    def test_with_mocking(self, mock_dependency):
        """Test with external dependency mocking."""
        # Configure mock
        mock_dependency.return_value = "mocked_result"
        
        # Test implementation
        result = self.instance.method_using_dependency()
        
        # Verify mock was called
        mock_dependency.assert_called_once()
        self.assertEqual(result, "expected_with_mock")
```

### Naming Conventions

- **Test files**: `test_<module_name>.py`
- **Test classes**: `Test<ClassName>`
- **Test methods**: `test_<functionality_being_tested>`
- **Descriptive names**: Use clear, descriptive names that explain what is being tested

### Best Practices

1. **Arrange-Act-Assert Pattern**

   ```python
   def test_example(self):
       # Arrange: Set up test data
       input_data = "test"
       
       # Act: Execute the code under test
       result = function_under_test(input_data)
       
       # Assert: Verify the results
       self.assertEqual(result, expected_value)
   ```

1. **Use Descriptive Test Names**

   ```python
   # Good
   def test_detect_sql_injection_with_union_select(self):

   # Bad
   def test_sql(self):
   ```

1. **Test Edge Cases**

   - Empty inputs
   - Invalid inputs
   - Boundary conditions
   - Error conditions

1. **Mock External Dependencies**

   ```python
   @patch('requests.get')
   @patch('smtplib.SMTP')
   def test_external_service_integration(self, mock_smtp, mock_requests):
       # Configure mocks
       mock_requests.return_value.status_code = 200
       mock_smtp.return_value.__enter__.return_value = Mock()
       
       # Test implementation
   ```

## Continuous Integration

### Pre-commit Hooks

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run manually
pre-commit run --all-files
```

### Test Automation

The project includes GitHub Actions workflows for:

- Running tests on multiple Python versions
- Generating coverage reports
- Code quality checks
- Security scanning

## Troubleshooting

### Common Issues

#### Virtual Environment & Dependencies

```bash
# If you can't activate the virtual environment
chmod +x .venv/bin/activate  # Linux/macOS

# If wrong Python version or need to recreate
python3 -m venv --clear .venv  # Recreate virtual environment
source .venv/bin/activate
pip install -r requirements.txt
pip install -r dev-requirements.txt

# If you have dependency conflicts
pip uninstall pytest pytest-cov pytest-mock
pip install -r dev-requirements.txt
pip check  # Check for remaining conflicts

# If Python can't find modules (import errors)
pip install -e .  # Install project in development mode
```

#### Test Execution Issues

```bash
# Clean coverage data and re-run
coverage erase
pytest --cov=src --cov-report=term-missing

# Debug test failures
pytest --pdb  # Run with Python debugger
pytest -v --tb=long  # Verbose output with full tracebacks

# Check specific test issues
pytest tests/test_specific.py::TestClass::test_method -v
```

#### Mock-related Failures

- Ensure mocks match the actual API signatures
- Use `patch` decorators in the correct order
- Verify mock return values match expected types

### Debugging Tests

```bash
# Run with Python debugger
pytest --pdb

# Show detailed output for failures
pytest -v --tb=long

# Add temporary debug output (remove before commit)
def test_debug_example(self):
    result = function_under_test()
    print(f"Debug: result = {result}")
    self.assertEqual(result, expected)
```

## Performance Testing

### Benchmark Tests

```bash
# Install pytest-benchmark
pip install pytest-benchmark

# Run benchmark tests
pytest --benchmark-only
```

### Memory Profiling

```bash
# Install memory profiler
pip install memory-profiler

# Profile specific test
pytest --profile
```

## Contributing Tests

### Before Submitting

1. **Run the full test suite**

   ```bash
   pytest --cov=src --cov-report=term-missing
   ```

1. **Ensure no regressions**

   - All existing tests must pass
   - New tests should follow established patterns

1. **Update documentation**

   - Add docstrings to new test methods
   - Update this file if adding new test categories

### Test Review Checklist

- [ ] Tests follow naming conventions
- [ ] Appropriate use of mocks
- [ ] Edge cases covered
- [ ] Clear and descriptive test names
- [ ] No external dependencies in tests
- [ ] Tests are deterministic
- [ ] Performance considerations addressed

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [unittest.mock Documentation](https://docs.python.org/3/library/unittest.mock.html)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Testing Best Practices](https://realpython.com/python-testing/)
