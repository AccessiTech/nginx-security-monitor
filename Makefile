# NGINX Security Monitor - Development Commands

.PHONY: help install install-clean install-dev test test-cov test-integration clean deps

help:
	@echo "NGINX Security Monitor - Available Commands:"
	@echo ""
	@echo "  install          - Install all dependencies"
	@echo "  install-clean    - Clean install (force reinstall all packages)"
	@echo "  install-core     - Install only core dependencies"
	@echo "  test             - Run tests"
	@echo "  test-cov         - Run tests with coverage"
	@echo "  test-integration - Run integration tests"
	@echo "  clean            - Clean build artifacts"
	@echo ""

install:
	pip install -r requirements.txt

install-clean:
	pip install -r requirements.txt --force-reinstall

install-core:
	pip install pyyaml>=6.0 cryptography>=3.4.8 psutil>=5.8.0

test:
	pytest

test-cov:
	pytest --cov=src --cov-report=term-missing --cov-report=html

test-integration:
	@echo "Running integration tests..."
	python -m tests.integration.run_integration_tests
	@echo "Integration tests completed."

test-integration-phase1:
	@echo "Running Phase 1 integration tests (Core Component Integration)..."
	python -m tests.integration.run_integration_tests --phase phase1
	@echo "Phase 1 integration tests completed."

test-integration-phase2:
	@echo "Running Phase 2 integration tests (Security Response Integration)..."
	python -m tests.integration.run_integration_tests --phase phase2
	@echo "Phase 2 integration tests completed."

test-integration-phase3:
	@echo "Running Phase 3 integration tests (Advanced Integration Scenarios)..."
	python -m tests.integration.run_integration_tests --phase phase3
	@echo "Phase 3 integration tests completed."

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +

freeze:
	pip freeze > requirements-frozen.txt
	@echo "Frozen requirements saved to requirements-frozen.txt"

unfreeze:
	@echo "To unfreeze requirements, use:"
	@echo "  make install-clean"
	@echo ""
	@echo "This will force reinstall all packages with latest compatible versions."
