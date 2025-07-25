#!/usr/bin/env python3
"""
Advanced test suite for log_processor.py to achieve 98% coverage.

This test file targets the remaining 3 uncovered lines to push coverage from 94% to 98%.
Missing lines: 122-124 (exception handling in parse_log_line)
"""

import unittest
from unittest.mock import Mock, patch

try:
    from nginx_security_monitor.log_processor import LogProcessor
except ImportError as e:
    raise ImportError(f"Could not import log_processor. Error: {e}")


class TestLogProcessorAdvanced(unittest.TestCase):
    """Advanced tests to achieve 98% coverage for log_processor.py."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_config = {"log_file": "/var/log/nginx/access.log"}
        self.mock_logger = Mock()
        self.processor = LogProcessor(self.mock_config, self.mock_logger)

    def test_parse_log_line_indexerror_exception_handling(self):
        """Test line 122-124: IndexError exception handling in parse_log_line."""
        # Create a line that will pass the initial length check but cause IndexError
        # when trying to access specific indices during parsing

        # The exception occurs when accessing parts[indices[key]] if indices are out of range
        # First, let's mock the config to return invalid indices
        problematic_line = (
            "192.168.1.1 - - [25/Dec/2023:10:00:00 +0000] GET /test HTTP/1.1 200 1234"
        )

        # Mock config manager to return indices that are out of range
        with patch.object(self.processor.config_manager, "get") as mock_get:
            # Return config that will cause IndexError
            def config_side_effect(key, default):
                if key == "log_parser.min_required_parts":
                    return 5  # Low enough that the line passes initial check
                elif key == "log_parser.field_indices":
                    return {
                        "ip_address": 50,  # Index way out of range
                        "timestamp": 3,
                        "request": 6,
                        "status_code": 8,
                        "response_size": 9,
                        "user_agent_start": 11,
                    }
                return default

            mock_get.side_effect = config_side_effect

            result = self.processor.parse_log_line(problematic_line)

            # Should return None due to exception
            self.assertIsNone(result)

            # Should log the warning
            self.mock_logger.warning.assert_called()
            warning_call = self.mock_logger.warning.call_args[0][0]
            self.assertIn("Failed to parse log line", warning_call)

    def test_parse_log_line_valueerror_exception_handling(self):
        """Test line 122-124: ValueError exception handling in parse_log_line."""
        # Create a scenario that causes ValueError during parsing
        problematic_line = (
            "192.168.1.1 - - [25/Dec/2023:10:00:00 +0000] GET /test HTTP/1.1 200 1234"
        )

        # Mock config manager to cause ValueError during dictionary operations
        with patch.object(self.processor.config_manager, "get") as mock_get:
            # Return invalid config that causes ValueError
            def config_side_effect(key, default):
                if key == "log_parser.min_required_parts":
                    return 5
                elif key == "log_parser.field_indices":
                    # Return something that will cause ValueError
                    raise ValueError("Configuration error")
                return default

            mock_get.side_effect = config_side_effect

            result = self.processor.parse_log_line(problematic_line)

            # Should return None due to exception
            self.assertIsNone(result)

            # Should log the warning
            self.mock_logger.warning.assert_called()
            warning_call = self.mock_logger.warning.call_args[0][0]
            self.assertIn("Failed to parse log line", warning_call)

    def test_parse_log_line_mixed_exception_scenarios(self):
        """Test various edge cases that could trigger the exception handler."""
        # Reset mock to ensure clean state
        self.mock_logger.reset_mock()

        # Test with line that has unusual structure but still trigger IndexError
        unusual_line = "short line"

        # Mock config to return indices that would cause IndexError
        with patch.object(self.processor.config_manager, "get") as mock_get:

            def config_side_effect(key, default):
                if key == "log_parser.min_required_parts":
                    return 1  # Very low so it passes initial check
                elif key == "log_parser.field_indices":
                    return {
                        "ip_address": 0,
                        "timestamp": 1000,  # Way out of range
                        "request": 6,
                        "status_code": 8,
                        "response_size": 9,
                        "user_agent_start": 11,
                    }
                return default

            mock_get.side_effect = config_side_effect

            result = self.processor.parse_log_line(unusual_line)

            # Should handle the exception gracefully
            self.assertIsNone(result)
            self.mock_logger.warning.assert_called()


if __name__ == "__main__":
    unittest.main()
