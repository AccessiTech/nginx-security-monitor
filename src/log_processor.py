#!/usr/bin/env python3
"""
Log Processor Module
Handles log file reading and parsing for the NGINX Security Monitor.
"""

import os
from src.config_manager import ConfigManager


config = ConfigManager.get_instance()


class LogProcessor:
    """Handles log file reading and parsing functionality."""

    def __init__(self, config, logger):
        """Initialize the log processor.

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.last_processed_size = 0
        self.config_manager = ConfigManager.get_instance()

    def get_new_log_entries(self, log_file_path):
        """Get only new log entries since last check.

        Args:
            log_file_path: Path to the log file

        Returns:
            list: List of parsed log entries
        """
        try:
            current_size = os.path.getsize(log_file_path)

            if current_size < self.last_processed_size:
                # Log file was rotated, start from beginning
                self.last_processed_size = 0

            if current_size == self.last_processed_size:
                # No new entries
                return []

            with open(log_file_path, "r") as file:
                file.seek(self.last_processed_size)
                new_lines = file.readlines()
                self.last_processed_size = current_size

                # Parse only new lines
                new_logs = []
                for line in new_lines:
                    if line.strip():
                        parsed_entry = self.parse_log_line(line.strip())
                        if parsed_entry:
                            new_logs.append(parsed_entry)

                return new_logs

        except FileNotFoundError:
            self.logger.error(f"Log file not found: {log_file_path}")
            return []
        except Exception as e:
            self.logger.error(f"Error reading log file: {e}")
            return []

    def parse_log_line(self, line):
        """Parse a single log line into structured data.

        Args:
            line: Raw log line string

        Returns:
            dict: Parsed log entry or None if parsing failed
        """
        try:
            parts = line.split()
            min_parts = self.config_manager.get("log_parser.min_required_parts", 10)
            indices = self.config_manager.get(
                "log_parser.field_indices",
                {
                    "ip_address": 0,
                    "timestamp": 3,
                    "request": 6,
                    "status_code": 8,
                    "response_size": 9,
                    "user_agent_start": 11,
                },
            )

            if len(parts) >= min_parts:  # Basic validation
                log_entry = {
                    "ip_address": parts[indices["ip_address"]],
                    "timestamp": (
                        parts[indices["timestamp"]][1:]
                        if parts[indices["timestamp"]].startswith("[")
                        else parts[indices["timestamp"]]
                    ),
                    "request": (
                        parts[indices["request"]][1:-1]
                        if parts[indices["request"]].startswith('"')
                        else parts[indices["request"]]
                    ),
                    "status_code": parts[indices["status_code"]],
                    "response_size": parts[indices["response_size"]],
                    "user_agent": (
                        " ".join(parts[indices["user_agent_start"] :])
                        if len(parts) > indices["user_agent_start"]
                        else ""
                    ),
                    "raw_line": line,
                }
                return log_entry
            else:
                self.logger.warning(f"Log line has insufficient parts: {line}")
                return None

        except (IndexError, ValueError) as e:
            self.logger.warning(f"Failed to parse log line: {line}, error: {e}")
            return None

    def reset_processed_size(self):
        """Reset the last processed size counter."""
        self.last_processed_size = 0

    def get_processed_size(self):
        """Get the current processed size.

        Returns:
            int: Last processed file size
        """
        return self.last_processed_size


# Let's run the full test suite with coverage to see the overall picture
# python -m pytest --cov=src --cov-report=term-missing -v tests/test_log_processor.py
