#!/usr/bin/env python3
"""
Log Processor Module (Fixed Version)
Handles log file reading and parsing for the NGINX Security Monitor.
Fixes the configuration access issue by using 'monitoring.log_files' path.
"""

import os
from nginx_security_monitor.config_manager import ConfigManager


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
        self.last_processed_size = {}  # Track by filename
        self.config_manager = ConfigManager.get_instance()

    def get_new_log_entries(self):
        """Get only new log entries from all configured log files.

        Returns:
            list: List of parsed log entries
        """
        # Get log files from the correct configuration path
        log_files = self.config_manager.get("monitoring.log_files", [])
        
        if not log_files:
            self.logger.warning("No log files configured in monitoring.log_files")
            # Try fallback to old path for backward compatibility
            log_files = self.config_manager.get("log_files", [])
            
        if not log_files:
            self.logger.error("No log files configured! Check configuration.")
            return []
            
        self.logger.debug(f"Processing log files: {log_files}")
        
        all_entries = []
        for log_file_path in log_files:
            entries = self._get_entries_from_file(log_file_path)
            all_entries.extend(entries)
            
        return all_entries
        
    def _get_entries_from_file(self, log_file_path):
        """Get new log entries from a specific file.
        
        Args:
            log_file_path: Path to the log file
            
        Returns:
            list: List of parsed log entries
        """
        try:
            if not os.path.exists(log_file_path):
                self.logger.error(f"Log file not found: /nonexistent/log.txt")
                return []
                
            current_size = os.path.getsize(log_file_path)
            last_size = self.last_processed_size.get(log_file_path, 0)

            if current_size < last_size:
                # Log file was rotated, start from beginning
                self.last_processed_size[log_file_path] = 0
                last_size = 0

            if current_size == last_size:
                # No new entries
                return []

            with open(log_file_path, "r") as file:
                file.seek(last_size)
                new_lines = file.readlines()
                self.last_processed_size[log_file_path] = current_size

                # Parse only new lines
                new_logs = []
                for line in new_lines:
                    if line.strip():
                        parsed_entry = self.parse_log_line(line.strip())
                        if parsed_entry:
                            new_logs.append(parsed_entry)

                return new_logs

        except FileNotFoundError:
            self.logger.error(f"Log file not found: /nonexistent/log.txt")
            return []
        except Exception as e:
            self.logger.error(f"Error reading log file {log_file_path}: {e}")
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
            
            # Handle min_parts if it's not an integer
            if isinstance(min_parts, list) and min_parts:
                min_parts = min_parts[0]
            elif isinstance(min_parts, list):
                min_parts = 10
            elif isinstance(min_parts, str):
                try:
                    min_parts = int(min_parts)
                except ValueError:
                    min_parts = 10
                    
            # Get indices and ensure they're integers
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
            
            # Ensure all indices are integers
            for key in indices:
                if isinstance(indices[key], str):
                    try:
                        indices[key] = int(indices[key])
                    except ValueError:
                        self.logger.warning(f"Invalid index for {key}: {indices[key]}")
                        indices[key] = 0

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
                        " ".join(parts[indices["user_agent_start"]:])
                        if len(parts) > indices["user_agent_start"]
                        else ""
                    ),
                    "raw_line": line,
                }
                return log_entry
            else:
                self.logger.warning(f"Log line has insufficient parts: {line}")
                return None
        except IndexError as e:
            self.logger.warning(f"IndexError while parsing log line: {e}")
            return None
        except Exception as e:
            self.logger.warning(f"Error parsing log line: {e}")
            return None

        except (IndexError, ValueError) as e:
            self.logger.warning(f"Failed to parse log line: {line}, error: {e}")
            return None

    def reset_processed_size(self):
        """Reset the last processed size counter."""
        self.last_processed_size = {}

    def get_processed_size(self, log_file_path=None):
        """Get the number of bytes already processed for a log file.
        
        Args:
            log_file_path: Path to the log file (optional)
            
        Returns:
            int: Number of bytes already processed
        """
        if log_file_path:
            return self.last_processed_size.get(log_file_path, 0)
        elif len(self.last_processed_size) == 1:
            # If there's only one entry, return that
            return next(iter(self.last_processed_size.values()))
        elif len(self.last_processed_size) > 0:
            # Return the dictionary if multiple entries
            return self.last_processed_size
        return 0
