#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Universal Log Handler for NGINX Security Monitor

This module implements a log handling system that works for both:
1. Regular file-based logs
2. Docker log streams (via stdout/stderr)

It automatically detects the log source type and adapts accordingly.
"""

import os
import sys
import time
import logging
import threading
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Iterator, Optional, Union

from nginx_security_monitor.config_manager import ConfigManager


class UniversalLogHandler:
    """
    Universal log handler that works with both file-based logs and Docker log streams.
    Automatically detects log source type and provides appropriate access method.
    """

    def __init__(self, config_manager=None):
        """Initialize the log handler."""
        self.logger = logging.getLogger("nginx-security-monitor.logs")
        self.config_manager = config_manager or ConfigManager.get_instance()
        self.docker_mode = False
        self.container_id = None
        
    def detect_log_source(self, log_path: str) -> Dict[str, Any]:
        """
        Detect the type of log source (file, symlink, docker, etc).
        
        Args:
            log_path: Path to the log file
            
        Returns:
            Dict with detection results:
                - type: 'file', 'symlink', 'docker', or 'unknown'
                - target: For symlinks, the target path
                - readable: Whether the log is readable
                - docker_info: For Docker logs, container and stream info
        """
        result = {
            "path": log_path,
            "type": "unknown",
            "readable": False,
            "target": None,
            "docker_info": None
        }
        
        try:
            path = Path(log_path)
            
            # Check if it's a regular file
            if path.is_file():
                result["type"] = "file"
                result["readable"] = os.access(log_path, os.R_OK)
                return result
                
            # Check if it's a symlink
            if path.is_symlink():
                result["type"] = "symlink"
                target = os.readlink(log_path)
                result["target"] = target
                
                # Check if symlinked to Docker stdout/stderr
                if target in ["/dev/stdout", "/dev/stderr"]:
                    result["type"] = "docker"
                    # Try to detect Docker container info
                    self.docker_mode = True
                    container_info = self._detect_docker_container()
                    if container_info:
                        result["docker_info"] = container_info
                        result["readable"] = True
                else:
                    # Regular symlink to another file
                    target_path = Path(target)
                    result["readable"] = target_path.is_file() and os.access(target, os.R_OK)
                
                return result
                
            # If not a file or symlink, check if we're in Docker environment
            if self._is_docker_environment():
                result["type"] = "docker"
                container_info = self._detect_docker_container()
                if container_info:
                    result["docker_info"] = container_info
                    result["readable"] = True
                return result
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error detecting log source for {log_path}: {e}")
            return result
    
    def _is_docker_environment(self) -> bool:
        """Check if we're running inside a Docker container."""
        # Check for .dockerenv file
        if os.path.exists("/.dockerenv"):
            return True
            
        # Check cgroup for docker
        try:
            with open("/proc/1/cgroup", "r") as f:
                content = f.read()
                if "docker" in content:
                    return True
        except:
            pass
            
        return False
        
    def _detect_docker_container(self) -> Optional[Dict[str, str]]:
        """Detect Docker container information."""
        try:
            # Get container ID from cgroup
            with open("/proc/self/cgroup", "r") as f:
                for line in f:
                    if "docker" in line:
                        parts = line.strip().split("/")
                        for part in reversed(parts):
                            if part and "docker" not in part:
                                self.container_id = part
                                return {
                                    "container_id": part,
                                    "type": "docker"
                                }
        except:
            pass
            
        return None
        
    def read_logs(self, log_path: str, tail: int = 100, follow: bool = False) -> Iterator[str]:
        """
        Universal log reader that works with both files and Docker logs.
        
        Args:
            log_path: Path to the log file or identifier
            tail: Number of lines to tail
            follow: Whether to follow the log (like tail -f)
            
        Returns:
            Iterator yielding log lines
        """
        source_info = self.detect_log_source(log_path)
        
        if source_info["type"] == "file" and source_info["readable"]:
            # Regular file handling
            yield from self._read_file_logs(log_path, tail, follow)
        elif source_info["type"] == "symlink" and source_info["readable"]:
            # Symlink handling - read the target file
            yield from self._read_file_logs(source_info["target"], tail, follow)
        elif source_info["type"] == "docker":
            # Docker log handling
            yield from self._read_docker_logs(log_path, tail, follow)
        else:
            self.logger.error(f"Cannot read from log source: {log_path}, type: {source_info['type']}")
            yield f"ERROR: Cannot read from log source {log_path}"
    
    def _read_file_logs(self, file_path: str, tail: int = 100, follow: bool = False) -> Iterator[str]:
        """Read logs from a regular file."""
        try:
            cmd = ["tail"]
            if follow:
                cmd.append("-f")
            if tail > 0:
                cmd.extend(["-n", str(tail)])
            cmd.append(file_path)
            
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            
            # Read and yield output lines
            for line in process.stdout:
                yield line.rstrip()
                
            if not follow:
                process.wait()
                
        except Exception as e:
            self.logger.error(f"Error reading file logs from {file_path}: {e}")
            yield f"ERROR: {str(e)}"
    
    def _read_docker_logs(self, log_path: str, tail: int = 100, follow: bool = False) -> Iterator[str]:
        """Read logs from Docker stdout/stderr."""
        try:
            if not self.container_id:
                self._detect_docker_container()
                
            if not self.container_id:
                self.logger.error("Cannot detect Docker container ID")
                yield "ERROR: Cannot detect Docker container ID"
                return
                
            cmd = ["docker", "logs"]
            if follow:
                cmd.append("-f")
            if tail > 0:
                cmd.extend(["--tail", str(tail)])
                
            # Determine if we should filter for stdout or stderr
            if log_path.endswith("access.log") or "/dev/stdout" in log_path:
                cmd.append("--stdout")
            elif log_path.endswith("error.log") or "/dev/stderr" in log_path:
                cmd.append("--stderr")
                
            cmd.append(self.container_id)
            
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            
            # Read and yield output lines
            for line in process.stdout:
                yield line.rstrip()
                
            if not follow:
                process.wait()
                
        except Exception as e:
            self.logger.error(f"Error reading Docker logs: {e}")
            yield f"ERROR: {str(e)}"
    
    def get_log_paths(self) -> List[str]:
        """
        Get list of configured log paths from config.
        
        Returns:
            List of log file paths
        """
        # First try to get from monitoring.log_files list
        log_files = self.config_manager.get("monitoring.log_files", [])
        
        # If empty, try individual access_log and error_log settings
        if not log_files:
            access_log = self.config_manager.get("logs.access_log")
            error_log = self.config_manager.get("logs.error_log")
            
            if access_log:
                log_files.append(access_log)
            if error_log:
                log_files.append(error_log)
                
        # If still empty, use defaults
        if not log_files:
            log_files = [
                "/var/log/nginx/access.log",
                "/var/log/nginx/error.log"
            ]
            
        return log_files

    def watch_logs(self, callback, log_paths=None, interval=1.0):
        """
        Watch logs for changes and call the callback function with new lines.
        
        Args:
            callback: Function to call with each new log line
            log_paths: List of log paths to watch
            interval: Polling interval in seconds
        """
        if log_paths is None:
            log_paths = self.get_log_paths()
            
        if not log_paths:
            self.logger.error("No log paths configured for watching")
            return
            
        threads = []
        for log_path in log_paths:
            thread = threading.Thread(
                target=self._watch_log_file,
                args=(log_path, callback, interval),
                daemon=True
            )
            threads.append(thread)
            thread.start()
            
        return threads
    
    def _watch_log_file(self, log_path, callback, interval):
        """Watch a single log file and call callback for new lines."""
        self.logger.info(f"Starting log watcher for {log_path}")
        
        source_info = self.detect_log_source(log_path)
        self.logger.info(f"Log source info: {source_info}")
        
        # Use the appropriate log reading method based on source type
        try:
            for line in self.read_logs(log_path, tail=0, follow=True):
                if line.startswith("ERROR:"):
                    self.logger.error(f"Error in log watcher: {line}")
                    time.sleep(interval)
                    continue
                    
                try:
                    callback(line, log_path)
                except Exception as e:
                    self.logger.error(f"Error in log callback: {e}")
        except Exception as e:
            self.logger.error(f"Log watching error for {log_path}: {e}")
