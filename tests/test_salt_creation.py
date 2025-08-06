#!/usr/bin/env python3

"""
Special test for salt file creation issues in CI environment.
This is a simplified test that focuses only on the salt file creation functionality.
"""

import os
import tempfile
import unittest
from unittest.mock import patch
import shutil
import sys

# Import our module to test
from nginx_security_monitor.crypto_utils import SecurityConfigManager


class TestSaltFileCreation(unittest.TestCase):
    """Test specifically focused on salt file creation."""

    def test_direct_salt_file_creation(self):
        """Test salt file creation directly with minimal dependencies."""
        # Create a temporary directory for testing
        temp_dir = tempfile.mkdtemp()
        try:
            # Create a salt file path in the temporary directory
            salt_file_path = os.path.join(temp_dir, "test_salt")
            
            # Print diagnostic information
            print(f"\nTemp directory: {temp_dir}")
            print(f"Salt file path: {salt_file_path}")
            print(f"Directory exists: {os.path.exists(temp_dir)}")
            
            # Ensure the file doesn't exist initially
            if os.path.exists(salt_file_path):
                os.unlink(salt_file_path)
            
            # Verify the file doesn't exist
            self.assertFalse(os.path.exists(salt_file_path))
            
            # Create an instance with this salt file
            with patch.dict(os.environ, {"NGINX_MONITOR_KEY": "test_key"}):
                manager = SecurityConfigManager(salt_file=salt_file_path)
            
                # Get salt - should create the file
                salt = manager._get_or_create_salt()
                
                # Verify the salt
                self.assertIsNotNone(salt)
                self.assertIsInstance(salt, bytes)
                self.assertEqual(len(salt), 16)
                
                # Check if the file was created
                self.assertTrue(os.path.exists(salt_file_path), 
                                f"Salt file {salt_file_path} does not exist")
                
                # If file exists, verify its contents
                if os.path.exists(salt_file_path):
                    with open(salt_file_path, "rb") as f:
                        file_salt = f.read()
                    self.assertEqual(salt, file_salt)
        
        finally:
            # Clean up
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
