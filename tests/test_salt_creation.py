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
                
                # Print details about the salt for debugging
                print(f"Salt type: {type(salt)}")
                print(f"Salt length: {len(salt)}")
                print(f"Salt bytes: {salt}")
                
                # Verify the salt - must be exactly 16 bytes
                EXPECTED_SALT_SIZE = 16
                self.assertIsNotNone(salt)
                self.assertIsInstance(salt, bytes)
                self.assertEqual(len(salt), EXPECTED_SALT_SIZE, f"Salt length is {len(salt)}, expected {EXPECTED_SALT_SIZE}")
                
                # Check if the file was created
                file_exists = os.path.exists(salt_file_path)
                print(f"File exists: {file_exists}")
                self.assertTrue(file_exists, f"Salt file {salt_file_path} does not exist")
                
                # If file exists, verify its contents
                if file_exists:
                    with open(salt_file_path, "rb") as f:
                        file_salt = f.read()
                    print(f"File salt length: {len(file_salt)}")
                    self.assertEqual(len(file_salt), EXPECTED_SALT_SIZE, "File salt has incorrect length")
                    self.assertEqual(salt, file_salt, "Memory salt and file salt don't match")
        
        finally:
            # Clean up
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
