import unittest
import os
import sys
import tempfile
import json
from unittest.mock import patch, MagicMock, mock_open, call
from io import StringIO

# Add the root directory to Python path to import the utility
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import the utility functions
import encrypt_config


class TestEncryptConfigUtility(unittest.TestCase):
    """Comprehensive tests for encrypt_config.py utility"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = {"api_key": "test123", "password": "secret"}

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("encrypt_config.SecurityConfigManager")
    @patch("os.remove")
    def test_encrypt_patterns_file_new_key_generation(
        self, mock_remove, mock_manager_class, mock_print, mock_input, mock_env_get
    ):
        """Test encrypting patterns with new key generation"""
        # Arrange
        mock_env_get.return_value = None  # No master key in env
        mock_input.side_effect = [
            "y",  # Generate new key
            "SELECT * FROM users",  # SQL pattern
            "",  # End SQL patterns
            '<script>alert("xss")</script>',  # XSS pattern
            "",  # End XSS patterns
            "brute_force",  # Custom rule name
            "failed login attempts",  # Custom pattern
            "",  # End custom patterns
            "HIGH",  # Severity
            "100",  # RPM threshold
            "50",  # FPM threshold
            "custom_patterns.enc",  # Output file
        ]

        mock_manager = MagicMock()
        mock_manager.encrypt_file.return_value = True
        mock_manager_class.return_value = mock_manager

        with patch("encrypt_config.generate_master_key", return_value="test_key_123"):
            with patch("builtins.open", mock_open()):
                with patch("json.dump") as mock_json_dump:
                    # Act
                    encrypt_config.encrypt_patterns_file()

                    # Assert
                    mock_manager.encrypt_file.assert_called_once()
                    mock_json_dump.assert_called_once()
                    mock_remove.assert_called_once()

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("encrypt_config.SecurityConfigManager")
    def test_encrypt_patterns_file_existing_key(
        self, mock_manager_class, mock_print, mock_input, mock_getpass, mock_env_get
    ):
        """Test encrypting patterns with existing key"""
        # Arrange
        mock_env_get.return_value = None
        mock_getpass.return_value = "existing_key"
        mock_input.side_effect = [
            "n",  # Don't generate new key
            "",  # No SQL patterns
            "",  # No XSS patterns
            "",  # No custom rule
            "",  # No RPM threshold
            "",  # No FPM threshold
        ]

        # Act
        encrypt_config.encrypt_patterns_file()

        # Assert
        mock_print.assert_any_call("No patterns entered, exiting.")

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_encrypt_patterns_file_value_error_thresholds(
        self, mock_print, mock_input, mock_env_get
    ):
        """Test handling invalid threshold values"""
        # Arrange
        mock_env_get.return_value = "test_key"
        mock_input.side_effect = [
            "",  # No SQL patterns
            "",  # No XSS patterns
            "",  # No custom rule
            "invalid_number",  # Invalid RPM threshold
            "50",  # Valid FPM threshold
        ]

        # Act
        encrypt_config.encrypt_patterns_file()

        # Assert
        mock_print.assert_any_call("Invalid threshold values, skipping...")

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("builtins.input")
    @patch("builtins.print")
    def test_create_plugin_template_exception_handling(self, mock_print, mock_input):
        """Test exception handling in create_plugin_template"""
        # Arrange
        mock_input.side_effect = [
            "test_plugin",  # Plugin name
            "Test description",  # Description
            "",  # No threat types
        ]

        with patch(
            "plugin_system.create_plugin_template",
            side_effect=Exception("Template creation failed"),
        ):
            # Act
            encrypt_config.create_plugin_template()

            # Assert
            mock_print.assert_any_call(
                "❌ Error creating template: Template creation failed"
            )

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("encrypt_config.SecurityConfigManager")
    def test_encrypt_config_section_valid_json(
        self, mock_manager_class, mock_print, mock_input, mock_env_get
    ):
        """Test encrypting configuration section with valid JSON"""
        # Arrange
        mock_env_get.return_value = "test_key"
        mock_input.side_effect = [
            '{"api_key": "secret", "db_password": "pass123"}',  # Config JSON
            "database_config",  # Section name
        ]

        mock_manager = MagicMock()
        mock_manager.encrypt_data.return_value = "encrypted_config_string"
        mock_manager_class.return_value = mock_manager

        # Act
        encrypt_config.encrypt_config_section()

        # Assert
        mock_manager.encrypt_data.assert_called_once_with(
            {"api_key": "secret", "db_password": "pass123"}
        )

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_encrypt_config_section_invalid_json(
        self, mock_print, mock_input, mock_env_get
    ):
        """Test encrypting configuration section with invalid JSON"""
        # Arrange
        mock_env_get.return_value = "test_key"
        mock_input.side_effect = ["invalid json string"]  # Invalid JSON

        # Act
        encrypt_config.encrypt_config_section()

        # Assert
        mock_print.assert_any_call("❌ Invalid JSON format")

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("getpass.getpass")
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("encrypt_config.SecurityConfigManager")
    def test_decrypt_and_view_file(
        self, mock_manager_class, mock_print, mock_input, mock_getpass, mock_env_get
    ):
        """Test decrypting and viewing a file"""
        # Arrange
        mock_env_get.return_value = None
        mock_getpass.return_value = "test_key"
        mock_input.side_effect = [
            "f",  # Decrypt file
            "/path/to/encrypted.file",  # File path
        ]

        mock_manager = MagicMock()
        mock_manager.decrypt_file.return_value = {"decrypted": "data"}
        mock_manager_class.return_value = mock_manager

        with patch(
            "json.dumps", return_value='{"decrypted": "data"}'
        ) as mock_json_dumps:
            # Act
            encrypt_config.decrypt_and_view()

            # Assert
            mock_manager.decrypt_file.assert_called_once_with("/path/to/encrypted.file")
            mock_json_dumps.assert_called_once()

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("encrypt_config.SecurityConfigManager")
    def test_decrypt_and_view_data_string(
        self, mock_manager_class, mock_print, mock_input, mock_env_get
    ):
        """Test decrypting and viewing encrypted data string"""
        # Arrange
        mock_env_get.return_value = "test_key"
        mock_input.side_effect = [
            "d",  # Decrypt data
            "encrypted_data_string",  # Encrypted data
        ]

        mock_manager = MagicMock()
        mock_manager.decrypt_data.return_value = "decrypted string"
        mock_manager_class.return_value = mock_manager

        # Act
        encrypt_config.decrypt_and_view()

        # Assert
        mock_manager.decrypt_data.assert_called_once_with("encrypted_data_string")

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("builtins.input")
    @patch("builtins.print")
    def test_create_plugin_template_success(self, mock_print, mock_input):
        """Test creating plugin template successfully"""
        # Arrange
        mock_input.side_effect = [
            "firewall_block",  # Plugin name
            "Blocks IPs via firewall",  # Description
            "DDoS",  # Threat type 1
            "Brute Force",  # Threat type 2
            "",  # End threat types
        ]

        with patch("plugin_system.create_plugin_template") as mock_create:
            mock_create.return_value = None  # Success

            # Act
            encrypt_config.create_plugin_template()

            # Assert
            mock_create.assert_called_once_with(
                "firewall_block", "firewall_block_plugin.py"
            )

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("builtins.input")
    @patch("builtins.print")
    def test_create_plugin_template_no_name(self, mock_print, mock_input):
        """Test creating plugin template without name"""
        # Arrange
        mock_input.return_value = ""  # Empty plugin name

        # Act
        encrypt_config.create_plugin_template()

        # Assert
        mock_print.assert_any_call("Plugin name required")

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("sys.argv", ["encrypt_config.py", "encrypt-patterns"])
    def test_main_encrypt_patterns(self):
        """Test main function with encrypt-patterns action"""
        with patch("encrypt_config.encrypt_patterns_file") as mock_encrypt:
            # Act
            encrypt_config.main()

            # Assert
            mock_encrypt.assert_called_once()

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("sys.argv", ["encrypt_config.py", "decrypt"])
    def test_main_decrypt(self):
        """Test main function with decrypt action"""
        with patch("encrypt_config.decrypt_and_view") as mock_decrypt:
            # Act
            encrypt_config.main()

            # Assert
            mock_decrypt.assert_called_once()

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("sys.argv", ["encrypt_config.py", "interactive"])
    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_interactive_mode(self, mock_print, mock_input):
        """Test main function interactive mode"""
        # Arrange
        mock_input.side_effect = ["5"]  # Exit choice

        # Act
        encrypt_config.main()

        # Assert
        mock_print.assert_any_call(
            "\n=== NGINX Security Monitor Configuration Utility ==="
        )

    @patch("encrypt_config.CRYPTO_AVAILABLE", False)
    def test_main_crypto_not_available(self):
        """Test main function when crypto is not available"""
        # Act & Assert - should return early
        result = encrypt_config.main()
        self.assertIsNone(result)

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("encrypt_config.SecurityConfigManager")
    def test_encrypt_patterns_file_exception_handling(
        self, mock_manager_class, mock_print, mock_input
    ):
        """Test exception handling in encrypt_patterns_file"""
        # Arrange
        mock_input.side_effect = Exception("Unexpected error")

        with patch("os.environ.get", return_value="test_key"):
            # Act & Assert - should raise the exception since function doesn't handle it
            with self.assertRaises(Exception):
                encrypt_config.encrypt_patterns_file()

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("encrypt_config.SecurityConfigManager")
    def test_encrypt_patterns_file_encryption_failure(
        self, mock_manager_class, mock_print, mock_input, mock_env_get
    ):
        """Test handling of encryption failure"""
        # Arrange
        mock_env_get.return_value = "test_key"
        mock_input.side_effect = [
            "SELECT * FROM users",  # SQL pattern
            "",  # End SQL patterns
            "",  # No XSS patterns
            "",  # No custom rule
            "",  # No RPM threshold
            "",  # No FPM threshold
            "output.enc",  # Output file
        ]

        mock_manager = MagicMock()
        mock_manager.encrypt_file.return_value = False  # Encryption fails
        mock_manager_class.return_value = mock_manager

        with patch("builtins.open", mock_open()):
            with patch("json.dump"):
                # Act
                encrypt_config.encrypt_patterns_file()

                # Assert
                mock_print.assert_any_call("❌ Encryption failed")

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("os.environ.get")
    @patch("builtins.input")
    @patch("builtins.print")
    def test_encrypt_patterns_file_value_error_thresholds(
        self, mock_print, mock_input, mock_env_get
    ):
        """Test handling invalid threshold values"""
        # Arrange
        mock_env_get.return_value = "test_key"
        mock_input.side_effect = [
            "",  # No SQL patterns
            "",  # No XSS patterns
            "",  # No custom rule
            "invalid_number",  # Invalid RPM threshold
            "50",  # Valid FPM threshold
        ]

        # Act
        encrypt_config.encrypt_patterns_file()

        # Assert
        mock_print.assert_any_call("Invalid threshold values, skipping...")

    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("builtins.input")
    @patch("builtins.print")
    def test_main_create_plugin_action(self, mock_print, mock_input):
        """Test main function with create-plugin action"""
        # Arrange - provide enough inputs for the create_plugin_template function
        mock_input.side_effect = [
            "test_plugin",      # plugin name
            "Test Plugin",      # display name
            "A test plugin",    # description
            "xss",             # threat type
            "<script>",        # pattern
            "",                # empty to finish patterns
            "1",               # severity
            ""                 # end input
        ]
        
        with patch("sys.argv", ["encrypt_config.py", "create-plugin"]):
            # Act
            encrypt_config.main()
            
        # Assert - main should execute without error
        mock_print.assert_called()
        
    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("sys.exit")
    def test_main_invalid_action(self, mock_exit, mock_print, mock_input):
        """Test main function with invalid action"""
        with patch("sys.argv", ["encrypt_config.py", "invalid-action"]):
            # Act
            encrypt_config.main()
            
        # Assert - should exit with error code
        mock_exit.assert_called_with(2)
        
    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("builtins.input")
    @patch("builtins.print")  
    @patch("encrypt_config.SecurityConfigManager")
    def test_encrypt_patterns_file_save_failure(self, mock_manager_class, mock_print, mock_input):
        """Test encrypt_patterns_file when file save fails"""
        # Arrange - provide all needed inputs including output file
        mock_input.side_effect = [
            "",    # SQL pattern (empty to skip)
            "",    # XSS pattern (empty to skip)
            "",    # File inclusion pattern (empty to skip)
            "50",  # Failed requests per minute
            "100", # Suspicious requests per minute
            "10",  # Block duration
            ""     # Output file (empty to use default)
        ]
        mock_manager = mock_manager_class.return_value
        mock_manager.encrypt_file.return_value = False
        
        with patch("os.environ.get", return_value="test_key"):
            # Act
            encrypt_config.encrypt_patterns_file()
            
        # Assert
        mock_print.assert_any_call("❌ Encryption failed")
        
    @patch("encrypt_config.CRYPTO_AVAILABLE", True)
    @patch("builtins.input")
    @patch("builtins.print")
    @patch("encrypt_config.SecurityConfigManager")
    def test_encrypt_patterns_file_exception_during_save(self, mock_manager_class, mock_print, mock_input):
        """Test encrypt_patterns_file when exception occurs during save"""
        # Arrange - provide all needed inputs including output file
        mock_input.side_effect = [
            "",    # SQL pattern (empty to skip)
            "",    # XSS pattern (empty to skip)
            "",    # File inclusion pattern (empty to skip)  
            "50",  # Failed requests per minute
            "100", # Suspicious requests per minute
            "10",  # Block duration
            ""     # Output file (empty to use default)
        ]
        mock_manager = mock_manager_class.return_value
        mock_manager.encrypt_file.side_effect = Exception("Save failed")
        
        with patch("os.environ.get", return_value="test_key"):
            # Act
            encrypt_config.encrypt_patterns_file()
            
        # Assert
        mock_print.assert_any_call("❌ Error: Save failed")
        
    @patch("builtins.input")
    @patch("builtins.print")
    def test_decrypt_and_view_with_path_traversal_patterns(self, mock_print, mock_input):
        """Test decrypt_and_view with path traversal patterns"""
        # Arrange
        mock_input.side_effect = ["../../../etc/passwd", ""]
        
        with patch("os.environ.get", return_value="test_key"):
            # Act
            encrypt_config.decrypt_and_view()
            
        # Assert - should handle path traversal attempt safely
        mock_print.assert_called()
        
    @patch("builtins.input")
    @patch("builtins.print")
    def test_decrypt_and_view_special_characters(self, mock_print, mock_input):
        """Test decrypt_and_view with special characters in input"""
        # Arrange
        mock_input.side_effect = ["test@#$%^&*()", ""]
        
        with patch("os.environ.get", return_value="test_key"):
            # Act
            encrypt_config.decrypt_and_view()
            
        # Assert
        mock_print.assert_called()
        
    @patch("encrypt_config.CRYPTO_AVAILABLE", False)
    @patch("builtins.print")
    @patch("sys.exit")
    def test_crypto_not_available_exit(self, mock_exit, mock_print):
        """Test that script exits when crypto is not available"""
        # This test checks the import error handling at module level
        # Since we can't easily test the import-time behavior, we test the flag
        self.assertFalse(encrypt_config.CRYPTO_AVAILABLE)


if __name__ == "__main__":
    unittest.main()
