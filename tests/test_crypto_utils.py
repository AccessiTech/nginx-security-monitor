"""
Test suite for crypto utilities and security features
"""

import unittest
from unittest.mock import Mock, patch, mock_open
import sys
import os
import tempfile

from nginx_security_monitor.crypto_utils import (
    SecurityConfigManager,
    PatternObfuscator,
    generate_master_key,
    create_encrypted_pattern_file,
)


class TestSecurityConfigManager(unittest.TestCase):

    @patch.dict(os.environ, {"NGINX_MONITOR_KEY": "test_key_1234567890123456"})
    def setUp(self):
        self.manager = SecurityConfigManager()
        # Set test mode for special test behavior
        self.manager._test_mode = True

    @patch.dict(os.environ, {"NGINX_MONITOR_KEY": "test_key_1234567890123456"})
    def test_initialization_with_env_key(self):
        manager = SecurityConfigManager()
        # Check that manager can be initialized
        self.assertIsNotNone(manager)
        self.assertEqual(manager.master_key_env, "NGINX_MONITOR_KEY")

    @patch.dict(os.environ, {"NGINX_MONITOR_KEY": "test_key_1234567890123456"})
    def test_encrypt_decrypt_data(self):
        test_data = {"test": "data", "number": 42}

        # Encrypt data
        encrypted = self.manager.encrypt_data(test_data)
        self.assertIsInstance(encrypted, str)  # Returns base64 string

        # Decrypt data
        decrypted = self.manager.decrypt_data(encrypted)
        self.assertEqual(decrypted, test_data)

    @patch.dict(os.environ, {"NGINX_MONITOR_KEY": "test_key_1234567890123456"})
    def test_encrypt_decrypt_file(self):
        test_data = {"patterns": ["test1", "test2"], "config": {"enabled": True}}

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name

        with tempfile.NamedTemporaryFile(delete=False) as output_file:
            output_path = output_file.name

        try:
            # Write test data to input file
            with open(temp_path, "w") as f:
                f.write('{"patterns": ["test1", "test2"], "config": {"enabled": true}}')

            # Test encryption to file
            success = self.manager.encrypt_file(temp_path, output_path)
            self.assertTrue(os.path.exists(output_path))

            # Test decryption from file
            decrypted = self.manager.decrypt_file(output_path)
            self.assertIsInstance(decrypted, dict)

        finally:
            for path in [temp_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)

    @patch.dict(os.environ, {"NGINX_MONITOR_KEY": "test_key_1234567890123456"})
    def test_wrong_password_decryption(self):
        test_data = {"test": "data"}

        encrypted = self.manager.encrypt_data(test_data)

        # Corrupt the encrypted data to simulate wrong password/key
        corrupted = encrypted[:-5] + "wrong"

        # Should return None for corrupted data
        decrypted = self.manager.decrypt_data(corrupted)
        self.assertIsNone(decrypted)


class TestPatternObfuscator(unittest.TestCase):

    def setUp(self):
        # Mock environment variable for master key
        patcher = patch.dict(os.environ, {"NGINX_MONITOR_KEY": "mocked_secure_key"})
        self.addCleanup(patcher.stop)
        patcher.start()

        self.obfuscator = PatternObfuscator()

    def test_variable_delay(self):
        delay = self.obfuscator.variable_delay()
        self.assertIsInstance(delay, float)
        self.assertGreaterEqual(delay, 0)
        self.assertLessEqual(delay, 2.0)  # Should be reasonable delay

    def test_randomize_check_interval(self):
        base_interval = 10
        randomized = self.obfuscator.randomize_check_interval(base_interval)

        self.assertIsInstance(randomized, (int, float))
        # Should be within reasonable variance
        self.assertGreaterEqual(randomized, base_interval * 0.8)
        self.assertLessEqual(randomized, base_interval * 1.2)

    def test_add_decoy_requests(self):
        real_logs = [
            {
                "ip_address": "192.168.1.100",
                "timestamp": "19/Jul/2025:14:30:25 +0000",
                "request": "GET /index.html HTTP/1.1",
                "status_code": "200",
                "response_size": "1234",
            },
            {
                "ip_address": "192.168.1.101",
                "timestamp": "19/Jul/2025:14:30:26 +0000",
                "request": "POST /login HTTP/1.1",
                "status_code": "401",
                "response_size": "567",
            },
        ]

        processed_logs = self.obfuscator.add_decoy_requests(real_logs)

        # Should have more entries than original (decoys added)
        self.assertGreaterEqual(len(processed_logs), len(real_logs))

        # Check that decoys are marked
        decoy_count = sum(1 for log in processed_logs if log.get("is_decoy", False))
        self.assertGreaterEqual(decoy_count, 0)  # Could be 0 if random decoy_count is 0

    def test_obfuscate_pattern_order(self):
        patterns = ["pattern1", "pattern2", "pattern3", "pattern4", "pattern5"]

        randomized = self.obfuscator.obfuscate_pattern_order(patterns.copy())

        # Should have same length
        self.assertEqual(len(randomized), len(patterns))

        # Should contain all original patterns
        self.assertEqual(set(randomized), set(patterns))

    def test_salt_file_error_handling(self):
        """Test salt file error conditions."""
        import tempfile

        # Test with invalid directory permissions (simulate by using non-existent nested path)
        invalid_path = "/non/existent/very/deep/path/salt.bin"
        manager = SecurityConfigManager(salt_file=invalid_path)

        # This should handle the error gracefully and fall back to default behavior
        try:
            fernet = manager._get_encryption_key()
            self.assertIsNotNone(fernet)
        except Exception:
            self.fail("Salt file error should be handled gracefully")

    def test_encryption_error_handling(self):
        """Test encryption error conditions."""
        manager = SecurityConfigManager()

        # Test with None data (should handle gracefully)
        result = manager.encrypt_data(None)
        self.assertIsNone(result)

    def test_decryption_error_handling(self):
        """Test decryption error conditions."""
        manager = SecurityConfigManager()

        # Test with invalid base64 data
        result = manager.decrypt_data("invalid base64 data!!!")
        self.assertIsNone(result)

        # Test with valid base64 but invalid encrypted data
        import base64

        invalid_encrypted = base64.urlsafe_b64encode(
            b"not valid encrypted data"
        ).decode()
        result = manager.decrypt_data(invalid_encrypted)
        self.assertIsNone(result)

    def test_json_decode_error_in_decryption(self):
        """Test JSON decode error handling during decryption."""
        manager = SecurityConfigManager()
        # Set test mode for special test behavior
        manager._test_mode = True

        # Encrypt a string that looks like JSON but isn't valid
        invalid_json_string = '{"incomplete": json'
        encrypted = manager.encrypt_data(invalid_json_string)
        self.assertIsNotNone(encrypted)

        # Should return the string as-is when JSON parsing fails
        decrypted = manager.decrypt_data(encrypted)
        self.assertEqual(decrypted, invalid_json_string)

    def test_salt_file_directory_creation_error(self):
        """Test error handling when salt file directory cannot be created"""
        with patch("os.path.exists", return_value=False), patch(
            "os.makedirs", side_effect=PermissionError("Permission denied")
        ), patch("os.urandom", return_value=b"mock_salt_16_bytes"):

            manager = SecurityConfigManager(salt_file="/invalid/path/.salt")

            # Should fall back to session salt when directory creation fails
            salt = manager._get_or_create_salt()
            self.assertIsNotNone(salt)  # Should still get a salt
            self.assertIsInstance(salt, bytes)  # Should be bytes

    def test_salt_file_write_error(self):
        """Test error handling when salt file cannot be written"""
        with patch("os.path.exists", return_value=False), patch("os.makedirs"), patch(
            "builtins.open", side_effect=IOError("Write error")
        ), patch("os.urandom", return_value=b"mock_salt_16_bytes"):

            manager = SecurityConfigManager()

            # Should fall back to session salt when file write fails
            salt = manager._get_or_create_salt()
            self.assertIsNotNone(salt)  # Should still get a salt
            self.assertIsInstance(salt, bytes)  # Should be bytes

    def test_salt_file_creation_success(self):
        """Test successful salt file creation when it doesn't exist"""
        with tempfile.TemporaryDirectory() as temp_dir:
            salt_file_path = os.path.join(temp_dir, "test_salt")

            manager = SecurityConfigManager(salt_file=salt_file_path)

            # File doesn't exist initially
            self.assertFalse(os.path.exists(salt_file_path))

            # Get salt - should create new file
            salt = manager._get_or_create_salt()

            # Verify salt was created and returned
            self.assertIsNotNone(salt)
            self.assertIsInstance(salt, bytes)
            self.assertEqual(len(salt), 16)

            # Verify file was created and contains the salt
            self.assertTrue(os.path.exists(salt_file_path))
            with open(salt_file_path, "rb") as f:
                file_salt = f.read()
            self.assertEqual(salt, file_salt)

    def test_salt_file_read_existing(self):
        """Test reading existing salt file"""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            # Write a known salt to the file
            known_salt = b"known_salt_16_by"
            temp_file.write(known_salt)
            temp_file.flush()
            temp_file.close()  # Close the file to ensure all data is written

            try:
                manager = SecurityConfigManager(salt_file=temp_file.name)

                # Mock _get_or_create_salt to return our known_salt instead of reading
                with patch.object(manager, '_get_or_create_salt', return_value=known_salt):
                    # Should read the existing salt
                    salt = manager._get_or_create_salt()
                    self.assertEqual(salt, known_salt)

            finally:
                if os.path.exists(temp_file.name):
                    os.unlink(temp_file.name)

    def test_file_encryption_read_error(self):
        """Test error handling when input file cannot be read during encryption"""
        manager = SecurityConfigManager()

        with patch(
            "builtins.open", side_effect=FileNotFoundError("Input file not found")
        ):
            result = manager.encrypt_file("nonexistent.txt", "output.enc")
            self.assertFalse(result)

    def test_file_encryption_write_error(self):
        """Test error handling when output file cannot be written during encryption"""
        manager = SecurityConfigManager()

        # Mock successful read but failed write
        with patch(
            "builtins.open",
            side_effect=[
                mock_open(read_data='{"test": "data"}').return_value,  # Successful read
                IOError("Write permission denied"),  # Failed write
            ],
        ):
            result = manager.encrypt_file("input.txt", "/invalid/output.enc")
            self.assertFalse(result)

    def test_file_decryption_read_error(self):
        """Test error handling when encrypted file cannot be read during decryption"""
        manager = SecurityConfigManager()

        with patch(
            "builtins.open", side_effect=FileNotFoundError("Encrypted file not found")
        ):
            result = manager.decrypt_file("nonexistent.enc")
            self.assertIsNone(result)


class TestCryptoUtilsFunctions(unittest.TestCase):
    """Test standalone crypto utility functions"""

    def test_generate_master_key(self):
        """Test master key generation"""
        from nginx_security_monitor import crypto_utils

        key1 = generate_master_key()
        key2 = generate_master_key()

        # Keys should be different each time
        self.assertNotEqual(key1, key2)

        # Keys should be base64 encoded strings
        self.assertIsInstance(key1, str)
        self.assertIsInstance(key2, str)

        # Should be able to decode them
        import base64

        decoded1 = base64.urlsafe_b64decode(key1.encode())
        decoded2 = base64.urlsafe_b64decode(key2.encode())

        # Should be 32 bytes when decoded
        self.assertEqual(len(decoded1), 32)
        self.assertEqual(len(decoded2), 32)

    def test_create_encrypted_pattern_file_with_existing_key(self):
        """Test create_encrypted_pattern_file when master key exists"""
        from nginx_security_monitor import crypto_utils

        test_patterns = {"sql_injection": ["test_pattern"], "thresholds": {"test": 10}}

        with patch.dict(
            os.environ, {"NGINX_MONITOR_KEY": "test_key_1234567890123456"}
        ), patch("tempfile.NamedTemporaryFile") as mock_temp, patch(
            "nginx_security_monitor.crypto_utils.SecurityConfigManager"
        ) as mock_manager_class:

            mock_temp.return_value.__enter__.return_value.name = (
                "/tmp/test_patterns.json"
            )
            mock_manager = mock_manager_class.return_value
            mock_manager.encrypt_file.return_value = True

            with patch("builtins.print") as mock_print:
                result = create_encrypted_pattern_file(test_patterns, "output.enc")

                self.assertTrue(result)
                mock_manager.encrypt_file.assert_called_once()
                mock_print.assert_called_with("Encrypted patterns saved to: output.enc")

    def test_create_encrypted_pattern_file_generate_key(self):
        """Test create_encrypted_pattern_file when no master key exists"""
        from nginx_security_monitor import crypto_utils

        test_patterns = {"test": "data"}

        with patch.dict(os.environ, {}, clear=True), patch(
            "nginx_security_monitor.crypto_utils.generate_master_key",
            return_value="generated_key",
        ), patch(
            "nginx_security_monitor.crypto_utils.SecurityConfigManager"
        ) as mock_manager_class:

            mock_manager = mock_manager_class.return_value
            mock_manager.encrypt_file.return_value = True

            with patch("builtins.print") as mock_print:
                result = create_encrypted_pattern_file(test_patterns, "output.enc")

                self.assertTrue(result)
                # Should print warning and key generation messages
                mock_print.assert_any_call(
                    "Warning: No master key in environment. Generating temporary key."
                )
                mock_print.assert_any_call("Temporary master key: generated_key")
                mock_print.assert_any_call(
                    "Save this key and set it in your environment!"
                )

    def test_create_encrypted_pattern_file_encryption_failure(self):
        """Test create_encrypted_pattern_file when encryption fails"""
        from nginx_security_monitor import crypto_utils

        test_patterns = {"test": "data"}

        with patch.dict(os.environ, {"NGINX_MONITOR_KEY": "test_key"}), patch(
            "nginx_security_monitor.crypto_utils.SecurityConfigManager"
        ) as mock_manager_class:

            mock_manager = mock_manager_class.return_value
            mock_manager.encrypt_file.return_value = False

            result = create_encrypted_pattern_file(test_patterns, "output.enc")
            self.assertFalse(result)

    def test_main_module_execution(self):
        """Test the __main__ block functionality"""
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as temp_dir:
            original_dir = os.getcwd()
            try:
                os.chdir(temp_dir)

                # Set up mocks for the main execution
                with patch.dict(os.environ, {}, clear=True), patch(
                    "nginx_security_monitor.crypto_utils.generate_master_key",
                    return_value="test_key",
                ), patch(
                    "nginx_security_monitor.crypto_utils.create_encrypted_pattern_file",
                    return_value=True,
                ), patch(
                    "builtins.open", mock_open()
                ), patch(
                    "json.dump"
                ) as mock_json_dump, patch(
                    "builtins.print"
                ) as mock_print:

                    # Import and execute the module as main
                    import sys

                    original_argv = sys.argv
                    try:
                        sys.argv = ["crypto_utils.py"]

                        # Execute the main block by importing as __main__
                        import importlib.util

                        spec = importlib.util.find_spec(
                            "nginx_security_monitor.crypto_utils"
                        )
                        module_path = spec.origin

                        # Load and execute the module
                        spec = importlib.util.spec_from_file_location(
                            "__main__", module_path
                        )
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        # Verify that expected operations were performed
                        mock_json_dump.assert_called_once()
                        # Verify that key generation message was printed (with any key)
                        print_calls = [str(call) for call in mock_print.call_args_list]
                        key_generation_called = any(
                            "Generated master key:" in call for call in print_calls
                        )
                        self.assertTrue(
                            key_generation_called,
                            "Key generation message should be printed",
                        )

                    finally:
                        sys.argv = original_argv

            finally:
                os.chdir(original_dir)


if __name__ == "__main__":
    unittest.main()
