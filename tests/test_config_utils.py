import unittest
import os
import sys
import yaml
from pathlib import Path
import tempfile
import shutil
import base64
import json
import requests

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


from unittest.mock import patch

MOCK_CONFIG_FILENAME = "temp_test_config.yaml"

# Patch the global CONFIG_FILE_PATH in config_utils *before* it's imported
with patch('src.config_utils.CONFIG_FILE_PATH', Path(MOCK_CONFIG_FILENAME)):
    from src import config_utils
    from src import pqc_utils 

class TestConfigUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up a temporary directory for test file operations."""
        cls.temp_dir = tempfile.mkdtemp(prefix="qu3_test_config_")
        cls.temp_dir_path = Path(cls.temp_dir)
        
        cls.kem_algo = pqc_utils.ALGORITHMS["kem"]
        cls.sig_algo = pqc_utils.ALGORITHMS["sig"]
        cls.dummy_kem_pk, cls.dummy_kem_sk = pqc_utils.generate_key_pair(cls.kem_algo)
        cls.dummy_sig_pk, cls.dummy_sig_sk = pqc_utils.generate_key_pair(cls.sig_algo)

    @classmethod
    def tearDownClass(cls):
        """Clean up the temporary directory."""
        shutil.rmtree(cls.temp_dir)
        
        if Path(MOCK_CONFIG_FILENAME).exists():
            os.remove(MOCK_CONFIG_FILENAME)

    def setUp(self):
        """Ensure clean state before each test (clear cache, remove mock file)."""
        config_utils._config_cache = None 
        if Path(MOCK_CONFIG_FILENAME).exists():
            os.remove(MOCK_CONFIG_FILENAME)

    def tearDown(self): 
        self.setUp()

    def test_01_load_config_defaults(self):
        """Test loading config when file doesn't exist (uses defaults)."""
        # Ensure file doesn't exist
        self.assertFalse(Path(MOCK_CONFIG_FILENAME).exists())
        config = config_utils.load_config()
        self.assertEqual(config, {})
        
        self.assertEqual(config_utils.get_key_dir(), Path(config_utils.DEFAULT_KEY_DIR_STR).expanduser().resolve())
        self.assertEqual(config_utils.get_server_url(), config_utils.DEFAULT_SERVER_URL)

    def test_02_load_config_custom(self):
        """Test loading config from a custom YAML file."""
        custom_config = {
            'key_directory': str(self.temp_dir_path / "custom_keys"),
            'server_url': 'http://custom.example.com:9000',
            'some_other_setting': 123
        }
        with open(MOCK_CONFIG_FILENAME, 'w') as f:
            yaml.dump(custom_config, f)

        config = config_utils.load_config()
        self.assertEqual(config, custom_config)
        self.assertEqual(config_utils.get_key_dir(), self.temp_dir_path / "custom_keys")
        self.assertEqual(config_utils.get_server_url(), 'http://custom.example.com:9000')
        self.assertEqual(config_utils.get_config_value('some_other_setting'), 123)
        
        config_utils._config_cache['server_url'] = 'cached_value'
        self.assertEqual(config_utils.get_server_url(), 'cached_value')

    def test_03_load_config_invalid_yaml(self):
        """Test loading config with invalid YAML content."""
        with open(MOCK_CONFIG_FILENAME, 'w') as f:
            f.write("key: value: nested_invalid") 

        config = config_utils.load_config()
        self.assertEqual(config, {}) 
        
        self.assertEqual(config_utils.get_key_dir(), Path(config_utils.DEFAULT_KEY_DIR_STR).expanduser().resolve())
        self.assertEqual(config_utils.get_server_url(), config_utils.DEFAULT_SERVER_URL)

    def test_04_save_load_key_pair(self):
        """Test saving and loading a key pair."""
        pub_path = self.temp_dir_path / "test_kem.pub"
        sec_path = self.temp_dir_path / "test_kem.sec"

        # Ensure files don't exist initially
        self.assertFalse(pub_path.exists())
        self.assertFalse(sec_path.exists())

        
        config_utils.save_key_pair_to_files(self.dummy_kem_pk, self.dummy_kem_sk, pub_path, sec_path)
        self.assertTrue(pub_path.exists())
        self.assertTrue(sec_path.exists())
        
        self.assertEqual(sec_path.stat().st_mode & 0o777, 0o600)

        
        loaded_pk, loaded_sk = config_utils.load_key_pair_from_files(pub_path, sec_path)
        self.assertEqual(loaded_pk, self.dummy_kem_pk)
        self.assertEqual(loaded_sk, self.dummy_kem_sk)

    def test_05_load_public_key(self):
        """Test loading just a public key."""
        pub_path = self.temp_dir_path / "test_sig.pub"
        sec_path = self.temp_dir_path / "test_sig.sec"
        config_utils.save_key_pair_to_files(self.dummy_sig_pk, self.dummy_sig_sk, pub_path, sec_path)

        loaded_pk = config_utils.load_public_key_from_file(pub_path)
        self.assertEqual(loaded_pk, self.dummy_sig_pk)

    def test_06_load_key_pair_not_found(self):
        """Test loading non-existent key pair raises FileNotFoundError."""
        pub_path = self.temp_dir_path / "non_existent.pub"
        sec_path = self.temp_dir_path / "non_existent.sec"
        with self.assertRaises(FileNotFoundError):
            config_utils.load_key_pair_from_files(pub_path, sec_path)

    def test_07_load_public_key_not_found(self):
        """Test loading non-existent public key raises FileNotFoundError."""
        pub_path = self.temp_dir_path / "non_existent.pub"
        with self.assertRaises(FileNotFoundError):
            config_utils.load_public_key_from_file(pub_path)

    

    @patch('src.config_utils.requests.get')
    def test_08_fetch_keys_success(self, mock_get):
        """Test successfully fetching and saving server keys."""
        
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'server_kem_public_key_b64': base64.b64encode(self.dummy_kem_pk).decode('utf-8'),
            'server_sign_public_key_b64': base64.b64encode(self.dummy_sig_pk).decode('utf-8')
        }
        mock_get.return_value = mock_response

        server_url = "http://mockserver.test:8000"
        kem_file = "server_kem.pub"
        sign_file = "server_sign.pub"
        kem_path = self.temp_dir_path / kem_file
        sign_path = self.temp_dir_path / sign_file

        # Ensure files don't exist initially
        self.assertFalse(kem_path.exists())
        self.assertFalse(sign_path.exists())

        
        result = config_utils.fetch_and_save_server_keys(server_url, self.temp_dir_path, kem_file, sign_file)

        
        self.assertTrue(result)
        mock_get.assert_called_once_with(f"{server_url}/keys", timeout=10)
        mock_response.raise_for_status.assert_called_once()
        self.assertTrue(kem_path.exists())
        self.assertTrue(sign_path.exists())
        self.assertEqual(kem_path.read_bytes(), self.dummy_kem_pk)
        self.assertEqual(sign_path.read_bytes(), self.dummy_sig_pk)

    @patch('src.config_utils.requests.get')
    def test_09_fetch_keys_network_error(self, mock_get):
        """Test fetching keys with a network error."""
        mock_get.side_effect = requests.exceptions.ConnectionError("Test connection error")
        server_url = "http://unreachable.test:8000"
        result = config_utils.fetch_and_save_server_keys(server_url, self.temp_dir_path)
        self.assertFalse(result)
        mock_get.assert_called_once_with(f"{server_url}/keys", timeout=10)

    @patch('src.config_utils.requests.get')
    def test_10_fetch_keys_http_error(self, mock_get):
        """Test fetching keys with an HTTP error response (e.g., 404)."""
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Not Found")
        mock_get.return_value = mock_response
        server_url = "http://mockserver.test:8000"
        result = config_utils.fetch_and_save_server_keys(server_url, self.temp_dir_path)
        self.assertFalse(result)
        mock_get.assert_called_once_with(f"{server_url}/keys", timeout=10)
        mock_response.raise_for_status.assert_called_once()

    @patch('src.config_utils.requests.get')
    def test_11_fetch_keys_bad_json(self, mock_get):
        """Test fetching keys with invalid JSON in the response."""
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Bad JSON", "", 0)
        mock_get.return_value = mock_response
        server_url = "http://mockserver.test:8000"
        result = config_utils.fetch_and_save_server_keys(server_url, self.temp_dir_path)
        self.assertFalse(result)
        mock_get.assert_called_once_with(f"{server_url}/keys", timeout=10)
        mock_response.raise_for_status.assert_called_once()
        mock_response.json.assert_called_once()

    @patch('src.config_utils.requests.get')
    def test_12_fetch_keys_missing_data(self, mock_get):
        """Test fetching keys with missing key data in the JSON response."""
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'server_kem_public_key_b64': 'abc='}
        mock_get.return_value = mock_response
        server_url = "http://mockserver.test:8000"
        result = config_utils.fetch_and_save_server_keys(server_url, self.temp_dir_path)
        self.assertFalse(result)

    @patch('src.config_utils.requests.get')
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    def test_13_fetch_keys_save_error(self, mock_open, mock_get):
        """Test fetching keys with an error during file saving."""
        mock_response = unittest.mock.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'server_kem_public_key_b64': base64.b64encode(self.dummy_kem_pk).decode('utf-8'),
            'server_sign_public_key_b64': base64.b64encode(self.dummy_sig_pk).decode('utf-8')
        }
        mock_get.return_value = mock_response
        
        mock_open.side_effect = IOError("Permission denied")

        server_url = "http://mockserver.test:8000"
        result = config_utils.fetch_and_save_server_keys(server_url, self.temp_dir_path)

        self.assertFalse(result)
        mock_get.assert_called_once()
        
        self.assertTrue(mock_open.called)

if __name__ == '__main__':
    unittest.main() 