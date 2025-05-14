import os
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import logging
import yaml
import requests
import json
import base64
from urllib.parse import urljoin

CONFIG_FILE_PATH = Path("config.yaml")
_config_cache: Optional[Dict[str, Any]] = None


DEFAULT_KEY_DIR_STR = "~/.qu3/keys"
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"

log = logging.getLogger(__name__)

def load_config() -> Dict[str, Any]:
    """Loads configuration from config.yaml, caches, and returns it."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    config: Dict[str, Any] = {}
    if CONFIG_FILE_PATH.exists():
        try:
            with open(CONFIG_FILE_PATH, 'r') as f:
                loaded_yaml = yaml.safe_load(f)
                if isinstance(loaded_yaml, dict):
                    config = loaded_yaml
                    log.info(f"Loaded configuration from {CONFIG_FILE_PATH}")
                else:
                    log.warning(f"Configuration file {CONFIG_FILE_PATH} does not contain a valid YAML dictionary.")
        except yaml.YAMLError as e:
            log.error(f"Error parsing configuration file {CONFIG_FILE_PATH}: {e}")
        except Exception as e:
            log.error(f"Error reading configuration file {CONFIG_FILE_PATH}: {e}")
    else:
        log.info(f"Configuration file {CONFIG_FILE_PATH} not found. Using default values.")

    _config_cache = config
    return _config_cache

def get_config_value(key: str, default: Any = None) -> Any:
    """Retrieves a value from the loaded configuration, falling back to a default."""
    config = load_config()
    return config.get(key, default)

def get_key_dir() -> Path:
    """Returns the configured directory path for storing PQC keys."""
    key_dir_str = get_config_value('key_directory', DEFAULT_KEY_DIR_STR)
    return Path(key_dir_str).expanduser().resolve()

def ensure_key_dir_exists(key_dir_path: Optional[Path] = None) -> Path:
    """Ensures the key directory exists, creating it if necessary.

    Args:
        key_dir_path: Optional specific path to ensure. If None, uses configured key_dir.

    Returns:
        The path to the key directory.
    """
    target_path = key_dir_path if key_dir_path is not None else get_key_dir()
    
    try:
        target_path.mkdir(parents=True, exist_ok=True)
        log.info(f"Ensured key directory exists: {target_path}")
    except OSError as e:
        log.error(f"Failed to create key directory {target_path}: {e}")
        raise
    return target_path

def get_server_url() -> str:
    """Returns the configured default MCP server URL."""
    return get_config_value('server_url', DEFAULT_SERVER_URL)


def save_key_pair_to_files(public_key: bytes, secret_key: bytes, pub_path: Path, sec_path: Path):
    """Saves a public/private key pair to the specified file paths."""
    try:
        pub_path.parent.mkdir(parents=True, exist_ok=True) 
        with open(pub_path, 'wb') as f_pub:
            f_pub.write(public_key)
        with open(sec_path, 'wb') as f_sec:
            f_sec.write(secret_key)
            
            os.chmod(sec_path, 0o600)
        log.info(f"Saved key pair: Public='{pub_path.name}', Secret='{sec_path.name}'")
    except OSError as e:
        log.exception(f"Failed to save key pair ('{pub_path.name}', '{sec_path.name}'): {e}")
        raise 

def load_key_pair_from_files(pub_path: Path, sec_path: Path) -> tuple[bytes, bytes]:
    """Loads a public/private key pair from the specified file paths."""
    try:
        with open(pub_path, 'rb') as f_pub:
            public_key = f_pub.read()
        with open(sec_path, 'rb') as f_sec:
            secret_key = f_sec.read()
        log.debug(f"Loaded key pair: Public='{pub_path.name}', Secret='{sec_path.name}'")
        return public_key, secret_key
    except FileNotFoundError:
        log.debug(f"Key pair files not found: '{pub_path.name}', '{sec_path.name}'")
        raise 
    except OSError as e:
        log.exception(f"Failed to load key pair ('{pub_path.name}', '{sec_path.name}'): {e}")
        raise 

def load_public_key_from_file(pub_path: Path) -> bytes:
    """Loads a public key from the specified file path."""
    try:
        with open(pub_path, 'rb') as f_pub:
            public_key = f_pub.read()
        log.debug(f"Loaded public key from '{pub_path.name}'")
        return public_key
    except FileNotFoundError:
        log.debug(f"Public key file not found: '{pub_path.name}'")
        raise 
    except OSError as e:
        log.exception(f"Failed to load public key from '{pub_path.name}': {e}")
        raise 

# Add function to fetch server keys
def fetch_and_save_server_keys(server_url: str, key_dir: Path, kem_pub_filename: str = "server_kem.pub", sign_pub_filename: str = "server_sign.pub") -> bool:
    """Fetches server public keys from the /keys endpoint and saves them.

    Args:
        server_url: The base URL of the MCP server.
        key_dir: The directory to save the keys into.
        kem_pub_filename: The filename for the server KEM public key.
        sign_pub_filename: The filename for the server signing public key.

    Returns:
        True if keys were fetched and saved successfully, False otherwise.
    """
    keys_endpoint = urljoin(server_url, "keys")
    log.info(f"Attempting to fetch server public keys from {keys_endpoint}...")
    try:
        response = requests.get(keys_endpoint, timeout=10)
        response.raise_for_status() # Raise HTTP errors
        keys_data = response.json()

        server_kem_pk_b64 = keys_data.get('server_kem_public_key_b64')
        server_sign_pk_b64 = keys_data.get('server_sign_public_key_b64')

        if not server_kem_pk_b64 or not server_sign_pk_b64:
            log.error("Server response from /keys is missing required key fields.")
            return False

        server_kem_pk = base64.b64decode(server_kem_pk_b64)
        server_sign_pk = base64.b64decode(server_sign_pk_b64)

        kem_path = key_dir / kem_pub_filename
        sign_path = key_dir / sign_pub_filename

        with open(kem_path, 'wb') as f:
            f.write(server_kem_pk)
        log.info(f"Saved server KEM public key to {kem_path}")

        with open(sign_path, 'wb') as f:
            f.write(server_sign_pk)
        log.info(f"Saved server signing public key to {sign_path}")

        return True

    except requests.exceptions.RequestException as e:
        log.error(f"Network error fetching server keys from {keys_endpoint}: {e}")
        return False
    except (json.JSONDecodeError, base64.binascii.Error, ValueError, TypeError) as e:
        log.error(f"Error decoding/parsing server keys response: {e}")
        return False
    except IOError as e:
        log.error(f"Error saving server keys to {key_dir}: {e}")
        return False
    except Exception as e:
        log.exception(f"Unexpected error fetching or saving server keys:")
        return False
