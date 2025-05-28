import os
import stat
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import logging
import yaml
import requests
import json
import base64
from urllib.parse import urljoin
import time

CONFIG_FILE_PATH = Path("config.yaml")
_config_cache: Optional[Dict[str, Any]] = None

DEFAULT_KEY_DIR_STR = "~/.qu3/keys"
DEFAULT_SERVER_URL = "http://127.0.0.1:8000"

# Security and reliability constants
MAX_CONFIG_FILE_SIZE = 1024 * 1024  # 1MB max config file size
REQUEST_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 1.0  # seconds

log = logging.getLogger(__name__)

def _validate_config_security(config_path: Path) -> bool:
    """Validate configuration file security permissions and size."""
    try:
        stat_info = config_path.stat()
        
        # Check file size
        if stat_info.st_size > MAX_CONFIG_FILE_SIZE:
            log.warning(f"Configuration file {config_path} is unusually large ({stat_info.st_size} bytes)")
            return False
        
        # Check permissions (should not be world-writable)
        if stat_info.st_mode & stat.S_IWOTH:
            log.warning(f"Configuration file {config_path} is world-writable (security risk)")
            return False
            
        return True
    except OSError as e:
        log.error(f"Failed to check security of config file {config_path}: {e}")
        return False

def load_config() -> Dict[str, Any]:
    """Loads configuration from config.yaml, caches, and returns it.
    
    Returns:
        Dictionary containing configuration values
        
    Raises:
        ValueError: If configuration is invalid
        OSError: If file operations fail
    """
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    config: Dict[str, Any] = {}
    if CONFIG_FILE_PATH.exists():
        # Validate security before loading
        if not _validate_config_security(CONFIG_FILE_PATH):
            log.warning(f"Security validation failed for {CONFIG_FILE_PATH}, using defaults")
            _config_cache = {}
            return _config_cache
            
        try:
            with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
                loaded_yaml = yaml.safe_load(f)
                if isinstance(loaded_yaml, dict):
                    config = loaded_yaml
                    log.info(f"Loaded configuration from {CONFIG_FILE_PATH}")
                else:
                    log.warning(f"Configuration file {CONFIG_FILE_PATH} does not contain a valid YAML dictionary.")
        except yaml.YAMLError as e:
            log.error(f"Error parsing configuration file {CONFIG_FILE_PATH}: {e}")
            raise ValueError(f"Invalid YAML in configuration file: {e}")
        except UnicodeDecodeError as e:
            log.error(f"Encoding error reading configuration file {CONFIG_FILE_PATH}: {e}")
            raise ValueError(f"Configuration file encoding error: {e}")
        except Exception as e:
            log.error(f"Error reading configuration file {CONFIG_FILE_PATH}: {e}")
            raise OSError(f"Failed to read configuration file: {e}")
    else:
        log.info(f"Configuration file {CONFIG_FILE_PATH} not found. Using default values.")

    # Validate configuration structure
    if config and not isinstance(config, dict):
        raise ValueError("Configuration must be a dictionary")

    _config_cache = config if config else {}
    return _config_cache

def get_config_value(key: str, default: Any = None) -> Any:
    """Retrieves a value from the loaded configuration, falling back to a default.
    
    Args:
        key: Configuration key to retrieve
        default: Default value if key is not found
        
    Returns:
        Configuration value or default
    """
    if not isinstance(key, str) or not key.strip():
        log.warning("Configuration key must be a non-empty string")
        return default
        
    config = load_config()
    return config.get(key, default)

def get_key_dir() -> Path:
    """Returns the configured directory path for storing PQC keys.
    
    Returns:
        Path object for the key directory
        
    Raises:
        ValueError: If key directory path is invalid
    """
    key_dir_str = get_config_value('key_directory', DEFAULT_KEY_DIR_STR)
    
    if not isinstance(key_dir_str, str) or not key_dir_str.strip():
        log.warning("Invalid key_directory in config, using default")
        key_dir_str = DEFAULT_KEY_DIR_STR
    
    try:
        key_dir = Path(key_dir_str).expanduser().resolve()
        
        # Security check: ensure key directory is not in a world-writable location
        if key_dir.exists():
            stat_info = key_dir.stat()
            if stat_info.st_mode & stat.S_IWOTH:
                log.warning(f"Key directory {key_dir} is world-writable (security risk)")
        
        return key_dir
    except Exception as e:
        log.error(f"Failed to resolve key directory path '{key_dir_str}': {e}")
        raise ValueError(f"Invalid key directory path: {e}")

def ensure_key_dir_exists(key_dir_path: Optional[Path] = None) -> Path:
    """Ensures the key directory exists, creating it if necessary.

    Args:
        key_dir_path: Optional specific path to ensure. If None, uses configured key_dir.

    Returns:
        The path to the key directory.
        
    Raises:
        OSError: If directory creation fails
        PermissionError: If insufficient permissions
    """
    target_path = key_dir_path if key_dir_path is not None else get_key_dir()
    
    try:
        target_path.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions on the key directory (owner only)
        try:
            os.chmod(target_path, 0o700)
            log.debug(f"Set secure permissions (700) on key directory: {target_path}")
        except OSError as e:
            log.warning(f"Failed to set secure permissions on {target_path}: {e}")
        
        log.info(f"Ensured key directory exists: {target_path}")
    except PermissionError as e:
        log.error(f"Permission denied creating key directory {target_path}: {e}")
        raise
    except OSError as e:
        log.error(f"Failed to create key directory {target_path}: {e}")
        raise
    
    return target_path

def get_server_url() -> str:
    """Returns the configured default MCP server URL.
    
    Returns:
        Server URL string
    """
    url = get_config_value('server_url', DEFAULT_SERVER_URL)
    
    if not isinstance(url, str) or not url.strip():
        log.warning("Invalid server_url in config, using default")
        return DEFAULT_SERVER_URL
    
    # Basic URL validation
    if not (url.startswith('http://') or url.startswith('https://')):
        log.warning(f"Server URL '{url}' does not start with http:// or https://")
    
    return url.strip()

def save_key_pair_to_files(public_key: bytes, secret_key: bytes, pub_path: Path, sec_path: Path):
    """Saves a public/private key pair to the specified file paths with secure permissions.
    
    Args:
        public_key: Public key bytes
        secret_key: Secret key bytes  
        pub_path: Path for public key file
        sec_path: Path for secret key file
        
    Raises:
        ValueError: If inputs are invalid
        OSError: If file operations fail
    """
    if not isinstance(public_key, bytes) or len(public_key) == 0:
        raise ValueError("Public key must be non-empty bytes")
    if not isinstance(secret_key, bytes) or len(secret_key) == 0:
        raise ValueError("Secret key must be non-empty bytes")
    if not isinstance(pub_path, Path) or not isinstance(sec_path, Path):
        raise ValueError("Paths must be Path objects")
    
    try:
        pub_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Save public key with readable permissions
        with open(pub_path, 'wb') as f_pub:
            f_pub.write(public_key)
        os.chmod(pub_path, 0o644)
        
        # Save secret key with restricted permissions
        with open(sec_path, 'wb') as f_sec:
            f_sec.write(secret_key)
        os.chmod(sec_path, 0o600)
        
        log.info(f"Saved key pair: Public='{pub_path.name}', Secret='{sec_path.name}' with secure permissions.")
    except OSError as e:
        log.exception(f"Failed to save key pair ('{pub_path.name}', '{sec_path.name}'): {e}")
        raise 

def load_key_pair_from_files(pub_path: Path, sec_path: Path) -> Tuple[bytes, bytes]:
    """Loads a public/private key pair from the specified file paths.
    
    Args:
        pub_path: Path to public key file
        sec_path: Path to secret key file
        
    Returns:
        Tuple of (public_key_bytes, secret_key_bytes)
        
    Raises:
        FileNotFoundError: If key files don't exist
        ValueError: If key files are invalid
        OSError: If file operations fail
    """
    if not isinstance(pub_path, Path) or not isinstance(sec_path, Path):
        raise ValueError("Paths must be Path objects")
    
    try:
        # Check file permissions for security
        if sec_path.exists():
            stat_info = sec_path.stat()
            if stat_info.st_mode & (stat.S_IRGRP | stat.S_IROTH):
                log.warning(f"Secret key file {sec_path} has overly permissive read permissions")
        
        with open(pub_path, 'rb') as f_pub:
            public_key = f_pub.read()
        with open(sec_path, 'rb') as f_sec:
            secret_key = f_sec.read()
            
        if len(public_key) == 0:
            raise ValueError(f"Public key file {pub_path} is empty")
        if len(secret_key) == 0:
            raise ValueError(f"Secret key file {sec_path} is empty")
            
        log.debug(f"Loaded key pair: Public='{pub_path.name}', Secret='{sec_path.name}'")
        return public_key, secret_key
    except FileNotFoundError:
        log.debug(f"Key pair files not found: '{pub_path.name}', '{sec_path.name}'")
        raise 
    except OSError as e:
        log.exception(f"Failed to load key pair ('{pub_path.name}', '{sec_path.name}'): {e}")
        raise 

def load_public_key_from_file(pub_path: Path) -> bytes:
    """Loads a public key from the specified file path.
    
    Args:
        pub_path: Path to public key file
        
    Returns:
        Public key bytes
        
    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key file is invalid
        OSError: If file operations fail
    """
    if not isinstance(pub_path, Path):
        raise ValueError("Path must be a Path object")
    
    try:
        with open(pub_path, 'rb') as f_pub:
            public_key = f_pub.read()
            
        if len(public_key) == 0:
            raise ValueError(f"Public key file {pub_path} is empty")
            
        log.debug(f"Loaded public key from '{pub_path.name}'")
        return public_key
    except FileNotFoundError:
        log.debug(f"Public key file not found: '{pub_path.name}'")
        raise 
    except OSError as e:
        log.exception(f"Failed to load public key from '{pub_path.name}': {e}")
        raise 

def fetch_and_save_server_keys(
    server_url: str, 
    key_dir: Path, 
    kem_pub_filename: str = "server_kem.pub", 
    sign_pub_filename: str = "server_sign.pub"
) -> bool:
    """Fetches server public keys from the /keys endpoint and saves them with retry logic.

    Args:
        server_url: The base URL of the MCP server.
        key_dir: The directory to save the keys into.
        kem_pub_filename: The filename for the server KEM public key.
        sign_pub_filename: The filename for the server signing public key.

    Returns:
        True if keys were fetched and saved successfully, False otherwise.
    """
    if not isinstance(server_url, str) or not server_url.strip():
        log.error("Server URL must be a non-empty string")
        return False
    if not isinstance(key_dir, Path):
        log.error("Key directory must be a Path object")
        return False
    
    keys_endpoint = urljoin(server_url.rstrip('/') + '/', "keys")
    log.info(f"Attempting to fetch server public keys from {keys_endpoint}...")
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(
                keys_endpoint, 
                timeout=REQUEST_TIMEOUT,
                headers={'User-Agent': 'qu3-client/1.0'}
            )
            response.raise_for_status()
            
            # Validate response content type
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type:
                log.warning(f"Unexpected content type from server: {content_type}")
            
            keys_data = response.json()

            server_kem_pk_b64 = keys_data.get('server_kem_public_key_b64')
            server_sign_pk_b64 = keys_data.get('server_sign_public_key_b64')

            if not server_kem_pk_b64 or not server_sign_pk_b64:
                log.error("Server response from /keys is missing required key fields.")
                return False

            # Validate base64 encoding
            try:
                server_kem_pk = base64.b64decode(server_kem_pk_b64)
                server_sign_pk = base64.b64decode(server_sign_pk_b64)
            except Exception as e:
                log.error(f"Failed to decode base64 keys from server: {e}")
                return False
            
            # Validate key sizes (basic sanity check)
            if len(server_kem_pk) < 32 or len(server_sign_pk) < 32:
                log.error("Server keys appear to be too small (possible corruption)")
                return False

            kem_path = key_dir / kem_pub_filename
            sign_path = key_dir / sign_pub_filename

            # Ensure directory exists
            key_dir.mkdir(parents=True, exist_ok=True)

            # Save keys with secure permissions
            with open(kem_path, 'wb') as f:
                f.write(server_kem_pk)
            os.chmod(kem_path, 0o644)
            log.info(f"Saved server KEM public key to {kem_path} with permissions set.")

            with open(sign_path, 'wb') as f:
                f.write(server_sign_pk)
            os.chmod(sign_path, 0o644)
            log.info(f"Saved server signing public key to {sign_path} with permissions set.")

            return True

        except requests.exceptions.Timeout as e:
            log.warning(f"Timeout fetching server keys (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
        except requests.exceptions.ConnectionError as e:
            log.warning(f"Connection error fetching server keys (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
        except requests.exceptions.HTTPError as e:
            log.error(f"HTTP error fetching server keys: {e}")
            return False  # Don't retry on HTTP errors
        except requests.exceptions.RequestException as e:
            log.warning(f"Network error fetching server keys (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            log.error(f"Error decoding/parsing server keys response: {e}")
            return False  # Don't retry on parsing errors
        except IOError as e:
            log.error(f"Error saving server keys to {key_dir}: {e}")
            return False  # Don't retry on I/O errors
        except Exception as e:
            log.exception(f"Unexpected error fetching or saving server keys:")
            return False
        
        if attempt < MAX_RETRIES - 1:
            log.info(f"Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)
    
    log.error(f"Failed to fetch server keys after {MAX_RETRIES} attempts")
    return False

def get_logging_config() -> Dict[str, Any]:
    """
    Retrieves logging configuration (level and file) from the global config.
    Defaults to INFO level and no file if not specified or invalid.
    
    Returns:
        Dictionary with 'level' and 'file' keys
    """
    config = load_config()
    logging_config = config.get('logging', {})

    if not isinstance(logging_config, dict):
        log.warning("Logging configuration is not a dictionary. Using default logging settings.")
        logging_config = {}

    level_str = logging_config.get('level', "INFO")
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    
    if not isinstance(level_str, str) or level_str.upper() not in valid_levels:
        log.warning(f"Invalid logging level '{level_str}'. Defaulting to INFO.")
        level_str = "INFO"
    else:
        level_str = level_str.upper()

    log_file = logging_config.get('file')
    if log_file is not None:
        if not isinstance(log_file, str) or not log_file.strip():
            log.warning(f"Invalid logging file path '{log_file}'. Defaulting to no file.")
            log_file = None
        else:
            # Validate log file path
            try:
                log_path = Path(log_file).expanduser()
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_file = str(log_path)
            except Exception as e:
                log.warning(f"Invalid log file path '{log_file}': {e}. Defaulting to no file.")
                log_file = None
    
    return {'level': level_str, 'file': log_file}
