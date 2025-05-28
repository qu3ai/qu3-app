"""
Environment and configuration validation utilities for qu3-app.

This module provides enhanced environment detection, configuration validation,
and runtime environment setup for the quantum-safe MCP client.
"""

import os
import sys
import platform
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import logging
import subprocess
import importlib.util

log = logging.getLogger(__name__)

class EnvironmentError(Exception):
    """Raised when environment validation fails."""
    pass

class DependencyError(EnvironmentError):
    """Raised when required dependencies are missing or incompatible."""
    pass

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information for debugging and compatibility checks.
    
    Returns:
        Dictionary containing system information
    """
    return {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'python_implementation': platform.python_implementation(),
        'python_executable': sys.executable,
        'working_directory': str(Path.cwd()),
        'user': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
        'home': str(Path.home()),
        'path_separator': os.pathsep,
        'environment_variables': {
            key: value for key, value in os.environ.items() 
            if key.startswith(('QU3_', 'LIBOQS_', 'OQS_'))
        }
    }

def check_python_version(min_version: Tuple[int, int] = (3, 8)) -> bool:
    """Check if Python version meets minimum requirements.
    
    Args:
        min_version: Minimum required Python version as (major, minor)
        
    Returns:
        True if version is sufficient
        
    Raises:
        DependencyError: If Python version is too old
    """
    current_version = sys.version_info[:2]
    if current_version < min_version:
        raise DependencyError(
            f"Python {min_version[0]}.{min_version[1]}+ required, "
            f"but running {current_version[0]}.{current_version[1]}"
        )
    
    log.debug(f"Python version check passed: {current_version} >= {min_version}")
    return True

def check_required_packages() -> Dict[str, Any]:
    """Check availability and versions of required packages.
    
    Returns:
        Dictionary with package information and status
        
    Raises:
        DependencyError: If critical packages are missing
    """
    required_packages = {
        'oqs': {'critical': True, 'min_version': None},
        'cryptography': {'critical': True, 'min_version': '3.0'},
        'requests': {'critical': True, 'min_version': '2.20'},
        'yaml': {'critical': True, 'min_version': None, 'import_name': 'yaml'},
        'typer': {'critical': True, 'min_version': '0.7'},
        'fastapi': {'critical': False, 'min_version': '0.68'},
        'uvicorn': {'critical': False, 'min_version': '0.15'},
    }
    
    package_status = {}
    missing_critical = []
    
    for package_name, info in required_packages.items():
        import_name = info.get('import_name', package_name)
        try:
            spec = importlib.util.find_spec(import_name)
            if spec is None:
                package_status[package_name] = {
                    'available': False,
                    'version': None,
                    'critical': info['critical']
                }
                if info['critical']:
                    missing_critical.append(package_name)
            else:
                # Try to get version
                try:
                    module = importlib.import_module(import_name)
                    version = getattr(module, '__version__', 'unknown')
                except Exception:
                    version = 'unknown'
                
                package_status[package_name] = {
                    'available': True,
                    'version': version,
                    'critical': info['critical']
                }
                
        except Exception as e:
            log.warning(f"Error checking package {package_name}: {e}")
            package_status[package_name] = {
                'available': False,
                'version': None,
                'critical': info['critical'],
                'error': str(e)
            }
            if info['critical']:
                missing_critical.append(package_name)
    
    if missing_critical:
        raise DependencyError(
            f"Critical packages missing: {', '.join(missing_critical)}. "
            f"Run 'pip install -r requirements.txt' to install dependencies."
        )
    
    return package_status

def check_liboqs_installation() -> Dict[str, Any]:
    """Check liboqs installation and available algorithms.
    
    Returns:
        Dictionary with liboqs status and available algorithms
    """
    try:
        import oqs
        
        # Get available algorithms
        kem_algorithms = oqs.get_enabled_kem_mechanisms()
        sig_algorithms = oqs.get_enabled_sig_mechanisms()
        
        # Check for required algorithms
        required_kem = "Kyber768"
        required_sig = "SPHINCS+-SHA2-128f-simple"
        
        status = {
            'available': True,
            'version': getattr(oqs, '__version__', 'unknown'),
            'kem_algorithms': kem_algorithms,
            'sig_algorithms': sig_algorithms,
            'required_kem_available': required_kem in kem_algorithms,
            'required_sig_available': required_sig in sig_algorithms,
        }
        
        if not status['required_kem_available']:
            log.warning(f"Required KEM algorithm {required_kem} not available")
        if not status['required_sig_available']:
            log.warning(f"Required signature algorithm {required_sig} not available")
            
        return status
        
    except ImportError as e:
        log.error(f"liboqs not available: {e}")
        return {
            'available': False,
            'error': str(e),
            'suggestion': 'Install liboqs-python: pip install liboqs-python'
        }
    except Exception as e:
        log.error(f"Error checking liboqs: {e}")
        return {
            'available': False,
            'error': str(e)
        }

def validate_file_permissions(file_path: Path, expected_mode: int) -> bool:
    """Validate file permissions for security.
    
    Args:
        file_path: Path to file to check
        expected_mode: Expected permission mode (e.g., 0o600)
        
    Returns:
        True if permissions are correct
    """
    try:
        if not file_path.exists():
            return False
            
        actual_mode = file_path.stat().st_mode & 0o777
        if actual_mode != expected_mode:
            log.warning(
                f"File {file_path} has permissions {oct(actual_mode)}, "
                f"expected {oct(expected_mode)}"
            )
            return False
        return True
    except Exception as e:
        log.error(f"Error checking permissions for {file_path}: {e}")
        return False

def setup_secure_environment() -> None:
    """Set up secure environment variables and settings."""
    # Disable Python bytecode generation for security
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    
    # Set secure umask for file creation
    try:
        os.umask(0o077)  # Only owner can read/write new files
        log.debug("Set secure umask (077)")
    except Exception as e:
        log.warning(f"Failed to set secure umask: {e}")
    
    # Clear potentially sensitive environment variables
    sensitive_vars = ['HISTFILE', 'LESSHISTFILE']
    for var in sensitive_vars:
        if var in os.environ:
            del os.environ[var]
            log.debug(f"Cleared sensitive environment variable: {var}")

def get_runtime_diagnostics() -> Dict[str, Any]:
    """Get comprehensive runtime diagnostics for troubleshooting.
    
    Returns:
        Dictionary with diagnostic information
    """
    diagnostics = {
        'timestamp': str(Path.cwd()),
        'system_info': get_system_info(),
    }
    
    try:
        diagnostics['python_version_check'] = check_python_version()
    except Exception as e:
        diagnostics['python_version_check'] = {'error': str(e)}
    
    try:
        diagnostics['package_status'] = check_required_packages()
    except Exception as e:
        diagnostics['package_status'] = {'error': str(e)}
    
    try:
        diagnostics['liboqs_status'] = check_liboqs_installation()
    except Exception as e:
        diagnostics['liboqs_status'] = {'error': str(e)}
    
    return diagnostics

def validate_environment() -> bool:
    """Perform comprehensive environment validation.
    
    Returns:
        True if environment is valid for running qu3-app
        
    Raises:
        EnvironmentError: If environment validation fails
    """
    log.info("Validating runtime environment...")
    
    try:
        # Check Python version
        check_python_version()
        
        # Check required packages
        package_status = check_required_packages()
        log.debug(f"Package status: {package_status}")
        
        # Check liboqs specifically
        liboqs_status = check_liboqs_installation()
        if not liboqs_status.get('available', False):
            raise EnvironmentError(
                f"liboqs not available: {liboqs_status.get('error', 'unknown error')}"
            )
        
        if not liboqs_status.get('required_kem_available', False):
            raise EnvironmentError("Required KEM algorithm not available in liboqs")
        
        if not liboqs_status.get('required_sig_available', False):
            raise EnvironmentError("Required signature algorithm not available in liboqs")
        
        # Set up secure environment
        setup_secure_environment()
        
        log.info("Environment validation passed")
        return True
        
    except (DependencyError, EnvironmentError):
        raise
    except Exception as e:
        raise EnvironmentError(f"Environment validation failed: {e}")

def get_config_recommendations() -> List[str]:
    """Get configuration recommendations based on current environment.
    
    Returns:
        List of configuration recommendations
    """
    recommendations = []
    
    # Check if running in development vs production
    if os.getenv('QU3_ENV') != 'production':
        recommendations.append("Set QU3_ENV=production for production deployments")
    
    # Check key directory security
    try:
        from .config_utils import get_key_dir
        key_dir = get_key_dir()
        if key_dir.exists():
            stat_info = key_dir.stat()
            if stat_info.st_mode & 0o077:
                recommendations.append(
                    f"Key directory {key_dir} has overly permissive permissions. "
                    "Run: chmod 700 ~/.qu3/keys"
                )
    except Exception:
        pass
    
    # Check for HTTPS usage
    try:
        from .config_utils import get_server_url
        server_url = get_server_url()
        if server_url.startswith('http://') and 'localhost' not in server_url and '127.0.0.1' not in server_url:
            recommendations.append(
                "Consider using HTTPS for server communication in production"
            )
    except Exception:
        pass
    
    return recommendations

if __name__ == "__main__":
    # CLI for environment diagnostics
    import json
    
    try:
        validate_environment()
        print("✅ Environment validation passed")
        
        diagnostics = get_runtime_diagnostics()
        print("\n📊 Runtime Diagnostics:")
        print(json.dumps(diagnostics, indent=2, default=str))
        
        recommendations = get_config_recommendations()
        if recommendations:
            print("\n💡 Recommendations:")
            for rec in recommendations:
                print(f"  • {rec}")
        
    except Exception as e:
        print(f"❌ Environment validation failed: {e}")
        sys.exit(1)

