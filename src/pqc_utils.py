from typing import Dict, Tuple, Any, Optional
import os
import oqs
import logging
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

class PQCError(Exception):
    """Base class for PQC related errors."""
    pass

class PQCKeyGenerationError(PQCError):
    """Error during PQC key generation."""
    pass

class PQCSignatureError(PQCError):
    """Error related to PQC signing or verification."""
    pass

class PQCKEMError(PQCError):
    """Error related to PQC KEM operations."""
    pass

class PQCEncryptionError(PQCError):
    """Error during AES encryption."""
    pass

class PQCDecryptionError(PQCError):
    """Error during AES decryption (e.g., InvalidTag)."""
    pass

class PQCRetryableError(PQCError):
    """Error that can be retried."""
    pass

ALGORITHMS = {
    "kem": "Kyber768",
    "sig": "SPHINCS+-SHA2-128f-simple"
}

AES_NONCE_BYTES = 12 
AES_KEY_BYTES = 32 

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 0.1  # seconds

log = logging.getLogger(__name__)

def _validate_algorithm_support():
    """Validate that required algorithms are supported by the current liboqs build."""
    for algo_type, algo_name in ALGORITHMS.items():
        if algo_type == "kem" and not oqs.is_kem_enabled(algo_name):
            raise ImportError(f"Required KEM algorithm '{algo_name}' is not enabled in this liboqs build.")
        elif algo_type == "sig" and not oqs.is_sig_enabled(algo_name):
            raise ImportError(f"Required Signature algorithm '{algo_name}' is not enabled in this liboqs build.")
        log.debug(f"PQC Algorithm Confirmed: {algo_type} = {algo_name}")

_validate_algorithm_support()

def _retry_on_failure(func, max_retries: int = MAX_RETRIES, delay: float = RETRY_DELAY):
    """Retry decorator for PQC operations that may fail transiently."""
    def wrapper(*args, **kwargs):
        last_exception = None
        for attempt in range(max_retries + 1):
            try:
                return func(*args, **kwargs)
            except (oqs.MechanismNotSupportedError, oqs.MechanismNotEnabledError) as e:
                # These are not retryable
                raise PQCError(f"PQC mechanism not supported: {e}")
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    log.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
                    delay *= 1.5
                else:
                    log.error(f"All {max_retries + 1} attempts failed for {func.__name__}")
        
        raise PQCRetryableError(f"Operation failed after {max_retries + 1} attempts: {last_exception}")
    return wrapper

def generate_key_pair(algo_name: str) -> Tuple[bytes, bytes]:
    """Generates a public and private key pair for the specified PQC algorithm.
    
    Args:
        algo_name: The name of the PQC algorithm (must be supported by liboqs)
        
    Returns:
        Tuple of (public_key_bytes, secret_key_bytes)
        
    Raises:
        PQCKeyGenerationError: If key generation fails
        ValueError: If algorithm is not supported
    """
    if not isinstance(algo_name, str) or not algo_name.strip():
        raise ValueError("Algorithm name must be a non-empty string")
    
    @_retry_on_failure
    def _generate():
        if oqs.is_kem_enabled(algo_name):
            with oqs.KeyEncapsulation(algo_name) as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
                log.info(f"Generated {algo_name} KEM key pair.")
                return public_key, secret_key
        elif oqs.is_sig_enabled(algo_name):
            with oqs.Signature(algo_name) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()
                log.info(f"Generated {algo_name} Signature key pair.")
                return public_key, secret_key
        else:
            raise ValueError(f"Unsupported or unknown PQC algorithm: {algo_name}")
    
    try:
        return _generate()
    except (PQCError, ValueError):
        raise
    except Exception as e:
        raise PQCKeyGenerationError(f"Unexpected error during {algo_name} key generation: {e}")

def sign_message(message: bytes, secret_key: bytes, sig_algo: str) -> bytes:
    """Signs a message using the provided private key and signature algorithm.
    
    Args:
        message: The message bytes to sign
        secret_key: The private key bytes for signing
        sig_algo: The signature algorithm name
        
    Returns:
        The signature bytes
        
    Raises:
        PQCSignatureError: If signing fails
        ValueError: If inputs are invalid
    """
    if not isinstance(message, bytes):
        raise ValueError("Message must be bytes")
    if not isinstance(secret_key, bytes) or len(secret_key) == 0:
        raise ValueError("Secret key must be non-empty bytes")
    if not isinstance(sig_algo, str) or not sig_algo.strip():
        raise ValueError("Signature algorithm must be a non-empty string")
    
    if not oqs.is_sig_enabled(sig_algo):
        raise PQCSignatureError(f"Signature algorithm '{sig_algo}' is not enabled or supported.")
    
    @_retry_on_failure
    def _sign():
        with oqs.Signature(sig_algo, secret_key) as sig:
            signature = sig.sign(message)
            log.debug(f"Message signed using {sig_algo}.")
            return signature
    
    try:
        return _sign()
    except PQCError:
        raise
    except Exception as e:
        raise PQCSignatureError(f"Unexpected error during message signing with {sig_algo}: {e}")

def verify_signature(message: bytes, signature: bytes, public_key: bytes, sig_algo: str) -> bool:
    """Verifies a signature against a message using the public key and signature algorithm.
    
    Args:
        message: The original message bytes
        signature: The signature bytes to verify
        public_key: The public key bytes for verification
        sig_algo: The signature algorithm name
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not isinstance(message, bytes):
        log.warning("Message must be bytes for signature verification")
        return False
    if not isinstance(signature, bytes) or len(signature) == 0:
        log.warning("Signature must be non-empty bytes for verification")
        return False
    if not isinstance(public_key, bytes) or len(public_key) == 0:
        log.warning("Public key must be non-empty bytes for verification")
        return False
    if not isinstance(sig_algo, str) or not sig_algo.strip():
        log.warning("Signature algorithm must be a non-empty string")
        return False
    
    if not oqs.is_sig_enabled(sig_algo):
        log.warning(f"Attempt to verify with unsupported/disabled sig algo: {sig_algo}")
        return False 
    
    try:
        with oqs.Signature(sig_algo) as sig:
            is_valid = sig.verify(message, signature, public_key)
            log.debug(f"Signature verification result using {sig_algo}: {is_valid}")
            return is_valid
    except (oqs.MechanismNotSupportedError, oqs.MechanismNotEnabledError) as e:
        log.warning(f"Signature verification failed for {sig_algo} (OQS Error): {e}")
        return False
    except Exception as e:
        log.warning(f"Unexpected error during signature verification for {sig_algo}: {e}")
        return False

def kem_encapsulate(kem_algo: str, public_key: bytes) -> Tuple[bytes, bytes]:
    """Performs KEM encapsulation using the recipient's public key.

    Args:
        kem_algo: The KEM algorithm name
        public_key: The recipient's public key bytes

    Returns:
        Tuple of (ciphertext_bytes, shared_secret_bytes)
        
    Raises:
        PQCKEMError: If KEM operation fails
        ValueError: If inputs are invalid
    """
    if not isinstance(kem_algo, str) or not kem_algo.strip():
        raise ValueError("KEM algorithm must be a non-empty string")
    if not isinstance(public_key, bytes) or len(public_key) == 0:
        raise ValueError("Public key must be non-empty bytes")
    
    if not oqs.is_kem_enabled(kem_algo):
        raise PQCKEMError(f"KEM algorithm '{kem_algo}' is not enabled or supported by current build flags.")
    
    @_retry_on_failure
    def _encapsulate():
        with oqs.KeyEncapsulation(kem_algo) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            log.debug(f"Performed KEM encapsulation using {kem_algo}.")
            return ciphertext, shared_secret
    
    try:
        return _encapsulate()
    except PQCError:
        raise
    except Exception as e:
        raise PQCKEMError(f"Unexpected error during KEM encapsulation with {kem_algo}: {e}")

def kem_decapsulate(kem_algo: str, ciphertext: bytes, secret_key: bytes) -> bytes:
    """Performs KEM decapsulation using the recipient's private key.

    Args:
        kem_algo: The KEM algorithm name
        ciphertext: The KEM ciphertext bytes
        secret_key: The recipient's private key bytes

    Returns:
        The derived shared secret bytes
        
    Raises:
        PQCKEMError: If KEM operation fails
        ValueError: If inputs are invalid
    """
    if not isinstance(kem_algo, str) or not kem_algo.strip():
        raise ValueError("KEM algorithm must be a non-empty string")
    if not isinstance(ciphertext, bytes) or len(ciphertext) == 0:
        raise ValueError("Ciphertext must be non-empty bytes")
    if not isinstance(secret_key, bytes) or len(secret_key) == 0:
        raise ValueError("Secret key must be non-empty bytes")
    
    if not oqs.is_kem_enabled(kem_algo):
        raise PQCKEMError(f"KEM algorithm '{kem_algo}' is not enabled or supported by current build flags.")
    
    @_retry_on_failure
    def _decapsulate():
        with oqs.KeyEncapsulation(kem_algo, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            log.debug(f"Performed KEM decapsulation using {kem_algo}.")
            return shared_secret
    
    try:
        return _decapsulate()
    except PQCError:
        raise
    except Exception as e:
        raise PQCKEMError(f"Unexpected error during KEM decapsulation with {kem_algo}: {e}")

def derive_aes_key(kem_shared_secret: bytes) -> bytes:
    """Derives a fixed-size AES key from the KEM shared secret using HKDF.
    
    Args:
        kem_shared_secret: The shared secret bytes from KEM operation
        
    Returns:
        The derived AES key bytes
        
    Raises:
        ValueError: If shared secret is invalid
        PQCError: If key derivation fails
    """
    if not isinstance(kem_shared_secret, bytes) or len(kem_shared_secret) == 0:
        raise ValueError("KEM shared secret must be non-empty bytes")
    
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_BYTES,
            salt=None, 
            info=b'qu3-aes-gcm-key', 
        )
        derived_key = hkdf.derive(kem_shared_secret)
        log.debug(f"Derived AES-{AES_KEY_BYTES*8} key using HKDF.")
        return derived_key
    except Exception as e:
        raise PQCError(f"Failed to derive AES key from shared secret: {e}")

def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Encrypts plaintext using AES-GCM with the given key.

    Args:
        key: The AES key (must be exactly AES_KEY_BYTES bytes)
        plaintext: The data to encrypt

    Returns:
        Tuple of (nonce_bytes, ciphertext_bytes)
        
    Raises:
        PQCEncryptionError: If encryption fails
        ValueError: If inputs are invalid
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES key must be exactly {AES_KEY_BYTES} bytes, got {len(key) if isinstance(key, bytes) else 'non-bytes'}. Use derive_aes_key.")
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes")

    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(AES_NONCE_BYTES)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        log.debug(f"AES-GCM Encryption complete. Nonce: {nonce.hex()[:16]}..., Ciphertext length: {len(ciphertext)}")
        return nonce, ciphertext
    except Exception as e:
        log.error(f"AES-GCM Encryption failed: {e}")
        raise PQCEncryptionError(f"AES-GCM encryption failed: {e}")

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypts AES-GCM ciphertext using the given key and nonce.

    Args:
        key: The AES key (must be exactly AES_KEY_BYTES bytes)
        nonce: The nonce (IV) used during encryption
        ciphertext: The encrypted data

    Returns:
        The original plaintext bytes

    Raises:
        PQCDecryptionError: If decryption fails
        ValueError: If inputs are invalid
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES key must be exactly {AES_KEY_BYTES} bytes, got {len(key) if isinstance(key, bytes) else 'non-bytes'}. Use derive_aes_key.")
    if not isinstance(nonce, bytes) or len(nonce) != AES_NONCE_BYTES:
        raise ValueError(f"Invalid nonce: expected {AES_NONCE_BYTES} bytes, got {len(nonce) if isinstance(nonce, bytes) else 'non-bytes'}")
    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext must be bytes")

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        log.debug("AES-GCM Decryption successful.")
        return plaintext
    except InvalidTag as e:
        log.error(f"AES-GCM Decryption failed due to InvalidTag: {e}")
        raise PQCDecryptionError(f"AES-GCM decryption failed (InvalidTag): {e}")
    except Exception as e: 
        log.error(f"AES-GCM Decryption failed with an unexpected error: {e}")
        raise PQCDecryptionError(f"AES-GCM decryption failed unexpectedly: {e}")
