from typing import Dict, Tuple, Any, Optional
import os
import oqs
import logging
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

class POCKEMError(PQCError):
    """Error related to PQC KEM operations."""
    pass

class PQCEncryptionError(PQCError):
    """Error during AES encryption."""
    pass

class PQCDecryptionError(PQCError):
    """Error during AES decryption (e.g., InvalidTag)."""
    pass

ALGORITHMS = {
    "kem": "Kyber768",
    "sig": "SPHINCS+-SHA2-128f-simple"
}

AES_NONCE_BYTES = 12 
AES_KEY_BYTES = 32 

log = logging.getLogger(__name__)
for algo_type, algo_name in ALGORITHMS.items():
    if algo_type == "kem" and not oqs.is_kem_enabled(algo_name):
        raise ImportError(f"Required KEM algorithm '{algo_name}' is not enabled in this liboqs build.")
    elif algo_type == "sig" and not oqs.is_sig_enabled(algo_name):
        raise ImportError(f"Required Signature algorithm '{algo_name}' is not enabled in this liboqs build.")
    log.debug(f"PQC Algorithm Confirmed: {algo_type} = {algo_name}")

def generate_key_pair(algo_name: str) -> tuple[bytes, bytes]:
    """Generates a public and private key pair for the specified PQC algorithm."""
    try:
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
    except oqs.OpenSSLError as e:
        raise PQCKeyGenerationError(f"Failed to generate {algo_name} key pair: {e}")
    except Exception as e:
        raise PQCKeyGenerationError(f"An unexpected error occurred during {algo_name} key generation: {e}")

def sign_message(message: bytes, secret_key: bytes, sig_algo: str) -> bytes:
    """Signs a message using the provided private key and signature algorithm."""
    if not oqs.is_sig_enabled(sig_algo):
        raise PQCSignatureError(f"Signature algorithm '{sig_algo}' is not enabled or supported.")
    try:
        with oqs.Signature(sig_algo, secret_key) as sig:
            signature = sig.sign(message)
            log.debug(f"Message signed using {sig_algo}.")
            return signature
    except oqs.OpenSSLError as e:
        raise PQCSignatureError(f"Failed to sign message using {sig_algo}: {e}")
    except Exception as e:
        raise PQCSignatureError(f"An unexpected error occurred during message signing with {sig_algo}: {e}")

def verify_signature(message: bytes, signature: bytes, public_key: bytes, sig_algo: str) -> bool:
    """Verifies a signature against a message using the public key and signature algorithm."""
    if not oqs.is_sig_enabled(sig_algo):
        log.warning(f"Attempt to verify with unsupported/disabled sig algo: {sig_algo}")
        return False 
    try:
        with oqs.Signature(sig_algo) as sig:
            is_valid = sig.verify(message, signature, public_key)
            log.debug(f"Signature verification result using {sig_algo}: {is_valid}")
            if not is_valid:
                pass
            return is_valid
    except oqs.OpenSSLError as e:
        log.warning(f"Signature verification failed for {sig_algo} (OpenSSLError): {e}")
        return False
    except Exception as e:
        log.warning(f"Unexpected error during signature verification for {sig_algo}: {e}")
        return False

def kem_encapsulate(kem_algo: str, public_key: bytes) -> tuple[bytes, bytes]:
    """Performs KEM encapsulation using the recipient's public key.

    Returns:
        tuple[bytes, bytes]: The generated ciphertext and the shared secret.
    """
    if not oqs.is_kem_enabled(kem_algo):
        raise POCKEMError(f"KEM algorithm '{kem_algo}' is not enabled or supported.")
    try:
        with oqs.KeyEncapsulation(kem_algo) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            log.debug(f"Performed KEM encapsulation using {kem_algo}.")
            return ciphertext, shared_secret
    except oqs.OpenSSLError as e:
        raise POCKEMError(f"KEM encapsulation failed for {kem_algo}: {e}")
    except Exception as e:
        raise POCKEMError(f"An unexpected error occurred during KEM encapsulation with {kem_algo}: {e}")

def kem_decapsulate(kem_algo: str, ciphertext: bytes, secret_key: bytes) -> bytes:
    """Performs KEM decapsulation using the recipient's private key.

    Returns:
        bytes: The derived shared secret.
    """
    if not oqs.is_kem_enabled(kem_algo):
        raise POCKEMError(f"KEM algorithm '{kem_algo}' is not enabled or supported.")
    try:
        with oqs.KeyEncapsulation(kem_algo, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
            log.debug(f"Performed KEM decapsulation using {kem_algo}.")
            return shared_secret
    except oqs.OpenSSLError as e:
        raise POCKEMError(f"KEM decapsulation failed for {kem_algo}: {e}")
    except Exception as e:
        raise POCKEMError(f"An unexpected error occurred during KEM decapsulation with {kem_algo}: {e}")

def derive_aes_key(kem_shared_secret: bytes) -> bytes:
    """Derives a fixed-size AES key from the KEM shared secret using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=None, 
        info=b'qu3-aes-gcm-key', 
    )
    derived_key = hkdf.derive(kem_shared_secret)
    log.debug(f"Derived AES-{AES_KEY_BYTES*8} key using HKDF.")
    return derived_key

def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypts plaintext using AES-GCM with the given key.

    Args:
        key: The AES key (assumed to be {AES_KEY_BYTES} bytes, e.g., derived via HKDF).
        plaintext: The data to encrypt.

    Returns:
        tuple[bytes, bytes]: The nonce (IV) used and the resulting ciphertext.
                           The nonce must be stored/sent alongside the ciphertext.
    """
    if len(key) != AES_KEY_BYTES:
        raise PQCEncryptionError(f"AES key must be exactly {AES_KEY_BYTES} bytes, got {len(key)}. Use derive_aes_key.")

    aesgcm = AESGCM(key)
    nonce = os.urandom(AES_NONCE_BYTES)
    try:
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        log.debug(f"AES-GCM Encryption complete. Nonce: {nonce.hex()}, Ciphertext length: {len(ciphertext)}")
        return nonce, ciphertext
    except Exception as e:
        log.error(f"AES-GCM Encryption failed: {e}")
        raise PQCEncryptionError(f"AES-GCM encryption failed: {e}")

def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypts AES-GCM ciphertext using the given key and nonce.

    Args:
        key: The AES key (must be {AES_KEY_BYTES} bytes).
        nonce: The nonce (IV) used during encryption.
        ciphertext: The encrypted data.

    Returns:
        bytes: The original plaintext.

    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails (ciphertext tampered or wrong key/nonce).
        ValueError: If key or nonce has incorrect length.
    """
    if len(key) != AES_KEY_BYTES:
        raise PQCDecryptionError(f"AES key must be exactly {AES_KEY_BYTES} bytes, got {len(key)}. Use derive_aes_key.")

    if len(nonce) != AES_NONCE_BYTES:
        raise PQCDecryptionError(f"Invalid nonce length, expected {AES_NONCE_BYTES} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        log.debug("AES-GCM Decryption successful.")
        return plaintext
    except InvalidTag as e:
        log.error(f"AES-GCM Decryption failed due to InvalidTag: {e}")
        raise PQCDecryptionError(f"AES-GCM decryption failed (InvalidTag): {e}")
    except Exception as e: 
        log.error(f"AES-GCM Decryption failed with an unexpected error: {e}")
        raise PQCDecryptionError(f"AES-GCM decryption failed unexpectedly: {e}") 
