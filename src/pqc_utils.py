from typing import Dict, Tuple, Any, Optional
import os
import oqs
import sys
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHMS = {
    "kem": "Kyber-768",
    "sig": "SPHINCS+-SHA256-128f-simple"
}

AES_NONCE_BYTES = 12 
AES_KEY_BYTES = 32 

log = logging.getLogger(__name__)
for algo_type, algo_name in ALGORITHMS.items():
    if algo_type == "kem" and not oqs.Mechanism.is_kem_enabled(algo_name):
        raise ImportError(f"Required KEM algorithm '{algo_name}' is not enabled in this liboqs build.")
    elif algo_type == "sig" and not oqs.Mechanism.is_sig_enabled(algo_name):
        raise ImportError(f"Required Signature algorithm '{algo_name}' is not enabled in this liboqs build.")
    log.debug(f"PQC Algorithm Confirmed: {algo_type} = {algo_name}")

def generate_key_pair(algo_name: str) -> tuple[bytes, bytes]:
    """Generates a public and private key pair for the specified PQC algorithm."""
    if oqs.Mechanism.is_kem_enabled(algo_name):
        with oqs.KeyEncapsulation(algo_name) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            log.info(f"Generated {algo_name} KEM key pair.")
            return public_key, secret_key
    elif oqs.Mechanism.is_sig_enabled(algo_name):
        with oqs.Signature(algo_name) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            log.info(f"Generated {algo_name} Signature key pair.")
            return public_key, secret_key
    else:
        raise ValueError(f"Unsupported or unknown PQC algorithm: {algo_name}")

def sign_message(message: bytes, secret_key: bytes, sig_algo: str) -> bytes:
    """Signs a message using the provided private key and signature algorithm."""
    if not oqs.Mechanism.is_sig_enabled(sig_algo):
        raise ValueError(f"Signature algorithm '{sig_algo}' is not enabled or supported.")
    with oqs.Signature(sig_algo, secret_key) as sig:
        signature = sig.sign(message)
        log.debug(f"Message signed using {sig_algo}.")
        return signature

def verify_signature(message: bytes, signature: bytes, public_key: bytes, sig_algo: str) -> bool:
    """Verifies a signature against a message using the public key and signature algorithm."""
    if not oqs.Mechanism.is_sig_enabled(sig_algo):
        raise ValueError(f"Signature algorithm '{sig_algo}' is not enabled or supported.")
    try:
        with oqs.Signature(sig_algo) as sig:
            is_valid = sig.verify(message, signature, public_key)
            log.debug(f"Signature verification result using {sig_algo}: {is_valid}")
            return is_valid
    except oqs.OpenSSLError as e:
        
        log.warning(f"Signature verification failed for {sig_algo}: {e}")
        return False

def kem_generate_keypair(kem_algo: str) -> tuple[bytes, bytes]:
    """Generates a KEM public and private key pair."""
    if not oqs.Mechanism.is_kem_enabled(kem_algo):
        raise ValueError(f"KEM algorithm '{kem_algo}' is not enabled or supported.")
    with oqs.KeyEncapsulation(kem_algo) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        log.debug(f"Generated {kem_algo} KEM key pair.")
        return public_key, secret_key

def kem_encapsulate(kem_algo: str, public_key: bytes) -> tuple[bytes, bytes]:
    """Performs KEM encapsulation using the recipient's public key.

    Returns:
        tuple[bytes, bytes]: The generated ciphertext and the shared secret.
    """
    if not oqs.Mechanism.is_kem_enabled(kem_algo):
        raise ValueError(f"KEM algorithm '{kem_algo}' is not enabled or supported.")
    with oqs.KeyEncapsulation(kem_algo) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
        log.debug(f"Performed KEM encapsulation using {kem_algo}.")
        return ciphertext, shared_secret

def kem_decapsulate(kem_algo: str, ciphertext: bytes, secret_key: bytes) -> bytes:
    """Performs KEM decapsulation using the recipient's private key.

    Returns:
        bytes: The derived shared secret.
    """
    if not oqs.Mechanism.is_kem_enabled(kem_algo):
        raise ValueError(f"KEM algorithm '{kem_algo}' is not enabled or supported.")
    with oqs.KeyEncapsulation(kem_algo, secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
        log.debug(f"Performed KEM decapsulation using {kem_algo}.")
        return shared_secret



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
    aes_key_size = AES_KEY_BYTES 
    if len(key) != aes_key_size:
        
        raise ValueError(f"AES key must be exactly {aes_key_size} bytes, got {len(key)}. Use derive_aes_key.")
    aes_key = key 

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(AES_NONCE_BYTES) 
    ciphertext = aesgcm.encrypt(nonce, plaintext, None) 
    log.debug(f"AES-GCM Encryption complete. Nonce: {nonce.hex()}, Ciphertext length: {len(ciphertext)}")
    return nonce, ciphertext

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
    aes_key_size = AES_KEY_BYTES 
    if len(key) != aes_key_size:
        raise ValueError(f"AES key must be exactly {aes_key_size} bytes, got {len(key)}. Use derive_aes_key.")
    aes_key = key

    if len(nonce) != AES_NONCE_BYTES:
        raise ValueError(f"Invalid nonce length, expected {AES_NONCE_BYTES} bytes, got {len(nonce)}")

    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        log.debug("AES-GCM Decryption successful.")
        return plaintext
    except Exception as e: 
        log.error(f"AES-GCM Decryption failed: {e}")
        raise 
