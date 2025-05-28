from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple
import base64
import os
import requests
import json
import logging
import time
from pathlib import Path
from cryptography.exceptions import InvalidTag
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from .pqc_utils import (
    ALGORITHMS,
    sign_message,
    verify_signature,
    kem_decapsulate,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    derive_aes_key,
    PQCError,
    PQCKEMError,
    PQCSignatureError,
    PQCEncryptionError,
    PQCDecryptionError
)

# Connection and retry configuration
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.3
RETRY_STATUS_CODES = [500, 502, 503, 504]

@dataclass
class MCPRequest:
    """Represents a request to an MCP server."""
    target_server_url: str
    model_id: str  
    input_data: Dict[str, Any] 
    policy_id: Optional[str] = None 
    pqc_signature: Optional[bytes] = None 
    client_signing_pubkey: Optional[bytes] = None

    def __post_init__(self):
        """Validate request data after initialization."""
        if not isinstance(self.target_server_url, str) or not self.target_server_url.strip():
            raise ValueError("target_server_url must be a non-empty string")
        if not isinstance(self.model_id, str) or not self.model_id.strip():
            raise ValueError("model_id must be a non-empty string")


    def to_dict(self) -> Dict[str, Any]:
        """Convert request to dictionary format."""
        data = {
            "modelId": self.model_id, 
            "inputData": self.input_data,
            "policyId": self.policy_id,
            "pqcSignature": base64.b64encode(self.pqc_signature).decode('utf-8') if self.pqc_signature else None,
            "clientSigningPubkey": base64.b64encode(self.client_signing_pubkey).decode('utf-8') if self.client_signing_pubkey else None
        }
        
        return {k: v for k, v in data.items() if v is not None}


@dataclass
class MCPResponse:
    """Represents a response from an MCP server."""
    status: str  
    output_data: Optional[Any] = None 
    error_message: Optional[str] = None 
    attestation_data: Optional[Dict[str, Any]] = None 
    attestation_signature: Optional[bytes] = None 
    audit_hash: Optional[str] = None 

    def __post_init__(self):
        """Validate response data after initialization."""
        if not isinstance(self.status, str) or not self.status.strip():
            raise ValueError("status must be a non-empty string")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPResponse':
        """Create MCPResponse from dictionary data."""
        if not isinstance(data, dict):
            raise ValueError("Response data must be a dictionary")
            
        raw_signature_b64 = data.get('attestation_signature_b64')
        logger = logging.getLogger(__name__)
        logger.debug(f"MCPResponse.from_dict: Raw attestation_signature_b64 from dict: {'PRESENT and NON-EMPTY' if raw_signature_b64 else ('PRESENT BUT EMPTY/NONE' if raw_signature_b64 == '' or raw_signature_b64 is None else 'MISSING')}")
        
        if raw_signature_b64 and len(raw_signature_b64) > 20:
             logger.debug(f"MCPResponse.from_dict: att_sig_b64 (first 20 chars): {raw_signature_b64[:20]}...")

        try:
            attestation_signature = base64.b64decode(raw_signature_b64) if raw_signature_b64 else None
        except Exception as e:
            logger.warning(f"Failed to decode attestation signature: {e}")
            attestation_signature = None

        return cls(
            status=data.get('status', 'error'),
            output_data=data.get('output_data'),
            error_message=data.get('error_message'),
            attestation_data=data.get('attestation_data'),
            attestation_signature=attestation_signature,
            audit_hash=data.get('audit_hash')
        )


class MCPClient:
    """Client for secure interaction with Quantum-Safe MCP Servers.

    Handles PQC key management (Kyber for KEM, SPHINCS+ for signatures),
    request signing, response attestation verification, and session management
    with enhanced error handling and connection pooling.
    """

    def __init__(
        self,
        server_url: str,
        client_kem_key_pair: Tuple[bytes, bytes],
        client_sign_key_pair: Tuple[bytes, bytes],
        server_kem_public_key: bytes,
        server_sign_public_key: bytes,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES
    ):
        """Initializes the MCP Client with required configuration and keys.

        Args:
            server_url: The base URL of the target MCP server.
            client_kem_key_pair: Tuple of (public_key_bytes, secret_key_bytes) for client KEM.
            client_sign_key_pair: Tuple of (public_key_bytes, secret_key_bytes) for client signing.
            server_kem_public_key: Public key bytes for server KEM.
            server_sign_public_key: Public key bytes for server signing.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts.

        Raises:
            ValueError: If any required key is missing or invalid.
        """
        self.log = logging.getLogger(__name__) 

        # Validate inputs
        self._validate_initialization_params(
            server_url, client_kem_key_pair, client_sign_key_pair,
            server_kem_public_key, server_sign_public_key
        )

        self.client_kem_pk_bytes, self.client_kem_sk_bytes = client_kem_key_pair
        self.client_sign_pk_bytes, self.client_sign_sk_bytes = client_sign_key_pair
        self.server_kem_pk_bytes = server_kem_public_key
        self.server_sign_pk_bytes = server_sign_public_key

        self._session_key: Optional[bytes] = None 
        self._is_connected = False
        self._connected_server_url: Optional[str] = None
        self._timeout = timeout
        self._max_retries = max_retries
        
        self._http_session = self._create_http_session()

        self.log.info("MCPClient initialized successfully with provided keys.")

    def _validate_initialization_params(
        self, 
        server_url: str,
        client_kem_key_pair: Tuple[bytes, bytes],
        client_sign_key_pair: Tuple[bytes, bytes],
        server_kem_public_key: bytes,
        server_sign_public_key: bytes
    ):
        """Validate initialization parameters."""
        if not isinstance(server_url, str) or not server_url.strip():
            raise ValueError("server_url must be a non-empty string")
        
        if not isinstance(client_kem_key_pair, tuple) or len(client_kem_key_pair) != 2:
            raise ValueError("client_kem_key_pair must be a tuple of (public_key, secret_key)")
        
        if not isinstance(client_sign_key_pair, tuple) or len(client_sign_key_pair) != 2:
            raise ValueError("client_sign_key_pair must be a tuple of (public_key, secret_key)")
        
        for key_name, key_bytes in [
            ("client_kem_public_key", client_kem_key_pair[0]),
            ("client_kem_secret_key", client_kem_key_pair[1]),
            ("client_sign_public_key", client_sign_key_pair[0]),
            ("client_sign_secret_key", client_sign_key_pair[1]),
            ("server_kem_public_key", server_kem_public_key),
            ("server_sign_public_key", server_sign_public_key),
        ]:
            if not isinstance(key_bytes, bytes) or len(key_bytes) == 0:
                raise ValueError(f"{key_name} must be non-empty bytes")

    def _create_http_session(self) -> requests.Session:
        """Create HTTP session with retry strategy and connection pooling."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=self._max_retries,
            status_forcelist=RETRY_STATUS_CODES,
            backoff_factor=BACKOFF_FACTOR,
            allowed_methods=["GET", "POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'qu3-client/1.0',
            'Accept': 'application/json'
        })
        
        return session

    def connect(self, server_url: str) -> bool:
        """Establishes a secure session with the target server via KEM handshake.

        Args:
            server_url: The base URL of the MCP server.

        Returns:
            bool: True if the connection and KEM handshake succeed, False otherwise.
        """
        if not isinstance(server_url, str) or not server_url.strip():
            self.log.error("Server URL must be a non-empty string")
            return False
            
        if self._is_connected:
            if server_url == self._connected_server_url:
                self.log.info(f"Already connected to {self._connected_server_url}. Skipping connection attempt.")
                return True
            else:
                self.log.warning(f"Client already connected to {self._connected_server_url}, disconnecting before connecting to {server_url}.")
                self.disconnect()

        if not self.client_kem_pk_bytes or not self.client_kem_sk_bytes or not self.client_sign_pk_bytes:
             self.log.error("Connection failed: Client KEM or Signing public keys are not loaded.")
             return False

        self.log.info(f"Initiating connection and KEM ({ALGORITHMS['kem']}) handshake with {server_url}...")

        handshake_endpoint = f"{server_url.rstrip('/')}/kem-handshake/initiate"
        
        for attempt in range(self._max_retries + 1):
            try:
                client_kem_pk_b64 = base64.b64encode(self.client_kem_pk_bytes).decode('utf-8')
                client_sign_pk_b64 = base64.b64encode(self.client_sign_pk_bytes).decode('utf-8')
                
                request_payload = {
                    "client_kem_pub_key_b64": client_kem_pk_b64,
                    "client_sign_pub_key_b64": client_sign_pk_b64
                }
                self.log.debug(f"Sending client KEM & Signing public keys to {handshake_endpoint}...")

                http_response = self._http_session.post(
                    handshake_endpoint, 
                    json=request_payload, 
                    timeout=self._timeout
                )
                http_response.raise_for_status() 

                response_data = http_response.json()
                ciphertext_b64 = response_data.get("kemCiphertextB64")
                if not ciphertext_b64:
                    self.log.error("Handshake failed: Server response missing KEM ciphertext.")
                    return False

                ciphertext = base64.b64decode(ciphertext_b64)
                self.log.debug(f"Received KEM ciphertext (length: {len(ciphertext)} bytes) from server.")

                kem_shared_secret = kem_decapsulate(ALGORITHMS['kem'], ciphertext, self.client_kem_sk_bytes)
                
                self._session_key = derive_aes_key(kem_shared_secret)
                self.log.info(f"Successfully derived AES session key (length: {len(self._session_key)} bytes). Secure session established.")

                self._connected_server_url = server_url
                self._is_connected = True
                self.log.info(f"Connection to {self._connected_server_url} successful.")
                return True

            except requests.exceptions.Timeout as e:
                self.log.warning(f"Timeout during handshake attempt {attempt + 1}/{self._max_retries + 1}: {e}")
            except requests.exceptions.ConnectionError as e:
                self.log.warning(f"Connection error during handshake attempt {attempt + 1}/{self._max_retries + 1}: {e}")
            except requests.exceptions.HTTPError as e:
                self.log.error(f"HTTP error during KEM handshake: {e}")
                return False  # Don't retry on HTTP errors
            except requests.exceptions.RequestException as e:
                self.log.warning(f"Network error during handshake attempt {attempt + 1}/{self._max_retries + 1}: {e}")
            except (json.JSONDecodeError, TypeError, ValueError, base64.binascii.Error) as e:
                self.log.error(f"Failed to decode or parse server handshake response: {e}")
                return False  # Don't retry on parsing errors
            except PQCKEMError as e:
                self.log.error(f"PQC KEM operation failed during handshake: {e}")
                return False  # Don't retry on PQC errors
            except Exception as e:
                self.log.exception(f"Unexpected error during KEM handshake attempt {attempt + 1}/{self._max_retries + 1}: {e}")
            
            if attempt < self._max_retries:
                delay = BACKOFF_FACTOR * (2 ** attempt)
                self.log.info(f"Retrying handshake in {delay:.1f} seconds...")
                time.sleep(delay)

        self.log.error(f"Failed to establish connection after {self._max_retries + 1} attempts")
        return False

    def send_request(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Sends a signed and encrypted request to the connected MCP server.

        Handles PQC signing of the request payload, AES-GCM encryption,
        network communication, decryption of the response, and verification
        of the server's attestation signature.
        """
        if not isinstance(request, MCPRequest):
            self.log.error("Request must be an MCPRequest instance")
            return MCPResponse(status='error', error_message="Invalid request type")
            
        if not self._session_key:
            self.log.error("Cannot send request: No active session key. Call connect() first.")
            return MCPResponse(status='error', error_message="Client not connected or session key missing.")
        if not self._connected_server_url:
            self.log.error("Cannot send request: Not connected to any server.")
            return MCPResponse(status='error', error_message="Client not connected.")

        self.log.info(f"Preparing encrypted & signed request for model '{request.model_id}' to {self._connected_server_url}...")

        payload_to_sign = {
            "target_server_url": request.target_server_url, 
            "model_id": request.model_id,
            "input_data": request.input_data,
        }
        
        payload_bytes_to_sign = json.dumps(payload_to_sign, sort_keys=True, separators=(',', ':')).encode('utf-8')
        self.log.debug(f"Payload to sign: {payload_bytes_to_sign.decode()}")

        try:
            self.log.debug(f"Signing payload with {ALGORITHMS['sig']}...")
            signature_bytes = sign_message(payload_bytes_to_sign, self.client_sign_sk_bytes, ALGORITHMS["sig"])
            self.log.debug(f"Signature generated ({len(signature_bytes)} bytes).")
        except PQCSignatureError as e:
            self.log.exception(f"PQC signing failed: {e}")
            return MCPResponse(status='error', error_message=f"Client-side PQC signing failed: {e}")
        except Exception as e:
            self.log.exception(f"Unexpected error during signing: {e}")
            return MCPResponse(status='error', error_message=f"Unexpected client-side signing error: {e}")

        payload_with_sig = payload_to_sign.copy() 
        payload_with_sig["pqc_signature_b64"] = base64.b64encode(signature_bytes).decode('utf-8')
        self.log.debug("Added signature to payload.")

        try:
            final_payload_bytes = json.dumps(payload_with_sig, sort_keys=True, separators=(',', ':')).encode('utf-8')
            self.log.debug(f"Encrypting final payload ({len(final_payload_bytes)} bytes) with AES-GCM...")
            nonce_bytes, ciphertext_bytes = encrypt_aes_gcm(self._session_key, final_payload_bytes)
            self.log.debug(f"Encryption successful. Nonce: {nonce_bytes.hex()[:16]}..., Ciphertext: {ciphertext_bytes.hex()[:16]}...")
        except PQCEncryptionError as e:
            self.log.exception(f"AES-GCM encryption failed: {e}")
            return MCPResponse(status='error', error_message=f"Client-side encryption failed: {e}")
        except (ValueError, TypeError) as e: 
            self.log.exception(f"AES-GCM encryption failed: {e}")
            return MCPResponse(status='error', error_message=f"Client-side encryption failed: {e}")
        except Exception as e:
            self.log.exception(f"Unexpected error during encryption: {e}")
            return MCPResponse(status='error', error_message=f"Unexpected client-side encryption error: {e}")

        request_body = {
            "clientKemPublicKeyB64": base64.b64encode(self.client_kem_pk_bytes).decode('utf-8'),
            "nonceB64": base64.b64encode(nonce_bytes).decode('utf-8'),
            "encryptedPayloadB64": base64.b64encode(ciphertext_bytes).decode('utf-8'),
        }

        inference_endpoint = f"{self._connected_server_url.rstrip('/')}/inference"
        self.log.info(f"Sending encrypted POST request to {inference_endpoint}...")

        for attempt in range(self._max_retries + 1):
            try:
                http_response = self._http_session.post(
                    inference_endpoint, 
                    json=request_body, 
                    timeout=self._timeout
                )
                http_response.raise_for_status()
                self.log.info(f"Received HTTP response: {http_response.status_code}")

                encrypted_response_data = http_response.json()
                nonce_b64 = encrypted_response_data.get("nonceB64")
                encrypted_payload_b64 = encrypted_response_data.get("encryptedPayloadB64")

                if not nonce_b64 or not encrypted_payload_b64:
                    self.log.error("Server response missing nonce or encrypted payload.")
                    return MCPResponse(status='error', error_message="Invalid encrypted response format from server")

                self.log.debug("Decrypting server response...")
                nonce = base64.b64decode(nonce_b64)
                encrypted_payload = base64.b64decode(encrypted_payload_b64)

                decrypted_payload_bytes = decrypt_aes_gcm(self._session_key, nonce, encrypted_payload)
                response_dict = json.loads(decrypted_payload_bytes.decode('utf-8'))
                self.log.debug(f"Received and decrypted response payload: {json.dumps(response_dict)[:200]}...")

                server_response = MCPResponse.from_dict(response_dict)
                break

            except requests.exceptions.Timeout as e:
                self.log.warning(f"Timeout sending request attempt {attempt + 1}/{self._max_retries + 1}: {e}")
                if attempt == self._max_retries:
                    return MCPResponse(status='error', error_message=f"Request timeout after {self._max_retries + 1} attempts")
            except requests.exceptions.ConnectionError as e:
                self.log.warning(f"Connection error sending request attempt {attempt + 1}/{self._max_retries + 1}: {e}")
                if attempt == self._max_retries:
                    return MCPResponse(status='error', error_message=f"Connection error after {self._max_retries + 1} attempts")
            except requests.exceptions.HTTPError as e:
                self.log.error(f"HTTP error sending request to {inference_endpoint}: {e}")
                return MCPResponse(status='error', error_message=f"HTTP error: {e}")
            except requests.exceptions.RequestException as e:
                self.log.warning(f"Network error sending request attempt {attempt + 1}/{self._max_retries + 1}: {e}")
                if attempt == self._max_retries:
                    return MCPResponse(status='error', error_message=f"Network error after {self._max_retries + 1} attempts: {e}")
            except (json.JSONDecodeError, base64.binascii.Error, ValueError, TypeError) as e:
                self.log.error(f"Error decoding/parsing server response: {e}")
                return MCPResponse(status='error', error_message=f"Failed to process server response: {e}")
            except PQCDecryptionError as e:
                self.log.error(f"Failed to decrypt server response: {e}")
                return MCPResponse(status='error', error_message=f"Server response decryption failed: {e}")
            except Exception as e:
                self.log.exception(f"Unexpected error handling server response attempt {attempt + 1}/{self._max_retries + 1}:")
                if attempt == self._max_retries:
                    return MCPResponse(status='error', error_message=f"Client-side response handling error: {e}")
            
            if attempt < self._max_retries:
                delay = BACKOFF_FACTOR * (2 ** attempt)
                self.log.info(f"Retrying request in {delay:.1f} seconds...")
                time.sleep(delay)

        # Verify server attestation
        self.log.info("Verifying server response attestation signature...")
        attestation_ok, verification_error_msg = self._verify_attestation(server_response)
        if not attestation_ok:
            error_prefix = "ATTENTION: Attestation verification FAILED"
            if verification_error_msg:
                error_prefix += f" ({verification_error_msg})"
            
            server_response.status = 'error' 
            server_response.error_message = f"{error_prefix}{'; ' + server_response.error_message if server_response.error_message else ''}"
            self.log.warning(server_response.error_message)
            return server_response
        else:
             self.log.info("Server attestation signature VERIFIED.")

        return server_response

    def encrypt_payload(self, payload_bytes: bytes) -> Tuple[bytes, bytes]:
        """Encrypts the given payload using the current session key.

        Args:
            payload_bytes: The bytes to encrypt.

        Returns:
            Tuple[bytes, bytes]: The nonce and the ciphertext.

        Raises:
            RuntimeError: If no active session key is available (client not connected).
            PQCError: If AES-GCM encryption fails.
        """
        if not isinstance(payload_bytes, bytes):
            raise ValueError("Payload must be bytes")
            
        if not self._session_key:
            self.log.error("Cannot encrypt payload: No active session key. Call connect() first.")
            raise RuntimeError("Cannot encrypt payload: No active session key. Client must be connected.")

        self.log.debug(f"Encrypting payload of length {len(payload_bytes)} bytes with AES-GCM using session key...")
        try:
            nonce, ciphertext = encrypt_aes_gcm(self._session_key, payload_bytes)
            self.log.debug(f"Payload encryption successful. Nonce: {nonce.hex()[:16]}..., Ciphertext: {ciphertext.hex()[:16]}...")
            return nonce, ciphertext
        except PQCEncryptionError as e:
            self.log.exception(f"AES-GCM encryption failed during encrypt_payload: {e}")
            raise PQCEncryptionError(f"Payload encryption failed: {e}")
        except Exception as e:
            self.log.exception(f"Unexpected error during encrypt_payload: {e}")
            raise RuntimeError(f"Payload encryption failed with an unexpected error: {e}")

    def is_connected(self) -> bool:
        """Check if client is currently connected to a server.
        
        Returns:
            True if connected, False otherwise
        """
        return self._is_connected and self._session_key is not None

    def get_connected_server(self) -> Optional[str]:
        """Get the URL of the currently connected server.
        
        Returns:
            Server URL if connected, None otherwise
        """
        return self._connected_server_url if self._is_connected else None

    def disconnect(self):
        """Disconnect from the current server and clean up resources."""
        if not self._is_connected:
            return 

        connected_url = self._connected_server_url
        self.log.info(f"Disconnecting from {connected_url}...")
        
        self._session_key = None
        self._is_connected = False
        self._connected_server_url = None
        
        if hasattr(self, '_http_session'):
            self._http_session.close()
            # Recreate session for potential future connections
            self._http_session = self._create_http_session()
        
        self.log.info(f"Disconnected from {connected_url}.")

    def _verify_attestation(self, response: MCPResponse) -> Tuple[bool, Optional[str]]:
        """Verifies the server's PQC attestation signature.

        Returns:
            Tuple[bool, Optional[str]]: (True if valid, error message if verification fails or data missing).
        """
        if not self.server_sign_pk_bytes:
            msg = "Cannot verify attestation: Server signing public key is not loaded."
            self.log.error(msg)
            return False, msg

        self.log.debug(f"_verify_attestation: response.attestation_data is {'PRESENT' if response.attestation_data else 'MISSING/EMPTY'}")
        sig_val = response.attestation_signature
        self.log.debug(f"_verify_attestation: response.attestation_signature is {'PRESENT and NON-EMPTY bytes' if sig_val and isinstance(sig_val, bytes) and len(sig_val) > 0 else ('NONE or EMPTY bytes' if sig_val == b'' or sig_val is None else 'UNEXPECTED TYPE')}")
        if sig_val and isinstance(sig_val, bytes) and len(sig_val) > 0:
             self.log.debug(f"_verify_attestation: att_sig (first 20 hex): {sig_val.hex()[:20]}...")

        if not response.attestation_data or not response.attestation_signature:
            msg = "Cannot verify attestation: Attestation data or signature missing."
            self.log.warning(msg)
            return False, msg

        try:
            attestation_string = json.dumps(response.attestation_data, sort_keys=True, separators=(',', ':'))
            attestation_bytes = attestation_string.encode('utf-8')
        except Exception as e:
            msg = f"Error serializing attestation data: {e}"
            self.log.exception(msg)
            return False, msg

        self.log.debug(f"Verifying server attestation signature ({ALGORITHMS['sig']}) against known server public key...")
        try:
            is_valid = verify_signature(
                attestation_bytes,
                response.attestation_signature,
                self.server_sign_pk_bytes,
                ALGORITHMS['sig']
            )
            if not is_valid:
                return False, "Signature mismatch"
            return True, None
        except PQCSignatureError as e:
            msg = f"Attestation signature verification failed (PQC Error): {e}"
            self.log.warning(msg)
            return False, msg
        except Exception as e:
            msg = f"Unexpected error during attestation signature verification: {e}"
            self.log.exception(msg) 
            return False, msg

    def __del__(self):
        """Cleanup when object is destroyed."""
        try:
            self.disconnect()
        except Exception:
            pass  # Ignore errors during cleanup
