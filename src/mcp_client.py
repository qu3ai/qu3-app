from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple
import base64
import os
import requests
import json
import oqs 
import sys 
import logging
from pathlib import Path
from cryptography.exceptions import InvalidTag, InvalidSignature 

from .pqc_utils import (
    KEM_ALG, SIG_ALG,
    sign_message,
    verify_signature,
    kem_decapsulate,
    ALGORITHMS,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    derive_aes_key,
    PQCError
)

@dataclass
class MCPRequest:
    target_server_url: str
    model_id: str  
    input_data: Dict[str, Any] 
    policy_id: Optional[str] = None 
    pqc_signature: Optional[bytes] = None 
    client_signing_pubkey: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
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
    status: str  
    output_data: Optional[Any] = None 
    error_message: Optional[str] = None 
    attestation_data: Optional[Dict[str, Any]] = None 
    attestation_signature: Optional[bytes] = None 
    audit_hash: Optional[str] = None 

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPResponse':
        return cls(
            status=data.get('status', 'error'), 
            output_data=data.get('outputData'), 
            error_message=data.get('errorMessage'),
            attestation_data=data.get('attestationData'),
            attestation_signature=base64.b64decode(data['attestationSignature']) if data.get('attestationSignature') else None,
            audit_hash=data.get('auditHash')
        )


class MCPClient:
    """Client for secure interaction with Quantum-Safe MCP Servers.

    Handles PQC key management (Kyber for KEM, SPHINCS+ for signatures),
    request signing, response attestation verification, and session management.

    Relies on the caller to provide necessary keys during initialization.
    """

    def __init__(
        self,
        server_url: str,
        client_kem_key_pair: Tuple[bytes, bytes],
        client_sign_key_pair: Tuple[bytes, bytes],
        server_kem_public_key: bytes,
        server_sign_public_key: bytes,
    ):
        """Initializes the MCP Client with required configuration and keys.

        Args:
            server_url: The base URL of the target MCP server.
            client_kem_key_pair: Tuple of (public_key_bytes, secret_key_bytes) for client KEM.
            client_sign_key_pair: Tuple of (public_key_bytes, secret_key_bytes) for client signing.
            server_kem_public_key: Public key bytes for server KEM.
            server_sign_public_key: Public key bytes for server signing.

        Raises:
            ValueError: If any required key is missing or invalid.
        """
        self.log = logging.getLogger(__name__) 

        
        if not all([
            server_url,
            client_kem_key_pair,
            client_kem_key_pair[0],
            client_kem_key_pair[1],
            client_sign_key_pair,
            client_sign_key_pair[0],
            client_sign_key_pair[1],
            server_kem_public_key,
            server_sign_public_key,
        ]):
            raise ValueError("Missing required arguments for MCPClient initialization (URL or Keys).")

        self._client_kem_keys = client_kem_key_pair
        self._client_sign_keys = client_sign_key_pair
        self._server_kem_pubkey = server_kem_public_key
        self._server_sign_pubkey = server_sign_public_key

        self._session_key: Optional[bytes] = None 
        self._is_connected = False
        self._connected_server_url: Optional[str] = None
        self._http_session = requests.Session() 
        self._http_session.headers.update({'Content-Type': 'application/json'})

        self.log.info("MCPClient initialized successfully with provided keys.")

    def connect(self, server_url: str) -> bool:
        """Establishes a secure session with the target server via KEM handshake.

        Args:
            server_url: The base URL of the MCP server.

        Returns:
            bool: True if the connection and KEM handshake succeed, False otherwise.
        """
        if self._is_connected:
            if server_url == self._connected_server_url:
                self.log.info(f"Already connected to {self._connected_server_url}. Skipping connection attempt.")
                return True
            else:
                self.log.warning(f"Client already connected to {self._connected_server_url}, disconnecting before connecting to {server_url}.")
                self.disconnect()

        if not self._client_kem_keys:
             self.log.error("Connection failed: Client KEM keys are not loaded.")
             return False

        self.log.info(f"Initiating connection and KEM ({KEM_ALG}) handshake with {server_url}...")
        client_kem_pubkey, client_kem_secretkey = self._client_kem_keys

        
        handshake_endpoint = f"{server_url.rstrip('/')}/kem-handshake/initiate"
        try:
            
            client_pk_b64 = base64.b64encode(client_kem_pubkey).decode('utf-8')
            request_payload = {"clientKemPublicKeyB64": client_pk_b64}
            self.log.debug(f"Sending client KEM public key to {handshake_endpoint}...")

            http_response = self._http_session.post(handshake_endpoint, json=request_payload, timeout=15)
            http_response.raise_for_status() 

            
            response_data = http_response.json()
            ciphertext_b64 = response_data.get("kemCiphertextB64")
            if not ciphertext_b64:
                self.log.error("Handshake failed: Server response missing KEM ciphertext.")
                return False

            ciphertext = base64.b64decode(ciphertext_b64)
            self.log.debug(f"Received KEM ciphertext (length: {len(ciphertext)} bytes) from server.")

            
            kem_shared_secret = kem_decapsulate(KEM_ALG, ciphertext, client_kem_secretkey)

            
            self._session_key = derive_aes_key(kem_shared_secret)
            self.log.info(f"Successfully derived AES session key (length: {len(self._session_key)} bytes). Secure session established.")

        except requests.exceptions.RequestException as e:
            self.log.exception(f"Network error during KEM handshake with {handshake_endpoint}: {e}")
            return False
        except (json.JSONDecodeError, TypeError, ValueError, base64.binascii.Error) as e:
            self.log.exception(f"Failed to decode or parse server handshake response: {e}")
            return False
        except oqs.OpenSSLError as e:
            
            self.log.exception(f"PQC KEM decapsulation failed: {e}")
            return False
        except Exception as e:
            self.log.exception(f"Unexpected error during KEM handshake: {e}")
            return False

        
        self._connected_server_url = server_url
        self._is_connected = True
        self.log.info(f"Connection to {self._connected_server_url} successful.")
        return True

    def send_request(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Sends a signed and encrypted request to the connected MCP server.

        Handles PQC signing of the request payload, AES-GCM encryption,
        network communication, decryption of the response, and verification
        of the server's attestation signature.
        """
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
            signature_bytes = sign_message(payload_bytes_to_sign, self._client_sign_keys[1], ALGORITHMS["sig"])
            self.log.debug(f"Signature generated ({len(signature_bytes)} bytes).")
        except PQCError as e:
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
        except (ValueError, TypeError, PQCError) as e: 
            self.log.exception(f"AES-GCM encryption failed: {e}")
            return MCPResponse(status='error', error_message=f"Client-side encryption failed: {e}")
        except Exception as e:
            self.log.exception(f"Unexpected error during encryption: {e}")
            return MCPResponse(status='error', error_message=f"Unexpected client-side encryption error: {e}")

        
        
        request_body = {
            "clientKemPublicKeyB64": base64.b64encode(self._client_kem_keys[0]).decode('utf-8'),
            "nonceB64": base64.b64encode(nonce_bytes).decode('utf-8'),
            "encryptedPayloadB64": base64.b64encode(ciphertext_bytes).decode('utf-8'),
        }

        
        inference_endpoint = f"{self._connected_server_url.rstrip('/')}/inference"
        self.log.info(f"Sending encrypted POST request to {inference_endpoint}...")

        try:
            http_response = self._http_session.post(inference_endpoint, json=request_body, timeout=30)
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

        except requests.exceptions.RequestException as e:
            self.log.error(f"Network error sending request to {inference_endpoint}: {e}")
            return MCPResponse(status='error', error_message=f"Network error: {e}")
        except (json.JSONDecodeError, base64.binascii.Error, ValueError, TypeError) as e:
            self.log.error(f"Error decoding/parsing server response: {e}")
            return MCPResponse(status='error', error_message=f"Failed to process server response: {e}")
        except InvalidTag: 
            self.log.error("Failed to decrypt server response (InvalidTag). Session key mismatch or corrupted data?")
            return MCPResponse(status='error', error_message="Failed to decrypt server response (InvalidTag).")
        except PQCError as e:
            self.log.error(f"Decryption failed: {e}")
            return MCPResponse(status='error', error_message=f"Server response decryption failed: {e}")
        except Exception as e:
            self.log.exception("Unexpected error handling server response:")
            return MCPResponse(status='error', error_message=f"Client-side response handling error: {e}")

        
        self.log.info("Verifying server response attestation signature...")
        if not self._verify_attestation(server_response):
            
            
            server_response.status = 'error' 
            server_response.error_message = (server_response.error_message + "; ATTENTION: Attestation verification FAILED" if server_response.error_message else "ATTENTION: Attestation verification FAILED")
            
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
        if not self._session_key:
            self.log.error("Cannot encrypt payload: No active session key. Call connect() first.")
            raise RuntimeError("Cannot encrypt payload: No active session key. Client must be connected.")

        self.log.debug(f"Encrypting payload of length {len(payload_bytes)} bytes with AES-GCM using session key...")
        try:
            nonce, ciphertext = encrypt_aes_gcm(self._session_key, payload_bytes)
            self.log.debug(f"Payload encryption successful. Nonce: {nonce.hex()[:16]}..., Ciphertext: {ciphertext.hex()[:16]}...")
            return nonce, ciphertext
        except Exception as e:
            self.log.exception(f"AES-GCM encryption failed during encrypt_payload: {e}")
            raise RuntimeError(f"Payload encryption failed: {e}")

    def disconnect(self):
        if not self._is_connected:
            return 

        connected_url = self._connected_server_url
        self.log.info(f"Disconnecting from {connected_url}...")
        self._session_key = None
        self._is_connected = False
        self._connected_server_url = None
        self._http_session.close()
        self.log.info(f"Disconnected from {connected_url}.")

    def _verify_attestation(self, response: MCPResponse) -> bool:
        """Verifies the server's PQC attestation signature (SPHINCS+) over the attestation_data.

        Returns:
            bool: True if the signature is valid and matches the loaded server public key,
                  False otherwise (including cases of missing data/signature or crypto errors).
        """
        if not self._server_sign_pubkey:
            self.log.error("Cannot verify attestation: Server signing public key is not loaded.")
            return False
        if not response.attestation_data or not response.attestation_signature:
            self.log.warning("Cannot verify attestation: Attestation data or signature missing in the server response.")
            
            return False 

        try:
            
            attestation_string = json.dumps(response.attestation_data, sort_keys=True, separators=(',', ':'))
            attestation_bytes = attestation_string.encode('utf-8')
        except Exception as e:
            self.log.exception(f"Error serializing attestation data for verification: {e}")
            return False

        self.log.debug(f"Verifying server attestation signature ({SIG_ALG}) against known server public key...")
        try:
            is_valid = verify_signature(
                attestation_bytes,
                response.attestation_signature,
                self._server_sign_pubkey,
                ALGORITHMS['sig']
            )
            return is_valid
        except oqs.OpenSSLError as e:
            
            self.log.warning(f"Attestation signature verification failed: {e}")
            return False
        except Exception as e:
            
            self.log.exception(f"Unexpected error during attestation signature verification: {e}")
            return False

    def __del__(self):
        self.disconnect()