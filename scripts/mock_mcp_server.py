import uvicorn
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, Field
import base64
import os
from pathlib import Path
import logging
import oqs
import json 
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone 
from cryptography.exceptions import InvalidTag, InvalidSignature


import sys
sys.path.insert(0, Path(__file__).parent.parent.resolve().__str__())

from src.mcp_client import MCPRequest as MCPRequestSchema, MCPResponse as MCPResponseSchema 
from src.pqc_utils import (
    generate_key_pair,
    sign_message,
    verify_signature,
    ALGORITHMS,
    kem_encapsulate,
    kem_decapsulate,
    encrypt_aes_gcm, 
    decrypt_aes_gcm, 
    derive_aes_key,
)
from src.config_utils import (
    save_key_pair_to_files,
    load_key_pair_from_files,
    load_public_key_from_file,
    get_key_dir,
)

app = FastAPI(title="MCP Server (Development/Test Instance)")

log = logging.getLogger(__name__)

KEY_DIR = get_key_dir()
SERVER_KEM_ALGO = ALGORITHMS["kem"]
SERVER_SIGN_ALGO = ALGORITHMS["sig"]

server_kem_key_pair_files = (KEY_DIR / "server_kem.pub", KEY_DIR / "server_kem.sec")
server_sign_key_pair_files = (KEY_DIR / "server_sign.pub", KEY_DIR / "server_sign.sec")
client_sign_pub_file = KEY_DIR / "client_sign.pub"

server_kem_pk, server_kem_sk = None, None
server_sign_pk, server_sign_sk = None, None
client_sign_pk = None


SESSION_KEYS: Dict[bytes, Dict[str, Any]] = {}
SESSION_TIMEOUT = timedelta(hours=1) 

def initialize_server_keys():
    global server_kem_pk, server_kem_sk, server_sign_pk, server_sign_sk, client_sign_pk
    print("Initializing Server Keys (Development Instance)...")
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    
    try:
        server_kem_pk, server_kem_sk = load_key_pair_from_files(*server_kem_key_pair_files)
        print(f"Server KEM keys loaded from {KEY_DIR}")
    except FileNotFoundError:
        print("Server KEM keys not found. Generating (for development instance)...")
        server_kem_pk, server_kem_sk = generate_key_pair(SERVER_KEM_ALGO)
        save_key_pair_to_files(server_kem_pk, server_kem_sk, *server_kem_key_pair_files)
        print(f"Server KEM keys generated and saved to {KEY_DIR}")
    except Exception as e:
        print(f"CRITICAL: Error initializing server KEM keys: {e}")
        server_kem_pk, server_kem_sk = None, None


    
    try:
        server_sign_pk, server_sign_sk = load_key_pair_from_files(*server_sign_key_pair_files)
        print(f"Server Signing keys loaded from {KEY_DIR}")
    except FileNotFoundError:
        print("Server Signing keys not found. Generating (for development instance)...")
        server_sign_pk, server_sign_sk = generate_key_pair(SERVER_SIGN_ALGO)
        save_key_pair_to_files(server_sign_pk, server_sign_sk, *server_sign_key_pair_files)
        print(f"Server Signing keys generated and saved to {KEY_DIR}")
    except Exception as e:
        print(f"CRITICAL: Error initializing server signing keys: {e}")
        server_sign_pk, server_sign_sk = None, None

    
    try:
        client_sign_pk = load_public_key_from_file(client_sign_pub_file)
        print(f"Client Signing public key loaded from {client_sign_pub_file}")
    except FileNotFoundError:
        print(f"WARNING: Client signing public key ({client_sign_pub_file.name}) not found.")
        print("Server will proceed but cannot verify client signatures.")
    except Exception as e:
        print(f"Error loading client signing public key: {e}")
        

    print("Server Key initialization complete.")


@app.on_event("startup")
def startup_event():
    initialize_server_keys()



class EncryptedRequest(BaseModel):
    client_kem_public_key_b64: str = Field(..., alias="clientKemPublicKeyB64")
    nonce_b64: str = Field(..., alias="nonceB64")
    encrypted_payload_b64: str = Field(..., alias="encryptedPayloadB64")

class EncryptedResponse(BaseModel):
    nonce_b64: str = Field(..., alias="nonceB64")
    encrypted_payload_b64: str = Field(..., alias="encryptedPayloadB64")

@app.get("/")
def read_root():
    """Basic health check endpoint."""
    return {"message": "MCP Development Server is running."}


class KEMHandshakeRequest(BaseModel):
    client_kem_pub_key_b64: str
    client_sign_pub_key_b64: str 

class KEMHandshakeResponse(BaseModel):
    kem_ciphertext_b64: str = Field(..., alias="kemCiphertextB64")
    

@app.post("/kem-handshake/initiate", response_model=KEMHandshakeResponse, response_model_by_alias=True)
def handle_kem_handshake(request: KEMHandshakeRequest):
    """Performs KEM encapsulation using the provided client KEM public key and stores the session key."""
    log.info("Received KEM handshake initiation request.")

    # Removed server_kem_pk check here as it's not directly used for encapsulation against client PK

    try:
        client_kem_pk_bytes = base64.b64decode(request.client_kem_pub_key_b64)
        client_sign_pk_bytes = base64.b64decode(request.client_sign_pub_key_b64) 
        log.debug(f"Received client KEM public key (length: {len(client_kem_pk_bytes)} bytes).")
        log.debug(f"Received client Signing public key (length: {len(client_sign_pk_bytes)} bytes).")

        ciphertext, shared_secret = kem_encapsulate(SERVER_KEM_ALGO, client_kem_pk_bytes)

        
        session_key = derive_aes_key(shared_secret)
        
        SESSION_KEYS[client_kem_pk_bytes] = {
            "session_key": session_key,
            "client_sign_pk": client_sign_pk_bytes,
            "timestamp": datetime.now(timezone.utc) 
        }
        log.info(f"KEM encapsulation successful. Stored session info for client {client_kem_pk_bytes.hex()[:16]}...")

        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

        return {"kemCiphertextB64": ciphertext_b64}

    except (base64.binascii.Error, ValueError) as e:
        log.error(f"Failed to decode client KEM public key: {e}")
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for client KEM public key.")
    except oqs.OpenSSLError as e:
        log.exception(f"PQC KEM encapsulation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Server-side KEM encapsulation failed: {e}")
    except Exception as e:
        log.exception(f"Unexpected error during KEM handshake: {e}")
        raise HTTPException(status_code=500, detail=f"Unexpected server error during KEM handshake.")



@app.post("/inference", response_model=EncryptedResponse)
def run_inference_secure(request: EncryptedRequest):
    """Handles encrypted and signed inference requests."""
    client_id_b64 = request.client_kem_public_key_b64 
    log.info(f"Received /inference request from client ID: {client_id_b64[:10]}...")

    
    try:
        client_kem_pk_bytes = base64.b64decode(client_id_b64)
    except (base64.binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Invalid client KEM public key format.")

    session_info = SESSION_KEYS.get(client_kem_pk_bytes)
    if not session_info:
        log.warning(f"No session info found for client ID: {client_id_b64[:10]}... Handshake required?")
        raise HTTPException(status_code=401, detail="No active session key. Perform KEM handshake.")

    
    now = datetime.now(timezone.utc)
    if now - session_info['timestamp'] > SESSION_TIMEOUT:
        log.warning(f"Session expired for client ID: {client_id_b64[:10]}...")
        
        
        raise HTTPException(status_code=401, detail="Session expired. Perform KEM handshake again.")

    session_key = session_info["session_key"]
    client_sign_pk_bytes = session_info["client_sign_pk"] 

    
    try:
        nonce = base64.b64decode(request.nonce_b64)
        encrypted_payload = base64.b64decode(request.encrypted_payload_b64)

        
        decrypted_payload_bytes = decrypt_aes_gcm(session_key, nonce, encrypted_payload)
        request_payload_dict = json.loads(decrypted_payload_bytes.decode('utf-8'))
        log.debug(f"Successfully decrypted request payload: {request_payload_dict}")

    except (base64.binascii.Error, json.JSONDecodeError, ValueError) as e:
        log.warning(f"Failed to decode/decrypt payload or parse JSON: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid encrypted request format: {e}")
    except Exception as e: 
        log.error(f"Decryption failed for client {client_id_b64[:10]}...: {e}")
        raise HTTPException(status_code=400, detail=f"Payload decryption failed: {e}")

    
    try:
        
        signature_b64 = request_payload_dict.get("pqc_signature_b64") 
        if not signature_b64:
            raise ValueError("Missing 'pqc_signature_b64' in decrypted payload.")

        signature_bytes = base64.b64decode(signature_b64)

        
        
        data_to_verify_dict = {
            "target_server_url": request_payload_dict.get("target_server_url"),
            "model_id": request_payload_dict.get("model_id"),
            "input_data": request_payload_dict.get("input_data"),
            
        }
        
        log.debug(f"Verifying signature against target_server_url: {data_to_verify_dict['target_server_url']}")

        
        message_bytes = json.dumps(data_to_verify_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')

        
        verify_signature(message_bytes, signature_bytes, client_sign_pk_bytes, SERVER_SIGN_ALGO)
        log.info(f"Client signature verified successfully for client {client_id_b64[:10]}...")

    except (base64.binascii.Error, ValueError) as e:
        log.warning(f"Error decoding signature or missing fields for verification: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid signature data format: {e}")
    except InvalidSignature:
         log.warning(f"Client signature verification FAILED for client {client_id_b64[:10]}...")
         raise HTTPException(status_code=403, detail="Invalid client signature")
    except Exception as e:
        log.exception(f"Unexpected error during signature verification: {e}")
        raise HTTPException(status_code=500, detail="Signature verification failed")
    
    model_id = request_payload_dict.get("model_id")
    raw_input_data = request_payload_dict.get("input_data", {})
    log.info(f"Processing inference for model '{model_id}'...")

    output_data: Any = None
    error_message: Optional[str] = None
    status = "success"

    processed_input_data = {}
    if isinstance(raw_input_data, str):
        try:
            parsed_data = json.loads(raw_input_data)
            if isinstance(parsed_data, dict):
                processed_input_data = parsed_data
            else:
                status = "error"
                error_message = "Invalid input_data: content of JSON string is not an object."
                log.warning(f"input_data string parsed, but not to a dict: {raw_input_data}")
        except json.JSONDecodeError as e:
            status = "error"
            error_message = f"Invalid input_data: failed to parse JSON string. ({e})"
            log.warning(f"Failed to parse input_data string '{raw_input_data}': {e}")
    elif isinstance(raw_input_data, dict):
        processed_input_data = raw_input_data
    else:
        status = "error"
        error_message = "Invalid input_data type: expected JSON object or JSON string."
        log.warning(f"input_data is of unexpected type: {type(raw_input_data)}. Value: {raw_input_data}")

    if status == "success":
        if model_id == "model_caps":
            text = processed_input_data.get("text")
            if isinstance(text, str):
                output_data = {"capitalized_text": text.upper()}
            else:
                status = "error"
                error_message = ("Invalid input for model_caps: 'text' field must be a string "
                                 "and present in input_data.")
                log.warning(f"model_caps: 'text' is not a string or missing. input_data: {processed_input_data}")
        elif model_id == "model_reverse":
            text = processed_input_data.get("text")
            if isinstance(text, str):
                output_data = {"reversed_text": text[::-1]}
            else:
                status = "error"
                error_message = ("Invalid input for model_reverse: 'text' field must be a string "
                                 "and present in input_data.")
                log.warning(f"model_reverse: 'text' is not a string or missing. input_data: {processed_input_data}")
        else:
            status = "error"
            error_message = f"Unknown model ID: '{model_id}'"

    log.info(f"Inference result - Status: {status}, Output Keys: {list(output_data.keys()) if isinstance(output_data, dict) else type(output_data)}")


    attestation_data = {
        "serverVersion": "mock-0.1.0",
        "modelId": model_id,
        "status": status,
        "inputHash": base64.b64encode(json.dumps(raw_input_data, sort_keys=True).encode()).decode(),
        "outputHash": base64.b64encode(json.dumps(output_data, sort_keys=True).encode()).decode(), 
        "timestamp": datetime.now(timezone.utc).isoformat() 
    }

    
    log.debug(f"Attempting to sign attestation. Server sign SK is {'set' if server_sign_sk else 'None'}. Algorithm: {SERVER_SIGN_ALGO}")
    try:
        attestation_string = json.dumps(attestation_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        attestation_signature_bytes = sign_message(attestation_string, server_sign_sk, SERVER_SIGN_ALGO)
        
        log.debug(f"Raw attestation_signature_bytes (len: {len(attestation_signature_bytes) if attestation_signature_bytes else 'None'}): {attestation_signature_bytes.hex()[:32] if attestation_signature_bytes else 'None'}...")

        if not attestation_signature_bytes:
            log.error("sign_message returned None or empty bytes, but no exception was raised.")
            attestation_signature_bytes = None 
            error_message = error_message or "Failed to generate server attestation signature (sign_message returned empty)."
            status = "error"
        else:
            log.debug("Server attestation data signed successfully.")

    except Exception as e:
        log.exception(f"Failed to sign server attestation: {e}")
        attestation_signature_bytes = None
        error_message = error_message or "Failed to generate server attestation signature (exception during sign_message)."
        status = "error"

    
    response_payload_cleartext = {
        "status": status,
        "output_data": output_data,
        "error_message": error_message,
        "attestation_data": attestation_data,
        "attestation_signature_b64": base64.b64encode(attestation_signature_bytes).decode('utf-8') if attestation_signature_bytes else None,
        "audit_hash": None 
    }

    
    try:
        response_payload_json = json.dumps(response_payload_cleartext).encode('utf-8')
        
        resp_nonce, resp_ciphertext = encrypt_aes_gcm(session_key, response_payload_json)
        log.debug("Response payload encrypted successfully.")

        return {
            "nonceB64": base64.b64encode(resp_nonce).decode('utf-8'),
            "encryptedPayloadB64": base64.b64encode(resp_ciphertext).decode('utf-8')
        }
    except Exception as e:
        log.exception(f"Failed to encrypt response payload: {e}")
        raise HTTPException(status_code=500, detail="Failed to encrypt server response")


class PolicyUpdateRequest(BaseModel):
    client_kem_pub_key_b64: str
    nonce_b64: str
    ciphertext_b64: str
    signature_b64: str

@app.post("/policy-update")
async def policy_update(request: PolicyUpdateRequest):
    log.info("Received request for /policy-update")
    try:
        
        client_kem_pk_bytes = base64.b64decode(request.client_kem_pub_key_b64)
        session_info = SESSION_KEYS.get(client_kem_pk_bytes)
        if not session_info:
            log.error("Session info not found for client KEM PK.")
            raise HTTPException(status_code=401, detail="Session not established or expired.")

        
        now = datetime.now(timezone.utc)
        if now - session_info['timestamp'] > SESSION_TIMEOUT:
            log.warning(f"Session expired for client KEM PK: {client_kem_pk_bytes.hex()[:16]}...")
            
            raise HTTPException(status_code=401, detail="Session expired. Perform KEM handshake again.")

        session_key = session_info["session_key"]
        client_sign_pk_bytes = session_info["client_sign_pk"]
        log.debug(f"Retrieved session info for client KEM PK (first 10 bytes): {client_kem_pk_bytes[:10].hex()}...")

        
        nonce_bytes = base64.b64decode(request.nonce_b64)
        ciphertext_bytes = base64.b64decode(request.ciphertext_b64)
        signature_bytes = base64.b64decode(request.signature_b64)
        log.debug("Decoded nonce, ciphertext, and signature from request.")

        
        try:
            decrypted_policy_bytes = decrypt_aes_gcm(session_key, nonce_bytes, ciphertext_bytes)
            log.debug("Policy content decrypted successfully.")
        except InvalidTag:
            log.error("Decryption failed: Invalid AES-GCM tag.")
            raise HTTPException(status_code=400, detail="Policy decryption failed (invalid tag).")
        except Exception as e:
            log.error(f"Decryption failed with unexpected error: {e}")
            raise HTTPException(status_code=500, detail=f"Policy decryption failed: {e}")

        try:
            
            verify_signature(decrypted_policy_bytes, signature_bytes, client_sign_pk_bytes, SERVER_SIGN_ALGO)
            log.info("Client signature VERIFIED successfully.")
        except InvalidSignature:
            log.error("Client signature verification FAILED.")
            raise HTTPException(status_code=403, detail="Invalid client signature on policy.")
        except Exception as e:
            log.error(f"Signature verification failed with unexpected error: {e}")
            raise HTTPException(status_code=500, detail=f"Policy signature verification failed: {e}")

        
        policy_content = decrypted_policy_bytes.decode('utf-8')
        log.info(f"Successfully received and verified policy update:\n--- POLICY START ---\n{policy_content}\n--- POLICY END ---")
        print(f"\n--- Received Policy Update ---\n{policy_content}\n-----------------------------")

        
        response_status = {"status": "Policy update received and verified successfully."}
        response_payload_bytes = json.dumps(response_status).encode('utf-8')

        
        server_signature = sign_message(response_payload_bytes, server_sign_sk, SERVER_SIGN_ALGO)
        log.debug("Server response signed.")

        
        resp_nonce_bytes, resp_ciphertext_bytes = encrypt_aes_gcm(session_key, response_payload_bytes)
        log.debug("Server response encrypted.")

        
        return {
            "nonce_b64": base64.b64encode(resp_nonce_bytes).decode('utf-8'),
            "ciphertext_b64": base64.b64encode(resp_ciphertext_bytes).decode('utf-8'),
            "signature_b64": base64.b64encode(server_signature).decode('utf-8')
        }

    
    except HTTPException as http_exc:
        
        raise http_exc
    except (ValueError, TypeError, base64.binascii.Error) as e: 
         
         log.error(f"Error decoding request data: {e}")
         raise HTTPException(status_code=400, detail=f"Invalid request format or base64 encoding: {e}")
    except Exception as e:
        log.exception("Unexpected error processing /policy-update:")
        raise HTTPException(status_code=500, detail="Internal server error during policy update.")


class ServerKeysResponse(BaseModel):
    server_kem_public_key_b64: str
    server_sign_public_key_b64: str

@app.get("/keys", response_model=ServerKeysResponse)
def get_server_public_keys():
    """Returns the server's public KEM and signing keys."""
    log.info("Request received for /keys endpoint.")
    if not server_kem_pk or not server_sign_pk:
        # This should not happen if startup initialization worked
        log.error("Server keys are not initialized. Cannot serve public keys.")
        raise HTTPException(status_code=503, detail="Server keys unavailable.")

    try:
        kem_pk_b64 = base64.b64encode(server_kem_pk).decode('utf-8')
        sign_pk_b64 = base64.b64encode(server_sign_pk).decode('utf-8')
        log.info("Sending server public keys.")
        return ServerKeysResponse(
            server_kem_public_key_b64=kem_pk_b64,
            server_sign_public_key_b64=sign_pk_b64
        )
    except Exception as e:
        log.exception("Error encoding server public keys:")
        raise HTTPException(status_code=500, detail="Error preparing server keys.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    print("Starting MCP Development Server...")
    uvicorn.run(app, host="127.0.0.1", port=8000) 