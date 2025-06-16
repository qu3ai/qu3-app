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
        
        # Text Analysis Models
        elif model_id == "sentiment_analysis":
            text = processed_input_data.get("text")
            if isinstance(text, str) and text.strip():
                try:
                    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
                    analyzer = SentimentIntensityAnalyzer()
                    scores = analyzer.polarity_scores(text)
                    
                    # Determine overall sentiment based on compound score
                    compound = scores['compound']
                    if compound >= 0.05:
                        sentiment = "positive"
                    elif compound <= -0.05:
                        sentiment = "negative"
                    else:
                        sentiment = "neutral"
                    
                    # Calculate confidence based on compound score magnitude
                    confidence = abs(compound)
                    if confidence < 0.05:
                        confidence = 0.1  # Low confidence for neutral
                    
                    output_data = {
                        "sentiment": sentiment,
                        "confidence": round(confidence, 3),
                        "compound_score": round(compound, 3),
                        "positive_score": round(scores['pos'], 3),
                        "negative_score": round(scores['neg'], 3),
                        "neutral_score": round(scores['neu'], 3),
                        "text_length": len(text),
                        "analysis_method": "VADER"
                    }
                except ImportError:
                    # Fallback to basic analysis if VADER not available
                    output_data = {
                        "sentiment": "neutral",
                        "confidence": 0.1,
                        "error": "VADER sentiment analysis not available",
                        "analysis_method": "fallback"
                    }
            else:
                status = "error"
                error_message = "Invalid input for sentiment_analysis: 'text' field must be a non-empty string."
                
        elif model_id == "keyword_extraction":
            text = processed_input_data.get("text")
            if isinstance(text, str) and text.strip():
                import re
                from collections import Counter
                import math
                
                # Remove punctuation and convert to lowercase
                words = re.findall(r'\b[a-zA-Z]{2,}\b', text.lower())
                
                # Comprehensive stop words list
                stop_words = {
                    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "her", "was", "one", "our", "out", "day", "get", "has", "him", "his", "how", "man", "new", "now", "old", "see", "two", "way", "who", "boy", "did", "its", "let", "put", "say", "she", "too", "use", "may", "come", "could", "each", "even", "find", "from", "have", "here", "into", "just", "like", "look", "make", "more", "most", "only", "over", "such", "take", "than", "that", "them", "well", "were", "what", "when", "will", "with", "would", "your", "this", "they", "been", "their", "said", "each", "which", "there", "time", "very", "after", "first", "never", "these", "think", "where", "being", "every", "great", "might", "shall", "still", "those", "under", "while"
                }
                
                # Filter out stop words and short words
                filtered_words = [word for word in words if word not in stop_words and len(word) >= 3]
                
                if not filtered_words:
                    output_data = {
                        "keywords": [],
                        "total_words": len(words),
                        "unique_words": 0,
                        "filtered_words": 0,
                        "analysis_method": "frequency_based"
                    }
                else:
                    # Count word frequency
                    word_counts = Counter(filtered_words)
                    total_filtered = len(filtered_words)
                    
                    # Calculate TF-IDF-like scores (simplified)
                    keywords_with_scores = []
                    for word, count in word_counts.items():
                        tf = count / total_filtered  # Term frequency
                        # Simple IDF approximation based on word length and frequency
                        idf = math.log(total_filtered / count) + (len(word) / 10)
                        score = tf * idf
                        keywords_with_scores.append({
                            "word": word,
                            "frequency": count,
                            "tf_score": round(tf, 4),
                            "relevance_score": round(score, 4)
                        })
                    
                    # Sort by relevance score and get top 10
                    keywords_with_scores.sort(key=lambda x: x["relevance_score"], reverse=True)
                    top_keywords = keywords_with_scores[:10]
                    
                    output_data = {
                        "keywords": top_keywords,
                        "total_words": len(words),
                        "unique_words": len(set(words)),
                        "filtered_words": len(filtered_words),
                        "unique_filtered": len(set(filtered_words)),
                        "analysis_method": "tf_idf_based"
                    }
            else:
                status = "error"
                error_message = "Invalid input for keyword_extraction: 'text' field must be a non-empty string."
        
        # Data Processing Models
        elif model_id == "json_formatter":
            data = processed_input_data.get("data")
            if data is not None:
                try:
                    # If data is a string, try to parse it as JSON
                    if isinstance(data, str):
                        import json
                        parsed_data = json.loads(data)
                    else:
                        parsed_data = data
                    
                    # Format with proper indentation
                    formatted_json = json.dumps(parsed_data, indent=2, sort_keys=True)
                    output_data = {
                        "formatted_json": formatted_json,
                        "is_valid": True,
                        "size_bytes": len(formatted_json)
                    }
                except (json.JSONDecodeError, TypeError) as e:
                    output_data = {
                        "formatted_json": None,
                        "is_valid": False,
                        "error": str(e)
                    }
            else:
                status = "error"
                error_message = "Invalid input for json_formatter: 'data' field is required."
                
        elif model_id == "csv_analyzer":
            csv_data = processed_input_data.get("csv_data")
            if isinstance(csv_data, str):
                try:
                    import csv
                    from io import StringIO
                    
                    # Parse CSV data
                    csv_reader = csv.reader(StringIO(csv_data))
                    rows = list(csv_reader)
                    
                    if not rows:
                        output_data = {"error": "Empty CSV data"}
                    else:
                        headers = rows[0] if rows else []
                        data_rows = rows[1:] if len(rows) > 1 else []
                        
                        # Basic analysis
                        analysis = {
                            "total_rows": len(data_rows),
                            "total_columns": len(headers),
                            "headers": headers,
                            "sample_data": data_rows[:3] if data_rows else [],
                            "column_stats": {}
                        }
                        
                        # Analyze each column
                        for i, header in enumerate(headers):
                            column_data = [row[i] if i < len(row) else "" for row in data_rows]
                            non_empty = [val for val in column_data if val.strip()]
                            
                            analysis["column_stats"][header] = {
                                "non_empty_count": len(non_empty),
                                "empty_count": len(column_data) - len(non_empty),
                                "sample_values": non_empty[:3]
                            }
                        
                        output_data = analysis
                except Exception as e:
                    output_data = {"error": f"CSV parsing error: {str(e)}"}
            else:
                status = "error"
                error_message = "Invalid input for csv_analyzer: 'csv_data' field must be a string."
        
        # Code Utility Models
        elif model_id == "code_formatter":
            code = processed_input_data.get("code")
            language = processed_input_data.get("language", "python")
            
            if isinstance(code, str):
                # Simple code formatting (basic indentation)
                lines = code.split('\n')
                formatted_lines = []
                indent_level = 0
                
                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        formatted_lines.append("")
                        continue
                    
                    # Decrease indent for closing brackets/keywords
                    if any(stripped.startswith(keyword) for keyword in ['end', '}', ')', ']', 'else:', 'elif', 'except:', 'finally:']):
                        indent_level = max(0, indent_level - 1)
                    
                    # Add indentation
                    formatted_lines.append("    " * indent_level + stripped)
                    
                    # Increase indent for opening brackets/keywords
                    if any(stripped.endswith(char) for char in ['{', '(', '[']) or any(stripped.endswith(keyword) for keyword in [':', 'then', 'do']):
                        indent_level += 1
                
                output_data = {
                    "formatted_code": '\n'.join(formatted_lines),
                    "language": language,
                    "original_lines": len(lines),
                    "formatted_lines": len(formatted_lines)
                }
            else:
                status = "error"
                error_message = "Invalid input for code_formatter: 'code' field must be a string."
                
        elif model_id == "code_validator":
            code = processed_input_data.get("code")
            language = processed_input_data.get("language", "python")
            
            if isinstance(code, str):
                issues = []
                
                # Basic validation checks
                if language.lower() == "python":
                    # Check for common Python issues
                    lines = code.split('\n')
                    for i, line in enumerate(lines, 1):
                        if line.strip():
                            # Check for mixed tabs and spaces
                            if '\t' in line and '    ' in line:
                                issues.append(f"Line {i}: Mixed tabs and spaces")
                            
                            # Check for missing colons
                            stripped = line.strip()
                            if any(stripped.startswith(keyword) for keyword in ['if ', 'for ', 'while ', 'def ', 'class ', 'try', 'except', 'else', 'elif']):
                                if not stripped.endswith(':'):
                                    issues.append(f"Line {i}: Missing colon after {stripped.split()[0]}")
                
                # Try to compile/parse if possible
                syntax_valid = True
                syntax_error = None
                
                if language.lower() == "python":
                    try:
                        compile(code, '<string>', 'exec')
                    except SyntaxError as e:
                        syntax_valid = False
                        syntax_error = str(e)
                        issues.append(f"Syntax Error: {syntax_error}")
                
                output_data = {
                    "is_valid": syntax_valid and len(issues) == 0,
                    "syntax_valid": syntax_valid,
                    "issues": issues,
                    "language": language,
                    "lines_checked": len(code.split('\n'))
                }
            else:
                status = "error"
                error_message = "Invalid input for code_validator: 'code' field must be a string."
        
        # Mathematical Models
        elif model_id == "math_calculator":
            expression = processed_input_data.get("expression")
            if isinstance(expression, str):
                try:
                    # Safe evaluation of mathematical expressions
                    import re
                    import math
                    
                    # Only allow safe mathematical operations
                    allowed_chars = set('0123456789+-*/().^ ')
                    allowed_functions = ['sin', 'cos', 'tan', 'log', 'sqrt', 'abs', 'pow']
                    
                    # Basic safety check
                    if all(c in allowed_chars or c.isalpha() for c in expression):
                        # Replace ^ with **
                        safe_expr = expression.replace('^', '**')
                        
                        # Create safe namespace
                        safe_dict = {
                            "__builtins__": {},
                            "sin": math.sin, "cos": math.cos, "tan": math.tan,
                            "log": math.log, "sqrt": math.sqrt, "abs": abs,
                            "pow": pow, "pi": math.pi, "e": math.e
                        }
                        
                        result = eval(safe_expr, safe_dict)
                        output_data = {
                            "result": result,
                            "expression": expression,
                            "is_valid": True
                        }
                    else:
                        output_data = {
                            "result": None,
                            "expression": expression,
                            "is_valid": False,
                            "error": "Expression contains invalid characters"
                        }
                except Exception as e:
                    output_data = {
                        "result": None,
                        "expression": expression,
                        "is_valid": False,
                        "error": str(e)
                    }
            else:
                status = "error"
                error_message = "Invalid input for math_calculator: 'expression' field must be a string."
                
        elif model_id == "statistics_analyzer":
            numbers = processed_input_data.get("numbers")
            if isinstance(numbers, list) and all(isinstance(x, (int, float)) for x in numbers):
                if len(numbers) > 0:
                    import statistics
                    
                    try:
                        output_data = {
                            "count": len(numbers),
                            "sum": sum(numbers),
                            "mean": statistics.mean(numbers),
                            "median": statistics.median(numbers),
                            "min": min(numbers),
                            "max": max(numbers),
                            "range": max(numbers) - min(numbers),
                            "std_dev": statistics.stdev(numbers) if len(numbers) > 1 else 0,
                            "variance": statistics.variance(numbers) if len(numbers) > 1 else 0
                        }
                    except Exception as e:
                        output_data = {"error": f"Statistics calculation error: {str(e)}"}
                else:
                    output_data = {"error": "Empty numbers list"}
            else:
                status = "error"
                error_message = "Invalid input for statistics_analyzer: 'numbers' field must be a list of numbers."
        
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


class ModelInfo(BaseModel):
    id: str
    name: str
    description: str
    category: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    example_input: Dict[str, Any]
    example_output: Dict[str, Any]

class ModelsResponse(BaseModel):
    models: list[ModelInfo]
    total_count: int

@app.get("/models", response_model=ModelsResponse)
def get_available_models():
    """Returns information about all available models."""
    log.info("Request received for /models endpoint.")
    
    models = [
        ModelInfo(
            id="model_caps",
            name="Text Capitalizer",
            description="Converts input text to uppercase",
            category="text_processing",
            input_schema={"text": "string (required)"},
            output_schema={"capitalized_text": "string"},
            example_input={"text": "hello world"},
            example_output={"capitalized_text": "HELLO WORLD"}
        ),
        ModelInfo(
            id="model_reverse",
            name="Text Reverser",
            description="Reverses the input text character by character",
            category="text_processing",
            input_schema={"text": "string (required)"},
            output_schema={"reversed_text": "string"},
            example_input={"text": "hello world"},
            example_output={"reversed_text": "dlrow olleh"}
        ),
        ModelInfo(
            id="sentiment_analysis",
            name="Sentiment Analyzer",
            description="Analyzes the sentiment of input text (positive, negative, neutral)",
            category="text_analysis",
            input_schema={"text": "string (required)"},
            output_schema={
                "sentiment": "string (positive|negative|neutral)",
                "confidence": "float (0.0-1.0)",
                "positive_indicators": "integer",
                "negative_indicators": "integer"
            },
            example_input={"text": "I love this amazing product!"},
            example_output={
                "sentiment": "positive",
                "confidence": 0.7,
                "positive_indicators": 2,
                "negative_indicators": 0
            }
        ),
        ModelInfo(
            id="keyword_extraction",
            name="Keyword Extractor",
            description="Extracts important keywords from text with frequency analysis",
            category="text_analysis",
            input_schema={"text": "string (required)"},
            output_schema={
                "keywords": "array of {word: string, frequency: integer}",
                "total_words": "integer",
                "unique_words": "integer"
            },
            example_input={"text": "Python programming is great for data analysis and machine learning"},
            example_output={
                "keywords": [{"word": "python", "frequency": 1}, {"word": "programming", "frequency": 1}],
                "total_words": 10,
                "unique_words": 9
            }
        ),
        ModelInfo(
            id="json_formatter",
            name="JSON Formatter",
            description="Formats and validates JSON data with proper indentation",
            category="data_processing",
            input_schema={"data": "string or object (required)"},
            output_schema={
                "formatted_json": "string",
                "is_valid": "boolean",
                "size_bytes": "integer"
            },
            example_input={"data": '{"name":"John","age":30}'},
            example_output={
                "formatted_json": "{\n  \"age\": 30,\n  \"name\": \"John\"\n}",
                "is_valid": True,
                "size_bytes": 32
            }
        ),
        ModelInfo(
            id="csv_analyzer",
            name="CSV Analyzer",
            description="Analyzes CSV data structure and provides statistics",
            category="data_processing",
            input_schema={"csv_data": "string (required)"},
            output_schema={
                "total_rows": "integer",
                "total_columns": "integer",
                "headers": "array of strings",
                "sample_data": "array of arrays",
                "column_stats": "object"
            },
            example_input={"csv_data": "name,age,city\nJohn,30,NYC\nJane,25,LA"},
            example_output={
                "total_rows": 2,
                "total_columns": 3,
                "headers": ["name", "age", "city"],
                "sample_data": [["John", "30", "NYC"]],
                "column_stats": {"name": {"non_empty_count": 2, "empty_count": 0}}
            }
        ),
        ModelInfo(
            id="code_formatter",
            name="Code Formatter",
            description="Formats code with proper indentation and structure",
            category="code_utilities",
            input_schema={"code": "string (required)", "language": "string (optional, default: python)"},
            output_schema={
                "formatted_code": "string",
                "language": "string",
                "original_lines": "integer",
                "formatted_lines": "integer"
            },
            example_input={"code": "def hello():\nprint('world')", "language": "python"},
            example_output={
                "formatted_code": "def hello():\n    print('world')",
                "language": "python",
                "original_lines": 2,
                "formatted_lines": 2
            }
        ),
        ModelInfo(
            id="code_validator",
            name="Code Validator",
            description="Validates code syntax and checks for common issues",
            category="code_utilities",
            input_schema={"code": "string (required)", "language": "string (optional, default: python)"},
            output_schema={
                "is_valid": "boolean",
                "syntax_valid": "boolean",
                "issues": "array of strings",
                "language": "string",
                "lines_checked": "integer"
            },
            example_input={"code": "def hello()\nprint('world')", "language": "python"},
            example_output={
                "is_valid": False,
                "syntax_valid": False,
                "issues": ["Syntax Error: invalid syntax"],
                "language": "python",
                "lines_checked": 2
            }
        ),
        ModelInfo(
            id="math_calculator",
            name="Math Calculator",
            description="Evaluates mathematical expressions safely",
            category="mathematics",
            input_schema={"expression": "string (required)"},
            output_schema={
                "result": "number or null",
                "expression": "string",
                "is_valid": "boolean",
                "error": "string (optional)"
            },
            example_input={"expression": "2 + 3 * 4"},
            example_output={
                "result": 14,
                "expression": "2 + 3 * 4",
                "is_valid": True
            }
        ),
        ModelInfo(
            id="statistics_analyzer",
            name="Statistics Analyzer",
            description="Calculates statistical measures for numerical data",
            category="mathematics",
            input_schema={"numbers": "array of numbers (required)"},
            output_schema={
                "count": "integer",
                "sum": "number",
                "mean": "number",
                "median": "number",
                "min": "number",
                "max": "number",
                "range": "number",
                "std_dev": "number",
                "variance": "number"
            },
            example_input={"numbers": [1, 2, 3, 4, 5]},
            example_output={
                "count": 5,
                "sum": 15,
                "mean": 3.0,
                "median": 3,
                "min": 1,
                "max": 5,
                "range": 4,
                "std_dev": 1.58,
                "variance": 2.5
            }
        )
    ]
    
    return ModelsResponse(models=models, total_count=len(models))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    print("Starting MCP Development Server...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
