import logging
from urllib.parse import urljoin
import click
import typer
import json
import os
import sys
from typing import Optional
from pathlib import Path
import base64
import requests
from cryptography.exceptions import InvalidSignature, InvalidTag

from .mcp_client import MCPClient, MCPRequest, MCPResponse
from .pqc_utils import generate_key_pair, load_public_key, load_key_pair, ALGORITHMS
from .config_utils import (
    save_key_pair_to_files,
    load_key_pair_from_files,
    get_key_dir,
    DEFAULT_SERVER_URL,
    DEFAULT_KEY_DIR,
    ensure_key_dir_exists,
    load_config,
    get_server_url,
    fetch_and_save_server_keys
)
from src import pqc_utils

app = typer.Typer()

get_key_dir().mkdir(parents=True, exist_ok=True)

client_kem_algo = ALGORITHMS["kem"]
client_sign_algo = ALGORITHMS["sig"]
server_kem_pub_file = get_key_dir() / "server_kem.pub"
server_sign_pub_file = get_key_dir() / "server_sign.pub"
client_kem_key_pair_files = (
    get_key_dir() / "client_kem.pub",
    get_key_dir() / "client_kem.sec",
)
client_sign_key_pair_files = (
    get_key_dir() / "client_sign.pub",
    get_key_dir() / "client_sign.sec",
)

log = logging.getLogger(__name__)

def initialize_client(config: dict, server_url_override: Optional[str] = None) -> Optional[dict]:
    """Initializes the MCPClient state, handling key loading/generation and server key fetching.

    Args:
        config: The loaded configuration dictionary.
        server_url_override: A server URL provided via CLI, overrides config.

    Returns:
        A dictionary containing the initialized MCPClient instance and client keys,
        or None if initialization fails.
    """
    log.info("Initializing MCP Client State...")

    key_dir = get_key_dir(config)
    ensure_key_dir_exists(key_dir)

    server_url = server_url_override or get_server_url(config)
    if not server_url:
        log.error("MCP Server URL is not configured and not provided.")
        print("Error: Server URL missing in config.yaml and --server-url option.")
        return None

    log.info(f"Using Key Directory: {key_dir}")
    log.info(f"Target Server URL: {server_url}")

    server_kem_pub_file = key_dir / "server_kem.pub"
    server_sign_pub_file = key_dir / "server_sign.pub"
    client_kem_pub_file, client_kem_sec_file = key_dir / "client_kem.pub", key_dir / "client_kem.sec"
    client_sign_pub_file, client_sign_sec_file = key_dir / "client_sign.pub", key_dir / "client_sign.sec"

    try:
        log.debug("Attempting to load client KEM keys...")
        client_kem_pk_bytes, client_kem_sk_bytes = load_key_pair_from_files(
            client_kem_pub_file, client_kem_sec_file
        )
        log.info(f"Client KEM keys loaded from {key_dir}")
    except FileNotFoundError:
        log.info("Client KEM keys not found. Generating new keys...")
        try:
            client_kem_pk_bytes, client_kem_sk_bytes = generate_key_pair(client_kem_algo)
            save_key_pair_to_files(
                client_kem_pk_bytes, client_kem_sk_bytes, client_kem_pub_file, client_kem_sec_file
            )
            log.info(f"Client KEM keys generated and saved to {key_dir}")
        except (pqc_utils.PQCError, IOError) as e:
            log.exception(f"Failed to generate or save client KEM keys: {e}")
            print(f"Error: Failed to generate/save client KEM keys: {e}")
            return None
    except (IOError, pqc_utils.PQCError) as e:
        log.exception(f"Failed to load client KEM keys: {e}")
        print(f"Error: Failed to load client KEM keys: {e}")
        return None

    try:
        log.debug("Attempting to load client signing keys...")
        client_sign_pk_bytes, client_sign_sk_bytes = load_key_pair_from_files(
            client_sign_pub_file, client_sign_sec_file
        )
        log.info(f"Client signing keys loaded from {key_dir}")
    except FileNotFoundError:
        log.info("Client signing keys not found. Generating new keys...")
        try:
            client_sign_pk_bytes, client_sign_sk_bytes = generate_key_pair(client_sign_algo)
            save_key_pair_to_files(
                client_sign_pk_bytes, client_sign_sk_bytes, client_sign_pub_file, client_sign_sec_file
            )
            log.info(f"Client signing keys generated and saved to {key_dir}")
        except (pqc_utils.PQCError, IOError) as e:
            log.exception(f"Failed to generate or save client signing keys: {e}")
            print(f"Error: Failed to generate/save client signing keys: {e}")
            return None
    except (IOError, pqc_utils.PQCError) as e:
        log.exception(f"Failed to load client signing keys: {e}")
        print(f"Error: Failed to load client signing keys: {e}")
        return None

    try:
        log.debug("Attempting to load server public keys...")
        server_kem_pk_bytes = load_public_key(server_kem_pub_file)
        server_sign_pk_bytes = load_public_key(server_sign_pub_file)
        log.info(f"Server public keys loaded from {key_dir}")
    except FileNotFoundError:
        log.warning(
            f"Server public keys ({server_kem_pub_file.name}, {server_sign_pub_file.name}) "
            f"not found locally in {key_dir}. Attempting to fetch from server..."
        )
        if fetch_and_save_server_keys(server_url, key_dir, server_kem_pub_file.name, server_sign_pub_file.name):
            log.info("Successfully fetched and saved server public keys.")
            try:
                server_kem_pk_bytes = load_public_key(server_kem_pub_file)
                server_sign_pk_bytes = load_public_key(server_sign_pub_file)
            except (IOError, pqc_utils.PQCError) as e:
                 log.exception(f"Failed to load server keys even after fetching: {e}")
                 print(f"Error: Failed to load server keys after fetching: {e}")
                 return None
        else:
            log.error("Failed to fetch server public keys from the server.")
            print(f"Error: Could not find server keys locally or fetch them from {server_url}/keys.")
            print("Please ensure the server is running and keys are available, or place them manually.")
            return None
    except (IOError, pqc_utils.PQCError) as e:
        log.exception(f"Error loading server public keys: {e}")
        print(f"Error: Failed to load server public keys: {e}")
        return None

    try:
        log.debug("Initializing MCPClient instance...")
        client = MCPClient(
            server_url=server_url, # Pass the definitive server URL
            client_kem_key_pair=(client_kem_pk_bytes, client_kem_sk_bytes),
            client_sign_key_pair=(client_sign_pk_bytes, client_sign_sk_bytes),
            server_kem_public_key=server_kem_pk_bytes,
            server_sign_public_key=server_sign_pk_bytes,
        )
        log.info("MCPClient instance created.")

        return {
            "client": client,
            "kem_pk_bytes": client_kem_pk_bytes,
            "sign_sk_bytes": client_sign_sk_bytes,
            "server_url": server_url
        }

    except ValueError as e:
        log.exception(f"Failed to initialize MCPClient: {e}")
        print(f"Error: Failed to initialize MCP client (likely invalid keys): {e}")
        return None
    except Exception as e:
        log.exception(f"Unexpected error initializing MCPClient instance: {e}")
        print(f"Error: Unexpected error initializing MCP client: {e}")
        return None


@app.command()
def run_inference(
    model_id: str = typer.Argument(..., help="The ID of the model to run."),
    input_data: str = typer.Argument(
        ..., help="The input data for the model (as a string)."
    ),
    server_url: str = typer.Option(
        DEFAULT_SERVER_URL, help="URL of the target MCP server."
    ),
):
    """
    Connects to an MCP server, sends a PQC-signed inference request,
    verifies the server's attestation, and displays the result.
    """
    typer.echo(f"--- QU3 Client: Running Inference --- ")
    typer.echo(f"Using key directory: {DEFAULT_KEY_DIR}")
    

    typer.echo(f"Target Server: {server_url}")
    typer.echo(f"Model ID: {model_id}")

    config = load_config()
    client_state = None

    try:
        client_state = initialize_client(config, server_url)
        if not client_state:
            raise typer.Exit(code=1)

        client = client_state["client"]

        if not client.connect(client_state["server_url"]):
            typer.secho("Failed to connect to the server (KEM handshake failed?).", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        request = MCPRequest(
            target_server_url=client_state["server_url"], # Use the resolved URL
            model_id=model_id,
            input_data=input_data,
        )

        response = client.send_request(request)

    except RuntimeError as e:
        typer.secho(f"Fatal: Failed to initialize MCP Client: {e}", fg=typer.colors.RED)
        typer.secho("Ensure prerequisite libraries are installed and keys are accessible/generatable.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except Exception as e:
         typer.secho(f"Fatal: Unexpected error initializing MCP Client: {e}", fg=typer.colors.RED)
         raise typer.Exit(code=1)
    finally:
        # Ensure disconnection if clent was initialized
        if client_state and client_state.get("client"):
            typer.echo("Disconnecting client...") # Added user feedback
            client_state["client"].disconnect()
            typer.echo("Client disconnected.")

    if response:
        typer.echo("\n--- Received Response ---")
        fg_color = typer.colors.GREEN if response.status == 'success' else typer.colors.RED
        if response.error_message and "Attestation verification FAILED" in response.error_message:
            fg_color = typer.colors.YELLOW

        typer.secho(f"Status: {response.status}", fg=fg_color)

        if response.output_data is not None:
            try:
                typer.echo(f"Output: {json.dumps(response.output_data, indent=2)}")
            except TypeError:
                 typer.echo(f"Output (raw): {response.output_data}")
        if response.error_message:
            error_color = typer.colors.RED if fg_color != typer.colors.YELLOW else typer.colors.YELLOW
            typer.secho(f"Error Message: {response.error_message}", fg=error_color)
        if response.attestation_data:
            typer.echo(f"Attestation Data: {response.attestation_data}")
        if response.attestation_signature:
            sig_hex = response.attestation_signature.hex()
            verification_failed = fg_color == typer.colors.YELLOW
            status = "(Verification FAILED)" if verification_failed else "(Verification OK)"
            sig_color = typer.colors.RED if verification_failed else typer.colors.GREEN
            typer.echo(f"Attestation Signature: {sig_hex[:20]}... {status}", fg=sig_color)
        if response.audit_hash:
            typer.echo(f"Audit Hash: {response.audit_hash}")
    else:
        typer.secho("No response object available to display (an error likely occurred during the request).", fg=typer.colors.RED)


    typer.echo("\n--- Inference Complete ---")


@app.command()
def generate_keys(
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite existing client keys if they exist."
    )
):
    """
    Generates and saves new PQC key pairs (KEM and signing) for this client instance.

    These keys are essential for establishing secure sessions and authenticating
    requests to the MCP server.
    Does NOT affect server keys.
    """
    print(f"Generating keys in: {get_key_dir()}")

    if not force:
        if client_kem_key_pair_files[0].exists() or client_kem_key_pair_files[1].exists():
            print(
                f"Client KEM key files already exist in {get_key_dir()}. Use --force to overwrite."
            )
            raise typer.Exit(code=1)
        if client_sign_key_pair_files[0].exists() or client_sign_key_pair_files[1].exists():
            print(
                f"Client signing key files already exist in {get_key_dir()}. Use --force to overwrite."
            )
            raise typer.Exit(code=1)

    print(f"Generating client KEM key pair ({client_kem_algo})...")
    client_kem_pk, client_kem_sk = generate_key_pair(client_kem_algo)
    save_key_pair_to_files(client_kem_pk, client_kem_sk, *client_kem_key_pair_files)
    print(f"Client KEM keys generated and saved.")

    print(f"Generating client signing key pair ({client_sign_algo})...")
    client_sign_pk, client_sign_sk = generate_key_pair(client_sign_algo)
    save_key_pair_to_files(client_sign_pk, client_sign_sk, *client_sign_key_pair_files)
    print(f"Client signing keys generated and saved.")

    print("\nKey generation complete.")
    print(
        f"IMPORTANT: Ensure the corresponding server public keys ({server_kem_pub_file.name}, {server_sign_pub_file.name}) "
        f"are present in {get_key_dir()} before running inference."
    )


@app.command()
def run_agent(
    workflow: str = typer.Argument(..., help="Workflow definition (e.g., 'modelA->modelB')."),
    initial_input: str = typer.Argument(..., help="Initial JSON input data for the workflow (e.g., '{\"key\": \"value\"}')."),
    server_url: str = typer.Option(
        DEFAULT_SERVER_URL, help="URL of the target MCP server."
    ),
):
    """
    Executes a multi-step agent workflow on the MCP server.
    """
    print("--- Running Agent Workflow --- ")
    print(f"Target Server: {server_url}")
    print(f"Workflow Definition: {workflow}")
    print(f"Initial Input: {initial_input}")

    try:
        steps = [s.strip() for s in workflow.split('->') if s.strip()]
        if not steps:
            raise ValueError("Workflow definition is empty or invalid.")
        current_input_dict = json.loads(initial_input)
    except json.JSONDecodeError:
        typer.secho(f"Error: Invalid JSON for initial input data: {initial_input}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except ValueError as e:
        typer.secho(f"Error parsing workflow: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"Parsed workflow steps: {steps}")

    client_state = None
    try:
        client_state = initialize_client(server_url)
        if not client_state:
            typer.secho(f"Failed to initialize client. Check key setup and server public key availability.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        client = client_state["client"]
        resolved_server_url = client_state["server_url"]

        # Connect (KEM Handshake)
        if not client.connect(resolved_server_url):
            typer.secho(f"Failed to establish secure connection with server {resolved_server_url}. KEM handshake failed?", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        final_output = None
        workflow_failed = False
        failure_step = -1
        failure_reason = ""

        for i, model_id in enumerate(steps):
            step_num = i + 1
            typer.echo(f"\n--- Executing Step {step_num}: Model '{model_id}' ---")
            try:
                input_json_str = json.dumps(current_input_dict, indent=2)
                typer.echo(f"Input for Step {step_num}: {input_json_str}")
            except TypeError:
                 typer.echo(f"Input for Step {step_num} (raw): {current_input_dict}") 


            request = MCPRequest(
                target_server_url=resolved_server_url,
                model_id=model_id,
                input_data=current_input_dict,
            )

            response = client.send_request(request)

            
            if not response:
                typer.secho(f"Error during step {step_num} ('{model_id}'): No response object received from client library.", fg=typer.colors.RED)
                typer.secho("Workflow execution aborted.", fg=typer.colors.RED)
                raise typer.Exit(code=1)

            
            verification_failed = "verification failed" in (response.error_message or "").lower()
            verification_ok = response.attestation_signature is not None and not verification_failed
            step_status_color = typer.colors.GREEN
            if response.status != 'success':
                step_status_color = typer.colors.RED
            elif verification_failed:
                step_status_color = typer.colors.YELLOW 

            typer.secho(f"Status from Step {step_num}: {response.status}", fg=step_status_color)

            
            if response.output_data is not None:
                try:
                    output_json_str = json.dumps(response.output_data, indent=2)
                    typer.echo(f"Output from Step {step_num}: {output_json_str}")
                except TypeError:
                    typer.echo(f"Output from Step {step_num} (raw): {response.output_data}") 
            else:
                typer.echo(f"Output from Step {step_num}: <None>")

            
            if response.error_message:
                
                error_color = typer.colors.RED if step_status_color != typer.colors.YELLOW else typer.colors.YELLOW
                typer.secho(f"Error Message from Step {step_num}: {response.error_message}", fg=error_color)

            
            if response.attestation_signature:
                status_text = "(Verified OK)" if verification_ok else "(Verification FAILED)"
                sig_color = typer.colors.GREEN if verification_ok else typer.colors.RED
                typer.secho(f"Attestation Signature: {response.attestation_signature.hex()[:20]}... {status_text}", fg=sig_color)
            elif response.status == 'success': 
                 typer.secho(f"Warning: No attestation signature received for Step {step_num}.", fg=typer.colors.YELLOW)
            
            if response.status != 'success' or verification_failed:
                 typer.secho(f"Workflow execution aborted due to error or failed verification in Step {step_num} ('{model_id}').", fg=typer.colors.RED)
                 raise typer.Exit(code=1)


            
            if i < len(steps) - 1:
                if not isinstance(response.output_data, dict):
                    typer.secho(
                        f"Error: Output from Step {step_num} ('{model_id}') is not a dictionary (required for the next step's input).",
                        fg=typer.colors.RED
                    )
                    typer.secho(f"Received output type: {type(response.output_data).__name__}", fg=typer.colors.RED)
                    typer.secho("Workflow execution aborted.", fg=typer.colors.RED)
                    raise typer.Exit(code=1)
                
                current_input_dict = response.output_data
            else:
                
                final_output = response.output_data
        

        typer.echo("\n--- Workflow Execution Successful ---")
        typer.echo(f"Final Output: {final_output}")

    except (RuntimeError, typer.Exit) as e:
        if isinstance(e, typer.Exit):
            raise e 
        typer.secho(f"Fatal Client Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except Exception as e:
         typer.secho(f"An unexpected error occurred during workflow execution: {e}", fg=typer.colors.RED)
         import traceback
         traceback.print_exc()
         raise typer.Exit(code=1)
    finally:
        if client_state and client_state.get("client"):
            client_state["client"].disconnect()


@click.command('update-policy')
@click.option('--policy-file', required=True, type=click.Path(exists=True, dir_okay=False, readable=True), help="Path to the policy file.")
@click.option('--server-url', default=None, help="MCP server URL (overrides config).")
def update_policy(policy_file: str, server_url: str | None):
    """Connects to the MCP, encrypts, signs, and sends a policy update."""
    config = load_config()
    if server_url is None:
        server_url = get_server_url(config)
    if not server_url:
        log.error("Server URL not found in config and not provided via CLI.")
        print("Error: Server URL missing.")
        return

    log.info(f"Attempting to update policy using file: {policy_file}")
    log.info(f"Target server URL: {server_url}")

    mcp_client = None 
    client_state = None
    try:
        client_state = initialize_client(config, server_url)
        if not client_state:
            log.error("Failed to initialize client state.")
            print("Error: Failed to initialize MCP client.")
            return

        mcp_client = client_state["client"]
        client_sign_sk_bytes = client_state["sign_sk_bytes"]
        client_kem_pk_bytes = client_state["kem_pk_bytes"]
        resolved_server_url = client_state["server_url"]

        with open(policy_file, 'r') as f:
            policy_content = f.read()
        policy_bytes = policy_content.encode('utf-8') 

        
        
        if not mcp_client.session_key:
             log.error("Client does not have a session key. Connection likely failed.")
             print("Error: Secure session not established.")
             return

        
        log.debug("Signing policy content...")
        policy_signature_bytes = pqc_utils.sign_message(policy_bytes, client_sign_sk_bytes, client_sign_algo)
        log.debug(f"Policy signature (first 10 bytes): {policy_signature_bytes[:10].hex()}...")

        
        log.debug("Encrypting policy content...")
        nonce_bytes, ciphertext_bytes = mcp_client.encrypt_payload(policy_bytes)
        log.debug(f"Nonce (first 10 bytes): {nonce_bytes[:10].hex()}...")
        log.debug(f"Ciphertext (first 10 bytes): {ciphertext_bytes[:10].hex()}...")

        
        request_data = {
            
            "client_kem_pub_key_b64": base64.b64encode(client_kem_pk_bytes).decode('utf-8'),
            "nonce_b64": base64.b64encode(nonce_bytes).decode('utf-8'),
            "ciphertext_b64": base64.b64encode(ciphertext_bytes).decode('utf-8'),
            "signature_b64": base64.b64encode(policy_signature_bytes).decode('utf-8')
        }

        policy_endpoint = urljoin(resolved_server_url.rstrip('/') + '/', "policy-update") # Use resolved URL
        log.info(f"Sending policy update to {policy_endpoint}")
        print(f"Sending policy update ({len(policy_bytes)} bytes) to {policy_endpoint}...")

        response = mcp_client.session.post(policy_endpoint, json=request_data, timeout=30) 
        response.raise_for_status() 
        log.info(f"Received response from server (Status: {response.status_code}).")

        response_data = response.json()

        
        log.debug("Processing server response...")
        resp_nonce_b64 = response_data.get('nonce_b64')
        resp_ciphertext_b64 = response_data.get('ciphertext_b64')
        resp_signature_b64 = response_data.get('signature_b64')

        if not all([resp_nonce_b64, resp_ciphertext_b64, resp_signature_b64]):
            log.error("Incomplete response received from server.")
            print("Error: Incomplete response from server.")
            return

        resp_nonce_bytes = base64.b64decode(resp_nonce_b64)
        resp_ciphertext_bytes = base64.b64decode(resp_ciphertext_b64)
        resp_signature_bytes = base64.b64decode(resp_signature_b64)

        log.debug(f"Response nonce (first 10 bytes): {resp_nonce_bytes[:10].hex()}...")
        log.debug(f"Response ciphertext (first 10 bytes): {resp_ciphertext_bytes[:10].hex()}...")
        log.debug(f"Response signature (first 10 bytes): {resp_signature_bytes[:10].hex()}...")

        try:
            
            decrypted_response_payload_bytes = mcp_client.decrypt_payload(resp_nonce_bytes, resp_ciphertext_bytes)
            log.debug("Server response decrypted.")
            
            server_status_message_str = decrypted_response_payload_bytes.decode('utf-8')
            log.info(f"Decrypted server status message: {server_status_message_str}")

            server_sign_pk_bytes = mcp_client.server_sign_pk_bytes 
            if not server_sign_pk_bytes:
                 log.error("Server signing public key not available. Cannot verify response.")
                 print("Error: Cannot verify server response (missing server public key).")
                 return

            log.debug("Verifying server signature...")
            pqc_utils.verify_signature(decrypted_response_payload_bytes, resp_signature_bytes, server_sign_pk_bytes, client_sign_algo)
            log.info("Server response signature VERIFIED successfully.")
            print(f"Server response signature VERIFIED.")

            
            try:
                status_json = json.loads(server_status_message_str)
                print(f"Server status: {status_json.get('status', server_status_message_str)}")
            except json.JSONDecodeError:
                 print(f"Server status (raw): {server_status_message_str}") 


        except (InvalidTag, ValueError) as e:
            log.error(f"Failed to decrypt server response: {e}")
            print("Error: Failed to decrypt the server's response. It might be corrupted or the session key is mismatched.")
        except InvalidSignature:
            log.error("Server response signature verification FAILED.")
            print("Error: Server response signature verification failed! The response may be tampered with or from an impostor.")
        except Exception as e: 
            log.error(f"Error processing decrypted server response: {e}")
            print(f"Error: Failed to process the server's decrypted response: {e}")


    except requests.exceptions.ConnectionError as e:
        log.error(f"Connection error during policy update: {e}")
        print(f"Error: Could not connect to the server at {server_url}.")
    except requests.exceptions.Timeout:
        log.error(f"Request timed out connecting to {server_url}")
        print("Error: The request to the server timed out.")
    except requests.exceptions.RequestException as e:
        log.error(f"Network error during policy update: {e}")
        print(f"Error: Network error communicating with the server: {e}")
    except FileNotFoundError:
        log.error(f"Policy file not found: {policy_file}")
        print(f"Error: Policy file not found at {policy_file}")
    except pqc_utils.PQCSignatureException as e:
        log.error(f"PQC signing error: {e}")
        print(f"Error: Failed to sign the policy content: {e}")
    except (pqc_utils.PQCEncryptionException, ValueError, TypeError) as e: 
         log.error(f"Encryption/Encoding error: {e}")
         print(f"Error: Failed to encrypt or encode the policy content: {e}")
    except Exception as e:
        log.exception("An unexpected error occurred during policy update:") 
        print(f"An unexpected error occurred: {e}")
    finally:
        if client_state and client_state.get("client"):
            client = client_state["client"]
            if client._is_connected:
                try:
                    client.disconnect()
                    log.info("Client disconnected.")
                except Exception as e:
                     log.error(f"Error during client disconnection: {e}")


if __name__ == "__main__":
    app()