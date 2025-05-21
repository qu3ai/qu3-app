import logging
from urllib.parse import urljoin
import typer
import json
import os
import sys
from typing import Optional, Any, Dict
from pathlib import Path
import base64
import requests
from cryptography.exceptions import InvalidSignature, InvalidTag

from .mcp_client import MCPClient, MCPRequest, MCPResponse
from .pqc_utils import generate_key_pair, ALGORITHMS, sign_message, verify_signature, decrypt_aes_gcm
from .config_utils import (
    save_key_pair_to_files,
    load_key_pair_from_files,
    get_key_dir,
    load_public_key_from_file,
    DEFAULT_SERVER_URL,
    ensure_key_dir_exists,
    load_config,
    get_server_url,
    fetch_and_save_server_keys,
    get_logging_config
)
from src import pqc_utils

logging_settings = get_logging_config()
numeric_level = getattr(logging, logging_settings['level'].upper(), logging.INFO)
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

if logging_settings['file']:
    logging.basicConfig(level=numeric_level, filename=logging_settings['file'], format=log_format)
else:
    logging.basicConfig(level=numeric_level, format=log_format)

log = logging.getLogger(__name__)

app = typer.Typer()

try:
    get_key_dir().mkdir(parents=True, exist_ok=True)
except Exception as e:
    log.error(f"Failed to create key directory {get_key_dir()}: {e}")
    pass

client_kem_algo = ALGORITHMS["kem"]
client_sign_algo = ALGORITHMS["sig"]

def _load_or_generate_client_key_pair(
    key_dir: Path, 
    key_name: str, 
    algo: str, 
    force_generate: bool = False
) -> Optional[tuple[bytes, bytes]]:
    """
    Loads a client key pair (public, secret) from files if they exist,
    or generates a new pair if they don't or if force_generate is True.

    Args:
        key_dir: The directory where keys are stored.
        key_name: The base name for the key files (e.g., "client_kem").
        algo: The PQC algorithm to use for key generation.
        force_generate: If True, always generates a new key pair, overwriting existing ones.

    Returns:
        A tuple (public_key_bytes, secret_key_bytes) or None if an error occurs.
    """
    pub_path = key_dir / f"{key_name}.pub"
    sec_path = key_dir / f"{key_name}.sec"
    key_type_log_name = key_name.replace("_", " ").upper() # For logging e.g. "CLIENT KEM"

    if force_generate:
        log.info(f"Force generating new {key_type_log_name} keys in {key_dir}...")
        try:
            pk_bytes, sk_bytes = generate_key_pair(algo)
            save_key_pair_to_files(pk_bytes, sk_bytes, pub_path, sec_path)
            log.info(f"New {key_type_log_name} keys generated and saved successfully.")
            if typer.get_current_context(resilient=True):
                typer.secho(f"{key_type_log_name} keys generated and saved.", fg=typer.colors.GREEN)
            return pk_bytes, sk_bytes
        except (pqc_utils.PQCError, IOError) as e:
            log.exception(f"Failed to generate or save {key_type_log_name} keys: {e}")
            if typer.get_current_context(resilient=True):
                typer.secho(f"Error: Failed to generate/save {key_type_log_name} keys: {e}", fg=typer.colors.RED, err=True)
            return None

    try:
        log.debug(f"Attempting to load {key_type_log_name} keys from {key_dir}...")
        pk_bytes, sk_bytes = load_key_pair_from_files(pub_path, sec_path)
        log.info(f"{key_type_log_name} keys loaded from {key_dir}")
        return pk_bytes, sk_bytes
    except FileNotFoundError:
        log.info(f"{key_type_log_name} keys not found in {key_dir}. Generating new keys...")
        try:
            pk_bytes, sk_bytes = generate_key_pair(algo)
            save_key_pair_to_files(pk_bytes, sk_bytes, pub_path, sec_path)
            log.info(f"{key_type_log_name} keys generated and saved to {key_dir}")
            return pk_bytes, sk_bytes
        except (pqc_utils.PQCError, IOError) as e:
            log.exception(f"Failed to generate or save {key_type_log_name} keys after FileNotFoundError: {e}")
            if typer.get_current_context(resilient=True):
                 typer.secho(f"Error: Failed to generate/save {key_type_log_name} keys: {e}", fg=typer.colors.RED, err=True)
            return None
    except (IOError, pqc_utils.PQCError) as e:
        log.exception(f"Failed to load {key_type_log_name} keys: {e}")
        if typer.get_current_context(resilient=True):
            typer.secho(f"Error: Failed to load {key_type_log_name} keys: {e}", fg=typer.colors.RED, err=True)
        return None

def _ensure_server_public_keys(key_dir: Path, server_url: str) -> Optional[tuple[bytes, bytes]]:
    """
    Ensures server public keys (KEM and signing) are available, loading them from files
    or fetching from the server if not found.

    Args:
        key_dir: The directory where keys are stored/expected.
        server_url: The URL of the MCP server to fetch keys from if needed.

    Returns:
        A tuple (server_kem_pk_bytes, server_sign_pk_bytes) or None if an error occurs.
    """
    server_kem_pub_path = key_dir / "server_kem.pub"
    server_sign_pub_path = key_dir / "server_sign.pub"

    try:
        log.debug("Attempting to load server public keys...")
        server_kem_pk_bytes = load_public_key_from_file(server_kem_pub_path)
        server_sign_pk_bytes = load_public_key_from_file(server_sign_pub_path)
        log.info(f"Server public keys loaded from {key_dir}")
        return server_kem_pk_bytes, server_sign_pk_bytes
    except FileNotFoundError:
        log.warning(
            f"Server public keys ({server_kem_pub_path.name}, {server_sign_pub_path.name}) "
            f"not found locally in {key_dir}. Attempting to fetch from server {server_url}..."
        )
        if typer.get_current_context(resilient=True):
            typer.echo(f"Server keys not found locally, attempting to fetch from {server_url}...")

        if fetch_and_save_server_keys(server_url, key_dir, server_kem_pub_path.name, server_sign_pub_path.name):
            log.info("Successfully fetched and saved server public keys.")
            if typer.get_current_context(resilient=True):
                typer.secho("Server keys fetched and saved successfully.", fg=typer.colors.GREEN)
            try:
                server_kem_pk_bytes = load_public_key_from_file(server_kem_pub_path)
                server_sign_pk_bytes = load_public_key_from_file(server_sign_pub_path)
                log.info(f"Server public keys loaded from {key_dir} after fetching.")
                return server_kem_pk_bytes, server_sign_pk_bytes
            except (IOError, pqc_utils.PQCError, FileNotFoundError) as e:
                 log.exception(f"Failed to load server keys even after successful fetching: {e}")
                 if typer.get_current_context(resilient=True):
                     typer.secho(f"Error: Failed to load server keys after fetching: {e}", fg=typer.colors.RED, err=True)
                 return None
        else:
            log.error(f"Failed to fetch server public keys from {server_url}.")
            if typer.get_current_context(resilient=True):
                typer.secho(f"Error: Could not find server keys locally or fetch them from {server_url}/keys.", fg=typer.colors.RED, err=True)
                typer.secho("Please ensure the server is running and keys are available, or place them manually.", fg=typer.colors.YELLOW, err=True)
            return None
    except (IOError, pqc_utils.PQCError) as e:
        log.exception(f"Error loading server public keys from {key_dir}: {e}")
        if typer.get_current_context(resilient=True):
            typer.secho(f"Error: Failed to load server public keys: {e}", fg=typer.colors.RED, err=True)
        return None

def initialize_client(config: dict, server_url_override: Optional[str] = None, force_new_client_keys: bool = False) -> Optional[dict]:
    """
    Initializes the MCPClient state by loading/generating client keys,
    ensuring server public keys are available, and then creating the MCPClient instance.

    Args:
        config: The loaded configuration dictionary.
        server_url_override: A server URL provided via CLI, overrides config.
        force_new_client_keys: If True, forces regeneration of client KEM and signing keys.
                               Used by the `generate-keys` command.

    Returns:
        A dictionary containing the initialized MCPClient instance and client keys,
        or None if initialization fails.
    """
    log.info("Initializing MCP Client State...")

    key_dir = get_key_dir()
    ensure_key_dir_exists(key_dir)

    resolved_server_url = server_url_override or get_server_url()
    if not resolved_server_url:
        log.error("MCP Server URL is not configured and not provided via CLI option.")
        if typer.get_current_context(resilient=True):
             typer.secho("Error: Server URL missing. Provide via --server-url or in config.yaml.", fg=typer.colors.RED, err=True)
        return None

    log.info(f"Using Key Directory: {key_dir}")
    log.info(f"Target Server URL: {resolved_server_url}")

    client_kem_keys = _load_or_generate_client_key_pair(
        key_dir, "client_kem", client_kem_algo, force_new_client_keys
    )
    if not client_kem_keys:
        log.error("Failed to load or generate client KEM keys.")
        return None
    client_kem_pk_bytes, client_kem_sk_bytes = client_kem_keys

    client_sign_keys = _load_or_generate_client_key_pair(
        key_dir, "client_sign", client_sign_algo, force_new_client_keys
    )
    if not client_sign_keys:
        log.error("Failed to load or generate client signing keys.")
        return None
    client_sign_pk_bytes, client_sign_sk_bytes = client_sign_keys

    server_keys = _ensure_server_public_keys(key_dir, resolved_server_url)
    if not server_keys:
        log.error("Failed to load or fetch server public keys.")
        return None
    server_kem_pk_bytes, server_sign_pk_bytes = server_keys
    
    try:
        log.debug("Initializing MCPClient instance...")
        client = MCPClient(
            server_url=resolved_server_url,
            client_kem_key_pair=(client_kem_pk_bytes, client_kem_sk_bytes),
            client_sign_key_pair=(client_sign_pk_bytes, client_sign_sk_bytes),
            server_kem_public_key=server_kem_pk_bytes,
            server_sign_public_key=server_sign_pk_bytes,
        )
        log.info("MCPClient instance created.")

        return {
            "client": client,
            "client_kem_pk_bytes": client_kem_pk_bytes,
            "client_sign_sk_bytes": client_sign_sk_bytes,
            "server_url": resolved_server_url
        }

    except ValueError as e:
        log.exception(f"Failed to initialize MCPClient: {e}")
        typer.secho(f"Error: Failed to initialize MCP client (likely invalid keys): {e}", fg=typer.colors.RED, err=True)
        return None
    except Exception as e:
        log.exception(f"Unexpected error initializing MCPClient instance: {e}")
        typer.secho(f"Error: Unexpected error initializing MCP client: {e}", fg=typer.colors.RED, err=True)
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
    typer.echo(f"Using key directory: {get_key_dir()}")
    

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
            target_server_url=client_state["server_url"],
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
        if client_state and client_state.get("client"):
            typer.echo("Disconnecting client...")
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
            typer.echo(f"Attestation Signature: {sig_hex[:20]}... {status}", color=sig_color)
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
    If --force is not used, it will not overwrite existing keys of a given type
    if they are already present and loadable.
    Does NOT affect server keys.
    """
    key_dir = get_key_dir()
    ensure_key_dir_exists(key_dir)
    typer.echo(f"Managing keys in: {key_dir}")

    # Determine if we need to check for existing files (if not --force)
    # _load_or_generate_client_key_pair handles the logic of checking existence 
    # if force_generate is False.
    # However, the original command had a specific behavior: if --force was *not* used,
    # it would exit if *any* key file existed. This is slightly different from the helper,
    # which would only skip generation for the specific key type if its files exist.
    # To replicate the original behavior for the "don't overwrite without --force" check:
    if not force:
        client_kem_pub_path = key_dir / "client_kem.pub"
        client_kem_sec_path = key_dir / "client_kem.sec"
        client_sign_pub_path = key_dir / "client_sign.pub"
        client_sign_sec_path = key_dir / "client_sign.sec"

        if client_kem_pub_path.exists() or client_kem_sec_path.exists():
            typer.secho(
                f"Client KEM key files already exist in {key_dir}. Use --force to overwrite.",
                fg=typer.colors.YELLOW,
            )
        if client_sign_pub_path.exists() or client_sign_sec_path.exists():
            typer.secho(
                f"Client signing key files already exist in {key_dir}. Use --force to overwrite.",
                fg=typer.colors.YELLOW,
            )
        if (client_kem_pub_path.exists() or client_kem_sec_path.exists()) and \
           (client_sign_pub_path.exists() or client_sign_sec_path.exists()) and \
           not force: # This last check for not force is a bit redundant due to outer if, but for clarity.
             typer.secho("Both KEM and Signing keys exist. Use --force to overwrite specific keys or all keys.", fg=typer.colors.YELLOW)
             # raise typer.Exit(code=1)

    typer.echo(f"Attempting to load or generate client KEM key pair ({client_kem_algo})...")
    kem_keys = _load_or_generate_client_key_pair(key_dir, "client_kem", client_kem_algo, force_generate=force)
    if kem_keys:
        typer.secho(f"Client KEM keys processed successfully.", fg=typer.colors.GREEN)
    else:
        typer.secho(f"Failed to process client KEM keys.", fg=typer.colors.RED, err=True)
        # raise typer.Exit(code=1)


    typer.echo(f"\nAttempting to load or generate client signing key pair ({client_sign_algo})...")
    sign_keys = _load_or_generate_client_key_pair(key_dir, "client_sign", client_sign_algo, force_generate=force)
    if sign_keys:
        typer.secho(f"Client signing keys processed successfully.", fg=typer.colors.GREEN)
    else:
        typer.secho(f"Failed to process client signing keys.", fg=typer.colors.RED, err=True)
        # raise typer.Exit(code=1)

    if kem_keys and sign_keys:
        typer.echo("\nKey management complete.")
    else:
        typer.secho("\nKey management encountered errors. Please check logs.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
        
    typer.secho(
        f"IMPORTANT: Ensure the corresponding server public keys (server_kem.pub, server_sign.pub) "
        f"are present in {key_dir} before running inference.", bold=True
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
    typer.echo("--- Running Agent Workflow --- ")
    typer.echo(f"Target Server: {server_url}")
    typer.echo(f"Workflow Definition: {workflow}")
    typer.echo(f"Initial Input: {initial_input}")

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
                
                next_model_id = steps[i+1]
                transformed_input = response.output_data
                if next_model_id in ["model_caps", "model_reverse"]:
                    log.debug(f"Next model '{next_model_id}' requires specific 'text' input. Attempting transformation.")
                    if isinstance(response.output_data, dict) and len(response.output_data) == 1:
                        key, value = list(response.output_data.items())[0]
                        if isinstance(value, str):
                            transformed_input = {"text": value}
                            log.info(f"Transformed input for '{next_model_id}': mapped '{key}' to 'text'.")
                        else:
                            log.warning(f"Output from '{model_id}' is a dict with one key, but value is not a string. Cannot auto-transform for '{next_model_id}'. Passing raw output.")
                    elif isinstance(response.output_data, str):
                        transformed_input = {"text": response.output_data}
                        log.info(f"Transformed input for '{next_model_id}': used raw string output from '{model_id}' as 'text'.")
                    else:
                        log.warning(f"Output from '{model_id}' is not a single-entry dict or a string. Cannot auto-transform for '{next_model_id}'. Passing raw output: {response.output_data}")
                
                current_input_dict = transformed_input
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


@app.command("update-policy")
def update_policy(
    policy_file: Path = typer.Option(
        ..., 
        help="Path to the policy file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        writable=False,
        readable=True,
        resolve_path=True,
    ),
    server_url: Optional[str] = typer.Option(
        None, 
        "--server-url", 
        help="MCP server URL (overrides config)."
    )
):
    """Connects to the MCP, encrypts, signs, and sends a policy update."""
    config = load_config()
    resolved_server_url = server_url or get_server_url()
    
    if not resolved_server_url:
        log.error("Server URL not found in config and not provided via CLI.")
        typer.secho("Error: Server URL missing.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    log.info(f"Attempting to update policy using file: {policy_file}")
    log.info(f"Target server URL: {resolved_server_url}")

    mcp_client = None 
    client_state = None
    try:
        client_state = initialize_client(config, resolved_server_url)
        if not client_state:
            log.error("Failed to initialize client state.")
            typer.secho("Error: Failed to initialize MCP client.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        mcp_client = client_state["client"]
        client_sign_sk_bytes = client_state["client_sign_sk_bytes"]
        client_kem_pk_bytes = client_state["client_kem_pk_bytes"]

        policy_content = policy_file.read_text(encoding='utf-8')
        policy_bytes = policy_content.encode('utf-8') 
        
        if not mcp_client.connect(resolved_server_url):
            log.error("Failed to connect to the server (KEM handshake failed?).")
            typer.secho("Error: Failed to connect to the server.", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        
        if not mcp_client.session_key:
             log.error("Client does not have a session key. Connection likely failed or was not established properly.")
             typer.secho("Error: Secure session not established.", fg=typer.colors.RED)
             raise typer.Exit(code=1)
        
        log.debug("Signing policy content...")
        policy_signature_bytes = sign_message(policy_bytes, client_sign_sk_bytes, client_sign_algo)
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

        policy_endpoint = urljoin(resolved_server_url.rstrip('/') + '/', "policy-update")
        log.info(f"Sending policy update to {policy_endpoint}")
        typer.echo(f"Sending policy update ({len(policy_bytes)} bytes) to {policy_endpoint}...")

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
            typer.secho("Error: Incomplete response from server.", fg=typer.colors.RED)
            raise typer.Exit(code=1)

        resp_nonce_bytes = base64.b64decode(resp_nonce_b64)
        resp_ciphertext_bytes = base64.b64decode(resp_ciphertext_b64)
        resp_signature_bytes = base64.b64decode(resp_signature_b64)

        log.debug(f"Response nonce (first 10 bytes): {resp_nonce_bytes[:10].hex()}...")
        log.debug(f"Response ciphertext (first 10 bytes): {resp_ciphertext_bytes[:10].hex()}...")
        log.debug(f"Response signature (first 10 bytes): {resp_signature_bytes[:10].hex()}...")

        try:
            decrypted_response_payload_bytes = decrypt_aes_gcm(mcp_client.session_key, resp_nonce_bytes, resp_ciphertext_bytes)
            log.debug("Server response for policy update decrypted.")
            
            server_status_message_str = decrypted_response_payload_bytes.decode('utf-8')
            log.info(f"Decrypted server status message: {server_status_message_str}")

            server_sign_pk_bytes = mcp_client.server_sign_pk_bytes 
            if not server_sign_pk_bytes:
                 log.error("Server signing public key not available. Cannot verify response.")
                 typer.secho("Error: Cannot verify server response (missing server public key).", fg=typer.colors.RED)
                 raise typer.Exit(code=1)

            log.debug("Verifying server signature on policy update response...")
            is_server_sig_valid = verify_signature(
                decrypted_response_payload_bytes, 
                resp_signature_bytes, 
                server_sign_pk_bytes, 
                ALGORITHMS["sig"]
            )
            if is_server_sig_valid:
                log.info("Server response signature VERIFIED successfully.")
                typer.secho("Server response signature VERIFIED.", fg=typer.colors.GREEN)
            else:
                log.error("Server response signature verification FAILED (verify_signature returned False).")
                typer.secho("Error: Server response signature verification failed!", fg=typer.colors.RED)
                raise InvalidSignature("Server response signature verification failed.")


            try:
                status_json = json.loads(server_status_message_str)
                typer.echo(f"Server status: {status_json.get('status', server_status_message_str)}")
            except json.JSONDecodeError:
                 typer.echo(f"Server status (raw): {server_status_message_str}") 

        except (InvalidTag, ValueError) as e:
            log.error(f"Failed to decrypt or decode server response: {e}")
            typer.secho(f"Error: Failed to decrypt/decode server's response: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        except InvalidSignature:
            log.error("Server response signature verification FAILED.")
            typer.secho("Error: Server response signature verification failed! The response may be tampered with or from an impostor.", fg=typer.colors.RED)
            raise typer.Exit(code=1)
        except Exception as e: 
            log.error(f"Error processing decrypted server response: {e}")
            typer.secho(f"Error: Failed to process the server's decrypted response: {e}", fg=typer.colors.RED)
            raise typer.Exit(code=1)

    except requests.exceptions.ConnectionError as e:
        log.error(f"Connection error during policy update: {e}")
        typer.secho(f"Error: Could not connect to the server at {resolved_server_url}.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except requests.exceptions.Timeout:
        log.error(f"Request timed out connecting to {resolved_server_url}")
        typer.secho("Error: The request to the server timed out.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except requests.exceptions.RequestException as e:
        log.error(f"Network error during policy update: {e}")
        typer.secho(f"Error: Network error communicating with the server: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except FileNotFoundError:
        log.error(f"Policy file not found: {policy_file}")
        typer.secho(f"Error: Policy file not found at {policy_file}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except pqc_utils.PQCSignatureException as e:
        log.error(f"PQC signing error: {e}")
        typer.secho(f"Error: Failed to sign the policy content: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except (pqc_utils.PQCEncryptionException, base64.binascii.Error, ValueError, TypeError) as e: 
         log.error(f"Encryption/Encoding error: {e}")
         typer.secho(f"Error: Failed to encrypt or encode the policy content: {e}", fg=typer.colors.RED)
         raise typer.Exit(code=1)
    except Exception as e:
        log.exception("An unexpected error occurred during policy update:") 
        typer.secho(f"An unexpected error occurred: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    finally:
        if client_state and client_state.get("client"):
            client = client_state["client"]
            if client._is_connected:
                try:
                    client.disconnect()
                    log.info("Client disconnected.")
                except Exception as e:
                     log.error(f"Error during client disconnection: {e}")
                     # typer.secho(f"Warning: Error during client disconnection: {e}", fg=typer.colors.YELLOW)


if __name__ == "__main__":
    app()