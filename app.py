# app.py
import os
import json
import asyncio
from flask import Flask, request, jsonify
import traceback
import base64
import time  # For managing TTL on derived keys

# Cryptography imports for X25519 and HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import MODEL_PROVIDER_MAP, DEFAULT_MODEL_FOR_PROVIDER

# Make DH_DERIVED_KEYS accessible to auth_handler if it's defined here
# Alternatively, use a shared cache like Redis.
# from auth_handler import gateway_auth_required, DH_DERIVED_KEYS # If moving DH_DERIVED_KEYS to auth_handler
from auth_handler import gateway_auth_required

from request_mapper import map_request_to_provider

# from response_mapper import normalize_response # Optional

# Import client functions
from llm_clients.openai_client import call_openai_model_unified, client_openai
from llm_clients.vertexai_client import (
    call_gemini_model_unified,
    client_vertexai,
)

app = Flask(__name__)

# --- Server's X25519 Key Pair (generated on startup) ---
# In a production environment, consider loading these from a secure configuration
# or using a Hardware Security Module (HSM).
# For simplicity here, we generate it when the app starts.
SERVER_X25519_PRIVATE_KEY = x25519.X25519PrivateKey.generate()
SERVER_X25519_PUBLIC_KEY_BYTES = SERVER_X25519_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
)
SERVER_X25519_PUBLIC_KEY_B64 = base64.b64encode(SERVER_X25519_PUBLIC_KEY_BYTES).decode(
    "utf-8"
)
print(f"Server X25519 Public Key (b64): {SERVER_X25519_PUBLIC_KEY_B64}")

from auth_handler import DH_DERIVED_KEYS, DH_SESSION_TTL_SECONDS


# Global error handler for uncaught exceptions
@app.errorhandler(Exception)
def handle_unexpected_error(e):
    traceback.print_exc()  # Log the full stack trace
    response = jsonify(
        {"error": "An unexpected internal server error occurred.", "details": str(e)}
    )
    response.status_code = 500
    return response


@app.route("/v1/dh/initiate", methods=["POST"])
async def initiate_dh_exchange():
    """
    Handles the initiation of a Diffie-Hellman key exchange.
    Client sends its X25519 public key, server responds with its X25519 public key.
    Both parties then derive a shared secret, from which a symmetric key is derived.
    """
    request_json = request.get_json()
    if not request_json:
        return jsonify({"error": "Request body is empty or not in JSON format."}), 400

    client_public_key_b64 = request_json.get("client_public_key")
    if not client_public_key_b64 or not isinstance(client_public_key_b64, str):
        return (
            jsonify(
                {
                    "error": "Missing or invalid 'client_public_key' (must be a base64 string)."
                }
            ),
            400,
        )

    try:
        client_public_key_bytes = base64.b64decode(client_public_key_b64)
        if len(client_public_key_bytes) != 32:  # X25519 public keys are 32 bytes
            return (
                jsonify(
                    {"error": "Invalid client public key length. Expected 32 bytes."}
                ),
                400,
            )

        # Load the client's public key
        client_x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
            client_public_key_bytes
        )
    except (base64.binascii.Error, ValueError) as e:
        return (
            jsonify(
                {"error": f"Invalid base64 encoding for client public key: {str(e)}"}
            ),
            400,
        )
    except Exception as e:  # Catch errors from from_public_bytes if key is invalid
        return jsonify({"error": f"Invalid client public key content: {str(e)}"}), 400

    # Perform X25519 key exchange to get the shared secret
    try:
        shared_secret_bytes = SERVER_X25519_PRIVATE_KEY.exchange(
            client_x25519_public_key
        )
    except Exception as e:  # Should not happen with valid keys, but good to be cautious
        traceback.print_exc()
        return jsonify({"error": f"Key exchange failed: {str(e)}"}), 500

    # Derive a symmetric key from the shared secret using HKDF
    # This derived key will be used for MACs or other symmetric operations in subsequent requests
    derived_symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # e.g., 32 bytes for HMAC-SHA256 key or AES-256
        salt=None,  # Optional: a non-secret salt.
        info=b"llm-gateway-dh-symmetric-key-v1",  # Context-specific info string
    ).derive(shared_secret_bytes)

    # Store the derived key, associated with the client's public key (acting as a session identifier)
    # This is a simplified in-memory store with basic TTL logic.
    # convert to base64
    derived_symmetric_key_b64 = base64.b64encode(derived_symmetric_key).decode("utf-8")
    print(derived_symmetric_key_b64)
    current_ts = time.time()
    DH_DERIVED_KEYS[derived_symmetric_key_b64] = {
        "public_key": client_public_key_b64,
        "timestamp": current_ts,
    }

    # Basic cleanup of expired keys (can be improved with a background task)
    keys_to_delete = [
        key_id
        for key_id, data in DH_DERIVED_KEYS.items()
        if current_ts - data.get("timestamp", 0) > DH_SESSION_TTL_SECONDS
    ]
    for key_id in keys_to_delete:
        del DH_DERIVED_KEYS[key_id]

    app.logger.info(
        f"DH exchange initiated with client_pk_b64: {client_public_key_b64[:10]}... Stored derived key."
    )

    return (
        jsonify(
            {
                "server_public_key": SERVER_X25519_PUBLIC_KEY_B64,
                # The client_public_key_b64 can serve as the session_id for subsequent requests
                # "session_id": client_public_key_b64
            }
        ),
        200,
    )


@app.route("/v1/chat/completions", methods=["POST"])
@gateway_auth_required  # This decorator will handle authentication
async def handle_chat_completions():
    # ... (rest of your existing handle_chat_completions function remains the same) ...
    # ... This function will now be protected by auth_handler.py, which needs ...
    # ... to implement logic for AuthMethod.DH_KEY_EXCHANGE using DH_DERIVED_KEYS ...
    request_data = request.get_json()
    if not request_data:
        return jsonify({"error": "Request body is empty or not in JSON format."}), 400

    model_requested = request_data.get("model")
    if not model_requested:
        return jsonify({"error": "Missing 'model' field in request."}), 400

    provider_name = MODEL_PROVIDER_MAP.get(model_requested)
    if not provider_name:
        if model_requested.startswith("gpt-"):
            provider_name = "openai"
        elif model_requested.startswith("gemini-") or model_requested.startswith(
            "models/gemini-"
        ):
            if model_requested.startswith("models/"):
                request_data["model"] = model_requested.split("models/")[1]
            provider_name = "vertexai"
        else:
            return (
                jsonify(
                    {
                        "error": f"Unsupported model or provider cannot be inferred: {model_requested}"
                    }
                ),
                400,
            )

    if provider_name == "openai" and not client_openai:
        return jsonify({"error": "OpenAI client not initialized on the server."}), 503
    if provider_name == "vertexai" and not client_vertexai:
        return (
            jsonify(
                {"error": "Vertex AI (Gemini) client not initialized on the server."}
            ),
            503,
        )

    try:
        provider_specific_params = map_request_to_provider(provider_name, request_data)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        app.logger.error(f"Error during request mapping: {e}", exc_info=True)
        return jsonify({"error": f"Error processing request data: {str(e)}"}), 400

    result = None
    try:
        if provider_name == "openai":
            result = await call_openai_model_unified(**provider_specific_params)
        elif provider_name == "vertexai":
            result = await call_gemini_model_unified(**provider_specific_params)
        else:
            return (
                jsonify({"error": "Internal configuration error: Unknown provider."}),
                500,
            )

        if result and result.get("error"):
            app.logger.error(
                f"Error from LLM client ({provider_name}): {result['error']}"
            )
            return jsonify(result), 502

        return jsonify(result)

    except ConnectionError as e:
        app.logger.error(
            f"LLM Provider ConnectionError ({provider_name}): {e}", exc_info=True
        )
        return (
            jsonify({"error": f"Connection error with {provider_name}: {str(e)}"}),
            503,
        )
    except Exception as e:
        app.logger.error(
            f"Unexpected error when calling LLM provider ({provider_name}): {e}",
            exc_info=True,
        )
        return (
            jsonify(
                {
                    "error": f"Unexpected error during model call to {provider_name}: {str(e)}"
                }
            ),
            500,
        )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 12457))
    print(
        f"Starting gateway on port {port}. For async, run with an ASGI server like Hypercorn or Uvicorn."
    )
    print(f"Example: hypercorn app:app -b 0.0.0.0:{port}")
    # To run with Hypercorn (recommended for async Flask):
    # hypercorn app:app -b 0.0.0.0:12457
    # For development, Flask's built-in server can run async routes if Werkzeug is recent enough,
    # but it will still run in a single-threaded context for the dev server.
    # app.run(debug=True, host="0.0.0.0", port=port) # Will warn about WSGI with async
