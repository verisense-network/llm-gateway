import time
import base64
from hashlib import sha256
from functools import wraps
from flask import request, jsonify  # Assuming Flask context

from coincurve.keys import PublicKey
from enum import Enum
from config import GATEWAY_API_KEYS
import json
import aiofiles


class AuthMethod(Enum):
    STATIC = "static"
    SIGNED = "signed"
    DH = "dh"  # Diffie-Hellman

    @classmethod
    def get_default(cls):
        return cls.STATIC


RECENTLY_USED_NONCES = {}  # Format: {(api_key_id, nonce): timestamp_of_receipt}
NONCE_EXPIRY_SECONDS = 60 * 5  # Nonces expire after 5 minutes for replay check
TIMESTAMP_TOLERANCE_SECONDS = 500  # Allowable clock skew in seconds


# --- Placeholder for AuthMethod if not defined elsewhere ---
class AuthMethod:
    BEARER_STATIC = "bearer_static"
    BEARER_SIGNED = "bearer_signed"
    DH_KEY_EXCHANGE = "dh_key_exchange"


# --- ECDSA Signature Verification Function ---
async def verify_signed_bearer_token_ecdsa(
    signature_base64: str,
    api_key_id: str,
    client_timestamp_str: str,
    nonce: str,
    http_method: str,
    http_path: str,
    body_hash_hex: str,
    current_gateway_api_keys: dict,
):
    """
    Verifies an ECDSA secp256k1 signature with recovery ID and anti-replay.
    """
    if not all([api_key_id, client_timestamp_str, nonce, signature_base64]):
        return False, "Missing one or more required elements for signed request."

    client_config_entry = current_gateway_api_keys.get(api_key_id)
    if (
        not client_config_entry
        or not isinstance(client_config_entry, dict)
        or "public_key_hex" not in client_config_entry
    ):
        return False, f"Public key not configured for API Key ID: {api_key_id}."

    public_key_hex = client_config_entry["public_key_hex"]

    try:
        expected_public_key_bytes = bytes.fromhex(public_key_hex)
        # Validate and create PublicKey object for the expected key
        expected_pk_obj = PublicKey(expected_public_key_bytes)
    except ValueError:
        return (
            False,
            f"Invalid configured public key format for API Key ID {api_key_id}.",
        )
    except (
        Exception
    ) as e:  # Catch errors from PublicKey() constructor e.g. invalid key length
        return (
            False,
            f"Error processing configured public key for {api_key_id}: {str(e)}",
        )

    # 1. Timestamp Validation
    try:
        client_timestamp = int(client_timestamp_str)
    except ValueError:
        return False, "Invalid timestamp format. Must be an integer (Unix seconds)."

    current_server_time = int(time.time())
    if not (
        current_server_time - TIMESTAMP_TOLERANCE_SECONDS
        <= client_timestamp
        <= current_server_time + TIMESTAMP_TOLERANCE_SECONDS
    ):
        return (
            False,
            f"Timestamp out of sync. Server: {current_server_time}, Client: {client_timestamp}. Tolerance: +/- {TIMESTAMP_TOLERANCE_SECONDS}s.",
        )

    # 2. Nonce Validation (Anti-Replay)
    # Clean up old nonces (basic in-memory cleanup)
    cutoff_time = current_server_time - NONCE_EXPIRY_SECONDS
    for key, stored_time in list(RECENTLY_USED_NONCES.items()):
        if stored_time < cutoff_time:
            del RECENTLY_USED_NONCES[key]

    nonce_key_tuple = (api_key_id, nonce)
    if nonce_key_tuple in RECENTLY_USED_NONCES:
        return False, "Replay attack detected: (api_key_id, nonce) pair already used."
    RECENTLY_USED_NONCES[nonce_key_tuple] = (
        current_server_time  # Store with server receipt time
    )

    # 3. Decode Signature
    try:
        signature_bytes = base64.b64decode(signature_base64)
        if len(signature_bytes) != 65:  # r(32)s(32)v(1)
            return False, "Invalid signature length. Expected 65 bytes (r, s, v)."
        # The recovery_id (v) is signature_bytes[64]. It should be 0 or 1.
        # coincurve.PublicKey.from_signature_and_message expects v to be 0 or 1.
    except (base64.binascii.Error, ValueError) as e:
        return False, f"Invalid base64 encoded signature: {str(e)}"

    # 4. Reconstruct the Signed Message
    # IMPORTANT: The client MUST sign this exact string format.
    message_string = f"{http_method}|{http_path}|{client_timestamp_str}|{nonce}|{api_key_id}|{body_hash_hex}"
    message_bytes = message_string.encode("utf-8")
    message_hash = sha256(message_bytes).digest()  # Use the raw digest

    # 5. Perform ECDSA Signature Verification (Recover Public Key and Compare)
    try:
        # Recover public key from signature and message hash
        recovered_pk_obj = PublicKey.from_signature_and_message(
            signature_bytes, message_hash, hasher=None
        )

        # Compare the canonical form of recovered public key with the expected one
        if recovered_pk_obj.format() == expected_pk_obj.format():
            return True, "Authorized"
        else:
            # Signature is valid for the message, but for a different public key than configured for this api_key_id
            # For security, do not leak which key was recovered in error messages to client.
            # Log details server-side for debugging if necessary.
            # print(f"DEBUG: Sig valid, but PK mismatch. Expected: {expected_pk_obj.format().hex()}, Recovered: {recovered_pk_obj.format().hex()} for API Key ID: {api_key_id}")
            return False, "Invalid signature or API Key ID."
    except Exception as e:
        # Catch any other unexpected errors during recovery/comparison.
        # Log 'e' for server-side debugging.
        # print(f"DEBUG: ECDSA verification processing error for API Key ID {api_key_id}: {str(e)}")
        return (
            False,
            f"Signature verification failed: {str(e)}",
        )


# --- Placeholder verification functions for other methods (from your snippet) ---
def verify_static_bearer_token(token, gateway_keys_config):
    # Example: Original logic used global GATEWAY_API_KEYS.
    # Adjust if your GATEWAY_API_KEYS structure for static keys is different.
    # This is a simplified check based on your original placeholder.
    if token in gateway_keys_config:
        return True
    return False


def verify_dh_negotiated_key(payload):
    print(f"Verifying DH negotiated key/payload: {payload}")
    return False, "DH key exchange verification not implemented in placeholder"


def gateway_auth_required(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Authorization header is missing"}), 401

        parts = auth_header.split()
        if parts[0].lower() != "bearer" or len(parts) == 1:
            return (
                jsonify(
                    {
                        "error": "Invalid Authorization header format. Expected 'Bearer <token_details>'"
                    }
                ),
                401,
            )

        auth_payload = parts[
            1
        ]  # This is the signature_base64 for signed method, or static token

        is_authorized = False
        auth_error_message = "Invalid API key or authentication method."
        CURRENT_AUTH_METHOD = request.headers.get("X-Auth-Method")
        if not CURRENT_AUTH_METHOD:
            CURRENT_AUTH_METHOD = AuthMethod.BEARER_STATIC
        if CURRENT_AUTH_METHOD == AuthMethod.BEARER_STATIC:
            if (
                len(parts) > 2
            ):  # Static keys usually don't have spaces if the key itself is the token
                return (
                    jsonify(
                        {"error": "Invalid Authorization header format for static key."}
                    ),
                    401,
                )
            # Pass the GATEWAY_API_KEYS for context if needed by the verification function
            is_authorized = verify_static_bearer_token(
                auth_payload, GATEWAY_API_KEYS["static_client_key"]
            )
            if not is_authorized:
                auth_error_message = "Invalid static API key."

        elif CURRENT_AUTH_METHOD == AuthMethod.BEARER_SIGNED:
            api_key_id = request.headers.get("X-Api-Key-Id")
            client_timestamp_str = request.headers.get("X-Timestamp")
            nonce = request.headers.get("X-Nonce")

            # Default body_hash to hash of empty string if not provided (e.g., for GET requests)
            # Client should explicitly send hash of empty string for bodyless requests they sign.
            # request_body_bytes = await request.get_data()  # Read body once
            # Re-assign body for handler if needed, or use a middleware to cache it.
            # For now, assume handler can also call get_data() or get_json() if Flask allows it after this.
            # A common pattern is to set request.cached_data = request_body_bytes here.

            client_body_hash_hex = request.headers.get("X-Body-Hash")

            if not all([api_key_id, client_timestamp_str, nonce, client_body_hash_hex]):
                missing_headers = []
                if not api_key_id:
                    missing_headers.append("X-Api-Key-Id")
                if not client_timestamp_str:
                    missing_headers.append("X-Timestamp")
                if not nonce:
                    missing_headers.append("X-Nonce")
                if not client_body_hash_hex:
                    missing_headers.append("X-Body-Hash")  # Body hash is now mandatory
                return (
                    jsonify(
                        {
                            "error": f"Missing required headers for signed request: {', '.join(missing_headers)}."
                        }
                    ),
                    401,
                )
            api_keys_file_path = GATEWAY_API_KEYS.get("signature_verification_only_key")
            if not api_keys_file_path or not isinstance(api_keys_file_path, str):
                # print("Error: 'signature_verification_only_key' path not configured or not a string in GATEWAY_API_KEYS.")
                return (
                    jsonify(
                        {
                            "error": "Server configuration error for signed request key path."
                        }
                    ),
                    500,
                )

            current_gateway_api_keys_from_file = None
            try:
                async with aiofiles.open(
                    api_keys_file_path, mode="r", encoding="utf-8"
                ) as file_handle:  # Renamed local variable for clarity
                    file_content = await file_handle.read()
                current_gateway_api_keys_from_file = json.loads(file_content)
            except FileNotFoundError:
                # Error: API keys file not found at the specified path.
                return jsonify({"error": "API keys file not found."}), 500
            except json.JSONDecodeError:
                # Error: Could not decode JSON from the API keys file.
                return jsonify({"error": "Invalid API keys file format."}), 500
            except Exception as e:  # Other possible I/O errors
                # Error: An unexpected error occurred while loading API keys.
                return (
                    jsonify(
                        {"error": "Failed to load API keys due to an internal error."}
                    ),
                    500,
                )

            if (
                current_gateway_api_keys_from_file is None
            ):  # If try-except did not successfully assign
                return (
                    jsonify({"error": "Failed to load API keys for verification."}),
                    500,
                )
            # The signature is in auth_payload
            is_authorized, auth_error_message = await verify_signed_bearer_token_ecdsa(
                signature_base64=auth_payload,
                api_key_id=api_key_id,
                client_timestamp_str=client_timestamp_str,
                nonce=nonce,
                http_method=request.method,
                http_path=request.path,
                body_hash_hex=client_body_hash_hex,  # Use client-provided hash
                current_gateway_api_keys=current_gateway_api_keys_from_file,
            )

        elif CURRENT_AUTH_METHOD == AuthMethod.DH_KEY_EXCHANGE:
            auth_result = verify_dh_negotiated_key(auth_payload)
            if isinstance(auth_result, tuple) and len(auth_result) == 2:
                is_authorized, auth_error_message = auth_result
            else:
                is_authorized = auth_result
                if not is_authorized:
                    auth_error_message = "DH key exchange verification failed."

        else:
            auth_error_message = (
                "Unsupported authentication method configured on gateway."
            )

        if not is_authorized:
            # Log the auth_error_message server-side for more details if it's sensitive
            # print(f"Authentication failed for {request.path}: {auth_error_message}")
            # Return a generic error to the client for security reasons for some failures
            if auth_error_message in [
                "Invalid signature or API Key ID.",
                "Invalid signature: Malformed or fails cryptographic verification.",
            ]:
                # For these specific cases, a generic message might be preferred to client
                return (
                    jsonify({"error": "Forbidden: Invalid credentials or signature."}),
                    403,
                )
            return jsonify({"error": auth_error_message}), 403  # 403 Forbidden

        return await f(*args, **kwargs)  # Pass request_body_bytes if needed by f

    return decorated_function


# Example Usage (you would import this decorator in your main app file)
# from flask import Flask
# app = Flask(__name__)

# client_openai = None # Placeholder
# client_vertexai = None # Placeholder
# MODEL_PROVIDER_MAP = {} # Placeholder
# map_request_to_provider = lambda x, y: {} # Placeholder
# call_openai_model_unified = lambda **kwargs: {} # Placeholder
# call_gemini_model_unified = lambda **kwargs: {} # Placeholder


# @app.route("/v1/chat/completions", methods=["POST"])
# @gateway_auth_required
# async def handle_chat_completions():
#     # ... your existing async route logic ...
#     request_data = request.get_json()
#     if not request_data:
#         return jsonify({"error": "Request body is empty or not in JSON format."}), 400
#     # ... rest of your function
#     return jsonify({"message": "Authenticated and processed by async handler!"})
