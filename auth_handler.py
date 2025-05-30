from functools import wraps
from flask import request, jsonify
from config import GATEWAY_API_KEYS

# Assuming AuthMethod, CURRENT_AUTH_METHOD, and verification functions
# (verify_static_bearer_token, etc.) are defined elsewhere in your application.
# For example:
# from .auth_utils import AuthMethod, CURRENT_AUTH_METHOD, verify_static_bearer_token, verify_signed_bearer_token, verify_dh_negotiated_key


# Placeholder for AuthMethod if not defined elsewhere for this snippet
class AuthMethod:
    BEARER_STATIC = "bearer_static"
    BEARER_SIGNED = "bearer_signed"
    DH_KEY_EXCHANGE = "dh_key_exchange"


# Placeholder for CURRENT_AUTH_METHOD
CURRENT_AUTH_METHOD = (
    AuthMethod.BEARER_STATIC
)  # Example, set this according to your app's logic


# Placeholder verification functions for the decorator to be runnable
def verify_static_bearer_token(token):
    # Replace with your actual static token verification logic
    # Example: return token in VALID_STATIC_TOKENS
    print(f"Verifying static token: {token}")
    return token in GATEWAY_API_KEYS.keys()


def verify_signed_bearer_token(token):
    # Replace with your actual signed token verification logic (e.g., JWT)
    print(f"Verifying signed token: {token}")
    # Example:
    # try:
    #   payload = jwt.decode(token, "your-secret-key", algorithms=["HS256"])
    #   return True, "Authorized"
    # except jwt.ExpiredSignatureError:
    #   return False, "Token has expired"
    # except jwt.InvalidTokenError:
    #   return False, "Invalid token"
    return False, "Signed token verification not implemented in placeholder"


def verify_dh_negotiated_key(payload):
    # Replace with your actual DH key exchange verification logic
    print(f"Verifying DH negotiated key/payload: {payload}")
    return False, "DH key exchange verification not implemented in placeholder"


def gateway_auth_required(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):  # Changed to async def
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Authorization header is missing"}), 401

        parts = auth_header.split()

        if parts[0].lower() != "bearer" or len(parts) == 1:
            return (
                jsonify(
                    {
                        "error": "Invalid Authorization header format. Expected 'Bearer <token_or_auth_details>'"
                    }
                ),
                401,
            )

        auth_token_or_payload = " ".join(
            parts[1:]
        )  # The rest of the header after "Bearer "

        is_authorized = False
        auth_error_message = "Invalid API key or authentication method."

        # IMPORTANT: If your verification functions (verify_static_bearer_token, etc.)
        # perform I/O operations (e.g., database lookups, external API calls),
        # they should ALSO be `async` and you would need to `await` them here.
        # For this example, we assume they are synchronous.
        if CURRENT_AUTH_METHOD == AuthMethod.BEARER_STATIC:
            if len(parts) > 2:  # Static keys shouldn't have spaces
                return (
                    jsonify(
                        {
                            "error": "Invalid Authorization header format for static key. Token should not contain spaces."
                        }
                    ),
                    401,
                )
            is_authorized = verify_static_bearer_token(auth_token_or_payload)
        elif CURRENT_AUTH_METHOD == AuthMethod.BEARER_SIGNED:
            # Assuming verify_signed_bearer_token can be sync or async.
            # If it's async: result = await verify_signed_bearer_token(...)
            # For now, assuming it's sync and returns a tuple (bool, str)
            auth_result = verify_signed_bearer_token(auth_token_or_payload)
            if isinstance(auth_result, tuple) and len(auth_result) == 2:
                is_authorized, auth_error_message = auth_result
            else:  # Fallback if it just returns a boolean
                is_authorized = auth_result
                if not is_authorized:
                    auth_error_message = "Signed token verification failed."

        elif CURRENT_AUTH_METHOD == AuthMethod.DH_KEY_EXCHANGE:
            # Assuming verify_dh_negotiated_key can be sync or async.
            # If it's async: result = await verify_dh_negotiated_key(...)
            auth_result = verify_dh_negotiated_key(auth_token_or_payload)
            if isinstance(auth_result, tuple) and len(auth_result) == 2:
                is_authorized, auth_error_message = auth_result
            else:  # Fallback
                is_authorized = auth_result
                if not is_authorized:
                    auth_error_message = "DH key exchange verification failed."
        else:
            auth_error_message = (
                "Unsupported authentication method configured on gateway."
            )

        if not is_authorized:
            return jsonify({"error": auth_error_message}), 403  # 403 Forbidden

        return await f(*args, **kwargs)  # Changed to await f

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

# if __name__ == "__main__":
#   pass
# For testing with Hypercorn: hypercorn your_app_file_name:app
# Ensure you have Flask installed with async support: pip install "flask[async]"
# And Hypercorn: pip install hypercorn
