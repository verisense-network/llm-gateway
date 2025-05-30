# app.py
import os
import json
import asyncio  # For running async client functions
from flask import Flask, request, jsonify
import traceback

from config import MODEL_PROVIDER_MAP, DEFAULT_MODEL_FOR_PROVIDER
from auth_handler import gateway_auth_required
from request_mapper import map_request_to_provider

# from response_mapper import normalize_response # Optional

# Import client functions
from llm_clients.openai_client import call_openai_model_unified, client_openai
from llm_clients.vertexai_client import (
    call_gemini_model_unified,
    client_vertexai,
)  # Ensure client_vertexai is the SDK client instance

app = Flask(__name__)


# Global error handler for uncaught exceptions
@app.errorhandler(Exception)
def handle_unexpected_error(e):
    traceback.print_exc()  # Log the full stack trace
    response = jsonify(
        {"error": "An unexpected internal server error occurred.", "details": str(e)}
    )
    response.status_code = 500
    return response


@app.route("/v1/chat/completions", methods=["POST"])
@gateway_auth_required
async def handle_chat_completions():  # Make the route async
    request_data = request.get_json()
    if not request_data:
        return jsonify({"error": "Request body is empty or not in JSON format."}), 400

    model_requested = request_data.get("model")
    if not model_requested:
        return jsonify({"error": "Missing 'model' field in request."}), 400

    provider_name = MODEL_PROVIDER_MAP.get(model_requested)
    if not provider_name:
        # Try to infer provider from model prefix if not in explicit map
        if model_requested.startswith("gpt-"):
            provider_name = "openai"
        elif model_requested.startswith("gemini-") or model_requested.startswith(
            "models/gemini-"
        ):  # Vertex AI models sometimes have "models/" prefix
            # Ensure model_requested is just the model ID for vertexai client
            if model_requested.startswith("models/"):
                request_data["model"] = model_requested.split("models/")[
                    1
                ]  # Adjust model name
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

    # Ensure the chosen provider's client is initialized
    if provider_name == "openai" and not client_openai:
        return jsonify({"error": "OpenAI client not initialized on the server."}), 503
    if (
        provider_name == "vertexai" and not client_vertexai
    ):  # Check the SDK client from vertexai_client.py
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
        print(f"Error during request mapping: {e}")
        traceback.print_exc()
        return jsonify({"error": f"Error processing request data: {str(e)}"}), 400

    result = None
    try:
        if provider_name == "openai":
            result = await call_openai_model_unified(**provider_specific_params)
        elif provider_name == "vertexai":
            # Pass the model name correctly from provider_specific_params
            result = await call_gemini_model_unified(**provider_specific_params)
        else:
            # This case should ideally be caught by provider_name check earlier
            return (
                jsonify({"error": "Internal configuration error: Unknown provider."}),
                500,
            )

        # Optional: further normalization if clients don't perfectly match
        # result = normalize_response(provider_name, result)

        if result and result.get("error"):
            # Log the detailed error on the server if it came from the LLM client
            print(f"Error from LLM client ({provider_name}): {result['error']}")
            # Determine appropriate status code based on error type if possible
            # For now, using 502 Bad Gateway if LLM provider failed
            return jsonify(result), 502

        # If streaming was requested and handled by client, the result might be a stream response
        # This example focuses on non-streaming JSON response.
        return jsonify(result)

    except ConnectionError as e:
        print(f"LLM Provider ConnectionError ({provider_name}): {e}")
        return (
            jsonify({"error": f"Connection error with {provider_name}: {str(e)}"}),
            503,
        )
    except Exception as e:
        print(f"Unexpected error when calling LLM provider ({provider_name}): {e}")
        traceback.print_exc()
        return (
            jsonify(
                {
                    "error": f"Unexpected error during model call to {provider_name}: {str(e)}"
                }
            ),
            500,
        )


if __name__ == "__main__":
    port = int(
        os.environ.get("PORT", 12457)
    )  # Changed port to avoid conflict if running both
    # For async Flask routes, you might need an ASGI server like Hypercorn or Uvicorn
    # app.run(debug=True, host="0.0.0.0", port=port) # Standard Flask dev server not ideal for async

    # To run with Hypercorn (example, install with `pip install hypercorn`):
    # hypercorn app:app -b 0.0.0.0:12457
    print(
        f"Starting gateway on port {port}. For async, run with an ASGI server like Hypercorn or Uvicorn."
    )
    print("Example: hypercorn app:app -b 0.0.0.0:{YOUR_PORT}")
    # For simplicity in a dev environment, you can use asyncio.run with app.run
    # but it's not the standard way for production.
    # If using Quart instead of Flask, async is more native.
    # With Flask, if you use `await` in route handlers, you typically need an ASGI server.
    # For basic testing without full ASGI setup for `await`:
    # You might need to run the async functions using `asyncio.run()` if your server doesn't support async routes directly.
    # However, modern Flask versions (2.x+) have some support for async route handlers when run with an ASGI server.
    # app.run(
    #     debug=True, host="0.0.0.0", port=port
    # )  # Dev server will warn about async with WSGI.
