# LLM Gateway API

## Overview

This project implements an API Gateway that provides a unified interface for accessing various Large Language Model (LLM) providers, such as OpenAI and Google Vertex AI (Gemini). It allows clients to send requests to a single endpoint, and the gateway routes these requests to the appropriate LLM provider based on the requested model. It also handles authentication and can be configured to map request and response formats.

## Features

* **Unified API Endpoint**: Single `/v1/chat/completions` endpoint for interacting with multiple LLM backends.
* **Multi-Provider Support**:
    * OpenAI (e.g., GPT-4o, GPT-3.5-turbo)
    * Google Vertex AI (e.g., Gemini 1.5 Pro, Gemini 1.5 Flash)
* **Model Routing**: Dynamically routes requests to the correct provider based on the model name specified in the request or inferred from model prefixes (e.g., "gpt-", "gemini-").
* **Authentication**: Secures the gateway endpoint using Bearer token authentication. Currently supports static API keys, with placeholders for signed tokens and DH key exchange.
* **Request Mapping**: Adapts a common gateway request format to the specific format required by each LLM provider.
* **Response Normalization (Basic)**: Includes a structure for normalizing responses from different providers to a consistent format (currently basic).
* **Configurable**: Easily configure API keys, model mappings, and default models via a central `config.py` file and environment variables.
* **Asynchronous Processing**: Utilizes `async/await` for non-blocking I/O when calling LLM provider APIs, suitable for ASGI servers like Hypercorn.

## Project Structure

```
.
├── app.py                    # Main Flask application, API routes, and request handling logic.
├── auth_handler.py           # Authentication decorator and verification logic.
├── config.py                 # Configuration for API keys, model mappings, etc. (Create from config-example.py)
├── config-example.py         # Example configuration file.
├── request_mapper.py         # Maps incoming requests to provider-specific formats.
├── response_mapper.py        # (Optional) Normalizes provider responses to a unified format.
├── llm_clients/              # Directory for LLM provider client implementations
│   ├── __init__.py
│   ├── openai_client.py      # Client for OpenAI API.
│   └── vertexai_client.py    # Client for Vertex AI (Gemini) API.
└── requirements.txt          # Python dependencies.
```

## Setup and Installation

### Prerequisites

* Python 3.8+
* `pip` for installing Python packages.

### Installation Steps

1.  **Clone the Repository** (if applicable)
    ```bash
    git clone https://github.com/verisense-network/llm-gateway.git
    cd llm-gateway
    ```

2.  **Create a Virtual Environment** (recommended)
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**
    Create a `requirements.txt` file with the following content:
    ```txt
    flask[async]
    openai>=1.0.0
    google-cloud-aiplatform
    hypercorn
    python-dotenv
    ```
    Then install them:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure the Gateway**
    * Copy `config-example.py` to `config.py`:
        ```bash
        cp config-example.py config.py
        ```
    * **Edit `config.py`**:
        * `GATEWAY_API_KEYS`: Add the API keys that your gateway users will use to authenticate with your gateway.
            ```python
            GATEWAY_API_KEYS = {
                "your_secure_gateway_user_key_1": {"description": "User 1 access key"},
                # Add more keys as needed
            }
            ```
        * `MODEL_PROVIDER_MAP`: Review and adjust if necessary.
        * `DEFAULT_MODEL_FOR_PROVIDER`: Set your preferred default models.
    * **Set Environment Variables** for LLM provider API keys. You can create a `.env` file in the project root for local development:
        ```env
        # .env
        OPENAI_API_KEY="sk-your_openai_api_key_here"
        VERTEX_AI_PROJECT_ID="your-gcp-project-id"
        VERTEX_AI_LOCATION="your-gcp-project-location" # e.g., us-central1
        # GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/gcp-service-account-key.json" # If using service account for Vertex AI
        ```
        The `config.py` file is set up to read these environment variables. Ensure your Google Cloud authentication is correctly set up for Vertex AI (e.g., via `gcloud auth application-default login` or service account).

5.  **Initialize LLM Clients**
    Ensure your `llm_clients/openai_client.py` and `llm_clients/vertexai_client.py` correctly initialize their respective API clients (e.g., `AsyncOpenAI()`, `GenerativeModel()`). The provided `app.py` imports these clients.

## Running the Application

This application is designed to run with an ASGI server due to its use of `async` route handlers. Hypercorn is recommended in the `app.py` comments.

```bash
hypercorn app:app -b 0.0.0.0:12457
```
Replace `12457` with your desired port if needed. The application will start, and the gateway will be accessible.

## API Endpoint

### `POST /v1/chat/completions`

This is the primary endpoint for sending chat completion requests to LLMs.

* **Method**: `POST`
* **Authentication**: `Bearer Token`
    * The client must include an `Authorization` header with a valid Bearer token.
    * Example: `Authorization: Bearer your_secure_gateway_user_key_1`
* **Request Body**: JSON payload similar to the OpenAI Chat Completions API.
    ```json
    {
        "model": "gpt-4o", // Or "gemini-1.5-flash-latest", etc.
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello, who are you?"}
        ],
        "max_tokens": 150,
        "temperature": 0.7,
        "stream": false // Streaming is passed to clients but full handling might vary
        // ... other common parameters like 'tools', 'tool_choice'
    }
    ```
    The `request_mapper.py` handles adapting these fields for the target LLM provider.

* **Example Successful Response (Non-Streaming)**:
    The response format aims to be compatible with the OpenAI ChatCompletion object structure.
    ```json
    {
        "id": "chatcmpl-xxxxxxxxxxxxxxxxxxxxxxx",
        "object": "chat.completion",
        "created": 1677652288,
        "model": "gpt-4o", // Actual model used by the provider
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "I am an AI assistant powered by a large language model."
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 20,
            "completion_tokens": 15,
            "total_tokens": 35
        }
        // For Vertex AI, the structure will be mapped to be as close as possible to this.
    }
    ```

* **Error Responses**:
    * `400 Bad Request`: Invalid JSON, missing required fields (e.g., `model`).
    * `401 Unauthorized`: Missing or invalid `Authorization` header.
    * `403 Forbidden`: Invalid API key provided in the Bearer token.
    * `500 Internal Server Error`: Unexpected error on the gateway.
    * `502 Bad Gateway`: Error received from the downstream LLM provider.
    * `503 Service Unavailable`: LLM client not initialized or connection error with the provider.

## Authentication Details

The gateway uses the `@gateway_auth_required` decorator defined in `auth_handler.py`. The active authentication strategy is determined by the `X-Auth-Method` header sent by the client, or defaults if the header is not present (currently defaults to static bearer tokens).

* **`AuthMethod.BEARER_STATIC`** (e.g., `X-Auth-Method: bearer_static` or default):
    * Clients send a pre-defined static API key as a Bearer token.
    * Example: `Authorization: Bearer your_secure_gateway_user_key_1`
    * These static keys are configured directly in `config.py` under `GATEWAY_API_KEYS` (see Configuration section).
    * The `verify_static_bearer_token` function in `auth_handler.py` checks if the provided token is one of the configured keys.

* **`AuthMethod.BEARER_SIGNED`** (e.g., `X-Auth-Method: bearer_signed`):
    * This method uses ECDSA (secp256k1) signatures for request authentication.
    * **Client Responsibilities**:
        1.  Construct a canonical message string:
            `HTTPMethod|HTTPPath|ClientTimestamp|Nonce|APIKeyID|RequestBodyHashHex`
            * `HTTPMethod`: e.g., "POST"
            * `HTTPPath`: e.g., "/v1/chat/completions"
            * `ClientTimestamp`: Unix timestamp (integer as a string) of when the request was created.
            * `Nonce`: A unique random string for each request to prevent replay attacks.
            * `APIKeyID`: The client's unique API Key ID.
            * `RequestBodyHashHex`: SHA256 hash of the raw request body, hex encoded. For GET requests or requests with no body, this should be the SHA256 hash of an empty string.
        2.  Compute the SHA256 hash of this UTF-8 encoded canonical message string.
        3.  Sign this hash using the client's private ECDSA (secp256k1) key. The signature must be in a format that includes the recovery ID (65 bytes: r, s, v).
        4.  Base64 encode the 65-byte signature.
    * **HTTP Headers**: The client must send the following headers:
        * `Authorization: Bearer <base64_encoded_signature>`
        * `X-Auth-Method: bearer_signed` (or the string value configured for `AuthMethod.BEARER_SIGNED`)
        * `X-Api-Key-Id: <your_api_key_id>`
        * `X-Timestamp: <client_timestamp_as_string>`
        * `X-Nonce: <your_unique_nonce>`
        * `X-Body-Hash: <sha256_hex_of_request_body>`
    * **Server-Side Verification**:
        * The gateway uses the `verify_signed_bearer_token_ecdsa` function in `auth_handler.py`.
        * It validates the timestamp against server time (within `TIMESTAMP_TOLERANCE_SECONDS`) and checks the nonce for anti-replay using `RECENTLY_USED_NONCES`.
        * It reconstructs the canonical message string and its hash using the provided headers and request details.
        * It recovers the public key from the provided signature and the reconstructed message hash.
        * This recovered public key is then compared against the expected public key configured for the `X-Api-Key-Id`. Public keys are loaded from a JSON file specified in `config.py` via `GATEWAY_API_KEYS["signature_verification_only_key"]` (see Configuration section).
    * The client's uncompressed public key (hex encoded) must be pre-configured on the server.
* **`AuthMethod.DH_KEY_EXCHANGE`** (e.g., `X-Auth-Method: dh_key_exchange`):
    * This method uses X25519 Diffie-Hellman key exchange for establishing a shared symmetric key between client and server.
    * **Key Exchange Process**:
        1. **Client initiates key exchange**: Send a POST request to `/v1/dh/initiate` with the client's X25519 public key.
        2. **Server responds**: Returns the server's X25519 public key.
        3. **Both parties derive shared secret**: Using X25519 key exchange algorithm.
        4. **Symmetric key derivation**: Both parties use HKDF-SHA256 to derive a 32-byte symmetric key from the shared secret with info string `"llm-gateway-dh-symmetric-key-v1"`.
    * **Initial Key Exchange Request**:
        * **Endpoint**: `POST /v1/dh/initiate`
        * **Request Body**:
            ```json
            {
              "client_public_key": "<base64_encoded_32_byte_x25519_public_key>"
            }
            ```
        * **Response**:
            ```json
            {
              "server_public_key": "<base64_encoded_32_byte_x25519_public_key>"
            }
            ```
    * **Subsequent Authenticated Requests**:
        * **HTTP Headers**:
            * `Authorization: Bearer <base64_encoded_derived_symmetric_key>`
            * `X-Auth-Method: dh_key_exchange`
        * The derived symmetric key serves as the Bearer token for authentication.
        * The server maintains an in-memory store of valid derived keys with TTL (configurable via `DH_SESSION_TTL_SECONDS`).
    * **Server-Side Verification**:
        * The gateway uses the `verify_dh_negotiated_key` function in `auth_handler.py`.
        * It checks if the provided symmetric key exists in the `DH_DERIVED_KEYS` store and hasn't expired.
        * Keys are automatically cleaned up when they exceed the configured TTL.
    * **Security Features**:
        * Each client-server pair generates a unique shared secret.
        * Symmetric keys have configurable expiration times.
        * No long-term key storage required on the client side after key exchange.
        * Forward secrecy: compromising one session doesn't affect others.

To change the default authentication method or manage how methods are selected, you would update logic within `gateway_auth_required` in `auth_handler.py`.

## Configuration (`config.py`)

* **`GATEWAY_API_KEYS`**: This dictionary serves a dual purpose based on the authentication method:
    * **For Static Bearer Tokens (`AuthMethod.BEARER_STATIC`)**:
        * Keys are the actual static API keys your users will send (e.g., "your\_secure\_gateway\_user\_key\_1").
        * Values can be a dictionary for metadata (e.g., `{"description": "User 1 access key"}`) or, if `verify_static_bearer_token` is simplified, the key itself might be checked against a list/set of keys.
        * The `auth_handler.py` uses `GATEWAY_API_KEYS.get("static_client_key")` to retrieve the expected static token in the provided code, implying a specific key name for the static token value.
        * Example for static token:
            ```python
            GATEWAY_API_KEYS = {
                "static_client_key": "the_actual_static_token_value_here",
                # other configurations
            }
            ```
            Or, if supporting multiple static keys identified by the token itself:
            ```python
            GATEWAY_API_KEYS = {
                "your_secure_gateway_user_key_1": {"description": "User 1 access key"},
                "another_static_key_value": {"description": "User 2 access key"},
                # ...
            }
            # Note: verify_static_bearer_token would need to check `auth_payload in GATEWAY_API_KEYS`
            ```
    * **For Signed Bearer Tokens (`AuthMethod.BEARER_SIGNED`)**:
        * It should contain a key, e.g., `"signature_verification_only_key"`, whose value is the **file path** to a JSON file.
        * This JSON file contains the mapping of `api_key_id` to their respective uncompressed ECDSA public key hex strings.
        * Example in `config.py`:
            ```python
            GATEWAY_API_KEYS = {
                "signature_verification_only_key": "/path/to/your/public_keys_config.json",
                "static_client_key": "optional_static_key_if_also_supported",
                # ... other configurations ...
            }
            ```
        * **Example `public_keys_config.json` file structure**:
            ```json
            {
              "client_id_for_ecdsa_1": {
                "public_key_hex": "04CLIENTS_UNCOMPRESSED_PUBLIC_KEY_HEX_STRING_HERE"
              },
              "client_id_for_ecdsa_2": {
                "public_key_hex": "04ANOTHER_CLIENTS_PUBLIC_KEY_HEX_STRING"
              }
            }
            ```
* **LLM Provider Keys**:
    * `OPENAI_API_KEY`: Your OpenAI API key.
    * `VERTEX_AI_PROJECT_ID`: Your Google Cloud Project ID for Vertex AI.
    * `VERTEX_AI_LOCATION`: The GCP region for Vertex AI (e.g., `us-central1`).
    * These are loaded from environment variables for security.
* **`MODEL_PROVIDER_MAP`**: Maps specific model names (e.g., "gpt-4o", "gemini-1.5-pro-latest") to provider identifiers ("openai", "vertexai").
* **`DEFAULT_MODEL_FOR_PROVIDER`**: Specifies a default model to use for each provider if the request doesn't specify one compatible with that provider.
* **`REQUEST_TIMEOUT`**: Timeout in seconds for requests made by the gateway to the LLM providers.
* **Constants from `auth_handler.py`** (though not directly in `config.py`, they are important for signed auth behavior):
    * `NONCE_EXPIRY_SECONDS`: How long a nonce is considered valid for replay protection.
    * `TIMESTAMP_TOLERANCE_SECONDS`: Allowable clock skew between client and server.
  
## Extending the Gateway

### Adding a New LLM Provider

1.  **Create a Client**: Add a new Python file in the `llm_clients/` directory (e.g., `newprovider_client.py`).
    * Implement an `async` function similar to `call_openai_model_unified` or `call_gemini_model_unified` that takes standardized parameters and calls the new provider's API.
    * Handle API key initialization for the new client (likely via environment variables and `config.py`).
2.  **Update `config.py`**:
    * Add a new provider identifier (e.g., "newprovider").
    * Add API key configurations for the new provider.
    * Update `MODEL_PROVIDER_MAP` with models from the new provider.
    * Update `DEFAULT_MODEL_FOR_PROVIDER` if applicable.
3.  **Update `app.py`**:
    * Import the new client function and client instance.
    * Add a new `elif provider_name == "newprovider":` block in `handle_chat_completions` to call your new client function.
    * Add a check for client initialization.
4.  **Update `request_mapper.py`**:
    * Add an `elif provider_name == "newprovider":` block in `map_request_to_provider` to handle any specific request parameter mapping for the new provider.
5.  **Update `response_mapper.py`** (Optional):
    * If the new provider's response format differs significantly, add logic to `normalize_response` to map it to the gateway's standard format.

### Modifying Authentication

* Implement the desired verification function in `auth_handler.py` (e.g., `verify_signed_bearer_token`).
* Change `CURRENT_AUTH_METHOD` in `auth_handler.py` to activate the new method.
