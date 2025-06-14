# config.py
import os

# --- Gateway's Own API Key Configuration ---
# This is the key that users of your gateway will use.
# In a production environment, use environment variables or a secure vault.

GATEWAY_API_KEYS = {
    "static_client_key": [
        "STATIC_CLIENT_KEY_HERE",
    ],
    "signature_verification_only_key": "valid_signature.json",
    # Add more keys as needed
}


# --- LLM Provider API Keys ---
# These are the keys for your gateway to access the actual LLM services.
# BEST PRACTICE: Load these from environment variables.

# Vertex AI (Google Cloud) Configuration
VERTEX_AI_PROJECT_ID = os.environ.get(
    "VERTEX_AI_PROJECT_ID", "your-gcp-project-id-here"
)  # Default value made generic
VERTEX_AI_LOCATION = os.environ.get(
    "VERTEX_AI_LOCATION", "us-central1"
)  # This is a common default region, usually not sensitive

# OpenAI Configuration
OPENAI_API_KEY = os.environ.get(
    "OPENAI_API_KEY", "sk-YOUR_OPENAI_API_KEY_PLACEHOLDER"
)  # Default value is already a placeholder

AMBIENT_API_KEY = os.environ.get("AMBIENT_API_KEY", "YOUR_AMBIENT_API_KEY_HERE")


# --- Model Mappings and Routing ---
# This helps decide which client to use based on the model name requested by the user.
# Users can request "gpt-3.5-turbo" and the gateway routes it to the OpenAI client.
# Users can request "gemini-1.5-flash" and the gateway routes it to Vertex AI client.
MODEL_PROVIDER_MAP = {
    # OpenAI Models
    "gpt-4o": "openai",
    "gpt-4-turbo": "openai",
    "gpt-3.5-turbo": "openai",
    # Vertex AI (Gemini) Models - ensure these model names are what your vertexai_client expects
    "gemini-1.5-pro-latest": "vertexai",  # Example, adjust to actual usable model strings
    "gemini-1.5-flash-latest": "vertexai",
    "gemini-1.0-pro": "vertexai",  # Example
    "gemini-pro": "vertexai",  # Alias for gemini-1.0-pro or similar
    "gemini-2.0-flash-001": "vertexai",  # From your attachment, ensure it's valid
    "deepseek-ai/DeepSeek-R1": "ambient",
}

# Default models if not specified or if a generic name is used
DEFAULT_MODEL_FOR_PROVIDER = {
    "openai": "gpt-3.5-turbo",
    "vertexai": "gemini-1.5-flash-latest",  # Or your preferred default gemini model
    "ambient": "deepseek-ai/DeepSeek-R1",
}

# --- Other Configurations ---
REQUEST_TIMEOUT = 30  # Timeout for requests to LLM providers in seconds
