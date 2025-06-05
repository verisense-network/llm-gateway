# request_mapper.py
import json
from config import DEFAULT_MODEL_FOR_PROVIDER


def map_request_to_provider(provider_name: str, original_request_data: dict):
    """
    Maps a unified gateway request to a provider-specific format.
    original_request_data is expected to be like:
    {
        "model": "requested_model_name",
        "messages": [{"role": "user", "content": "Hello"}, ...],
        "instructions": "Be a helpful assistant.", (optional)
        "tools": [{"type": "function", "function": {...}}], (optional, OpenAI format)
        "tool_choice": "auto", (optional, OpenAI format)
        "max_tokens": 100, (optional)
        "temperature": 0.7, (optional)
        "stream": False (optional)
        ... other common parameters
    }
    """
    model_name = original_request_data.get(
        "model", DEFAULT_MODEL_FOR_PROVIDER.get(provider_name)
    )
    messages = original_request_data.get("messages", [])
    tools = original_request_data.get("tools")  # OpenAI format
    tool_choice = original_request_data.get("tool_choice", "auto")  # OpenAI specific
    instructions = original_request_data.get("instructions")
    max_tokens = original_request_data.get("max_tokens")
    temperature = original_request_data.get("temperature")
    top_p = original_request_data.get("top_p")  # OpenAI specific
    stream = original_request_data.get("stream", False)

    # Common parameters that can be passed to most clients
    provider_params = {
        "model_name": model_name,
        "messages_list": messages,  # Expects list of {"role": ..., "content": ...}
        # And function/tool call/response structures within messages
        "tools_list": tools,
        "instructions": instructions,
        "max_tokens": max_tokens,
        "temperature": temperature,
        # Stream is more complex, as the handling of streamed responses differs.
        # For now, just passing the flag.
    }

    if provider_name == "openai":
        # OpenAI specific parameters
        provider_params["tool_choice"] = tool_choice
        provider_params["top_p"] = top_p
        provider_params["stream"] = stream
        # OpenAI messages can directly include system role from instructions
        # and tool/function call structures. The openai_client handles internal mapping if needed.
        # Ensure messages_list is directly usable by openai_client.

    elif provider_name == "vertexai":
        # VertexAI (Gemini) specific mapping if needed.
        # The vertexai_client's `call_gemini_model_unified` is designed to take
        # similar inputs (messages_list, tools_list in OpenAI format, instructions).
        # No major structural changes here, the client handles it.
        # `stream` is not explicitly handled by the current vertexai_client example.
        pass
    elif provider_name == "ambient":
        # Ambient specific mapping if needed.
        # The ambient_client's `call_ambient_model_unified` is designed to take
        # similar inputs (messages_list, tools_list in OpenAI format, instructions).
        # No major structural changes here, the client handles it.
        # `stream` is not explicitly handled by the current ambient_client example.
        pass
    else:
        raise ValueError(f"Unknown provider name: {provider_name}")

    return provider_params
