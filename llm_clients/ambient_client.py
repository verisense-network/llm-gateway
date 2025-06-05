# llm_clients/ambient_client.py
import os
import json
import time
from openai import (
    OpenAI,
    APIConnectionError,
    RateLimitError,
    APIStatusError,
    AsyncOpenAI,
)  # Use OpenAI SDK for Ambient API compatibility
from config import AMBIENT_API_KEY, REQUEST_TIMEOUT

client_ambient = None
if AMBIENT_API_KEY and AMBIENT_API_KEY != "YOUR_AMBIENT_API_KEY_HERE":
    try:
        client_ambient = AsyncOpenAI(
            api_key=AMBIENT_API_KEY,
            base_url="https://api.ambient.xyz/v1",
            timeout=REQUEST_TIMEOUT,
        )
        print("Ambient Client initialized successfully.")
    except Exception as e:
        print(f"Ambient Client initialization failed: {e}")
        client_ambient = None
else:
    print(
        "Warning: AMBIENT_API_KEY is not set or is a placeholder. Ambient client not initialized."
    )


async def call_ambient_model_unified(
    model_name: str,
    messages_list: list,
    tools_list: list = None,
    tool_choice: str = "auto",
    instructions: str = None,
    max_tokens: int = None,
    temperature: float = None,
    top_p: float = None,
    stream: bool = False,
):
    """
    Unified interface to call Ambient model (Chat Completions).
    model_name: Name of the Ambient model (e.g., "deepseek-ai/DeepSeek-R1")
    messages_list: List of message dictionaries (OpenAI format).
                   Includes {"role": "system", "content": instructions} if instructions are provided.
                   Tool calls: role="assistant", tool_calls=[{"id":..., "type":"function", "function":{"name":..., "arguments":"..."}}]
                   Tool responses: role="tool", tool_call_id=..., name=..., content= (json result string)
    tools_list: List of tool dictionaries (OpenAI format: {"type": "function", "function": {"name": ..., "description": ..., "parameters": ...}})
    tool_choice: OpenAI tool_choice parameter ("none", "auto", or {"type": "function", "function": {"name": "my_function"}})
    instructions: System instructions (will be added as a system message).
    max_tokens, temperature, top_p: Standard OpenAI parameters.
    stream: Whether to stream the response.

    Returns a dictionary compatible with the unified gateway response (OpenAI's chat completion object structure).
    """
    if not client_ambient:
        return {"error": "Ambient Client not initialized."}

    # Prepare messages for Ambient, including system instructions
    prepared_messages = []
    if instructions:
        prepared_messages.append({"role": "system", "content": instructions})

    for msg in messages_list:
        # Basic validation/mapping if your internal message format differs slightly
        # For now, assume messages_list is already in OpenAI's expected format
        # (e.g. role: "user", "assistant", "tool"; content; tool_calls; tool_call_id; name for tool)
        role = msg.get("role")
        content = msg.get("content")

        # OpenAI expects 'tool_calls' from assistant and 'tool_call_id' for tool responses
        # This mapping should ideally happen in the request_mapper
        if role == "assistant" and msg.get(
            "function_call"
        ):  # If gateway uses "function_call"
            # Convert to OpenAI's "tool_calls"
            fc = msg["function_call"]
            prepared_messages.append(
                {
                    "role": "assistant",
                    "content": None,  # OpenAI expects content to be null if tool_calls are present
                    "tool_calls": [
                        {
                            "id": f"call_{os.urandom(6).hex()}",  # Generate a placeholder ID if not provided
                            "type": "function",
                            "function": {
                                "name": fc["name"],
                                "arguments": fc[
                                    "arguments"
                                ],  # Expects arguments to be a JSON string
                            },
                        }
                    ],
                }
            )
        elif role == "function":  # If gateway uses "function" role for tool response
            prepared_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": msg.get(
                        "tool_call_id", msg.get("id", "unknown_tool_call_id")
                    ),  # Try to get an ID
                    "name": msg.get(
                        "function_name", msg.get("name")
                    ),  # Get function name
                    "content": content,  # Expects content to be JSON string result
                }
            )
        else:
            prepared_messages.append(msg)

    api_params = {
        "model": model_name,
        "messages": prepared_messages,
    }
    if tools_list:
        api_params["tools"] = tools_list
        api_params["tool_choice"] = (
            tool_choice  # "auto" is default, "none" to disable, or specify a function
        )
    if max_tokens is not None:
        api_params["max_tokens"] = max_tokens
    if temperature is not None:
        api_params["temperature"] = temperature
    if top_p is not None:
        api_params["top_p"] = top_p
    if stream:
        api_params["stream"] = True

    try:
        if stream:
            # For streaming, return the stream object
            stream_response = await client_ambient.chat.completions.create(**api_params)
            return stream_response
        else:
            completion = await client_ambient.chat.completions.create(**api_params)

            # The 'completion' object is already very close to the desired unified format
            # We can convert it to a dictionary to ensure JSON serializability
            response_dict = (
                completion.model_dump()
            )  # Converts the Pydantic model to a dict

            # Ambient API returns responses in OpenAI-compatible format
            # The response includes special fields like 'reasoning_content' and 'merkle_root'
            # which are specific to Ambient's enhanced capabilities

            return response_dict  # This is already in a good "unified" format

    except APIConnectionError as e:
        print(f"Ambient API Connection Error: {e}")
        return {"error": f"Ambient API Connection Error: {str(e)}"}
    except RateLimitError as e:
        print(f"Ambient API Rate Limit Error: {e}")
        return {"error": f"Ambient API Rate Limit Error: {str(e)}"}
    except APIStatusError as e:  # Catches other API errors e.g. 4xx, 5xx
        print(f"Ambient API Status Error: {e.status_code} - {e.response}")
        return {"error": f"Ambient API Status Error: {e.status_code} - {str(e)}"}
    except Exception as e:
        print(f"Ambient API error: {e}")
        return {"error": f"Ambient API error: {str(e)}"}
