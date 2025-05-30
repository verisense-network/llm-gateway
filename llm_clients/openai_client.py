# llm_clients/openai_client.py
import os
import json
import time
from openai import (
    OpenAI,
    APIConnectionError,
    RateLimitError,
    APIStatusError,
    AsyncOpenAI,
)  # Use new OpenAI SDK
from config import OPENAI_API_KEY, REQUEST_TIMEOUT

client_openai = None
if OPENAI_API_KEY and OPENAI_API_KEY != "YOUR_OPENAI_API_KEY_HERE":
    try:
        client_openai = AsyncOpenAI(api_key=OPENAI_API_KEY, timeout=REQUEST_TIMEOUT)
        print("OpenAI Client initialized successfully.")
    except Exception as e:
        print(f"OpenAI Client initialization failed: {e}")
        client_openai = None
else:
    print(
        "Warning: OPENAI_API_KEY is not set or is a placeholder. OpenAI client not initialized."
    )


async def call_openai_model_unified(
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
    Unified interface to call OpenAI model (Chat Completions).
    model_name: Name of the OpenAI model (e.g., "gpt-3.5-turbo")
    messages_list: List of message dictionaries (OpenAI format).
                   Includes {"role": "system", "content": instructions} if instructions are provided.
                   Tool calls: role="assistant", tool_calls=[{"id":..., "type":"function", "function":{"name":..., "arguments":"..."}}]
                   Tool responses: role="tool", tool_call_id=..., name=..., content= (json result string)
    tools_list: List of tool dictionaries (OpenAI format: {"type": "function", "function": {"name": ..., "description": ..., "parameters": ...}})
    tool_choice: OpenAI tool_choice parameter ("none", "auto", or {"type": "function", "function": {"name": "my_function"}})
    instructions: System instructions (will be added as a system message).
    max_tokens, temperature, top_p: Standard OpenAI parameters.
    stream: Whether to stream the response (not fully handled in this simplified unified response, but passed to API).

    Returns a dictionary compatible with the unified gateway response (OpenAI's chat completion object structure).
    """
    if not client_openai:
        return {"error": "OpenAI Client not initialized."}

    # Prepare messages for OpenAI, including system instructions
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
        api_params["stream"] = (
            True  # Note: handling streamed response needs more complex logic
        )

    try:
        if stream:
            # Simplified: Streaming not fully implemented for unified response, just returns the stream object for now.
            # In a real gateway, you'd iterate over the stream and yield parts.
            # For non-streaming in this example, we get the full response.
            # This example will focus on non-streaming unified response.
            return {
                "error": "Streaming is enabled but not fully handled by this unified client example for OpenAI."
            }

        completion = await client_openai.chat.completions.create(
            **api_params
        )  # Use async for create

        # The 'completion' object is already very close to the desired unified format
        # We can convert it to a dictionary to ensure JSON serializability
        # and make minor adjustments if needed (e.g. standardizing function_call arguments to string)
        response_dict = completion.model_dump()  # Converts the Pydantic model to a dict

        # OpenAI's 'tool_calls' (list) vs older 'function_call' (object)
        # Our unified format in vertexai_client used choice.message.function_call (object)
        # Let's adapt OpenAI response to match that structure if we want strict uniformity
        # or decide that the OpenAI structure is the "unified" one for choices.
        # For this example, let's assume the OpenAI structure is good and VertexAI client will map to it.
        # (VertexAI client's response was already adapted to be similar to OpenAI's choice structure)

        # Ensure function call arguments are JSON strings if present in tool_calls
        if response_dict.get("choices"):
            for choice in response_dict["choices"]:
                if choice.get("message", {}).get("tool_calls"):
                    for tc in choice["message"]["tool_calls"]:
                        if tc.get("type") == "function" and isinstance(
                            tc.get("function", {}).get("arguments"), dict
                        ):
                            # This should already be a string from OpenAI, but good practice to ensure
                            # OpenAI's SDK usually returns arguments as a string.
                            pass  # Arguments are typically already strings.
                        # If our internal standard is one function_call object:
                        # choice["message"]["function_call"] = tc["function"]
                        # choice["message"]["content"] = None # if function_call is primary
                        # del choice["message"]["tool_calls"]

        return response_dict  # This is already in a good "unified" format

    except APIConnectionError as e:
        print(f"OpenAI API Connection Error: {e}")
        return {"error": f"OpenAI API Connection Error: {str(e)}"}
    except RateLimitError as e:
        print(f"OpenAI API Rate Limit Error: {e}")
        return {"error": f"OpenAI API Rate Limit Error: {str(e)}"}
    except APIStatusError as e:  # Catches other API errors e.g. 4xx, 5xx
        print(f"OpenAI API Status Error: {e.status_code} - {e.response}")
        return {"error": f"OpenAI API Status Error: {e.status_code} - {str(e)}"}
    except Exception as e:
        print(f"OpenAI API error: {e}")
        return {"error": f"OpenAI API error: {str(e)}"}
