# response_mapper.py


def normalize_response(provider_name: str, provider_response: dict):
    """
    Normalizes the response from an LLM provider to a standard gateway format.
    For now, we assume clients return a format very similar to OpenAI's ChatCompletion object.
    """
    if provider_response.get("error"):
        return provider_response  # Pass through errors

    # Example: Ensure 'object' type is consistent if not already
    # if provider_name == "vertexai" and "object" not in provider_response:
    #     provider_response["object"] = "chat.completion" # Already done in vertexai_client

    # Example: Standardize tool_calls vs function_call if there were inconsistencies
    # choices = provider_response.get("choices", [])
    # for choice in choices:
    #    message = choice.get("message", {})
    #    if "tool_calls" in message and "function_call" not in message:
    #        # If unified format prefers single function_call and tool_calls has one item
    #        if len(message["tool_calls"]) == 1 and message["tool_calls"][0].get("type") == "function":
    #            message["function_call"] = message["tool_calls"][0]["function"]
    #            # message["content"] = None # As per OpenAI spec
    #            # del message["tool_calls"]
    #    elif "function_call" in message and "tool_calls" not in message:
    #        # Convert to tool_calls if that's the standard
    #        # pass

    return provider_response
