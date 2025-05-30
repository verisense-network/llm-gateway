# llm_clients/vertexai_client.py
import os
import json
from google import (
    genai as google_genai_sdk,
)  # Renamed to avoid conflict with our genai variable
from google.genai import types as google_genai_types  # Renamed
import traceback
from config import VERTEX_AI_PROJECT_ID, VERTEX_AI_LOCATION
import time


# --- Assumed class definitions (can be moved to a shared models.py if also used by openai_client) ---
class Tool:
    def __init__(self, name, description, parameters):
        self.name = name
        self.description = description
        self.parameters = parameters


class Assistant:  # This might be specific to your gateway's internal representation
    def __init__(self, model, tools_data, instructions):
        self.model = model
        self.tools = []
        if tools_data:
            for td in tools_data:
                self.tools.append(
                    Tool(
                        name=td.get("name"),
                        description=td.get("description"),
                        parameters=td.get("parameters"),
                    )
                )
        self.instructions = instructions


class Message:  # This might be specific to your gateway's internal representation
    def __init__(self, role, content, function_name=None, function_args=None):
        self.role = role
        self.content = content
        self.function_name = function_name
        self.function_args = function_args


# --- End of assumed class definitions ---

client_vertexai = None
try:
    if not VERTEX_AI_PROJECT_ID or VERTEX_AI_PROJECT_ID == "YOUR_PROJECT_ID":
        print(
            "Warning: VERTEX_AI_PROJECT_ID is not set to a custom value. Please set the environment variable."
        )
        # Potentially raise an error or use a default for non-production
        if VERTEX_AI_PROJECT_ID == "YOUR_PROJECT_ID":  # If it's still the placeholder
            raise ValueError("VERTEX_AI_PROJECT_ID must be set.")
    client_vertexai = google_genai_sdk.Client(
        vertexai=True, project=VERTEX_AI_PROJECT_ID, location=VERTEX_AI_LOCATION
    )
    print(
        f"Vertex AI Client initialized successfully: Project ID={VERTEX_AI_PROJECT_ID}, Location={VERTEX_AI_LOCATION}"
    )
except Exception as e:
    print(f"Vertex AI Client (Gemini) initialization failed: {e}")
    traceback.print_exc()
    client_vertexai = None  # Ensure client is None if init fails


def build_schema(schema_dict_str):
    try:
        if isinstance(schema_dict_str, str):
            schema_dict = json.loads(schema_dict_str)
        elif isinstance(schema_dict_str, dict):
            schema_dict = schema_dict_str
        else:
            return None
    except json.JSONDecodeError as e:
        print(f"JSON parsing error (build_schema): {e} - Input: {schema_dict_str}")
        return None

    schema_type_str = str(
        schema_dict.get("type", "")
    ).upper()  # Ensure string and uppercase for enum matching

    if schema_type_str == "OBJECT":
        properties = schema_dict.get("properties", {})
        prop_schemas = {}
        if properties:
            for name, prop in properties.items():
                built_prop = build_schema(prop)
                if built_prop:
                    prop_schemas[name] = built_prop
        required = schema_dict.get("required", None)
        return google_genai_types.Schema(
            type=google_genai_types.Type.OBJECT,
            properties=prop_schemas,
            required=required,
        )
    else:
        try:
            type_enum = (
                getattr(google_genai_types.Type, schema_type_str)
                if schema_type_str
                else google_genai_types.Type.TYPE_UNSPECIFIED
            )
        except AttributeError:
            print(f"Unknown schema type: {schema_type_str}. Will use TYPE_UNSPECIFIED.")
            type_enum = google_genai_types.Type.TYPE_UNSPECIFIED

        return google_genai_types.Schema(
            type=type_enum,
            description=schema_dict.get("description"),
        )


async def call_gemini_model_unified(
    model_name: str,
    messages_list: list,
    tools_list: list = None,
    instructions: str = None,
    max_tokens: int = None,
    temperature: float = None,
):
    """
    Unified interface to call Gemini model.
    model_name: Name of the Gemini model to use (e.g., "gemini-1.5-flash-latest")
    messages_list: List of dictionaries, each with "role" and "content".
                   For function calls from model: "role":"assistant", "function_call":{"name":..., "arguments":...}
                   For function responses to model: "role":"tool", "tool_call_id": (optional), "name": ..., "content": (json result string)
    tools_list: List of tool dictionaries (OpenAI format: {"type": "function", "function": {"name": ..., "description": ..., "parameters": ...}})
    instructions: System instructions for the model.
    max_tokens: Max tokens for the response.
    temperature: Temperature for sampling.

    Returns a dictionary compatible with the unified gateway response.
    """
    if not client_vertexai:
        print("Error: Vertex AI Client (Gemini) not initialized.")
        return {"error": "Vertex AI Client (Gemini) not initialized."}

    function_decls = []
    if tools_list:
        for tool_info in tools_list:
            if tool_info.get("type") == "function":
                func_spec = tool_info.get("function", {})
                params_schema = None
                if func_spec.get("parameters"):
                    params_schema = build_schema(func_spec["parameters"])

                if func_spec.get("name") and func_spec.get("description"):
                    decl = google_genai_types.FunctionDeclaration(
                        name=func_spec["name"],
                        description=func_spec["description"],
                        parameters=params_schema if params_schema else None,
                    )
                    function_decls.append(decl)
                else:
                    print(
                        f"Tool '{func_spec.get('name')}' is missing name or description, skipped."
                    )

    tools_config_for_model = (
        [google_genai_types.Tool(function_declarations=function_decls)]
        if function_decls
        else None
    )

    contents_for_model = []
    for msg_data in messages_list:
        role = msg_data.get("role", "").lower()
        content = msg_data.get("content")  # Can be text or structured for tool calls

        # Map gateway roles to Gemini SDK roles
        if role == "assistant":
            role = "model"
        elif (
            role == "system"
        ):  # Gemini takes system instructions separately or as first user message
            # For now, we rely on the system_instruction parameter of GenerativeModel
            # If system message is in messages_list, we could prepend it or handle it.
            # For simplicity here, we'll assume system instructions are passed via the 'instructions' param.
            print(
                f"System role in messages_list will be handled by 'instructions' parameter. Content: {content}"
            )
            continue  # Skip adding it as a direct message if handled by `system_instruction`
        elif role == "function":  # This is a function response from our side
            role = "tool"  # Gemini expects "tool" for function responses

        parts = []
        if role == "user":
            parts.append(
                google_genai_types.Part.from_text(
                    text=str(content if content is not None else "")
                )
            )
        elif role == "model":  # Response from LLM (can be text or function call)
            if msg_data.get("function_call"):  # Model wants to call a function
                fc = msg_data["function_call"]
                args_dict = fc.get("arguments", {})
                if isinstance(args_dict, str):  # if arguments is a JSON string
                    try:
                        args_dict = json.loads(args_dict)
                    except json.JSONDecodeError:
                        print(
                            f"Failed to parse model's function_call arguments JSON: {args_dict}"
                        )
                        # Decide error handling, for now, pass as is or empty.
                        args_dict = {}
                parts.append(
                    google_genai_types.Part.from_function_call(
                        name=fc["name"], args=args_dict
                    )
                )
            elif content is not None:  # Plain text response from model
                parts.append(google_genai_types.Part.from_text(text=str(content)))
            # If content is None and no function_call, it's an empty model message
        elif role == "tool":  # Function response from client to the model
            # Gateway receives this as {"role": "tool", "name": "func_name", "content": "{...json_string...}"}
            # or potentially "tool_call_id" if we map that. Gemini's Part.from_function_response takes name and response dict.
            tool_name = msg_data.get(
                "name"
            )  # Name of the function whose result this is
            response_data_content = msg_data.get("content")  # JSON string or dict

            response_dict = {}
            if isinstance(response_data_content, str):
                try:
                    response_dict = json.loads(response_data_content)
                except json.JSONDecodeError:
                    print(
                        f"Failed to parse tool's response content JSON: {response_data_content}"
                    )
                    response_dict = {
                        "error": "failed to parse content",
                        "raw_content": response_data_content,
                    }
            elif isinstance(response_data_content, dict):
                response_dict = response_data_content
            else:  # Unexpected content type
                response_dict = {
                    "error": "unexpected content type for tool response",
                    "raw_content": str(response_data_content),
                }

            if tool_name:
                parts.append(
                    google_genai_types.Part.from_function_response(
                        name=tool_name,
                        response=response_dict,
                    )
                )
            else:
                print(f"Tool message missing function name: {msg_data}")
                continue
        else:  # e.g. "system" if not handled above, or other unknown roles
            print(f"Unsupported message role for Gemini conversion: {role}")
            continue

        if parts:
            contents_for_model.append(
                google_genai_types.Content(role=role, parts=parts)
            )
        elif (
            role == "model"
            and not msg_data.get("function_call")
            and msg_data.get("content") is None
        ):
            # Handle empty model (assistant) message if necessary, Gemini expects non-empty parts
            # This can happen if the previous turn was a function call and the model had no text part.
            # Gemini usually requires parts. If parts is empty, this content item might be skipped or cause error.
            # One strategy: add an empty text part if allowed, or ensure model outputs always have some content/fc.
            print(
                f"Empty model message parts for role '{role}', msg: {msg_data}. This might be an issue for Gemini."
            )
            # contents_for_model.append(google_genai_types.Content(role=role, parts=[google_genai_types.Part.from_text("")]))

    generation_config = {}
    if max_tokens is not None:
        generation_config["max_output_tokens"] = max_tokens
    if temperature is not None:
        generation_config["temperature"] = temperature
    # Add other params like top_p, top_k if needed

    try:
        response = client_vertexai.models.generate_content(  # Use async for better performance in gateway
            model=model_name,
            contents=(
                contents_for_model
                if len(contents_for_model) > 1
                else (contents_for_model[0] if contents_for_model else "")
            ),
            config=google_genai_types.GenerateContentConfig(  # Using generation_config instead of config
                tools=tools_list,
                # tool_config is part of generation_config for function calling strategy
                automatic_function_calling=google_genai_types.AutomaticFunctionCallingConfig(
                    disable=True
                ),
            ),
        )

    except Exception as e:
        print(f"Vertex AI API error (Gemini): {e}")
        traceback.print_exc()
        return {"error": f"Vertex AI API error (Gemini): {str(e)}"}

    # Parse the response
    try:
        if not response.candidates:
            return {"error": "Model response contained no candidates (Gemini)."}

        candidate = response.candidates[0]

        # Default choice structure
        choice = {
            "index": 0,
            "message": {
                "role": "assistant",  # Unified role
                "content": None,  # Will be filled with text or None if function_call
                "function_call": None,  # Will be {"name": ..., "arguments": ...}
                # "tool_calls" could also be used for consistency with OpenAI if multiple FCs are possible
            },
            "finish_reason": (
                candidate.finish_reason.name if candidate.finish_reason else "UNKNOWN"
            ),
        }

        if candidate.content and candidate.content.parts:
            text_content_parts = []
            for part in candidate.content.parts:
                if part.function_call:
                    fc_obj = part.function_call
                    choice["message"]["function_call"] = {
                        "name": fc_obj.name,
                        "arguments": json.dumps(
                            dict(fc_obj.args)
                        ),  # Standardize arguments to JSON string
                    }
                    # Per OpenAI format, if function_call is present, content is often null.
                    # We will set text_content_parts to empty if a function call is the primary content.
                    text_content_parts = []  # Clear text if function call is primary
                    break  # Assuming one function call per part for now, or primary one

                if hasattr(part, "text") and part.text is not None:
                    text_content_parts.append(part.text)

            if text_content_parts:  # If there was text and no overriding function call
                choice["message"]["content"] = "".join(text_content_parts)
            elif (
                not choice["message"]["function_call"]
                and choice["message"]["content"] is None
            ):
                # If no function call and content is still None (e.g. empty parts but STOP reason)
                choice["message"]["content"] = ""

        # Fallback for response.text if primary parsing fails (less likely with new SDK structure)
        if (
            choice["message"]["content"] is None
            and not choice["message"]["function_call"]
        ):
            if hasattr(response, "text") and response.text:
                choice["message"]["content"] = response.text
            elif (
                choice["finish_reason"] == "STOP"
            ):  # If it stopped but no content was parsed
                choice["message"]["content"] = ""

        # Construct the unified response structure
        # For usage, you might want to include an ID, object type, created timestamp, etc.
        # Similar to OpenAI's response structure for completions.
        unified_response = {
            "id": f"gemini-compl-{os.urandom(8).hex()}",  # Placeholder ID
            "object": "chat.completion",  # Mimicking OpenAI's type
            "created": int(time.time()),  # Timestamp
            "model": model_name,  # Echo back the model used
            "choices": [choice],
            "usage": {  # Placeholder for usage, Gemini API might provide token counts differently
                "prompt_tokens": None,  # Extract if available from response.usage_metadata
                "completion_tokens": None,  # Extract if available
                "total_tokens": None,
            },
        }
        if hasattr(response, "usage_metadata") and response.usage_metadata:
            unified_response["usage"][
                "prompt_tokens"
            ] = response.usage_metadata.prompt_token_count
            unified_response["usage"][
                "completion_tokens"
            ] = response.usage_metadata.candidates_token_count
            unified_response["usage"][
                "total_tokens"
            ] = response.usage_metadata.total_token_count

        return unified_response

    except Exception as e:
        print(f"Error parsing Gemini model response: {e}")
        traceback.print_exc()
        return {"error": f"Error parsing Gemini model response: {str(e)}"}


# Note: The Flask app integration from your original attachment is removed from this client file.
# The client file should only contain logic to call the LLM.
# The Flask app will import and use this call_gemini_model_unified function.
