import pytest
import time
import base64
import json
from hashlib import sha256
from coincurve.keys import PrivateKey, PublicKey

# Make sure 'auth_utils.py' is in the Python path or same directory
# If your file is named differently, adjust the import.
from auth_handler import (
    verify_signed_bearer_token_ecdsa,
    RECENTLY_USED_NONCES,
    TIMESTAMP_TOLERANCE_SECONDS,
    NONCE_EXPIRY_SECONDS,
    AuthMethod,
    # GATEWAY_API_KEYS will be mocked or set per test
)

# Test payload as provided by the user
TEST_PAYLOAD = {
    "model": "gemini-2.0-flash-001",
    "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Who won the world series in 2020?"},
    ],
    "max_tokens": 50,
    "temperature": 0.7,
}


@pytest.fixture(autouse=True)
def clear_nonces_before_each_test():
    """Ensures RECENTLY_USED_NONCES is cleared before each test."""
    RECENTLY_USED_NONCES.clear()
    yield  # This is where the test runs


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_successful():
    """Tests successful ECDSA signature verification."""
    # 1. Generate a new key pair for this test
    # Use a known private key for reproducible tests, or generate one
    # For this example, we generate one.
    priv_key = PrivateKey()  # Generates a new random private key
    # Get the uncompressed public key in hex format (04 + x + y)
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()

    # 2. Prepare request parameters
    api_key_id = "test_client_ecdsa_001"
    client_timestamp_str = str(int(time.time()))
    # Ensure nonce is unique for each run if tests run close in time
    nonce = "testnonce_" + str(int(time.time() * 1000000))
    http_method = "POST"
    http_path = "/v1/chat/completions"

    # Calculate body hash from the TEST_PAYLOAD
    # Ensure compact JSON encoding (no extra spaces) as the client would do
    request_body_json = json.dumps(TEST_PAYLOAD, separators=(",", ":"))
    body_hash_hex = sha256(request_body_json.encode("utf-8")).hexdigest()

    # 3. Construct the message to sign (must match the format in the function)
    message_string = f"{http_method}|{http_path}|{client_timestamp_str}|{nonce}|{api_key_id}|{body_hash_hex}"
    message_bytes = message_string.encode("utf-8")
    message_hash = sha256(message_bytes).digest()  # Raw digest for signing

    # 4. Create signature using coincurve
    # sign_recoverable produces a 65-byte signature (r,s,v) where v is 0 or 1.
    signature_bytes = priv_key.sign_recoverable(message_hash, hasher=None)
    assert len(signature_bytes) == 65
    signature_base64 = base64.b64encode(signature_bytes).decode("utf-8")

    # 5. Configure GATEWAY_API_KEYS for the test
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}

    # 6. Call the verification function
    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64=signature_base64,
        api_key_id=api_key_id,
        client_timestamp_str=client_timestamp_str,
        nonce=nonce,
        http_method=http_method,
        http_path=http_path,
        body_hash_hex=body_hash_hex,
        current_gateway_api_keys=current_gateway_api_keys,
    )

    # 7. Assertions
    assert is_authorized is True
    assert message == "Authorized"


## --- Failure Case Tests ---


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_missing_elements():
    """Tests failure when required elements are missing."""
    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64="",  # Empty signature
        api_key_id="some_id",
        client_timestamp_str=str(int(time.time())),
        nonce="some_nonce",
        http_method="POST",
        http_path="/test",
        body_hash_hex="some_hash",
        current_gateway_api_keys={"some_id": {"public_key_hex": "04abcd..."}},
    )
    assert is_authorized is False
    assert "Missing one or more required elements" in message


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_public_key_not_configured():
    """Tests failure when the public key for the given api_key_id is not found."""
    api_key_id = "unknown_client_id"
    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64="c2lnbmF0dXJl",  # dummy base64
        api_key_id=api_key_id,
        client_timestamp_str=str(int(time.time())),
        nonce="testnonce_unknown_pk",
        http_method="POST",
        http_path="/test",
        body_hash_hex="somehash",
        current_gateway_api_keys={},  # Empty config
    )
    assert is_authorized is False
    assert f"Public key not configured for API Key ID: {api_key_id}" in message


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_invalid_public_key_hex_format():
    """Tests failure with an incorrectly formatted public key hex string."""
    api_key_id = "client_with_bad_pk_format"
    current_gateway_api_keys = {
        api_key_id: {"public_key_hex": "04not-a-valid-hex-string-because-of-hyphens"}
    }
    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64="c2lnbmF0dXJl",
        api_key_id=api_key_id,
        client_timestamp_str=str(int(time.time())),
        nonce="testnonce_bad_pk_format",
        http_method="POST",
        http_path="/test",
        body_hash_hex="somehash",
        current_gateway_api_keys=current_gateway_api_keys,
    )
    assert is_authorized is False
    assert (
        f"Invalid configured public key format for API Key ID {api_key_id}" in message
    )


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_error_processing_public_key():
    """Tests failure when PublicKey object cannot be created from hex (e.g., wrong length)."""
    api_key_id = "client_with_short_pk"
    current_gateway_api_keys = {
        # Public key hex too short for uncompressed secp256k1 key (needs 04 + 64 bytes)
        api_key_id: {"public_key_hex": "04112233445566778899aabbccddeeff"}
    }
    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64="c2lnbmF0dXJl",
        api_key_id=api_key_id,
        client_timestamp_str=str(int(time.time())),
        nonce="testnonce_short_pk",
        http_method="POST",
        http_path="/test",
        body_hash_hex="somehash",
        current_gateway_api_keys=current_gateway_api_keys,
    )
    assert is_authorized is False
    assert (
        f"Invalid configured public key format for API Key ID {api_key_id}" in message
    )


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_invalid_timestamp_format():
    """Tests failure with a non-integer timestamp string."""
    priv_key = PrivateKey()
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()
    api_key_id = "test_client_ts_format"
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}

    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64="c2lnbmF0dXJl",
        api_key_id=api_key_id,
        client_timestamp_str="not_an_integer_timestamp",  # Invalid format
        nonce="testnonce_ts_format",
        http_method="POST",
        http_path="/test",
        body_hash_hex="somehash",
        current_gateway_api_keys=current_gateway_api_keys,
    )
    assert is_authorized is False
    assert "Invalid timestamp format. Must be an integer (Unix seconds)." in message


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_timestamp_too_old():
    """Tests failure when timestamp is outside the tolerance window (too old)."""
    priv_key = PrivateKey()
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()
    api_key_id = "test_client_ts_old"
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}
    # Timestamp older than tolerance allows
    client_timestamp_str = str(int(time.time()) - TIMESTAMP_TOLERANCE_SECONDS - 60)

    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64="c2lnbmF0dXJl",
        api_key_id=api_key_id,
        client_timestamp_str=client_timestamp_str,
        nonce="testnonce_ts_old",
        http_method="POST",
        http_path="/test",
        body_hash_hex="somehash",
        current_gateway_api_keys=current_gateway_api_keys,
    )
    assert is_authorized is False
    assert "Timestamp out of sync" in message


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_timestamp_too_new():
    """Tests failure when timestamp is outside the tolerance window (in the future)."""
    priv_key = PrivateKey()
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()
    api_key_id = "test_client_ts_new"
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}
    # Timestamp newer than tolerance allows (simulating significant clock skew)
    client_timestamp_str = str(int(time.time()) + TIMESTAMP_TOLERANCE_SECONDS + 60)

    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64="c2lnbmF0dXJl",
        api_key_id=api_key_id,
        client_timestamp_str=client_timestamp_str,
        nonce="testnonce_ts_new",
        http_method="POST",
        http_path="/test",
        body_hash_hex="somehash",
        current_gateway_api_keys=current_gateway_api_keys,
    )
    assert is_authorized is False
    assert "Timestamp out of sync" in message


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_replay_attack():
    """Tests failure when the same nonce is used twice (replay attack)."""
    priv_key = PrivateKey()
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()
    api_key_id = "test_client_replay"
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}

    client_timestamp_str = str(int(time.time()))
    nonce = "replayed_nonce_" + str(int(time.time() * 1000000))
    http_method = "POST"
    http_path = "/replay"
    body_hash_hex = sha256(b"replay_body").hexdigest()

    message_string = f"{http_method}|{http_path}|{client_timestamp_str}|{nonce}|{api_key_id}|{body_hash_hex}"
    message_hash = sha256(message_string.encode("utf-8")).digest()
    signature_bytes = priv_key.sign_recoverable(message_hash, hasher=None)
    signature_base64 = base64.b64encode(signature_bytes).decode("utf-8")

    # First call (should be successful)
    is_authorized1, message1 = await verify_signed_bearer_token_ecdsa(
        signature_base64,
        api_key_id,
        client_timestamp_str,
        nonce,
        http_method,
        http_path,
        body_hash_hex,
        current_gateway_api_keys,
    )
    assert is_authorized1 is True
    assert message1 == "Authorized"

    # Second call with the same nonce (should fail)
    # Simulate a very slight delay, timestamp should still be valid generally
    client_timestamp_str_replay = str(int(time.time()))  # Can be same or slightly newer
    is_authorized2, message2 = await verify_signed_bearer_token_ecdsa(
        signature_base64,
        api_key_id,
        client_timestamp_str_replay,
        nonce,  # SAME NONCE
        http_method,
        http_path,
        body_hash_hex,
        current_gateway_api_keys,
    )
    assert is_authorized2 is False
    assert "Replay attack detected" in message2


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_nonce_cleanup():
    """Tests that old nonces are cleaned up."""
    priv_key = PrivateKey()
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()
    api_key_id = "test_client_nonce_cleanup"
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}

    # Add an old nonce that should be expired
    old_nonce = "very_old_nonce"
    # Timestamp well before NONCE_EXPIRY_SECONDS
    timestamp_of_old_nonce = int(time.time()) - NONCE_EXPIRY_SECONDS - 300
    RECENTLY_USED_NONCES[(api_key_id, old_nonce)] = timestamp_of_old_nonce
    assert (api_key_id, old_nonce) in RECENTLY_USED_NONCES

    # Prepare and make a new valid request to trigger cleanup
    client_timestamp_str = str(int(time.time()))
    nonce = "new_nonce_for_cleanup" + str(int(time.time() * 1000000))
    http_method = "GET"
    http_path = "/cleanup"
    body_hash_hex = sha256(b"").hexdigest()
    message_string = f"{http_method}|{http_path}|{client_timestamp_str}|{nonce}|{api_key_id}|{body_hash_hex}"
    message_hash = sha256(message_string.encode("utf-8")).digest()
    signature_bytes = priv_key.sign_recoverable(message_hash, hasher=None)
    signature_base64 = base64.b64encode(signature_bytes).decode("utf-8")

    await verify_signed_bearer_token_ecdsa(
        signature_base64,
        api_key_id,
        client_timestamp_str,
        nonce,
        http_method,
        http_path,
        body_hash_hex,
        current_gateway_api_keys,
    )

    # The old nonce should now be removed
    assert (api_key_id, old_nonce) not in RECENTLY_USED_NONCES
    assert (api_key_id, nonce) in RECENTLY_USED_NONCES  # The new one should be there


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_invalid_base64_signature():
    """Tests failure with an invalid Base64 encoded signature string."""
    priv_key = PrivateKey()
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()
    api_key_id = "test_client_bad_b64"
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}

    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64="this is not valid base64!@#$%^",  # Invalid base64
        api_key_id=api_key_id,
        client_timestamp_str=str(int(time.time())),
        nonce="testnonce_bad_b64",
        http_method="POST",
        http_path="/test",
        body_hash_hex="somehash",
        current_gateway_api_keys=current_gateway_api_keys,
    )
    assert is_authorized is False
    assert "Invalid signature length. Expected 65 bytes (r, s, v)." in message


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_invalid_signature_length():
    """Tests failure when the decoded signature is not 65 bytes."""
    priv_key = PrivateKey()
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()
    api_key_id = "test_client_sig_len"
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}
    # Encode a string that is not 65 bytes long when decoded
    short_signature_base64 = base64.b64encode(b"short_signature_bytes").decode("utf-8")

    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64=short_signature_base64,
        api_key_id=api_key_id,
        client_timestamp_str=str(int(time.time())),
        nonce="testnonce_sig_len",
        http_method="POST",
        http_path="/test",
        body_hash_hex="somehash",
        current_gateway_api_keys=current_gateway_api_keys,
    )
    assert is_authorized is False
    assert "Invalid signature length. Expected 65 bytes (r, s, v)." in message


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_mismatched_public_key():
    """Tests failure when signature is valid but for a different public key than configured."""
    # Key pair used for signing
    signer_priv_key = PrivateKey()

    # A different key pair whose public key is configured for the API Key ID
    configured_priv_key = PrivateKey()
    configured_pub_key_hex = configured_priv_key.public_key.format(
        compressed=False
    ).hex()

    api_key_id = "test_client_mismatch_pk"
    client_timestamp_str = str(int(time.time()))
    nonce = "testnonce_mismatch_pk_" + str(int(time.time() * 1000000))
    http_method = "POST"
    http_path = "/mismatch"
    body_hash_hex = sha256(b"mismatch_body").hexdigest()

    # Message signed by signer_priv_key
    message_string = f"{http_method}|{http_path}|{client_timestamp_str}|{nonce}|{api_key_id}|{body_hash_hex}"
    message_hash = sha256(message_string.encode("utf-8")).digest()
    signature_bytes = signer_priv_key.sign_recoverable(message_hash, hasher=None)
    signature_base64 = base64.b64encode(signature_bytes).decode("utf-8")

    # Configure GATEWAY_API_KEYS with the *configured_pub_key_hex*
    current_gateway_api_keys = {api_key_id: {"public_key_hex": configured_pub_key_hex}}

    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64,
        api_key_id,
        client_timestamp_str,
        nonce,
        http_method,
        http_path,
        body_hash_hex,
        current_gateway_api_keys,
    )
    assert is_authorized is False
    assert (
        "Invalid signature or API Key ID." in message
    )  # This is the expected generic error


@pytest.mark.asyncio
async def test_verify_signed_bearer_token_ecdsa_tampered_message_content():
    """Tests failure when message content (e.g., body_hash) is tampered after signing."""
    priv_key = PrivateKey()
    pub_key_hex = priv_key.public_key.format(compressed=False).hex()
    api_key_id = "test_client_tampered"
    current_gateway_api_keys = {api_key_id: {"public_key_hex": pub_key_hex}}

    client_timestamp_str = str(int(time.time()))
    nonce = "testnonce_tamper_" + str(int(time.time() * 1000000))
    http_method = "POST"
    http_path = "/tamper"
    original_body_json = json.dumps({"data": "original"}, separators=(",", ":"))
    original_body_hash_hex = sha256(original_body_json.encode("utf-8")).hexdigest()

    # Sign the original message
    message_string = f"{http_method}|{http_path}|{client_timestamp_str}|{nonce}|{api_key_id}|{original_body_hash_hex}"
    message_hash = sha256(message_string.encode("utf-8")).digest()
    signature_bytes = priv_key.sign_recoverable(message_hash, hasher=None)
    signature_base64 = base64.b64encode(signature_bytes).decode("utf-8")

    # Tamper the body hash before verification
    tampered_body_hash_hex = sha256(b"tampered_content").hexdigest()

    is_authorized, message = await verify_signed_bearer_token_ecdsa(
        signature_base64,
        api_key_id,
        client_timestamp_str,
        nonce,
        http_method,
        http_path,
        tampered_body_hash_hex,  # Use tampered hash
        current_gateway_api_keys,
    )
    assert is_authorized is False
    # Expectation: The recovered public key will not match the configured one,
    # or signature recovery itself will fail for the new hash.
    assert (
        "Invalid signature or API Key ID." in message
        or "Signature verification failed" in message
    )


if __name__ == "__main__":
    # print a valid http request with the headers
    print("## Example HTTP Request for ECDSA Signed Bearer Token ##\n")

    # 1. Generate a new ECDSA key pair for the client

    client_priv_key = PrivateKey()  # coincurve.keys.PrivateKey
    client_pub_key_uncompressed_hex = client_priv_key.public_key.format(
        compressed=False
    ).hex()

    # This public key would be configured on the server side (in GATEWAY_API_KEYS)
    api_key_id_for_signing = "test_client_ecdsa_001"
    print(f"Client's API Key ID: {api_key_id_for_signing}")
    print(
        f"Client's Public Key (to be configured on server for this ID): {client_pub_key_uncompressed_hex}\n"
    )

    # Simulate server's configuration for this client
    # In a real scenario, this GATEWAY_API_KEYS would be on the server.
    # For this example, we use it to show what the server expects.
    simulated_server_gateway_api_keys = {
        api_key_id_for_signing: {"public_key_hex": client_pub_key_uncompressed_hex}
        # ... other client configurations
    }

    # 2. Define request parameters
    http_method = "POST"
    # Example target URL for the request (scheme and host are for curl example)
    target_url = "http://localhost:12457/v1/chat/completions"
    http_path = "/v1/chat/completions"  # Path part of the URL

    # Sample JSON payload for the request body
    request_payload = {
        "model": "gemini-2.0-flash-001",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Generate a sample cURL request."},
        ],
        "max_tokens": 100,
    }
    request_body_json_str = json.dumps(
        request_payload, separators=(",", ":")
    )  # Compact JSON

    # 3. Prepare elements for the signature
    client_timestamp_str = str(int(time.time()))
    nonce = "my-unique-nonce-" + str(int(time.time() * 1000000))  # Ensure uniqueness
    body_hash_hex = sha256(request_body_json_str.encode("utf-8")).hexdigest()

    # 4. Construct the message string to be signed
    # Format: HTTPMethod|HTTPPath|Timestamp|Nonce|APIKeyID|BodyHashHex
    message_to_sign_str = f"{http_method}|{http_path}|{client_timestamp_str}|{nonce}|{api_key_id_for_signing}|{body_hash_hex}"
    message_to_sign_bytes = message_to_sign_str.encode("utf-8")
    message_hash_to_sign = sha256(message_to_sign_bytes).digest()  # Raw digest

    # 5. Sign the hash with the client's private key
    # coincurve's sign_recoverable produces a 65-byte signature (r,s,v)
    signature_bytes = client_priv_key.sign_recoverable(
        message_hash_to_sign, hasher=None
    )
    signature_base64 = base64.b64encode(signature_bytes).decode("utf-8")

    print("--- Request Details ---")
    print(f"HTTP Method: {http_method}")
    print(f"HTTP Path: {http_path}")
    print(f"API Key ID (X-Api-Key-Id): {api_key_id_for_signing}")
    print(f"Timestamp (X-Timestamp): {client_timestamp_str}")
    print(f"Nonce (X-Nonce): {nonce}")
    print(f"Body Hash (X-Body-Hash): {body_hash_hex}")
    print(f"Message Signed by Client:\n{message_to_sign_str}")
    print(
        f"Signature (Authorization: Bearer <signature_base64>):\n{signature_base64}\n"
    )
    print(f"Request Body (JSON):\n{request_body_json_str}\n")

    print("--- Example cURL command ---")
    # Construct the cURL command
    curl_command = f"curl -X {http_method} '{target_url}' \\\n"
    curl_command += f"  -H 'Authorization: Bearer {signature_base64}' \\\n"
    curl_command += f"  -H 'X-Auth-Method: {AuthMethod.BEARER_SIGNED}' \\\n"  # Specify signed method
    curl_command += f"  -H 'X-Api-Key-Id: {api_key_id_for_signing}' \\\n"
    curl_command += f"  -H 'X-Timestamp: {client_timestamp_str}' \\\n"
    curl_command += f"  -H 'X-Nonce: {nonce}' \\\n"
    curl_command += f"  -H 'X-Body-Hash: {body_hash_hex}' \\\n"
    curl_command += f"  -H 'Content-Type: application/json' \\\n"
    curl_command += f"  -d '{request_body_json_str}'"

    print(curl_command)
    print("\n--- Verification Check (Simulated Server-Side) ---")
    # Now, let's try to verify this signature with the `verify_signed_bearer_token_ecdsa` function
    # This simulates what the server would do upon receiving the request.
    # Note: verify_signed_bearer_token_ecdsa is async, so we'd need an event loop to run it here.
    # For simplicity, we'll just print the parameters that would be passed.

    print(
        "Parameters that would be passed to verify_signed_bearer_token_ecdsa on the server:"
    )
    print(f"  signature_base64: '{signature_base64}'")
    print(f"  api_key_id: '{api_key_id_for_signing}'")
    print(f"  client_timestamp_str: '{client_timestamp_str}'")
    print(f"  nonce: '{nonce}'")
    print(f"  http_method: '{http_method}'")
    print(f"  http_path: '{http_path}'")
    print(f"  body_hash_hex: '{body_hash_hex}'")
    print(
        f"  current_gateway_api_keys (on server): {{ '{api_key_id_for_signing}': {{ 'public_key_hex': '{client_pub_key_uncompressed_hex}' }} }}"
    )

    # To actually run the verification in this __main__ block:
    import asyncio

    async def main_verify():
        is_authorized, message = await verify_signed_bearer_token_ecdsa(
            signature_base64=signature_base64,
            api_key_id=api_key_id_for_signing,
            client_timestamp_str=client_timestamp_str,
            nonce=nonce,
            http_method=http_method,
            http_path=http_path,
            body_hash_hex=body_hash_hex,
            current_gateway_api_keys=simulated_server_gateway_api_keys,
        )
        print("\n--- Simulated Verification Result ---")
        if is_authorized:
            print(f"✅ Signature VERIFIED: {message}")
        else:
            print(f"❌ Signature VERIFICATION FAILED: {message}")

    # Run the async verification
    print(
        "\nAttempting direct verification using the generated signature and parameters..."
    )
    asyncio.run(main_verify())
