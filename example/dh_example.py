import httpx  # For making asynchronous HTTP requests
import base64
import json
import asyncio

# Cryptography imports for X25519 and HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Server gateway URL (modify according to your actual server address and port)
GATEWAY_BASE_URL = "http://localhost:12457"
DH_INITIATE_ENDPOINT = f"{GATEWAY_BASE_URL}/v1/dh/initiate"


async def perform_dh_key_exchange():
    """
    Perform the Diffie-Hellman key exchange process.
    Returns (client_public_key_b64, derived_symmetric_key) or (None, None) if failed.
    """
    # 1. Client generates its own X25519 key pair
    client_private_key = x25519.X25519PrivateKey.generate()
    client_public_key = client_private_key.public_key()

    client_public_key_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    client_public_key_b64 = base64.b64encode(client_public_key_bytes).decode("utf-8")

    print(f"Client generated X25519 public key (Base64): {client_public_key_b64}")

    # 2. Prepare request payload
    request_payload = {"client_public_key": client_public_key_b64}

    # 3. Send POST request to the server
    async with httpx.AsyncClient() as client:
        try:
            print(f"Sending key exchange request to {DH_INITIATE_ENDPOINT} ...")
            response = await client.post(DH_INITIATE_ENDPOINT, json=request_payload)
            response.raise_for_status()  # Raise exception for 4xx or 5xx status codes

            response_data = response.json()
            server_public_key_b64 = response_data.get("server_public_key")

            if not server_public_key_b64:
                print("Error: 'server_public_key' not found in server response")
                return None, None

            print(
                f"Received X25519 public key from server (Base64): {server_public_key_b64}"
            )

        except httpx.HTTPStatusError as e:
            print(f"HTTP error: {e.response.status_code} - {e.response.text}")
            return None, None
        except httpx.RequestError as e:
            print(f"Request error: {e}")
            return None, None
        except json.JSONDecodeError:
            print("Error: Failed to decode JSON response from server")
            return None, None

    # 4. Decode server's public key
    try:
        server_public_key_bytes = base64.b64decode(server_public_key_b64)
        if len(server_public_key_bytes) != 32:
            print(
                f"Error: Invalid server public key length (expected 32 bytes, got {len(server_public_key_bytes)})"
            )
            return None, None
        server_x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
            server_public_key_bytes
        )
    except (base64.binascii.Error, ValueError) as e:
        print(f"Error: Failed to decode server public key (invalid Base64): {e}")
        return None, None
    except Exception as e:
        print(f"Error: Unknown error while processing server public key: {e}")
        return None, None

    # 5. Client performs X25519 key exchange to compute shared secret
    try:
        shared_secret_bytes_client = client_private_key.exchange(
            server_x25519_public_key
        )
        print(
            f"Client computed shared secret (first 5 bytes hex): {shared_secret_bytes_client[:5].hex()}..."
        )
    except Exception as e:
        print(f"Error: Client failed to compute shared secret: {e}")
        return None, None

    # 6. Derive symmetric key from shared secret using HKDF
    #    (HKDF parameters must match exactly with the server)
    derived_symmetric_key_client = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Length of derived key (e.g., for HMAC-SHA256 or AES-256)
        salt=None,  # Optional salt (must match server if used)
        info=b"llm-gateway-dh-symmetric-key-v1",  # Context info (must match server)
    ).derive(shared_secret_bytes_client)

    print(
        f"Client derived symmetric key (first 5 bytes hex): {derived_symmetric_key_client[:5].hex()}..."
    )
    derived_symmetric_key_client_b64 = base64.b64encode(
        derived_symmetric_key_client
    ).decode("utf-8")
    # 7. The client now has client_public_key_b64 (as session identifier) and derived_symmetric_key_client
    #    These two values will be used for authenticating subsequent requests.
    return client_public_key_b64, derived_symmetric_key_client_b64


async def main():
    print("Starting Diffie-Hellman key exchange with LLM gateway...")

    # Perform key exchange
    client_id, symmetric_key_b64 = await perform_dh_key_exchange()
    DH_KEY_EXCHANGE = "dh_key_exchange"
    if client_id and symmetric_key_b64:
        print("\nKey exchange successful!")
        print(f"  Client ID (your public key Base64): {client_id}")
        print(f"  Derived symmetric key (Base64): {symmetric_key_b64}")
        print(
            "\nYou can now use this client ID and symmetric key to authenticate subsequent API requests."
        )
        print(
            "For example, send the client ID in the Bearer token or X-Api-Key-Id header,"
        )
        print(
            "and use the symmetric key to generate an HMAC for the request content (e.g., in the X-Request-MAC header)."
        )
    else:
        print("\nKey exchange failed.")
    # Print the curl command to perform the request
    print(f"curl -X POST '{GATEWAY_BASE_URL}/v1/chat/completions' \\")
    print(f"  -H 'Authorization: Bearer {symmetric_key_b64}' \\")
    print(f"  -H 'X-Auth-Method: {DH_KEY_EXCHANGE}' \\")
    print(f"  -H 'Content-Type: application/json' \\")
    print(
        f'  -d \'{{"model": "gemini-2.0-flash-001", "messages": [{{"role": "user", "content": "Hello ECDSA!"}}]}}\''
    )


if __name__ == "__main__":
    asyncio.run(main())
