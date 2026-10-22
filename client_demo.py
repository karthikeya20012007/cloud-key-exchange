
import json
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidTag

from crypto_utils import (
    generate_key_pair,
    public_key_to_base64,
    derive_shared_key,
    encrypt_message,
    decrypt_message,
)

BASE_URL = "http://127.0.0.1:8000"


def api_request(path, method="GET", payload=None):
    """Send a JSON request to the FastAPI server."""
    data = None

    headers = {"Accept": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"API returned HTTP {exc.code}: {detail}"
        ) from exc


def main():
    print("=" * 60)
    print("CLOUD KEY-EXCHANGE CLIENT DEMONSTRATION")
    print("=" * 60)

    # Alice and Bob generate their own key pairs locally.
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    print("\n[1] Alice and Bob generated their key pairs.")

    # Only public keys are registered with the server.
    api_request(
        "/users/alice/keys",
        method="POST",
        payload={
            "public_key": public_key_to_base64(alice_public)
        },
    )

    api_request(
        "/users/bob/keys",
        method="POST",
        payload={
            "public_key": public_key_to_base64(bob_public)
        },
    )

    print("[2] Public keys registered with the server.")

    # Retrieve each other's public keys from the server.
    alice_peer_public = api_request(
        "/users/bob/keys"
    )["public_key"]

    bob_peer_public = api_request(
        "/users/alice/keys"
    )["public_key"]

    import base64

    alice_peer_public = base64.b64decode(
        alice_peer_public,
        validate=True,
    )
    bob_peer_public = base64.b64decode(
        bob_peer_public,
        validate=True,
    )

    # Each client independently derives the same key.
    alice_key = derive_shared_key(
        alice_private,
        alice_peer_public,
    )

    bob_key = derive_shared_key(
        bob_private,
        bob_peer_public,
    )

    assert alice_key == bob_key
    print("[3] Shared-key agreement: SUCCESS")

    # Alice encrypts locally before sending the message.
    plaintext = "Confidential cloud data"
    encrypted = encrypt_message(plaintext, alice_key)

    print("\n[4] Alice sends encrypted data to the server.")
    print("    Plaintext sent to server: NO")
    print("    Ciphertext:", encrypted["ciphertext"])

    # Server stores ciphertext, nonce, sender and recipient.
    stored = api_request(
        "/messages",
        method="POST",
        payload={
            "sender": "alice",
            "recipient": "bob",
            "ciphertext": encrypted["ciphertext"],
            "nonce": encrypted["nonce"],
        },
    )

    message_id = stored["message_id"]
    print("    Message ID:", message_id)

    # Bob retrieves ciphertext and decrypts locally.
    received = api_request(
        f"/messages/{message_id}"
    )

    decrypted = decrypt_message(
        {
            "nonce": received["nonce"],
            "ciphertext": received["ciphertext"],
        },
        bob_key,
    )

    assert decrypted == plaintext
    print("\n[5] Bob decrypts the message.")
    print("    Decrypted message:", decrypted)
    print("    Decryption verification: SUCCESS")

    # Verify AES-GCM detects a modified ciphertext.
    tampered = dict(encrypted)
    tampered["ciphertext"] = (
        "AA" + tampered["ciphertext"][2:]
    )

    print("\n[6] Testing ciphertext tampering.")

    try:
        decrypt_message(tampered, bob_key)
        print("    Tampering detection: FAILED")
    except (InvalidTag, ValueError):
        print("    Tampering detection: SUCCESS")

    print("\n" + "=" * 60)
    print("DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("=" * 60)


if __name__ == "__main__":
    main()
