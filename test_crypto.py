
from cryptography.exceptions import InvalidTag

from crypto_utils import (
    generate_key_pair,
    derive_shared_key,
    encrypt_message,
    decrypt_message,
)


def main():
    print("=" * 55)
    print(" PRIVACY-PRESERVING KEY EXCHANGE DEMONSTRATION")
    print("=" * 55)

    # 1. Alice and Bob independently generate key pairs.
    alice_private, alice_public = generate_key_pair()
    bob_private, bob_public = generate_key_pair()

    print("\n[1] Key pairs generated successfully.")

    # 2. Each party derives a key using the other party's public key.
    alice_key = derive_shared_key(alice_private, bob_public)
    bob_key = derive_shared_key(bob_private, alice_public)

    print("[2] Alice and Bob derived their encryption keys.")

    # 3. Verify that both derived the same key.
    if alice_key != bob_key:
        raise RuntimeError("Key agreement failed!")

    print("[3] Shared key agreement: SUCCESS")
    print("    Both parties derived the same 256-bit key.")
    print("    Private keys were not exchanged.")

    # 4. Alice encrypts a confidential message.
    message = "Confidential cloud data"
    encrypted_data = encrypt_message(message, alice_key)

    print("\n[4] Alice encrypted her message.")
    print("    Original message:", message)
    print("    Ciphertext:", encrypted_data["ciphertext"])
    print("    Nonce:", encrypted_data["nonce"])

    # 5. Bob decrypts the message using his derived key.
    decrypted_message = decrypt_message(encrypted_data, bob_key)

    print("\n[5] Bob decrypted the message.")
    print("    Decrypted message:", decrypted_message)

    assert decrypted_message == message
    print("    Decryption verification: SUCCESS")

    # 6. Test tampering detection.
    tampered_data = encrypted_data.copy()
    tampered_data["ciphertext"] = (
        "AA" + tampered_data["ciphertext"][2:]
    )

    print("\n[6] Testing ciphertext tampering.")

    try:
        decrypt_message(tampered_data, bob_key)
        print("    WARNING: Tampering was not detected.")
    except (InvalidTag, ValueError):
        print("    Tampering detected: SUCCESS")

    print("\n" + "=" * 55)
    print(" ALL CRYPTOGRAPHIC TESTS COMPLETED")
    print("=" * 55)


if __name__ == "__main__":
    main()
