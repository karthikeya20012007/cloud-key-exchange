
import os
import base64

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key_pair():
    """Generate an ECDH private/public key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key, public_key_bytes


def public_key_to_base64(public_key_bytes: bytes) -> str:
    """Encode a public key for transport through JSON."""
    return base64.b64encode(public_key_bytes).decode("ascii")


def derive_shared_key(private_key, peer_public_key_bytes):
    """Derive a 256-bit AES key using ECDH and HKDF-SHA256."""
    peer_public_key = serialization.load_pem_public_key(
        peer_public_key_bytes
    )

    if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
        raise ValueError("Peer key must be an elliptic-curve public key.")

    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cloud-key-exchange-v1",
    ).derive(shared_secret)


def encrypt_message(message: str, aes_key: bytes) -> dict:
    """Encrypt a message using AES-GCM."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        message.encode("utf-8"),
        None,
    )

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_message(encrypted_data: dict, aes_key: bytes) -> str:
    """Decrypt and authenticate an AES-GCM message."""
    nonce = base64.b64decode(
        encrypted_data["nonce"],
        validate=True,
    )
    ciphertext = base64.b64decode(
        encrypted_data["ciphertext"],
        validate=True,
    )

    if len(nonce) != 12:
        raise ValueError("Invalid AES-GCM nonce length.")

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        None,
    )

    return plaintext.decode("utf-8")
