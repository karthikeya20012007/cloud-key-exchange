
import base64
import uuid
from datetime import datetime, timezone
from typing import Literal

from pathlib import Path

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(
    title="Privacy-Preserving Key Exchange",
    description=(
        "A microproject demonstrating ECDH key exchange, "
        "client-side encryption, and cloud ciphertext storage."
    ),
    version="1.0.0",
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")

# In-memory storage for this educational prototype.
# Data is lost when the server restarts.
public_keys: dict[str, str] = {}
messages: dict[str, dict] = {}


class PublicKeyRequest(BaseModel):
    public_key: str = Field(min_length=1, max_length=4096)


class MessageRequest(BaseModel):
    sender: str = Field(min_length=1, max_length=50)
    recipient: str = Field(min_length=1, max_length=50)
    ciphertext: str = Field(min_length=1, max_length=100000)
    nonce: str = Field(min_length=1, max_length=100)
    # Base64-encoded AES-GCM ciphertext, including its authentication tag.
    # The server does not receive plaintext or derived encryption keys.


class MessageResponse(BaseModel):
    message_id: str
    sender: str
    recipient: str
    ciphertext: str
    nonce: str
    created_at: str


@app.get("/")
def home():
    return {
        "project": "Privacy-Preserving Key Exchange",
        "status": "running",
        "cryptography": ["ECDH", "HKDF-SHA256", "AES-256-GCM"],
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/users/{user}/keys")
def register_public_key(
    user: str,
    request: PublicKeyRequest,
):
    user = user.strip().lower()

    if user not in {"alice", "bob"}:
        raise HTTPException(
            status_code=400,
            detail="User must be alice or bob.",
        )

    try:
        decoded_key = base64.b64decode(
            request.public_key,
            validate=True,
        )
        if not decoded_key:
            raise ValueError("Empty public key.")
    except (ValueError, base64.binascii.Error):
        raise HTTPException(
            status_code=400,
            detail="Public key must be valid Base64.",
        )

    # This endpoint validates the encoding only.
    # A production implementation must parse the key, verify its type,
    # authenticate its owner, and prevent key-substitution attacks.
    public_keys[user] = request.public_key

    return {
        "status": "registered",
        "user": user,
        "message": "Public key stored. Private keys are not accepted.",
    }


@app.get("/users/{user}/keys")
def get_public_key(user: str):
    user = user.strip().lower()

    if user not in {"alice", "bob"}:
        raise HTTPException(
            status_code=400,
            detail="User must be alice or bob.",
        )

    if user not in public_keys:
        raise HTTPException(
            status_code=404,
            detail="Public key not registered.",
        )

    return {
        "user": user,
        "public_key": public_keys[user],
    }


@app.post("/messages", response_model=MessageResponse)
def store_message(request: MessageRequest):
    sender = request.sender.strip().lower()
    recipient = request.recipient.strip().lower()

    if sender not in {"alice", "bob"} or recipient not in {"alice", "bob"}:
        raise HTTPException(
            status_code=400,
            detail="Sender and recipient must be alice or bob.",
        )

    if sender == recipient:
        raise HTTPException(
            status_code=400,
            detail="Sender and recipient must be different.",
        )

    if sender not in public_keys or recipient not in public_keys:
        raise HTTPException(
            status_code=409,
            detail="Both users must register public keys first.",
        )

    try:
        ciphertext_bytes = base64.b64decode(
            request.ciphertext,
            validate=True,
        )
        nonce_bytes = base64.b64decode(
            request.nonce,
            validate=True,
        )
        if not ciphertext_bytes:
            raise ValueError("Empty ciphertext.")
        if len(nonce_bytes) != 12:
            raise ValueError("Invalid nonce length.")
    except (ValueError, base64.binascii.Error):
        raise HTTPException(
            status_code=400,
            detail="Ciphertext or nonce is invalid Base64, or nonce length is invalid.",
        )

    message_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    record = {
        "message_id": message_id,
        "sender": sender,
        "recipient": recipient,
        "ciphertext": request.ciphertext,
        "nonce": request.nonce,
        "created_at": created_at,
    }

    messages[message_id] = record

    return record


@app.get("/messages/{message_id}", response_model=MessageResponse)
def retrieve_message(message_id: str):
    record = messages.get(message_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Message not found.",
        )

    return record


@app.get("/messages")
def list_messages(
    recipient: Literal["alice", "bob"] | None = None,
):
    results = list(messages.values())

    if recipient is not None:
        results = [
            message
            for message in results
            if message["recipient"] == recipient
        ]

    return {
        "count": len(results),
        "messages": results,
    }


@app.delete("/messages")
def clear_messages():
    # Demonstration endpoint only; not suitable for an exposed production API.
    count = len(messages)
    messages.clear()

    return {
        "status": "cleared",
        "deleted_messages": count,
    }
