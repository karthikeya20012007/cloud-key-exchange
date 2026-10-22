
"use strict";

// KeyShield: browser-side ECDH + HKDF + AES-GCM.
// Only public keys and encrypted message data are sent to FastAPI.

const API = "";

const state = {
    alice: { privateKey: null, publicKey: null, registered: false },
    bob: { privateKey: null, publicKey: null, registered: false },
    lastMessage: null,
};

const $ = (id) => document.getElementById(id);

function log(message) {
    const container = $("activity-log");
    const entry = document.createElement("p");
    entry.className = "log-entry";
    entry.textContent = `${new Date().toLocaleTimeString()} — ${message}`;
    container.prepend(entry);
}

function feedback(message, type = "") {
    const element = $("message-feedback");
    element.textContent = message;
    element.className = `feedback ${type}`.trim();
}

function setParticipantStatus(user, message, ready = false) {
    $(`${user}-status`).textContent = message;
    $(`${user}-status`).classList.toggle("ready", ready);
}

function updateControls() {
    const aliceReady = state.alice.registered;
    const bobReady = state.bob.registered;
    const bothReady = aliceReady && bobReady;

    $("send-message").disabled = !bothReady;
    $("key-status").textContent = bothReady ? "Ready" : "Pending";

    if (bothReady) {
        feedback("Both public keys are registered. Secure messaging is ready.", "success");
    }
}

function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;

    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(
            ...bytes.subarray(i, i + chunkSize)
        );
    }

    return btoa(binary);
}

function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

function pemFromBytes(bytes) {
    const base64 = bytesToBase64(bytes);
    const lines = base64.match(/.{1,64}/g) || [];

    return [
        "-----BEGIN PUBLIC KEY-----",
        ...lines,
        "-----END PUBLIC KEY-----",
    ].join("\n") + "\n";
}

function bytesFromPem(pem) {
    const base64 = pem
        .replace(/-----BEGIN PUBLIC KEY-----/g, "")
        .replace(/-----END PUBLIC KEY-----/g, "")
        .replace(/\s/g, "");

    return base64ToBytes(base64);
}

// The existing FastAPI API stores Base64-encoded PEM text.
async function exportPublicKeyForServer(publicKey) {
    const spki = await crypto.subtle.exportKey("spki", publicKey);
    const pem = pemFromBytes(new Uint8Array(spki));

    return btoa(pem);
}

async function importPublicKeyFromServer(encodedPem) {
    const pem = atob(encodedPem);
    const spki = bytesFromPem(pem);

    return crypto.subtle.importKey(
        "spki",
        spki,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
    );
}

async function apiRequest(path, options = {}) {
    const response = await fetch(`${API}${path}`, {
        ...options,
        headers: {
            ...(options.body ? { "Content-Type": "application/json" } : {}),
            ...options.headers,
        },
    });

    const text = await response.text();
    let data = {};

    try {
        data = text ? JSON.parse(text) : {};
    } catch {
        throw new Error(`Server returned an unexpected response (${response.status}).`);
    }

    if (!response.ok) {
        const detail = typeof data.detail === "string"
            ? data.detail
            : `Request failed (${response.status}).`;

        throw new Error(detail);
    }

    return data;
}

async function generateKeys(user) {
    const participant = state[user];

    try {
        const pair = await crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256",
            },
            true,
            ["deriveBits"]
        );

        participant.privateKey = pair.privateKey;
        participant.publicKey = pair.publicKey;
        participant.registered = false;

        $(`${user}-key-state`).textContent = "ECDH P-256 key pair generated";
        $(`${user}-register`).disabled = false;

        setParticipantStatus(user, "Key generated", false);
        log(`${capitalize(user)} generated an ECDH key pair in the browser.`);

        updateControls();
        feedback(`${capitalize(user)}'s keys generated. Register the public key next.`, "success");
    } catch (error) {
        log(`Key generation failed: ${error.message}`);
        feedback(`Key generation failed: ${error.message}`, "error");
    }
}

async function registerPublicKey(user) {
    const participant = state[user];

    if (!participant.publicKey) {
        feedback(`Generate ${capitalize(user)}'s keys first.`, "error");
        return;
    }

    try {
        const encodedKey = await exportPublicKeyForServer(participant.publicKey);

        await apiRequest(`/users/${user}/keys`, {
            method: "POST",
            body: JSON.stringify({ public_key: encodedKey }),
        });

        participant.registered = true;

        setParticipantStatus(user, "Registered", true);
        $(`${user}-key-state`).textContent = "Public key registered";
        $(`${user}-register`).disabled = true;

        log(`${capitalize(user)} registered a public key with FastAPI.`);
        updateControls();
    } catch (error) {
        log(`Public-key registration failed: ${error.message}`);
        feedback(`Registration failed: ${error.message}`, "error");
    }
}

// Derive the same AES key independently on each participant's side.
// The HKDF parameters match crypto_utils.py.
async function deriveAesKey(privateKey, peerPublicKey) {
    const sharedSecret = await crypto.subtle.deriveBits(
        {
            name: "ECDH",
            public: peerPublicKey,
        },
        privateKey,
        256
    );

    const hkdfKey = await crypto.subtle.importKey(
        "raw",
        sharedSecret,
        "HKDF",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: new TextEncoder().encode("cloud-key-exchange-v1"),
        },
        hkdfKey,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function getRegisteredPublicKey(user) {
    const result = await apiRequest(`/users/${user}/keys`);

    return importPublicKeyFromServer(result.public_key);
}

async function encryptMessage(plaintext, aesKey) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: nonce,
            tagLength: 128,
        },
        aesKey,
        new TextEncoder().encode(plaintext)
    );

    return {
        nonce: bytesToBase64(nonce),
        ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    };
}

async function decryptMessage(encrypted, aesKey) {
    const nonce = base64ToBytes(encrypted.nonce);
    const ciphertext = base64ToBytes(encrypted.ciphertext);

    if (nonce.length !== 12) {
        throw new Error("Invalid AES-GCM nonce length.");
    }

    const plaintext = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: nonce,
            tagLength: 128,
        },
        aesKey,
        ciphertext
    );

    return new TextDecoder().decode(plaintext);
}

async function sendMessage() {
    const plaintext = $("message-input").value;

    if (!plaintext.trim()) {
        feedback("Enter a message before sending.", "error");
        return;
    }

    if (!state.alice.registered || !state.bob.registered) {
        feedback("Generate and register both public keys first.", "error");
        return;
    }

    $("send-message").disabled = true;

    try {
        // Alice fetches Bob's public key and derives the encryption key.
        const bobPublicKey = await getRegisteredPublicKey("bob");
        const aliceAesKey = await deriveAesKey(
            state.alice.privateKey,
            bobPublicKey
        );

        // Bob independently derives the corresponding decryption key.
        const alicePublicKey = await getRegisteredPublicKey("alice");
        const bobAesKey = await deriveAesKey(
            state.bob.privateKey,
            alicePublicKey
        );

        const encrypted = await encryptMessage(plaintext, aliceAesKey);

        // Send only ciphertext and nonce to the server.
        const stored = await apiRequest("/messages", {
            method: "POST",
            body: JSON.stringify({
                sender: "alice",
                recipient: "bob",
                ciphertext: encrypted.ciphertext,
                nonce: encrypted.nonce,
            }),
        });

        state.lastMessage = {
            messageId: stored.message_id,
            bobAesKey,
            encrypted,
        };

        $("ciphertext-output").textContent = JSON.stringify(
            {
                message_id: stored.message_id,
                sender: stored.sender,
                recipient: stored.recipient,
                ciphertext: stored.ciphertext,
                nonce: stored.nonce,
            },
            null,
            2
        );

        // Bob fetches the stored record rather than using the local copy.
        const received = await apiRequest(
            `/messages/${encodeURIComponent(stored.message_id)}`
        );

        const decrypted = await decryptMessage(received, bobAesKey);

        $("plaintext-output").textContent = decrypted;
        $("decrypt-status").textContent = "Verified";
        $("decrypt-status").classList.add("ready");

        log("Alice encrypted a message locally and uploaded ciphertext.");
        log(`Server stored message ${stored.message_id}.`);
        log("Bob fetched and authenticated the ciphertext successfully.");

        feedback("Message sent and decrypted successfully. Plaintext was not sent to the API.", "success");

        await refreshMessages();
    } catch (error) {
        $("decrypt-status").textContent = "Failed";
        $("plaintext-output").textContent = "Decryption was not completed.";
        log(`Messaging failed: ${error.message}`);
        feedback(`Messaging failed: ${error.message}`, "error");
    } finally {
        updateControls();
    }
}

async function refreshMessages() {
    try {
        const result = await apiRequest("/messages");
        const messages = result.messages || [];

        $("message-count").textContent = String(result.count ?? messages.length);

        const container = $("storage-list");
        container.replaceChildren();

        if (messages.length === 0) {
            const empty = document.createElement("div");
            empty.className = "empty-state";
            empty.textContent = "No messages stored on the server.";
            container.appendChild(empty);
            return;
        }

        for (const message of messages) {
            const row = document.createElement("div");
            row.className = "storage-row";

            const id = document.createElement("span");
            id.textContent = message.message_id;

            const route = document.createElement("span");
            route.textContent = `${message.sender} → ${message.recipient}`;

            const created = document.createElement("span");
            created.textContent = message.created_at
                ? new Date(message.created_at).toLocaleString()
                : "Unknown";

            row.append(id, route, created);
            container.appendChild(row);
        }
    } catch (error) {
        log(`Could not refresh server storage: ${error.message}`);
    }
}

async function testTampering() {
    if (!state.lastMessage) {
        feedback("Send a message before testing tampering.", "error");
        return;
    }

    try {
        const original = state.lastMessage.encrypted;
        const tamperedBytes = base64ToBytes(original.ciphertext);

        if (tamperedBytes.length === 0) {
            throw new Error("Ciphertext is empty.");
        }

        // Flip a bit in the ciphertext while preserving the nonce.
        tamperedBytes[0] ^= 1;

        const tampered = {
            nonce: original.nonce,
            ciphertext: bytesToBase64(tamperedBytes),
        };

        try {
            await decryptMessage(tampered, state.lastMessage.bobAesKey);

            $("decrypt-status").textContent = "Unexpected success";
            $("decrypt-status").classList.remove("ready");
            $("plaintext-output").textContent = "Warning: modified ciphertext was accepted.";
            feedback("Tampering test failed: modified data was decrypted.", "error");
            log("WARNING: tampered ciphertext was unexpectedly accepted.");
        } catch {
            $("decrypt-status").textContent = "Tampering detected";
            $("decrypt-status").classList.add("ready");
            $("plaintext-output").textContent =
                "Tampered ciphertext rejected. AES-GCM authentication failed as expected.";

            feedback("Tampering detected: AES-GCM rejected the modified ciphertext.", "success");
            log("Tampering test passed: AES-GCM rejected modified ciphertext.");
        }
    } catch (error) {
        feedback(`Tampering test could not run: ${error.message}`, "error");
    }
}

function capitalize(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
}

async function checkConnection() {
    const dot = document.querySelector(".sidebar-bottom .status-dot");

    try {
        await apiRequest("/health");
        $("connection-status").textContent = "API connected";
        dot.classList.add("online");
        log("FastAPI health check passed.");
    } catch {
        $("connection-status").textContent = "API unavailable";
        dot.classList.remove("online");
        log("FastAPI is unavailable. Start the backend and refresh.");
    }
}

function initializeTamperingButton() {
    const button = document.createElement("button");
    button.id = "test-tampering";
    button.className = "button button-secondary";
    button.textContent = "Test Ciphertext Tampering";
    button.addEventListener("click", testTampering);

    $("refresh-messages").parentElement.appendChild(button);
}

$("alice-generate").addEventListener("click", () => generateKeys("alice"));
$("bob-generate").addEventListener("click", () => generateKeys("bob"));

$("alice-register").addEventListener("click", () => registerPublicKey("alice"));
$("bob-register").addEventListener("click", () => registerPublicKey("bob"));

$("send-message").addEventListener("click", sendMessage);
$("refresh-messages").addEventListener("click", refreshMessages);

$("clear-display").addEventListener("click", () => {
    $("activity-log").replaceChildren();
    log("Activity display cleared. Server records were not deleted.");
});

initializeTamperingButton();
checkConnection();
refreshMessages();
