"use strict";

// CloudKey: browser-side ECDH + HKDF + AES-GCM.
// Only public keys and encrypted message data are sent to FastAPI.

const API = "";

const state = {
    alice: { privateKey: null, publicKey: null, registered: false },
    bob: { privateKey: null, publicKey: null, registered: false },
    lastMessage: null,
};

const $ = (id) => document.getElementById(id);

// --------------------------------------------------
// Activity log and user feedback
// --------------------------------------------------

function log(message) {
    const container = $("activity-log");
    if (!container) return;

    const entry = document.createElement("p");
    entry.className = "log-entry";
    entry.textContent =
        `${new Date().toLocaleTimeString()} — ${message}`;

    container.prepend(entry);
}

function feedback(message, type = "") {
    const element = $("message-feedback");
    if (!element) return;

    element.textContent = message;
    element.className = `feedback ${type}`.trim();
}

function capitalize(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
}

function setParticipantStatus(user, message, ready = false) {
    $(`${user}-status`).textContent = message;
    $(`${user}-status`).classList.toggle("ready", ready);
}

function updateControls() {
    const bothReady =
        state.alice.registered && state.bob.registered;

    $("send-message").disabled = !bothReady;
    $("key-status").textContent = bothReady ? "Ready" : "Pending";
}

// --------------------------------------------------
// Base64 and public-key encoding helpers
// --------------------------------------------------

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

// FastAPI stores Base64-encoded PEM text.
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

// --------------------------------------------------
// FastAPI request helper
// --------------------------------------------------

async function apiRequest(path, options = {}) {
    const response = await fetch(`${API}${path}`, {
        ...options,
        headers: {
            ...(options.body
                ? { "Content-Type": "application/json" }
                : {}),
            ...options.headers,
        },
    });

    const text = await response.text();
    let data = {};

    try {
        data = text ? JSON.parse(text) : {};
    } catch {
        throw new Error(
            `Server returned an unexpected response (${response.status}).`
        );
    }

    if (!response.ok) {
        const detail =
            typeof data.detail === "string"
                ? data.detail
                : `Request failed (${response.status}).`;

        throw new Error(detail);
    }

    return data;
}

// --------------------------------------------------
// ECDH key generation and public-key registration
// --------------------------------------------------

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

        // A new key pair invalidates the previous message's
        // tampering-test context.
        state.lastMessage = null;

        $(`${user}-key-state`).textContent =
            "ECDH P-256 key pair generated";

        $(`${user}-register`).disabled = false;

        setParticipantStatus(user, "Key generated", false);

        log(
            `${capitalize(user)} generated an ECDH key pair in the browser.`
        );

        updateControls();

        feedback(
            `${capitalize(user)}'s keys generated. Register the public key next.`,
            "success"
        );
    } catch (error) {
        log(`Key generation failed: ${error.message}`);
        feedback(`Key generation failed: ${error.message}`, "error");
    }
}

async function registerPublicKey(user) {
    const participant = state[user];

    if (!participant.publicKey) {
        feedback(
            `Generate ${capitalize(user)}'s keys first.`,
            "error"
        );
        return;
    }

    try {
        const encodedKey =
            await exportPublicKeyForServer(participant.publicKey);

        await apiRequest(`/users/${user}/keys`, {
            method: "POST",
            body: JSON.stringify({
                public_key: encodedKey,
            }),
        });

        participant.registered = true;

        setParticipantStatus(user, "Registered", true);

        $(`${user}-key-state`).textContent =
            "Public key registered";

        $(`${user}-register`).disabled = true;

        log(
            `${capitalize(user)} registered a public key with FastAPI.`
        );

        updateControls();

        feedback(
            `${capitalize(user)}'s public key registered successfully.`,
            "success"
        );
    } catch (error) {
        log(`Public-key registration failed: ${error.message}`);

        feedback(
            `Registration failed: ${error.message}`,
            "error"
        );
    }
}

// --------------------------------------------------
// ECDH shared-secret derivation and HKDF
// --------------------------------------------------

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
            info: new TextEncoder().encode(
                "cloud-key-exchange-v1"
            ),
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

    if (!result.public_key) {
        throw new Error(
            `${capitalize(user)}'s registered public key was not found.`
        );
    }

    return importPublicKeyFromServer(result.public_key);
}

// --------------------------------------------------
// AES-256-GCM encryption and decryption
// --------------------------------------------------

async function encryptMessage(plaintext, aesKey) {
    // A fresh, random 96-bit nonce is used for each encryption.
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
        ciphertext: bytesToBase64(
            new Uint8Array(ciphertext)
        ),
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

// --------------------------------------------------
// Refresh stored messages
// FIX: This function was missing in the previous code.
// --------------------------------------------------

async function refreshMessages() {
    const container = $("stored-messages");

    if (!container) {
        console.warn(
            'Dashboard element "stored-messages" was not found.'
        );
        return;
    }

    try {
        const result = await apiRequest("/messages");

        // Support common response formats:
        // 1. An array of message records
        // 2. { "messages": [...] }
        // 3. { "items": [...] }
        const messages = Array.isArray(result)
            ? result
            : Array.isArray(result.messages)
                ? result.messages
                : Array.isArray(result.items)
                    ? result.items
                    : [];

        container.replaceChildren();

        if (messages.length === 0) {
            const empty = document.createElement("p");
            empty.className = "empty-state";
            empty.textContent =
                "No encrypted messages stored yet.";

            container.appendChild(empty);
            return;
        }

        // Display newest messages first when timestamps are available.
        messages.sort((a, b) => {
            const aTime = Date.parse(a.created_at || "") || 0;
            const bTime = Date.parse(b.created_at || "") || 0;

            return bTime - aTime;
        });

        for (const message of messages) {
            const card = document.createElement("div");
            card.className = "stored-message";

            const route = document.createElement("strong");

            const sender = String(
                message.sender || "Unknown"
            );

            const recipient = String(
                message.recipient || "Unknown"
            );

            route.textContent =
                `${capitalize(sender)} → ${capitalize(recipient)}`;

            const id = document.createElement("p");
            id.className = "stored-message-id";

            id.textContent =
                `Message ID: ${
                    message.message_id ||
                    message.id ||
                    "Unavailable"
                }`;

            const details = document.createElement("p");
            details.className = "stored-message-details";

            const ciphertextLength =
                typeof message.ciphertext === "string"
                    ? message.ciphertext.length
                    : 0;

            const createdAt = message.created_at
                ? new Date(message.created_at).toLocaleString()
                : "Timestamp unavailable";

            details.textContent =
                `Encrypted payload: ${ciphertextLength} characters · ${createdAt}`;

            card.append(route, id, details);
            container.appendChild(card);
        }
    } catch (error) {
        console.error("Message refresh failed:", error);

        container.replaceChildren();

        const errorMessage = document.createElement("p");
        errorMessage.className = "empty-state error";
        errorMessage.textContent =
            `Could not load stored messages: ${error.message}`;

        container.appendChild(errorMessage);
    }
}

// --------------------------------------------------
// Bidirectional encrypted messaging
// Alice -> Bob OR Bob -> Alice
// --------------------------------------------------

async function sendMessage() {
    const plaintext = $("message-input").value;
    const sender = $("sender-select").value;

    const recipient =
        sender === "alice" ? "bob" : "alice";

    if (!plaintext.trim()) {
        feedback("Enter a message before sending.", "error");
        return;
    }

    if (
        !state[sender].registered ||
        !state[recipient].registered
    ) {
        feedback(
            "Generate and register both public keys first.",
            "error"
        );
        return;
    }

    $("send-message").disabled = true;

    try {
        // The sender retrieves the recipient's public key.
        const recipientPublicKey =
            await getRegisteredPublicKey(recipient);

        // The sender derives the encryption key.
        const senderAesKey = await deriveAesKey(
            state[sender].privateKey,
            recipientPublicKey
        );

        // The recipient derives the matching decryption key.
        const senderPublicKey =
            await getRegisteredPublicKey(sender);

        const recipientAesKey = await deriveAesKey(
            state[recipient].privateKey,
            senderPublicKey
        );

        // Encrypt locally before sending anything to the server.
        const encrypted = await encryptMessage(
            plaintext,
            senderAesKey
        );

        // The server receives ciphertext, nonce, and routing metadata.
        const stored = await apiRequest("/messages", {
            method: "POST",
            body: JSON.stringify({
                sender,
                recipient,
                ciphertext: encrypted.ciphertext,
                nonce: encrypted.nonce,
            }),
        });

        if (!stored.message_id) {
            throw new Error(
                "The server did not return a message ID."
            );
        }

        state.lastMessage = {
            messageId: stored.message_id,
            sender,
            recipient,
            recipientAesKey,
            encrypted,
        };

        // Display the encrypted record, not the plaintext.
        $("ciphertext-output").textContent =
            JSON.stringify(
                {
                    message_id: stored.message_id,
                    sender: stored.sender || sender,
                    recipient: stored.recipient || recipient,
                    ciphertext:
                        stored.ciphertext || encrypted.ciphertext,
                    nonce: stored.nonce || encrypted.nonce,
                },
                null,
                2
            );

        // The recipient fetches the stored ciphertext.
        const received = await apiRequest(
            `/messages/${encodeURIComponent(stored.message_id)}`
        );

        // Only the recipient's independently derived key decrypts it.
        const decrypted = await decryptMessage(
            received,
            recipientAesKey
        );

        $("plaintext-output").textContent = decrypted;
        $("decrypt-status").textContent = "Verified";
        $("decrypt-status").classList.add("ready");

        log(
            `${capitalize(sender)} encrypted and sent a message to ${capitalize(recipient)}.`
        );

        log(
            `${capitalize(recipient)} fetched the ciphertext and authenticated the message.`
        );

        feedback(
            `${capitalize(sender)} → ${capitalize(recipient)}: message encrypted, stored, and decrypted successfully.`,
            "success"
        );

        // Clear the input only after successful delivery and decryption.
        $("message-input").value = "";

        // Update the stored-message list.
        await refreshMessages();
    } catch (error) {
        $("decrypt-status").textContent = "Failed";
        $("decrypt-status").classList.remove("ready");

        $("plaintext-output").textContent =
            "Decryption was not completed.";

        log(`Messaging failed: ${error.message}`);

        feedback(
            `Messaging failed: ${error.message}`,
            "error"
        );
    } finally {
        updateControls();
    }
}

// --------------------------------------------------
// AES-GCM ciphertext tampering test
// --------------------------------------------------

async function testTampering() {
    if (!state.lastMessage) {
        feedback(
            "Send a message before testing tampering.",
            "error"
        );
        return;
    }

    try {
        const original = state.lastMessage.encrypted;
        const tamperedBytes =
            base64ToBytes(original.ciphertext);

        if (tamperedBytes.length === 0) {
            throw new Error("Ciphertext is empty.");
        }

        // Change one bit while keeping the nonce unchanged.
        tamperedBytes[0] ^= 1;

        const tampered = {
            nonce: original.nonce,
            ciphertext: bytesToBase64(tamperedBytes),
        };

        try {
            // FIX: use recipientAesKey, not the outdated bobAesKey.
            await decryptMessage(
                tampered,
                state.lastMessage.recipientAesKey
            );

            $("decrypt-status").textContent =
                "Unexpected success";

            $("decrypt-status").classList.remove("ready");

            $("plaintext-output").textContent =
                "Warning: modified ciphertext was accepted.";

            feedback(
                "Tampering test failed: modified data was decrypted.",
                "error"
            );

            log(
                "WARNING: tampered ciphertext was unexpectedly accepted."
            );
        } catch {
            // AES-GCM authentication should reject modified ciphertext.
            $("decrypt-status").textContent =
                "Tampering detected";

            $("decrypt-status").classList.add("ready");

            $("plaintext-output").textContent =
                "Tampered ciphertext rejected. AES-GCM authentication failed as expected.";

            feedback(
                "Tampering detected: AES-GCM rejected the modified ciphertext.",
                "success"
            );

            log(
                "Tampering test passed: AES-GCM rejected modified ciphertext."
            );
        }
    } catch (error) {
        feedback(
            `Tampering test could not run: ${error.message}`,
            "error"
        );
    }
}

// --------------------------------------------------
// API connection status
// --------------------------------------------------

async function checkConnection() {
    const dot = document.querySelector(
        ".sidebar-bottom .status-dot"
    );

    try {
        await apiRequest("/health");

        $("connection-status").textContent = "API connected";

        if (dot) {
            dot.classList.add("online");
        }

        log("FastAPI health check passed.");
    } catch {
        $("connection-status").textContent = "API unavailable";

        if (dot) {
            dot.classList.remove("online");
        }

        log(
            "FastAPI is unavailable. Start the backend and refresh."
        );
    }
}

// --------------------------------------------------
// Dynamic sender and recipient display
// --------------------------------------------------

function updateMessageRoute() {
    const sender = $("sender-select").value;

    const recipient =
        sender === "alice" ? "bob" : "alice";

    $("recipient-display").textContent =
        capitalize(recipient);

    $("message-route-label").textContent =
        `MESSAGE FROM ${sender.toUpperCase()} TO ${recipient.toUpperCase()}`;
}

// --------------------------------------------------
// Initialize dashboard controls
// --------------------------------------------------

function initializeTamperingButton() {
    const refreshButton = $("refresh-messages");

    if (!refreshButton || !refreshButton.parentElement) {
        console.warn(
            "Could not initialize tampering test button."
        );
        return;
    }

    // Prevent duplicate buttons if initialization runs again.
    if ($("test-tampering")) {
        return;
    }

    const button = document.createElement("button");

    button.id = "test-tampering";
    button.className = "button button-secondary";
    button.textContent = "Test Ciphertext Tampering";

    button.addEventListener("click", testTampering);

    refreshButton.parentElement.appendChild(button);
}

function initializeDashboard() {
    // Sender selection and dynamic route label.
    $("sender-select").addEventListener(
        "change",
        updateMessageRoute
    );

    updateMessageRoute();

    // Key-generation buttons.
    $("alice-generate").addEventListener(
        "click",
        () => generateKeys("alice")
    );

    $("bob-generate").addEventListener(
        "click",
        () => generateKeys("bob")
    );

    // Public-key registration buttons.
    $("alice-register").addEventListener(
        "click",
        () => registerPublicKey("alice")
    );

    $("bob-register").addEventListener(
        "click",
        () => registerPublicKey("bob")
    );

    // Messaging and message refresh.
    $("send-message").addEventListener(
        "click",
        sendMessage
    );

    $("refresh-messages").addEventListener(
        "click",
        refreshMessages
    );

    // Clear only the visible activity log.
    $("clear-display").addEventListener("click", () => {
        $("activity-log").replaceChildren();

        log(
            "Activity display cleared. Server records were not deleted."
        );
    });

    initializeTamperingButton();

    updateControls();

    // Initial backend checks and message history loading.
    checkConnection();
    refreshMessages();
}

// Wait until the HTML elements exist before attaching listeners.
if (document.readyState === "loading") {
    document.addEventListener(
        "DOMContentLoaded",
        initializeDashboard
    );
} else {
    initializeDashboard();
}