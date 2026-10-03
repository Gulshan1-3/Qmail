# QuMail Protocol Specification

**Version:** 1  
**Status:** Draft  
**Classification:** Technical Protocol  

---

## 1. Envelope Format

QuMail messages are transported as standard RFC 822 messages with a `multipart/encrypted` body:

```
Content-Type: multipart/encrypted;
    protocol="application/vnd.qumail.v1";
    boundary="<boundary>"

--<boundary>
Content-Type: application/vnd.qumail.v1+json

{ <QuMail envelope header JSON> }

--<boundary>
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

<Base64-encoded AES-256-GCM ciphertext>

--<boundary>--
```

---

## 2. Envelope Header Schema

```json
{
  "version": 1,
  "security_level": "hybrid_pqc",
  "message_id": "<UUID-v4>",
  "sender_sae": 1,
  "recipient_sae": 2,
  "key_ids": ["<UUID-v4>"],
  "timestamp_epoch_secs": 1790678117,
  "tag_b64": null,
  "nonce_b64": "<base64-12-bytes>",
  "pqc_ciphertext_b64": "<base64-ml-kem-768-ciphertext>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `version` | u16 | Protocol version. Currently `1`. |
| `security_level` | string | One of: `baseline`, `qaes`, `hybrid_pqc`, `quantum_otp` |
| `message_id` | UUID | Unique per-message ID used in AAD for domain separation |
| `sender_sae` | u64 | Sender's SAE node identifier |
| `recipient_sae` | u64 | Receiver's SAE node identifier |
| `key_ids` | array | QKD key slot IDs consumed for this message |
| `timestamp_epoch_secs` | u64 | Unix timestamp at encryption time (part of AAD) |
| `tag_b64` | string? | Base64 Carter-Wegman Poly1305 MAC tag (L3 OTP only) |
| `nonce_b64` | string? | Base64 96-bit AES-GCM nonce (L2, L2.5) |
| `pqc_ciphertext_b64` | string? | Base64 ML-KEM-768 encapsulated ciphertext (L2.5 only) |

---

## 3. Security Level Processing

### L1 — Baseline
- No QuMail envelope. Inner MIME passed through as-is.
- Protected only by TLS on the SMTP/IMAP transport.

### L2 — Q-AES-256-GCM
```
QKD_key (1024 bytes)
    │
    └── HKDF-SHA256(salt="qumail-l2-aes", info=AAD)
            ├── → aes_key [32 bytes]
            └── → nonce    [12 bytes]
                    │
                    └── AES-256-GCM.Encrypt(plaintext, aad=CryptoContext.to_aad_bytes())
                            ├── → ciphertext
                            └── → (auth tag embedded in ciphertext)
```

### L2.5 — Hybrid PQC
```
ML-KEM-768.Encapsulate(recipient_ek)
    ├── → K_PQC  [32 bytes]
    └── → pqc_ciphertext [1088 bytes] → stored in envelope header

QKD_key (1024 bytes) → K_QKD

K_combined = HKDF-SHA256(salt=message_id, ikm=K_QKD ‖ K_PQC)
    └── → AES-256-GCM.Encrypt(plaintext, aad=CryptoContext.to_aad_bytes())
```

### L3 — Quantum OTP
```
QKD_key (len ≥ |plaintext| + 32 bytes)
    ├── otp_key   = QKD_key[0..len(plaintext)]
    └── mac_key   = QKD_key[len(plaintext)..len(plaintext)+32]

ciphertext = plaintext XOR otp_key
tag        = Poly1305(mac_key, ciphertext ‖ AAD)    ← Carter-Wegman MAC
```

---

## 4. AAD Construction

Authenticated Associated Data (AAD) binds the ciphertext to its cryptographic context:

```
AAD = protocol_version (u16, big-endian)
    ‖ sender_sae (u64, big-endian)
    ‖ recipient_sae (u64, big-endian)
    ‖ message_id (UTF-8 bytes)
    ‖ timestamp_epoch_secs (u64, big-endian)
```

The `CryptoContext::to_aad_bytes()` method produces this canonical serialization.

---

## 5. Key ID Protocol

- Sender: `KeyManager::reserve()` → obtains `key_id`
- Sender: encrypts → `KeyManager::commit()` → key permanently consumed
- Sender: puts `key_id` in envelope header
- Receiver: reads `key_id` from header → `KeyManager::get_decryption_keys(peer_sae, &[key_id])`
- Receiver: decrypts → key is marked consumed on receiver side

Key IDs are UUIDs v4. They are **not secret** — the key material they reference is.

---

## 6. Inner MIME Structure

The encrypted plaintext is a complete RFC 822 MIME message:

```
From: alice@isro.gov.in
To: bob@isro.gov.in
Subject: <original subject>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="..."

--...
Content-Type: text/plain; charset=utf-8

<message body>

--...
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="data.bin"
Content-Transfer-Encoding: base64

<base64 attachment data>
--...--
```

The entire inner RFC 822 message (including headers) is the plaintext fed to the encryption engine.

---

## 7. Version Negotiation

- Current version: `1`
- Unknown `version` values must cause hard rejection (`InvalidEnvelope` error)
- No silent fallback to weaker security levels is permitted

---

## 8. MIME Detection

A receiver detects a QuMail envelope by:
1. Checking `Content-Type` starts with `multipart/encrypted`
2. Checking `protocol="application/vnd.qumail.v1"` parameter
3. Finding a sub-part with `Content-Type: application/vnd.qumail.v1+json`

If detection fails, the message is treated as unencrypted L1 Baseline.
