# QuMail — Quantum-Safe Email Client

## System Design & Implementation Specification

**Status:** Draft  
**Classification:** Technical Architecture  
**Primary Language:** Rust  
**Target Platforms:** Linux, Windows  
**Primary Interfaces:** SMTP, IMAP, MIME, ETSI GS QKD 014  
**Security Model:** Classical + PQC + QKD-assisted encryption  

---

## 1. Overview

QuMail is a cross-platform secure email client designed for environments where long-term confidentiality is important and where Quantum Key Distribution (QKD) infrastructure may be available.

The system integrates three layers:

1. **Conventional email infrastructure** — SMTP, IMAP, MIME and TLS.
2. **Post-quantum cryptography** — for protection against future cryptanalytic capabilities.
3. **QKD-derived symmetric keys** — for applications requiring stronger key-distribution guarantees.

The system is designed so that QKD functionality is an implementation detail of the cryptographic/key-management layer rather than a requirement imposed on the email transport layer.

This allows QuMail messages to continue traversing conventional SMTP infrastructure while the message payload itself is protected by QuMail's encryption envelope.

---

# 2. Problem

Traditional email security does not provide a single mechanism that simultaneously addresses:

* long-term confidentiality against future quantum attacks,
* protection when mail servers are compromised,
* integration with QKD key-management infrastructure,
* large attachments,
* offline/pre-distributed key material,
* and compatibility with existing SMTP/IMAP infrastructure.

The primary security concern is **Harvest-Now-Decrypt-Later (HNDL)**: an adversary may capture encrypted traffic today and attempt decryption later when stronger cryptanalytic capabilities become available.

QuMail therefore separates:

**mail transport security**  
from  
**message confidentiality and authenticity**.

TLS protects the transport connection, while QuMail protects the message payload.

---

# 3. Goals

### 3.1 Primary goals

QuMail must:

* provide end-to-end encryption at the message layer;
* support multiple security levels;
* integrate with an ETSI GS QKD 014-compatible KME;
* support a local pre-distributed key bank;
* securely consume and zeroize key material;
* encrypt large attachments without requiring an equivalent amount of QKD material for AES-based modes;
* preserve MIME attachments during encryption/decryption;
* support conventional SMTP/IMAP servers;
* provide a clean Rust workspace with independently testable components;
* expose cryptographic policy through a single dispatcher rather than coupling the UI to cryptographic implementations.

### 3.2 Secondary goals

The system should:

* support offline operation when pre-distributed keys are available;
* expose key inventory and operational state to the UI;
* support hybrid PQC/QKD modes;
* provide deterministic test environments using simulated QKD infrastructure;
* make cryptographic implementations replaceable without changing the mail engine.

---

# 4. Non-Goals

The following are outside the core system:

* replacing SMTP or IMAP;
* implementing a new mail server;
* providing anonymity for network-level metadata;
* protecting a compromised endpoint after plaintext has been exposed;
* guaranteeing that email headers remain confidential when conventional SMTP infrastructure is used;
* implementing a physical QKD device;
* providing production certification for cryptographic algorithms;
* implementing steganography in the initial release.

The original proposal describes a stealth/steganographic Level 4, but that feature should remain outside the core implementation until the lower security levels are operational and independently reviewed.

---

# 5. Security Model

## 5.1 Adversaries

QuMail considers four primary adversaries.

### Network adversary

The attacker may:

* passively capture traffic;
* modify traffic;
* replay packets;
* reorder packets;
* perform active network attacks.

### Mail-server adversary

A compromised SMTP relay or IMAP server may attempt to:

* read message bodies;
* modify stored messages;
* inspect attachments;
* correlate message metadata.

### Quantum adversary

The attacker is assumed to eventually possess computational capabilities capable of breaking classical public-key assumptions such as RSA and discrete-logarithm based systems.

### Local/endpoint adversary

The attacker may attempt:

* memory inspection;
* key extraction;
* cache/timing observation;
* recovery of sensitive data from process memory.

---

# 6. Security Invariants

The following properties are architectural invariants rather than optional features.

### Key non-reuse

A key segment allocated for one-time use must never be allocated again.

### Key ownership

Only the component that owns a reserved key may consume it.

### Zeroization

Sensitive key material and plaintext buffers must be zeroized when their lifetime ends.

### Authentication before release

Ciphertext must not be released to the application as plaintext until integrity/authenticity verification succeeds.

### Domain separation

Keys used for encryption, authentication, metadata protection, and other purposes must be derived or allocated using explicit domain separation.

### Failure closed

Insufficient key material, authentication failure, malformed envelopes, or inconsistent key state must fail the operation rather than silently downgrade security.

---

# 7. Security Levels

QuMail exposes security policy through a single abstraction:

```rust
pub enum SecurityLevel {
    Baseline,
    Qaes,
    HybridPqc,
    QuantumOtp,
}
```

The UI, mail engine, and transport layers must not implement cryptographic decisions themselves.

| Level | Primary Protection                         | Key Source                       |
| ----- | ------------------------------------------ | -------------------------------- |
| L1    | Conventional TLS/MIME                      | Classical infrastructure         |
| L2    | AES-256-GCM                                | QKD-derived symmetric material   |
| L2.5  | Hybrid PQC + symmetric encryption          | QKD + PQC                        |
| L3    | One-time-pad construction + authentication | Dedicated symmetric key material |

The five-tier table in the original design also describes a Level 4 stealth mode; this design treats that as experimental/out-of-scope rather than a production security level.

---

# 8. Architecture

QuMail is organized as a Cargo workspace.

```text
                         +----------------------+
                         |      qumail-ui       |
                         |   egui / Slint       |
                         +----------+-----------+
                                    |
                                    v
                         +----------------------+
                         |     qumail-core      |
                         |----------------------|
                         | Account Manager      |
                         | Mail Orchestrator    |
                         | Crypto Dispatcher    |
                         | Policy / State       |
                         +----+------------+----+
                              |            |
                +-------------+            +-------------+
                v                                          v
       +-------------------+                    +-------------------+
       |   qumail-crypto   |                    |    qumail-net     |
       |-------------------|                    |-------------------|
       | Encryption        |                    | SMTP              |
       | Authentication    |                    | IMAP              |
       | Key derivation    |                    | MIME              |
       | Secure buffers    |                    | RFC 822           |
       +---------+---------+                    +-------------------+
                 |
                 v
       +-------------------+
       |    qumail-kme     |
       |-------------------|
       | KeyManager trait  |
       | ETSI 014 client   |
       | Local key bank    |
       | QKD simulator     |
       +-------------------+
```

---

# 9. Workspace Structure

```text
qumail/
├── Cargo.toml
├── crates/
│   ├── qumail-core/
│   ├── qumail-crypto/
│   ├── qumail-kme/
│   ├── qumail-net/
│   ├── qumail-ui/
│   └── qumail-cli/
├── tests/
│   ├── integration/
│   ├── interoperability/
│   └── fixtures/
└── docs/
    ├── architecture.md
    ├── security.md
    └── protocol.md
```

The source proposal already identifies this modular split as the target architecture.

---

# 10. Module Responsibilities

## 10.1 `qumail-core`

Owns application-level orchestration.

Responsibilities:

* accounts;
* drafts;
* sent/outbox state;
* message lifecycle;
* security policy;
* crypto dispatch;
* coordination between network and KME layers.

It must not contain low-level cryptographic implementations.

---

## 10.2 `qumail-crypto`

Owns all cryptographic operations.

Responsibilities:

* encryption/decryption;
* authentication;
* key derivation;
* secure buffers;
* cryptographic serialization;
* security-level implementation.

Primary interface:

```rust
pub trait CryptoProvider {
    fn encrypt(
        &self,
        level: SecurityLevel,
        input: &[u8],
        context: &CryptoContext,
    ) -> Result<EncryptedMessage, CryptoError>;

    fn decrypt(
        &self,
        input: &[u8],
        context: &CryptoContext,
    ) -> Result<Vec<u8>, CryptoError>;
}
```

---

## 10.3 `qumail-kme`

Owns key acquisition and lifecycle.

Responsibilities:

* ETSI GS QKD 014 client;
* local key bank;
* key reservation;
* key consumption;
* key state transitions;
* key zeroization;
* QKD simulator.

The original architecture specifies status, encapsulation, and decapsulation operations together with mutual TLS authentication.

---

## 10.4 `qumail-net`

Owns all email protocol interactions.

Responsibilities:

* SMTP;
* IMAP;
* MIME serialization;
* MIME parsing;
* message synchronization;
* attachment handling.

It must treat encrypted QuMail payloads as opaque application data.

---

## 10.5 `qumail-ui`

Owns presentation only.

The UI may request:

```text
SecurityLevel::Qaes
SecurityLevel::HybridPqc
SecurityLevel::QuantumOtp
```

but must not directly call AES, HKDF, KME REST endpoints, or manipulate raw key material.

---

# 11. Key Management

## 11.1 `KeyManager` abstraction

All key sources are accessed through one interface:

```rust
pub trait KeyManager {
    async fn reserve(
        &self,
        request: KeyRequest,
    ) -> Result<KeyReservation, KeyError>;

    async fn commit(
        &self,
        reservation: KeyReservation,
    ) -> Result<(), KeyError>;

    async fn release(
        &self,
        reservation: KeyReservation,
    ) -> Result<(), KeyError>;
}
```

This allows the same cryptographic engine to operate against:

```text
ETSI QKD KME
       |
       +-- Remote production KME
       |
       +-- Local key bank
       |
       +-- QKD simulator
       |
       +-- Test key provider
```

---

# 12. Key State Machine

A key must have an explicit lifecycle.

```text
          +-----------+
          | Available |
          +-----+-----+
                |
             reserve
                |
                v
          +-----------+
          | Reserved  |
          +--+-----+--+
             |     |
          commit  release
             |     |
             v     v
        +---------+ +-----------+
        |Consumed | | Available |
        +---------+ +-----------+
             |
          zeroize
             |
             v
        +-----------+
        | Zeroized  |
        +-----------+
```

A crash or process termination must never cause a consumed key to become available again.

---

# 13. Local Key Bank

The local store supports disconnected or pre-distributed deployments.

The original design specifies a bank containing 100 key slots with metadata tracking availability, reservation and consumption.

Recommended logical representation:

```rust
struct KeySlot {
    slot_id: u32,
    key_id: KeyId,
    state: KeyState,
    key_length: usize,
    created_at: SystemTime,
    reserved_at: Option<SystemTime>,
    consumed_at: Option<SystemTime>,
}
```

Raw key bytes should not be exposed through application-level database queries.

Instead:

```text
Database
   |
   +-- metadata
   |
Secure key storage
   |
   +-- encrypted / protected key material
```

The exact platform storage mechanism is deployment-specific.

---

# 14. ETSI QKD Interface

`qumail-kme` exposes a typed Rust abstraction over the HTTP API.

Conceptually:

```text
qumail-kme
    |
    v
Etsi014Client
    |
    +-- status()
    +-- enc_keys()
    +-- dec_keys()
```

The original specification identifies:

* key inventory/status retrieval;
* sender-side key acquisition;
* receiver-side key recovery;
* mutual TLS client authentication.

The protocol implementation must keep the wire format isolated from the rest of the application.

---

# 15. Message Processing Pipeline

## Sending

```text
Compose
   |
   v
Build inner MIME message
   |
   v
Select SecurityLevel
   |
   v
Request key material
   |
   v
Encrypt + authenticate
   |
   v
Build QuMail envelope
   |
   v
Serialize MIME
   |
   v
SMTP
```

## Receiving

```text
IMAP
  |
  v
Parse RFC 822
  |
  v
Detect QuMail envelope
  |
  v
Parse QuMail header
  |
  v
Recover required key material
  |
  v
Authenticate ciphertext
  |
  v
Decrypt
  |
  v
Parse inner MIME
  |
  v
Display message / attachments
```

---

# 16. MIME Envelope

QuMail messages are transported as ordinary MIME messages with an application-specific encrypted part.

Example:

```text
Content-Type:
multipart/encrypted;
protocol="application/vnd.qumail.v1"
```

The envelope contains two logical components:

```text
QuMail Header
    |
    +-- protocol version
    +-- security level
    +-- sender SAE
    +-- recipient SAE
    +-- key allocation references
    +-- authentication metadata

Encrypted Payload
    |
    +-- inner MIME message
        |
        +-- headers
        +-- text
        +-- attachments
```

The source design uses key identifiers/allocations in the QuMail header and a binary payload encoded through MIME/base64.

---

# 17. Separation of Metadata

Only information required to route and process the encrypted envelope should appear outside the encrypted payload.

The inner message should contain application-visible information such as:

```text
Subject
Body
Attachments
Message-specific metadata
```

The outer message contains transport information required by SMTP/IMAP plus the minimum QuMail processing metadata.

This does not make SMTP headers anonymous; conventional email routing metadata remains observable.

---

# 18. Cryptographic Context

Every encryption operation receives an explicit context:

```rust
pub struct CryptoContext {
    pub protocol_version: u16,
    pub message_id: MessageId,
    pub sender_sae: SaeId,
    pub recipient_sae: SaeId,
    pub key_id: KeyId,
}
```

Authenticated associated data should be constructed from a canonical serialization of this context.

Avoid independently concatenating strings because ambiguity in serialization can create authentication bugs.

---

# 19. Level 2 Processing

Level 2 uses a symmetric AEAD construction with key material ultimately originating from the KME/QKD layer.

Conceptually:

```text
QKD key material
       |
       v
     KDF
       |
       +------> encryption key
       |
       +------> nonce / required context material
       |
       v
    AEAD
       |
       +------> ciphertext
       +------> authentication tag
```

The original document specifies AES-256-GCM with an HKDF-based derivation and authenticated context.

The implementation must enforce unique nonce usage and define exactly how message identifiers and KME key identifiers participate in domain separation.

---

# 20. Level 3 Processing

Level 3 uses one-time symmetric key material.

Conceptually:

```text
Plaintext
    XOR
One-time key material
    |
    v
Ciphertext
    |
    v
Information-theoretic authentication
```

The original proposal explicitly recognizes that a pure OTP is malleable and therefore adds a separate authentication construction.

This implementation must be treated as a cryptographic subsystem requiring independent review. In particular, claims regarding information-theoretic authentication, MAC construction, key sizing, key separation, and one-time usage must be validated against the exact algorithm and security proof being implemented.

---

# 21. Error Handling

All modules use typed errors.

Example:

```rust
#[derive(Debug, thiserror::Error)]
pub enum QuMailError {
    #[error("key management failure")]
    KeyManagement(#[from] KeyError),

    #[error("cryptographic failure")]
    Crypto(#[from] CryptoError),

    #[error("mail transport failure")]
    Network(#[from] NetworkError),

    #[error("invalid QuMail envelope")]
    InvalidEnvelope,

    #[error("message authentication failed")]
    AuthenticationFailed,
}
```

Errors must not expose:

* raw key material;
* plaintext;
* authentication secrets;
* private certificates;
* internal storage contents.

---

# 22. Failure Behaviour

The system must define behaviour for common failures.

| Failure                    | Expected behaviour                                   |
| -------------------------- | ---------------------------------------------------- |
| KME unavailable            | Retry according to policy; do not silently downgrade |
| Insufficient key material  | Abort encryption                                     |
| Invalid key ID             | Reject message                                       |
| Authentication failure     | Reject plaintext release                             |
| Malformed MIME             | Reject envelope safely                               |
| Attachment corruption      | Fail verification/decryption                         |
| Key reservation crash      | Reconcile state before reuse                         |
| Unsupported security level | Return typed error                                   |
| Invalid protocol version   | Reject or invoke explicit compatibility policy       |

Security downgrade must require an explicit policy decision.

---

# 23. Concurrency

Mail synchronization, encryption and KME operations are asynchronous.

Architecture:

```text
                 +----------------+
                 | async runtime  |
                 +-------+--------+
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
       IMAP task      SMTP task      KME task
          |              |              |
          +--------------+--------------+
                         |
                         v
                   Core state
```

Key reservations must be atomic from the perspective of concurrent send operations.

Two concurrent messages must never obtain the same one-time key allocation.

---

# 24. Persistence

Persistent state is divided into:

### Mail state

* accounts;
* drafts;
* message IDs;
* synchronization state;
* folder metadata.

### Key state

* key identifiers;
* key lifecycle state;
* allocation metadata.

### Secrets

* encryption keys;
* authentication credentials;
* client certificates/private keys.

Secrets must not be treated as ordinary application data.

---

# 25. Observability

The production system must provide structured logs and metrics without leaking secrets.

Useful metrics:

```text
mail.send.success
mail.send.failure
mail.receive.success
mail.receive.failure

crypto.encrypt.duration
crypto.decrypt.duration

kme.request.duration
kme.request.failure

keybank.available
keybank.reserved
keybank.consumed

mime.parse.failure
authentication.failure
```

Never log:

```text
plaintext
raw ciphertext
raw keys
passwords
private keys
authentication tags
```

Message identifiers may be logged only where they do not create an unacceptable metadata leak.

---

# 26. Testing Strategy

Testing is divided into five layers.

## Unit tests

Each crate tests its own logic independently.

Examples:

```text
key allocation
state transitions
MIME parsing
envelope serialization
crypto context serialization
error mapping
```

## Cryptographic tests

Use known-answer vectors where available.

Verify:

```text
encrypt -> decrypt
wrong key -> failure
modified ciphertext -> failure
modified AAD -> failure
reused key -> rejection
invalid nonce -> rejection
```

## Integration tests

Run:

```text
UI
 |
Core
 |
Crypto
 |
KME simulator
 |
SMTP/IMAP test server
```

## Interoperability tests

Verify that QuMail envelopes survive:

* MIME serialization;
* base64 encoding;
* SMTP transport;
* storage in IMAP;
* retrieval and reconstruction.

## Fault-injection tests

Simulate:

* network interruption;
* KME timeout;
* process crash during reservation;
* corrupted key-bank metadata;
* corrupted ciphertext;
* partial attachment transfer.

---

# 27. Acceptance Criteria

A stage is considered complete only when the following are true.

### Crypto

* encryption/decryption round trips pass;
* authentication failures never expose plaintext;
* key reuse is prevented;
* sensitive buffers are zeroized;
* large attachments work without truncation.

### KME

* status requests work;
* key acquisition works;
* key retrieval works;
* mTLS authentication works;
* concurrent reservations are safe.

### Mail

* ordinary MIME messages remain compatible;
* QuMail messages survive SMTP transport;
* IMAP synchronization does not lose encrypted payloads;
* attachments are restored exactly.

### Architecture

* crates remain independently testable;
* UI has no direct cryptographic implementation;
* network layer has no direct key-management implementation;
* KME implementation can be swapped for a simulator.

---

# 28. Development Roadmap

## Phase 1 — Domain Model

Build:

```text
SecurityLevel
MessageId
KeyId
SaeId
CryptoContext
QuMailError
```

Establish crate boundaries before implementing protocol logic.

---

## Phase 2 — Key Management

Implement:

```text
KeyManager
KeyReservation
KeyBankStore
Etsi014Client
QkdSimulator
```

Then add concurrency and crash-recovery tests.

---

## Phase 3 — Cryptographic Engine

Implement:

```text
L1
L2
L2.5
L3
```

behind a single dispatcher.

The original roadmap follows the same progression from workspace decomposition to the multi-level cryptographic engine.

---

## Phase 4 — MIME + Mail Pipeline

Implement:

```text
MIME builder
MIME parser
SMTP
IMAP
attachment extraction
encrypted envelope detection
```

The original roadmap specifically identifies attachment handling and IMAP synchronization as a dedicated stage.

---

## Phase 5 — Desktop Client

Implement the three-pane client:

```text
+------------+------------------+--------------------+
| Folders    | Message List     | Reading Pane       |
|            |                  |                    |
| Inbox      | sender           | subject            |
| Sent       | subject          | body               |
| Drafts     | security badge   | attachments        |
+------------+------------------+--------------------+
```

Compose should expose:

```text
Recipient
Subject
Message
Attachments
Security Level
Key availability
```

The original UI proposal also includes security-level badges, attachment chips, a security selector, and a KME key gauge.

---

# 29. Future Work

After the core system is stable:

### Hybrid PQC

Integrate standardized PQC algorithms behind explicit interfaces.

### QKD + PQC hybrid modes

Use independent cryptographic mechanisms so that compromise of one mechanism does not automatically compromise the other.

### Ratcheting

Investigate per-message or per-thread key evolution.

### Experimental stealth mechanisms

Keep steganography/chaffing isolated from the core protocol so experimentation cannot weaken the baseline security model.

The original roadmap identifies ML-KEM/ML-DSA, QKD-reseeded ratcheting, and decoy/steganographic mechanisms as later enhancements.

---

# 30. Security Review Requirements

Before describing QuMail as production-grade or RFC-grade, the following require dedicated review:

1. cryptographic construction correctness;
2. authentication security proof and exact primitive selection;
3. OTP key-consumption semantics;
4. nonce generation and uniqueness;
5. crash consistency of key consumption;
6. secure storage of the local key bank;
7. zeroization guarantees across Rust abstractions and OS boundaries;
8. protocol downgrade resistance;
9. MIME canonicalization;
10. metadata leakage;
11. endpoint compromise assumptions;
12. interoperability with the exact ETSI QKD deployment.

These items should be tracked as explicit security-review issues rather than hidden inside implementation tasks.

---

# 31. Design Principle

The central architectural rule is:

> **Email transports messages. QuMail protects messages. The KME supplies key material. The UI selects policy.**

Each layer should have one job:

```text
UI
 ↓
Policy / orchestration
 ↓
Cryptography
 ↓
Key management
 ↓
Mail transport
```

No layer should bypass the abstraction below it.

This separation is what makes the system testable, replaceable, and suitable for eventually connecting a real QKD deployment.
