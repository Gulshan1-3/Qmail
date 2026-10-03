# QuMail Security Analysis

**Version:** 1  
**Status:** Draft  
**Classification:** Security Architecture  

---

## 1. Threat Model

### 1.1 Adversary Capabilities

| Adversary | Capabilities |
|-----------|-------------|
| **Network** | Passive capture, MITM, replay, reorder, modification of ciphertext |
| **Mail Server** | Read stored messages, modify stored messages, inspect metadata |
| **Quantum (future)** | Break RSA, ECDH, DSA via Shor's algorithm |
| **Endpoint** | Memory inspection, timing attacks, cache observation |

### 1.2 Harvest-Now-Decrypt-Later (HNDL)

The primary threat QuMail is designed to defeat. An adversary captures encrypted traffic today and decrypts it when quantum computers become capable (~2030–2035).

**QuMail's defense:** QKD-derived keys are generated from quantum-physical randomness and never traverse the network. ML-KEM-768 is believed resistant to all known quantum algorithms (no Shor's equivalent exists for MLWE problems).

---

## 2. Security Properties by Level

| Level | Confidentiality | Integrity | Forward Secrecy | Quantum-Safe |
|-------|----------------|-----------|-----------------|-------------|
| L1 Baseline | TLS only | TLS only | Partial (TLS) | ❌ |
| L2 Q-AES-256-GCM | AES-256-GCM | GCM auth tag + AAD | Yes (OTP key consumed) | ✅ (QKD key source) |
| L2.5 Hybrid PQC | AES-256-GCM | GCM auth tag + AAD | Yes | ✅ (QKD + ML-KEM-768) |
| L3 Quantum OTP | Vernam XOR | Carter-Wegman Poly1305 | Yes (OTP consumed) | ✅ (information-theoretic) |

---

## 3. Cryptographic Primitives

| Primitive | Algorithm | Standard | Security Level |
|-----------|-----------|----------|----------------|
| Symmetric encryption | AES-256-GCM | NIST FIPS 197 | 256-bit classical, quantum-reduces to 128-bit |
| Key derivation | HKDF-SHA256 | RFC 5869 | 256-bit PRF security |
| Post-quantum KEM | ML-KEM-768 | NIST FIPS 203 (2024) | MLWE-768 hardness |
| OTP authentication | Poly1305 | RFC 8439 | 128-bit Carter-Wegman security |
| Random generation | OS CSPRNG | getrandom crate | Platform-provided |
| QKD key source | ETSI GS QKD 014 | ETSI standard | Physics-based, information-theoretically secure |

---

## 4. Key Management Security

### 4.1 Key Lifecycle Invariants

```
Available → Reserved → Consumed → Zeroized
```

- **No reuse:** A consumed key ID can never be re-allocated
- **Crash safety:** Reserved-but-not-committed keys are reconciled with TTL expiry on restart
- **Zeroization:** Raw key bytes are held in `Zeroizing<Vec<u8>>` (zeroized on drop)
- **Concurrency:** Atomic state transitions prevent two operations obtaining the same key

### 4.2 Key Storage

- Key bank stored as JSON with base64-encoded key material
- Key bytes are base64 only during serialization; deserialized into `Zeroizing` buffers
- **Production recommendation:** Key bank file should be on an encrypted filesystem (LUKS)

### 4.3 Key ID Privacy

Key IDs are UUIDs placed in the plaintext envelope header. They are **not secret** — they identify which slot to look up, not the key value. An adversary learning a key ID gains no cryptographic advantage without the corresponding key material.

---

## 5. AAD and Domain Separation

Every encryption operation is bound to its context via Authenticated Associated Data:

```
AAD = version ‖ sender_sae ‖ recipient_sae ‖ message_id ‖ timestamp
```

This prevents:
- **Cross-protocol attacks:** A ciphertext from one SAE pair cannot be replayed to another
- **Replay attacks:** `message_id` (UUID) is unique per message
- **Downgrade attacks:** `version` is authenticated — changing it fails verification

---

## 6. Attack Resistance Analysis

### 6.1 Ciphertext Tampering (Active MITM)

- **L2 / L2.5:** AES-256-GCM authentication tag covers ciphertext + AAD. Any single-bit modification causes decryption to fail with `DecryptionFailed`. Plaintext is never released on authentication failure.
- **L3:** Carter-Wegman Poly1305 MAC over ciphertext + AAD. OTP is malleable without the MAC; the MAC is information-theoretically secure given a one-time MAC key.

### 6.2 Key Exhaustion

When the key bank reaches 0 available slots, all L2/L2.5/L3 operations fail hard. The system does **not** silently fall back to L1 Baseline. This is the "failure-closed" invariant.

### 6.3 Replay Attacks

Each message uses a fresh `MessageId` (UUID v4) included in AAD. Replaying the same ciphertext with the same key ID fails because:
- The key is already `Consumed` on the receiver side
- Even with a different key, the AAD contains the original `message_id`, not the replayed one

### 6.4 Quantum Computer Attack (Shor's Algorithm)

- **L2:** AES-256-GCM key is derived from QKD material, not a classical key exchange. Shor's algorithm cannot derive QKD keys — they were never transmitted classically.
- **L2.5:** Even if QKD were somehow compromised, ML-KEM-768 provides a second independent layer (no known quantum algorithm attacks MLWE). Even if ML-KEM-768 were broken, the QKD layer still provides security.
- **L3:** Vernam OTP is information-theoretically secure — quantum computing is irrelevant.

### 6.5 Side-Channel Attacks

- AES-256-GCM uses constant-time implementations from the `aes-gcm` crate (backed by hardware AES-NI where available)
- ML-KEM-768 decapsulation uses constant-time implicit rejection (`ml-kem` crate, FIPS 203 compliant)
- Key comparison uses constant-time equality where applicable

---

## 7. Known Limitations

| Limitation | Impact | Mitigation |
|------------|--------|-----------|
| SMTP headers not encrypted | From/To/Subject visible to mail servers | Use inner MIME for sensitive subjects; consider encrypted subjects extension |
| Key bank is a JSON file | At risk if filesystem is compromised | Use encrypted filesystem (LUKS); restrict file permissions to 0600 |
| No forward secrecy between sessions | Old key bank can decrypt old messages | Key bank slots are consumed (OTP semantics); old consumed slots have no key material |
| No anonymity | Sender/receiver SAE IDs in plaintext header | Acceptable for ISRO closed-network use case |
| No endpoint protection | Plaintext visible after decryption | Out of scope (see Non-Goals in architecture.md) |
| Poly1305 tag is 128-bit | Theoretical 128-bit security for L3 MAC | Sufficient for current threat model; upgrade to BLAKE3 for future versions |

---

## 8. Security Review Checklist

Before describing QuMail as production-grade, the following require independent review:

- [ ] Cryptographic construction correctness (especially Dual-PRF combiner)
- [ ] OTP key-consumption atomicity under concurrent access
- [ ] Nonce uniqueness guarantees across all execution paths
- [ ] Zeroization of key material across Rust drops and OS memory pages
- [ ] Protocol version downgrade resistance
- [ ] MIME canonicalization for AAD construction
- [ ] Key bank file permissions and encrypted storage
- [ ] mTLS certificate validation in ETSI QKD 014 client
- [ ] Interoperability with real ETSI QKD hardware deployments

---

## 9. Compliance References

| Standard | Relevance |
|----------|----------|
| NIST FIPS 197 | AES specification |
| NIST FIPS 203 (2024) | ML-KEM-768 (Module-Lattice KEM) |
| NIST SP 800-38D | AES-GCM specification |
| RFC 5869 | HKDF key derivation |
| RFC 8439 | ChaCha20-Poly1305 (Poly1305 MAC reused in L3) |
| ETSI GS QKD 014 | QKD key management REST API |
| ISRO SIH1523 | Problem statement and requirements |
