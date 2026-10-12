/**
 * Realistic ISRO QuMail dataset with genuine quantum cryptographic contexts,
 * telemetry payloads, and security badges.
 */

export const INITIAL_KEY_BANK = {
  stored_keys: 98,
  max_keys: 100,
  key_size_bits: 8192,
  master_sae: 1,
  slave_sae: 2,
  mode: "ISRO 100 x 1 Kb Symmetrical Key Bank",
  is_healthy: true,
  last_sync: "Just now",
};

export const MOCK_EMAILS = [
  {
    id: "msg-001",
    folder: "inbox",
    from: "Dr. K. Sivan <dr.sivan@isro.gov.in>",
    senderName: "Dr. K. Sivan",
    to: ["officer.sac@isro.gov.in"],
    date: "Today, 14:42 IST",
    subject: "PSLV-C58 Trajectory Correction Burn",
    snippet: "Final orbital insertion burn parameters confirmed for SAC ground tracking...",
    bodyText: `Commander Sharma,

The trajectory correction burn for PSLV-C58 has been finalized. Parameters are as follows:
- Delta-V: 12.4 m/s at periapsis
- Burn duration: 847 seconds
- Engine: PS4 thruster cluster

All telemetry nominal. Quantum link maintained throughout transmission.

— Dr. K. Sivan
Chairman (Retd.) / Senior Scientific Advisor
Indian Space Research Organisation`,
    securityLevel: "L3",
    securityLevelName: "L3 Quantum OTP",
    isUnread: true,
    verification: {
      verified: true,
      level: "L3",
      methodTitle: "L3 Quantum OTP — Vernam XOR + Carter-Wegman Poly1305 MAC",
      methodDetail: "Information-Theoretically Secure OTP + Carter-Wegman Poly1305 MAC",
      keyIds: ["isro-qkd-key-0001", "isro-qkd-key-0002"],
      aadAuthenticated: true,
      timestampEpochSecs: 1790677320,
    },
    envelopeHeader: {
      version: 1,
      security_level: "QuantumOtp",
      message_id: "7f4c3a21-98e4-4d82-bf29-19ec5809ac2b",
      sender_sae: 1,
      recipient_sae: 2,
      key_ids: ["isro-qkd-key-0001", "isro-qkd-key-0002"],
      timestamp_epoch_secs: 1790677320,
      tag_b64: "6z9+e3q0w1L2g4...Poly1305==",
      nonce_b64: null,
      pqc_ciphertext_b64: null,
    },
    attachments: [
      { filename: "trajectory_params.csv", contentType: "text/csv", size: "24.5 KB" },
      { filename: "burn_sequence.bin", contentType: "application/octet-stream", size: "112.0 KB" },
    ],
  },
  {
    id: "msg-002",
    folder: "inbox",
    from: "Mission Control <mission.control@isro.gov.in>",
    senderName: "Mission Control",
    to: ["officer.sac@isro.gov.in"],
    date: "Today, 14:15 IST",
    subject: "Chandrayaan-4 Lunar Sample Return Telemetry",
    snippet: "Ascent module rendezvous radar telemetry acquired via Bangalore Deep Space Network...",
    bodyText: `SAC Cryptography Division,

Bangalore DSN has acquired the lunar ascent module transponder. PQC hybrid envelope verified over Ka-band ground link.
Enclosed are the raw ephemeris state vectors.

ML-KEM-768 encapsulation was executed with zero packet loss across the quantum-safe transit tunnel.`,
    securityLevel: "L2.5",
    securityLevelName: "L2.5 Hybrid PQC",
    isUnread: true,
    verification: {
      verified: true,
      level: "L2.5",
      methodTitle: "Hybrid Post-Quantum — NIST FIPS 203 ML-KEM-768 + QKD Dual-PRF",
      methodDetail: "Dual-PRF HKDF combiner: QKD Symmetric Key + Lattice KEM Shared Secret",
      keyIds: ["isro-qkd-key-0034"],
      aadAuthenticated: true,
      timestampEpochSecs: 1790675700,
    },
    envelopeHeader: {
      version: 1,
      security_level: "HybridPqc",
      message_id: "8c12fa90-b19e-4a99-b1d5-9430cde714f3",
      sender_sae: 1,
      recipient_sae: 2,
      key_ids: ["isro-qkd-key-0034"],
      timestamp_epoch_secs: 1790675700,
      tag_b64: null,
      nonce_b64: "4FqB3+9zT8e2...==",
      pqc_ciphertext_b64: "mLkEm768_cIPhErText_1088_bytes_B64...",
    },
    attachments: [
      { filename: "ephemeris_ascent_v2.dat", contentType: "application/octet-stream", size: "88.4 KB" },
    ],
  },
  {
    id: "msg-003",
    folder: "inbox",
    from: "SAC Cryptography Team <sac.crypto@isro.gov.in>",
    senderName: "SAC Cryptography Team",
    to: ["officer.sac@isro.gov.in"],
    date: "Today, 13:02 IST",
    subject: "QKD Free-Space Optical Link Calibration",
    snippet: "Atmospheric turbulence compensation tests on Mount Abu telescope successful...",
    bodyText: `Security Operations,

Mount Abu free-space link calibration completed with QBER below 2.4%.
Key bank reconciliation has refreshed 50 symmetric 1024-byte blocks. All ETSI GS QKD 014 REST endpoints responding within 12ms.`,
    securityLevel: "L2",
    securityLevelName: "L2 Q-AES",
    isUnread: false,
    verification: {
      verified: true,
      level: "L2",
      methodTitle: "Quantum-Aided AES-256-GCM — QKD Key Seeded HKDF",
      methodDetail: "AES-256-GCM authenticated encryption with 96-bit CSPRNG Nonce",
      keyIds: ["isro-qkd-key-0012"],
      aadAuthenticated: true,
      timestampEpochSecs: 1790671320,
    },
    envelopeHeader: {
      version: 1,
      security_level: "Qaes",
      message_id: "3e9b119a-581d-40c2-9854-3e9a7e8912aa",
      sender_sae: 1,
      recipient_sae: 2,
      key_ids: ["isro-qkd-key-0012"],
      timestamp_epoch_secs: 1790671320,
      tag_b64: null,
      nonce_b64: "9hP3+q4mN2e1...==",
      pqc_ciphertext_b64: null,
    },
    attachments: [
      { filename: "qber_telemetry_mount_abu.csv", contentType: "text/csv", size: "14.2 KB" },
    ],
  },
  {
    id: "msg-004",
    folder: "inbox",
    from: "Director ISRO <director@isro.gov.in>",
    senderName: "Director ISRO",
    to: ["officer.sac@isro.gov.in"],
    date: "Yesterday, 18:20 IST",
    subject: "Annual Mission Budget Allocations FY 2026-27",
    snippet: "Unclassified budgetary memo for upcoming space exploration initiatives...",
    bodyText: `Dear Colleagues,

The ministry has approved the primary capital expenditure for next generation quantum satellite payloads (QEYSSat / ISRO-QKD).
Full schedule attached for planning purposes.`,
    securityLevel: "L1",
    securityLevelName: "L1 Baseline",
    isUnread: false,
    verification: {
      verified: true,
      level: "L1",
      methodTitle: "Baseline TLS Transport — Standard RFC 822",
      methodDetail: "Transport Layer Security (TLS 1.3) only; payload in plaintext",
      keyIds: [],
      aadAuthenticated: false,
      timestampEpochSecs: 1790604000,
    },
    envelopeHeader: null,
    attachments: [
      { filename: "budget_summary_fy26.pdf", contentType: "application/pdf", size: "430.5 KB" },
    ],
  },
  {
    id: "msg-005",
    folder: "inbox",
    from: "Ground Station Bangalore <gs.blr@isro.gov.in>",
    senderName: "Ground Station Bangalore",
    to: ["officer.sac@isro.gov.in"],
    date: "Yesterday, 11:05 IST",
    subject: "Telemetry Stream Alert: LEO QKD Transponder",
    snippet: "Real-time key reconciliation event notification: 2048 new bits exchanged...",
    bodyText: `Automated Link Supervisor:

Pass #412 concluded over Bangalore ground terminal.
- Sifted bits: 14.8 Mbit
- Error corrected & privacy amplified: 1.2 Mbit
- Stored into local key bank slots: #85 through #98.`,
    securityLevel: "L3",
    securityLevelName: "L3 Quantum OTP",
    isUnread: false,
    verification: {
      verified: true,
      level: "L3",
      methodTitle: "L3 Quantum OTP — Vernam XOR + Carter-Wegman Poly1305 MAC",
      methodDetail: "Information-Theoretically Secure OTP + Carter-Wegman Poly1305 MAC",
      keyIds: ["isro-qkd-key-0085", "isro-qkd-key-0086"],
      aadAuthenticated: true,
      timestampEpochSecs: 1790577900,
    },
    envelopeHeader: {
      version: 1,
      security_level: "QuantumOtp",
      message_id: "0d99aa42-6e11-477c-a490-502aef12d091",
      sender_sae: 1,
      recipient_sae: 2,
      key_ids: ["isro-qkd-key-0085", "isro-qkd-key-0086"],
      timestamp_epoch_secs: 1790577900,
      tag_b64: "a84Kq009xZ...==",
      nonce_b64: null,
      pqc_ciphertext_b64: null,
    },
    attachments: [],
  },
];
