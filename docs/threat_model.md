# Security Threat Model & Cryptographic Analysis
## Project: Secure Software License Distribution System
**Course:** Cryptography and Network Security (CNS) | **Team:** Team 07 (SoCSE)

---

### 1. Security Architecture Objectives
The primary security objective of this system is to prevent and mitigate unauthorized software copying, license fabrication, tampering, sharing, and post-revocation usage through modern cryptographic primitives.

---

### 2. Threat Matrix & Cryptographic Mitigations

| Threat | Attack Vector | Security Primitive | Defense Mechanism | Inherent Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **Fake License Forgery** | Attacker attempts to generate their own fake license key or file. | **Ed25519 Asymmetric Digital Signatures** | Digital signatures can only be generated using the server's Private Signing Key. The client application only holds the Public Key. | Does not prevent an attacker from modifying client binary instructions via disassembly/debugging (DRM limitation). |
| **License Modification / Tampering** | Attacker modifies expiry date, user ID, or features in `license.lic`. | **Ed25519 + Deterministic SHA-256** | Any change of even 1 bit in the canonical payload invalidates the digital signature and breaks the integrity hash. | The client application must verify both signature and hash on startup. |
| **License Sharing / Multi-Machine Copying** | A valid license file is copied to multiple computers. | **Device / Hardware Fingerprinting** | License is bound to a SHA-256 machine fingerprint derived from OS, node, and hardware attributes. Mismatch halts software execution. | Sophisticated attackers can virtualize or spoof hardware attributes. |
| **Post-Revocation Software Use** | A refunded or breached user keeps using the software offline. | **Online Status Synchronization** | Protected app queries `POST /licenses/validate` to verify revocation status against server registry. | A strictly air-gapped machine with a valid offline signature cannot detect immediate revocation until reconnected. |
| **Brute-Force & Dictionary Attacks** | Attacker attempts password guessing on user or admin accounts. | **Argon2id Salted Password Hashing** | Uses the memory-hard, GPU-resistant Argon2id algorithm (Password Hashing Competition winner). | Users must still choose sufficiently long passwords. |
| **Token Tampering / Elevation of Privilege** | Attacker modifies role from `'USER'` to `'ADMIN'` in bearer token. | **RFC 7519 HMAC-SHA256 Signatures** | Token signatures are recomputed on every request using the server's `SECRET_KEY` and compared with constant-time equality. | `SECRET_KEY` must be kept secret on the server. |
| **Audit Log Erasure / Tampering** | Malicious DB admin attempts to delete or alter evidence of unauthorized access. | **Cryptographic SHA-256 Hash Chaining** | Each log entry computes `SHA-256(prev_hash + data)`. Altering any historical log breaks the linear hash chain for all subsequent entries. | A malicious root admin could theoretically recompute the entire chain from scratch if they have offline database control. |
| **Timing Analysis Attacks** | Measuring response times to deduce cryptographic signature bytes. | **Constant-Time Verification (`hmac.compare_digest`)** | Ensures string/digest evaluation runs in identical execution time regardless of character mismatch position. | Requires clean execution environments. |

---

### 3. Cryptographic Separation Summary
- **Authentication:** *Who is the user?* -> Verified via Argon2id.
- **Authorization:** *What is the user allowed to do?* -> Enforced via RBAC guards & license feature gating.
- **Confidentiality:** *Prevent unauthorized data reading* -> AES-256-GCM AEAD encryption.
- **Integrity:** *Detect data tampering* -> Canonical SHA-256 digests.
- **Authenticity & Non-Repudiation:** *Prove genuine issuance* -> Ed25519 digital signatures.
