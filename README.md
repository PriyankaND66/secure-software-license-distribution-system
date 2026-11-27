# Secure Software License Distribution System
**Course:** Cryptography and Network Security (CNS)  
**Team:** Team 07 (SoCSE)  
**Team Members:**
- **Arudha Goudar (01fe23bcs059)** — Authentication & RBAC Backend
- **Harshavardhan Undodi (01fe23bcs219)** — Cryptographic Key Engine & License Generation
- **Sumit Rathod (01fe23bcs167)** — Client-Side Validator & Protected Application (`SecureEditor`)
- **Priyanka N D (01fe23bcs184)** — Web Interface & Administrator Dashboard

---

## 1. System Overview
The **Secure Software License Distribution System** is an end-to-end, cryptographically enforced software licensing platform designed to prevent unauthorized copying, modification, sharing, and fraudulent license generation.

### Cryptographic Foundation
- **Ed25519 Asymmetric Digital Signatures:** Server signs with Private Key (`ed25519_private.pem`); Client verifies with Public Key (`ed25519_public.pem`).
- **AES-256-GCM AEAD Encryption:** Encrypts sensitive feature payloads with 12-byte cryptographic nonces.
- **SHA-256 Canonical Digests:** Deterministic hashing for tamper detection and linear audit chain integrity.
- **Argon2id Password Hashing:** Salted, memory-hard hashing defending against dictionary and GPU cracking.
- **RFC 7519 HMAC-SHA256 Bearer Tokens:** Constant-time verified session authentication.

---

## 2. Project Layout

```text
c:\Users\HP\Documents\Projects\CNS\
├── backend/
│   ├── main.py                  # FastAPI server entry point
│   ├── config.py                # Centralized paths and cryptographic configuration
│   ├── database/
│   │   ├── db.py                # SQLite connection, schema & audit chain logic
│   │   └── seed.py              # Database seeding script
│   ├── models/                  # Pydantic schemas (user, software, license)
│   ├── routes/                  # API routers (auth, licenses, admin)
│   ├── services/
│   │   ├── crypto_service.py    # Ed25519, AES-GCM, SHA-256 key management
│   │   ├── auth_service.py      # Argon2id, JWT tokens, RBAC guards
│   │   └── license_generator.py # Canonical hashing, signing, licensing engine
│   └── keys/                    # Server private & master keys (SERVER ONLY)
├── frontend/
│   ├── index.html               # Project overview landing page
│   ├── login.html               # Authentication portal with viva demo buttons
│   ├── register.html            # Registration portal
│   ├── dashboard.html           # User license management & download portal
│   ├── admin.html               # Admin metrics, license revocation & audit verifier
│   ├── css/style.css            # Dark cybersecurity UI theme
│   └── js/api.js                # API client with automatic bearer headers
├── client/
│   ├── protected_app.py         # SecureEditor demo protected application
│   ├── license_validator.py     # 7-stage client validation engine
│   ├── device.py                # Privacy-conscious machine fingerprint utility
│   └── keys/                    # Client public verification key (ONLY)
├── tests/                       # 47 unit & security test cases
└── docs/
    └── threat_model.md          # Security threat model & attack analysis
```

---

## 3. Quick Start Guide

### Step 1: Initialize Database & Seed Demo Accounts
```powershell
python -m backend.database.seed
```

### Step 2: Start the FastAPI Backend Server
```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 3: Open the Web Portal
Open your web browser and navigate to:
- **Web Interface:** [http://127.0.0.1:8000/ui/](http://127.0.0.1:8000/ui/)
- **Interactive Swagger Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Step 4: Run the Complete Test Suite (47 Tests)
```powershell
python -m unittest discover tests
```

---

## 4. Eight Step-by-Step Viva Demonstration Scenarios

### Demo 1: User Registration & Authentication (Arudha)
1. Go to `http://127.0.0.1:8000/ui/login.html`.
2. Click **"User Demo"** (populates `testuser` / `User@123456`).
3. Click **Authenticate**. The server verifies the Argon2id hash and issues an HMAC-SHA256 signed Bearer token.
4. Try typing a wrong password: Show the **"USER_LOGIN_FAILED"** error and audit log.

### Demo 2: Admin Direct License Generation (Priyanka & Harshavardhan)
1. Log in as **"Admin Demo"** (`admin` / `Admin@123456`) -> redirected to `admin.html`.
2. Click **"+ Generate Custom License"**.
3. Select software `SecureEditor`, license type `STANDARD`, select features:
   - `basic_editing`
   - `export_pdf`
4. Click **Sign & Store License**. Show the server generating the Ed25519 signature and AES-GCM ciphertext.

### Demo 3: User Downloads License & Activates (Priyanka)
1. In the User Portal (`dashboard.html`), view the issued license.
2. Click **"📥 .lic"** button to download `license.lic` to your computer.

### Demo 4: Access Granted in Protected Software (Sumit)
Place `license.lic` in the application directory and run:
```powershell
python client/protected_app.py --license license.lic --offline
```
**Result:**
- Signature verified (`[YES]`)
- Integrity digest verified (`[YES]`)
- Expiry date verified (`[YES]`)
- Software association verified (`[YES]`)
- **STATUS: ACCESS GRANTED**
- Features unlocked: `basic_editing`, `export_pdf`.

### Demo 5: Tampered License Attack (Viva Attack Demo)
Open `license.lic` in a text editor and change `user_email` to `hacker@evil.com`. Run:
```powershell
python client/protected_app.py --license license.lic --offline
```
**Result:**
- `DIGITAL SIGNATURE VERIFICATION FAILED`
- **STATUS: ACCESS DENIED [X]**

### Demo 6: Expired License Detection
Run with an expired license:
```powershell
python -m unittest tests/test_client_validation.py -k test_expired_license_fails_validation
```
**Result:**
- `LICENSE EXPIRED`
- **STATUS: ACCESS DENIED [X]**

### Demo 7: Administrative Revocation
1. In `admin.html`, find the license and click **"Revoke"**.
2. Run `SecureEditor` with online validation enabled:
   ```powershell
   python client/protected_app.py --license license.lic
   ```
**Result:**
- Server flags: `This license has been REVOKED by the administrator.`
- **STATUS: ACCESS DENIED [X]**

### Demo 8: Device Mismatch Defense (License Copying Attack)
To test device binding, the license must be legitimately signed by the server for **Computer A**, and then executed on an unauthorized **Computer B**:

**Option A (Automated Side-by-Side Comparison Script):**
```powershell
python demo_device_mismatch.py
```
*This demonstrates Computer A being GRANTED access and Computer B being DENIED access with `DEVICE_MISMATCH` side-by-side.*

**Option B (Interactive Application Demo):**
1. Generate an authentic license bound to `DEV-OFFICIAL-PC`:
   ```powershell
   python -c "
   import json
   from backend.models.license import LicenseGenerateRequest
   from backend.services.license_generator import create_license
   req = LicenseGenerateRequest(user_id=2, software_id=1, license_type='STANDARD', device_id='DEV-OFFICIAL-PC', features=['basic_editing', 'export_pdf'])
   res = create_license(req)
   with open('bound_license.lic', 'w', encoding='utf-8') as f:
       json.dump(res['license_file'], f, indent=2)
   "
   ```
2. Run on authorized Computer A (`DEV-OFFICIAL-PC`):
   ```powershell
   python client/protected_app.py --license bound_license.lic --offline --device-id DEV-OFFICIAL-PC
   ```
   **Result:** `[STATUS] : ACCESS GRANTED`
3. Try copying and running on unauthorized Computer B (`DEV-ROGUE-LAPTOP`):
   ```powershell
   python client/protected_app.py --license bound_license.lic --offline --device-id DEV-ROGUE-LAPTOP
   ```
   **Result:** 
   - `[STATUS] : ACCESS DENIED [X]`
   - `[REASON CODE] : DEVICE_MISMATCH`
   - `[DIAGNOSTIC] : DEVICE BINDING MISMATCH: License is bound to device 'DEV-OFFICIAL-PC', but current hardware is 'DEV-ROGUE-LAPTOP'. License sharing is prohibited.`

---

## 5. Cryptographic Audit Chain Integrity Verification
In the Admin Dashboard (`admin.html`), click **"🛡️ Verify Chain Integrity"**.
The server traverses all database audit records, recalculating:
$$\text{Entry Hash} = \text{SHA-256}(\text{prev\_hash} \parallel \text{timestamp} \parallel \text{event} \parallel \text{details})$$
Proves to the examination committee that the system is **tamper-evident**.
