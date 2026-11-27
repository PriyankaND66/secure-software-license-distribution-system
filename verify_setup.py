"""
System Verification Script (Phase 2 Sanity Check)
Run this script to verify your development environment, folder structure,
and cryptographic dependencies.
"""
import sys
import os
from pathlib import Path

def print_status(component: str, ok: bool, details: str = ""):
    symbol = "[PASS]" if ok else "[FAIL]"
    print(f"{symbol:7} | {component:35} | {details}")

def main():
    print("=" * 75)
    print(" SECURE SOFTWARE LICENSE DISTRIBUTION SYSTEM - SETUP VERIFICATION")
    print("=" * 75)
    all_passed = True

    # 1. Python Version Check
    py_ver = sys.version_info
    ver_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    py_ok = (py_ver.major == 3 and py_ver.minor >= 10)
    print_status("Python Version (>= 3.10)", py_ok, f"Found Python {ver_str}")
    if not py_ok:
        all_passed = False

    # 2. Package Imports Check
    required_pkgs = [
        ("fastapi", "FastAPI Framework"),
        ("uvicorn", "ASGI Server"),
        ("cryptography", "Cryptographic Primitives"),
        ("argon2", "Argon2 Password Hashing"),
        ("pydantic", "Data Validation & Models"),
        ("requests", "HTTP Client"),
    ]
    for module_name, desc in required_pkgs:
        try:
            __import__(module_name)
            print_status(f"Dependency: {module_name}", True, desc)
        except ImportError as e:
            print_status(f"Dependency: {module_name}", False, f"Missing: {e}")
            all_passed = False

    # 3. Cryptography Primitives Smoke Test
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from argon2 import PasswordHasher
        import hashlib

        # Ed25519 Signature test
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        msg = b"CNS-Verification-2026"
        sig = priv.sign(msg)
        pub.verify(sig, msg)

        # AES-256-GCM test
        key = AESGCM.generate_key(bit_length=256)
        aes = AESGCM(key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, msg, None)
        pt = aes.decrypt(nonce, ct, None)
        assert pt == msg

        # SHA-256 test
        h = hashlib.sha256(msg).hexdigest()

        # Argon2 test
        ph = PasswordHasher()
        pw_hash = ph.hash("demo_password")
        assert ph.verify(pw_hash, "demo_password")

        print_status("Crypto Primitives (Ed25519/AES/SHA/Argon2)", True, "All primitives operational")
    except Exception as e:
        print_status("Crypto Primitives", False, f"Error: {e}")
        all_passed = False

    # 4. Folder Structure Check
    expected_dirs = [
        "backend",
        "backend/database",
        "backend/models",
        "backend/routes",
        "backend/services",
        "backend/keys",
        "frontend",
        "frontend/css",
        "frontend/js",
        "client",
        "client/keys",
        "tests",
        "docs",
    ]
    base_dir = Path(__file__).resolve().parent
    missing_dirs = []
    for d in expected_dirs:
        if not (base_dir / d).is_dir():
            missing_dirs.append(d)
    
    if not missing_dirs:
        print_status("Directory Scaffold", True, "All 13 project folders exist")
    else:
        print_status("Directory Scaffold", False, f"Missing: {missing_dirs}")
        all_passed = False

    # 5. FastAPI App Initialization Check
    try:
        from backend.main import app
        print_status("FastAPI Application App Object", True, f"Loaded title: '{app.title}'")
    except Exception as e:
        print_status("FastAPI Application App Object", False, f"Failed to import backend.main:app: {e}")
        all_passed = False

    print("=" * 75)
    if all_passed:
        print("[SUCCESS] Phase 2 Setup Verification PASSED! You are ready for Phase 3.")
    else:
        print("[WARNING] Setup verification had errors. Please check the failures above.")
    print("=" * 75)

if __name__ == "__main__":
    main()
