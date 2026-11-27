"""
Cryptographic Engine Module
Implements Ed25519 asymmetric signatures, AES-256-GCM AEAD encryption,
deterministic SHA-256 canonical hashing, and key lifecycle management.
"""
import os
import json
import base64
import hashlib
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from backend.config import (
    ED25519_PRIVATE_KEY_PATH,
    ED25519_PUBLIC_KEY_PATH,
    CLIENT_PUBLIC_KEY_PATH,
    AES_MASTER_KEY_PATH,
    BACKEND_KEYS_DIR,
    CLIENT_KEYS_DIR
)

# ---------------------------------------------------------------------------
# Key Lifecycle Management
# ---------------------------------------------------------------------------

def ensure_cryptographic_keys() -> None:
    """
    Checks if asymmetric (Ed25519) and symmetric (AES-256) master keys exist.
    If not, generates them and securely stores them.
    Also synchronizes the Ed25519 public verification key to the client directory.
    """
    BACKEND_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    CLIENT_KEYS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Asymmetric Ed25519 Keypair
    if not ED25519_PRIVATE_KEY_PATH.exists() or not ED25519_PUBLIC_KEY_PATH.exists():
        # Generate new Ed25519 256-bit asymmetric private key
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize Private Key (PKCS#8 PEM format)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(ED25519_PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_pem)

        # Serialize Public Key (SubjectPublicKeyInfo PEM format)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(ED25519_PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_pem)

    # Always ensure client directory has the latest Public Key (and NEVER the private key!)
    with open(ED25519_PUBLIC_KEY_PATH, "rb") as f_src:
        pub_bytes = f_src.read()
    with open(CLIENT_PUBLIC_KEY_PATH, "wb") as f_dst:
        f_dst.write(pub_bytes)

    # 2. Master AES-256 Symmetric Key
    if not AES_MASTER_KEY_PATH.exists():
        aes_key = AESGCM.generate_key(bit_length=256)
        with open(AES_MASTER_KEY_PATH, "wb") as f:
            f.write(aes_key)

def load_private_signing_key() -> ed25519.Ed25519PrivateKey:
    """Loads the license server's Ed25519 private key for digital signing."""
    ensure_cryptographic_keys()
    with open(ED25519_PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_verification_key(public_key_path: Optional[Path] = None) -> ed25519.Ed25519PublicKey:
    """Loads the Ed25519 public key for signature verification."""
    path = public_key_path or ED25519_PUBLIC_KEY_PATH
    if not path.exists():
        ensure_cryptographic_keys()
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_aes_master_key() -> bytes:
    """Loads the 256-bit AES symmetric key used for encrypting license payloads."""
    ensure_cryptographic_keys()
    with open(AES_MASTER_KEY_PATH, "rb") as f:
        return f.read()

# ---------------------------------------------------------------------------
# Cryptographic Operations
# ---------------------------------------------------------------------------

def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """
    Deterministic serialization: sorts keys and removes unnecessary whitespace.
    Guarantees that identical data always produces the exact same byte sequence.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def compute_sha256_digest(data: Dict[str, Any]) -> str:
    """
    Computes a deterministic SHA-256 hexadecimal digest over canonical JSON data.
    Provides integrity verification.
    """
    raw_bytes = canonical_json_bytes(data)
    return hashlib.sha256(raw_bytes).hexdigest()

def sign_data(data_bytes: bytes, private_key: Optional[ed25519.Ed25519PrivateKey] = None) -> str:
    """
    Signs arbitrary byte data using Ed25519 digital signature.
    Returns Base64 encoded signature.
    """
    key = private_key or load_private_signing_key()
    signature_bytes = key.sign(data_bytes)
    return base64.b64encode(signature_bytes).decode("utf-8")

def verify_signature(
    data_bytes: bytes,
    signature_b64: str,
    public_key: Optional[ed25519.Ed25519PublicKey] = None
) -> bool:
    """
    Verifies that the Ed25519 signature over data_bytes is mathematically valid.
    Returns True if valid, False if tampered or forged.
    """
    key = public_key or load_public_verification_key()
    try:
        signature_bytes = base64.b64decode(signature_b64)
        key.verify(signature_bytes, data_bytes)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False

def encrypt_license_payload(
    payload: Dict[str, Any],
    aes_key: Optional[bytes] = None
) -> Tuple[str, str]:
    """
    Encrypts sensitive license attributes using AES-256-GCM (Authenticated Encryption).
    Generates a unique 12-byte cryptographic nonce for every operation.
    Returns (ciphertext_b64, nonce_b64).
    """
    key = aes_key or load_aes_master_key()
    aesgcm = AESGCM(key)
    
    # Generate 12-byte cryptographically secure random nonce
    nonce = os.urandom(12)
    plaintext_bytes = canonical_json_bytes(payload)
    
    # AES-GCM ciphertext includes the 16-byte authentication tag
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    return (
        base64.b64encode(ciphertext).decode("utf-8"),
        base64.b64encode(nonce).decode("utf-8")
    )

def decrypt_license_payload(
    ciphertext_b64: str,
    nonce_b64: str,
    aes_key: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Decrypts and verifies authentication tag for an AES-256-GCM ciphertext.
    Raises ValueError if ciphertext was tampered with or modified.
    """
    key = aes_key or load_aes_master_key()
    aesgcm = AESGCM(key)
    
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(decrypted_bytes.decode("utf-8"))
