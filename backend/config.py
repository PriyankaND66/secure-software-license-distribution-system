"""
Application Configuration Module
Centralizes paths, cryptographic constants, and runtime settings.
"""
from pathlib import Path
import os

# Base Directories
BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
DB_NAME = "license_test.db" if os.getenv("TEST_MODE") == "1" else "license_system.db"
DATABASE_PATH = BACKEND_DIR / "database" / DB_NAME
BACKEND_KEYS_DIR = BACKEND_DIR / "keys"
CLIENT_KEYS_DIR = BASE_DIR / "client" / "keys"

# Ensure key directories exist
BACKEND_KEYS_DIR.mkdir(parents=True, exist_ok=True)
CLIENT_KEYS_DIR.mkdir(parents=True, exist_ok=True)

# Cryptographic Key Paths
ED25519_PRIVATE_KEY_PATH = BACKEND_KEYS_DIR / "ed25519_private.pem"
ED25519_PUBLIC_KEY_PATH = BACKEND_KEYS_DIR / "ed25519_public.pem"
CLIENT_PUBLIC_KEY_PATH = CLIENT_KEYS_DIR / "ed25519_public.pem"
AES_MASTER_KEY_PATH = BACKEND_KEYS_DIR / "aes_master.key"

# Security & Session Settings
SECRET_KEY = os.getenv("APP_SECRET_KEY", "cns-secure-license-distribution-system-secret-key-2026")
TOKEN_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 hours

# Server Settings
HOST = "127.0.0.1"
PORT = 8000
API_PREFIX = "/api/v1"
