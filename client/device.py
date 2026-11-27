"""
Device Fingerprinting Utility
Generates a privacy-conscious, non-sensitive hardware/platform fingerprint
represented as a truncated SHA-256 cryptographic digest.
"""
import hashlib
import platform
import uuid
import os
from typing import Optional

def get_machine_fingerprint(override_device_id: Optional[str] = None) -> str:
    """
    Computes a deterministic machine identity fingerprint.
    Uses non-invasive OS and hardware attributes (platform + node + MAC node).
    Returns a formatted string like 'DEV-A81E-4B02'.
    """
    if override_device_id:
        return override_device_id
        
    env_override = os.getenv("DEMO_DEVICE_ID")
    if env_override:
        return env_override
        
    raw_ident = f"{platform.system()}:{platform.node()}:{uuid.getnode()}:{platform.machine()}"
    digest = hashlib.sha256(raw_ident.encode("utf-8")).hexdigest().upper()
    
    # Format into user-readable 8-char hex code: DEV-XXXX-XXXX
    return f"DEV-{digest[:4]}-{digest[4:8]}"

if __name__ == "__main__":
    fingerprint = get_machine_fingerprint()
    print("=" * 50)
    print("MACHINE FINGERPRINT DETECTED:")
    print(f"Device ID: {fingerprint}")
    print("=" * 50)
