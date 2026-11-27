"""
Cryptographic Engine Test Suite
Tests Ed25519 digital signatures, AES-256-GCM AEAD encryption,
SHA-256 canonical integrity digests, and tamper rejection.
"""
import unittest
from backend.services.crypto_service import (
    ensure_cryptographic_keys,
    load_private_signing_key,
    load_public_verification_key,
    load_aes_master_key,
    canonical_json_bytes,
    compute_sha256_digest,
    sign_data,
    verify_signature,
    encrypt_license_payload,
    decrypt_license_payload
)

class TestCryptoService(unittest.TestCase):
    def setUp(self):
        ensure_cryptographic_keys()

    def test_key_loading(self):
        priv = load_private_signing_key()
        pub = load_public_verification_key()
        aes_key = load_aes_master_key()
        self.assertIsNotNone(priv)
        self.assertIsNotNone(pub)
        self.assertEqual(len(aes_key), 32)  # 256 bits

    def test_canonical_json_bytes_is_deterministic(self):
        # Different ordering of keys in python dict must produce identical bytes
        d1 = {"z": 10, "a": "hello", "m": [1, 2, 3]}
        d2 = {"a": "hello", "m": [1, 2, 3], "z": 10}
        self.assertEqual(canonical_json_bytes(d1), canonical_json_bytes(d2))

    def test_sha256_digest(self):
        data = {"license_id": "LIC-TEST-0001", "user_id": 1}
        digest1 = compute_sha256_digest(data)
        digest2 = compute_sha256_digest(data)
        self.assertEqual(digest1, digest2)
        self.assertEqual(len(digest1), 64)  # 64 hex chars = 256 bits

    def test_ed25519_sign_and_verify_valid(self):
        test_payload = b"Secure Software License Data Payload"
        sig_b64 = sign_data(test_payload)
        is_valid = verify_signature(test_payload, sig_b64)
        self.assertTrue(is_valid)

    def test_ed25519_rejects_tampered_payload(self):
        original_payload = b"Original Authentic License Payload"
        sig_b64 = sign_data(original_payload)
        
        # Tampered payload (attacker modified 1 byte)
        tampered_payload = b"Original Authentic License PayloaX"
        is_valid = verify_signature(tampered_payload, sig_b64)
        self.assertFalse(is_valid)

    def test_ed25519_rejects_corrupted_signature(self):
        payload = b"Valid Payload"
        sig_b64 = sign_data(payload)
        # Flip a character in signature string
        corrupt_sig = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
        is_valid = verify_signature(payload, corrupt_sig)
        self.assertFalse(is_valid)

    def test_aes_gcm_encrypt_decrypt_valid(self):
        secret_payload = {
            "features": ["basic_editing", "export_pdf", "cloud_sync"],
            "tier": "ENTERPRISE",
            "device_limit": 5
        }
        ciphertext_b64, nonce_b64 = encrypt_license_payload(secret_payload)
        decrypted = decrypt_license_payload(ciphertext_b64, nonce_b64)
        self.assertEqual(decrypted, secret_payload)

    def test_aes_gcm_tamper_detection(self):
        secret_payload = {"tier": "STANDARD"}
        ciphertext_b64, nonce_b64 = encrypt_license_payload(secret_payload)
        
        # Tamper with the base64 ciphertext
        import base64
        raw_ct = bytearray(base64.b64decode(ciphertext_b64))
        raw_ct[0] ^= 0xFF  # Corrupt first byte
        tampered_ct_b64 = base64.b64encode(raw_ct).decode("utf-8")
        
        with self.assertRaises(Exception):
            decrypt_license_payload(tampered_ct_b64, nonce_b64)

if __name__ == "__main__":
    unittest.main()
