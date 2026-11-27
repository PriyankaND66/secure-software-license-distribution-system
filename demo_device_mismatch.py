"""
Demo 8 Helper Script: Device Binding & Anti-Piracy Demonstration
Demonstrates legitimate server issuance of a device-bound license
and how the application permits the authorized machine while blocking unauthorized machines.
"""
import json
from pathlib import Path
from backend.models.license import LicenseGenerateRequest
from backend.services.license_generator import create_license
from client.license_validator import validate_license_file
from client.protected_app import print_validation_report

def main():
    print("=" * 80)
    print("      CNS PROJECT - DEMO 8: DEVICE BINDING & ANTI-PIRACY DEMONSTRATION")
    print("=" * 80)

    # Step 1: Server legitimately issues a license bound to Machine A
    print("\n[Step 1] License Server generating authentic license bound to 'DEV-OFFICIAL-PC'...")
    req = LicenseGenerateRequest(
        user_id=2,
        software_id=1,
        license_type="STANDARD",
        device_id="DEV-OFFICIAL-PC",
        features=["basic_editing", "export_pdf"]
    )
    result = create_license(req)
    bound_license_path = Path("bound_license.lic")
    with open(bound_license_path, "w", encoding="utf-8") as f:
        json.dump(result["license_file"], f, indent=2)
    print(f"         License {result['license_id']} signed by server and saved to: {bound_license_path.resolve()}\n")

    # Step 2: Run software on Authorized Machine (DEV-OFFICIAL-PC)
    print("-" * 80)
    print("TEST CASE A: Running software on the AUTHORIZED computer ('DEV-OFFICIAL-PC')")
    print("-" * 80)
    res_authorized = validate_license_file(
        bound_license_path,
        force_offline=True,
        override_device_id="DEV-OFFICIAL-PC"
    )
    print_validation_report(res_authorized)

    # Step 3: Run software on Unauthorized Machine (DEV-ROGUE-LAPTOP)
    print("\n" + "-" * 80)
    print("TEST CASE B: License file copied and executed on an UNAUTHORIZED computer ('DEV-ROGUE-LAPTOP')")
    print("-" * 80)
    res_rogue = validate_license_file(
        bound_license_path,
        force_offline=True,
        override_device_id="DEV-ROGUE-LAPTOP"
    )
    print_validation_report(res_rogue)

    print("=" * 80)
    print("DEMO 8 CONCLUSION:")
    print("  1. The digital signature was VALID in both cases (issued by legitimate server).")
    print("  2. Machine A was GRANTED access because the hardware fingerprint matched.")
    print("  3. Machine B was DENIED access with 'DEVICE_MISMATCH' because the fingerprint differed.")
    print("=" * 80)

if __name__ == "__main__":
    main()
