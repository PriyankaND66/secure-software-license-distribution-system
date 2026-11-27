"""
Protected Demo Client Application: SecureEditor
A protected document and note editor demonstrating:
1. Pre-execution License Validation (Signature, Integrity, Expiry, Status, Device).
2. Dynamic Feature-Based Licensing (Authorization).
3. Clear Access Granted vs Access Denied screens for viva demonstrations.
"""
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to sys.path so it runs standalone
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.license_validator import validate_license_file, ValidationResult
from client.device import get_machine_fingerprint

BANNER = r"""
================================================================================
   ____                      ______    ___ __            
  / __/__ ______ ______ ___ / ____/___/ (_) /____  _____ 
 _\ \/ -_) __/ // / __// -_) __/ _  / / / __/ _ \/ ___/ 
/___/\__/\__/\_,_/_/   \__/___/\_,_/_/_/\__/\___/_/     
   CNS Project - Protected Application Demo (v1.0.0)
================================================================================
"""

def print_validation_report(result: ValidationResult):
    print("=" * 80)
    print("                 LICENSE CRYPTOGRAPHIC AUDIT REPORT")
    print("=" * 80)
    
    if result.is_valid:
        print("[STATUS]        : ACCESS GRANTED")
        print(f"[LICENSE ID]    : {result.license_id}")
        print(f"[LICENSED TO]   : {result.user_email}")
        print(f"[TIER]          : {result.license_type}")
        print(f"[EXPIRES ON]    : {result.expiry_date}")
        print(f"[DEVICE BOUND]  : {result.device_id}")
        print(f"[MODE]          : {result.validation_mode}")
        print(f"[MESSAGE]       : {result.message}")
        print("-" * 80)
        print("ENABLED FEATURES (AUTHORIZATION CHECK):")
        all_features = [
            ("basic_editing", "Basic Document Editing"),
            ("export_pdf", "Export to PDF/Text"),
            ("cloud_sync", "Encrypted Cloud Backup"),
            ("advanced_analytics", "Text Metrics & Security Analytics")
        ]
        for code, label in all_features:
            if code in result.features:
                print(f"  [YES] UNLOCKED : {label} ({code})")
            else:
                print(f"  [NO ] LOCKED   : {label} ({code}) - Upgrade Required")
    else:
        print("[STATUS]        : ACCESS DENIED [X]")
        print(f"[REASON CODE]   : {result.status_code}")
        print(f"[DIAGNOSTIC]    : {result.message}")
        if result.license_id:
            print(f"[TARGET LIC]    : {result.license_id}")
    print("=" * 80)

def run_editor(result: ValidationResult):
    """Simple interactive document manager demonstrating feature gating."""
    docs = {
        "welcome.txt": "Welcome to SecureEditor! This software requires a cryptographically valid license."
    }
    
    while True:
        print("\n--- SecureEditor Menu ---")
        print("1. View Documents")
        print("2. Create New Document (Requires 'basic_editing')")
        print("3. Export Document (Requires 'export_pdf')")
        print("4. Cloud Backup (Requires 'cloud_sync')")
        print("5. Document Analytics (Requires 'advanced_analytics')")
        print("6. Inspect License Details")
        print("7. Exit")
        
        choice = input("\nSelect an option (1-7): ").strip()
        
        if choice == "1":
            print("\nAvailable Documents:")
            for name, content in docs.items():
                print(f"\n[{name}]:\n{content}")
                
        elif choice == "2":
            if "basic_editing" not in result.features:
                print("\n[ACCESS DENIED]: 'basic_editing' is disabled by your license policy.")
                continue
            title = input("Document name: ").strip()
            text = input("Content: ").strip()
            docs[title] = text
            print(f"Document '{title}' saved successfully.")
            
        elif choice == "3":
            if "export_pdf" not in result.features:
                print("\n[ACCESS DENIED]: 'export_pdf' is disabled on this license tier.")
                continue
            title = input("Document name to export: ").strip()
            if title in docs:
                export_path = Path(f"exported_{title}")
                with open(export_path, "w", encoding="utf-8") as f:
                    f.write(docs[title])
                print(f"[SUCCESS]: Exported to {export_path.resolve()}")
            else:
                print(f"Document '{title}' not found.")
                
        elif choice == "4":
            if "cloud_sync" not in result.features:
                print("\n[FEATURE LOCKED]: 'cloud_sync' requires a PERPETUAL or ENTERPRISE tier license.")
                continue
            print("[SYNC]: Encrypting and uploading documents to remote secure vault... (Simulated)")
            
        elif choice == "5":
            if "advanced_analytics" not in result.features:
                print("\n[FEATURE LOCKED]: 'advanced_analytics' is not included in this license.")
                continue
            total_words = sum(len(content.split()) for content in docs.values())
            print(f"\n[ANALYTICS]: Total Documents: {len(docs)} | Total Words: {total_words}")
            
        elif choice == "6":
            print_validation_report(result)
            
        elif choice == "7":
            print("\nExiting SecureEditor. Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1-7.")

def main():
    parser = argparse.ArgumentParser(description="SecureEditor - Protected Application Demo")
    parser.add_argument("--license", "-l", default="license.lic", help="Path to license.lic file")
    parser.add_argument("--offline", action="store_true", help="Force offline validation mode")
    parser.add_argument("--device-id", help="Override device ID to test device binding")
    parser.add_argument("--interactive", "-i", action="store_true", help="Launch interactive document editor")
    args = parser.parse_args()

    print(BANNER)
    lic_path = Path(args.license)
    print(f"[*] Detecting machine hardware fingerprint: {get_machine_fingerprint(args.device_id)}")
    print(f"[*] Loading license file: {lic_path.resolve()}")
    print("[*] Initiating 7-stage cryptographic validation pipeline...\n")

    result = validate_license_file(
        license_path=lic_path,
        force_offline=args.offline,
        override_device_id=args.device_id
    )

    print_validation_report(result)

    if not result.is_valid:
        print("\n[CRITICAL ERROR]: SOFTWARE EXECUTION HALTED DUE TO SECURITY VIOLATION.")
        sys.exit(1)

    print("\n[SUCCESS]: Cryptographic integrity and licensing confirmed. Launching application environment.")
    if args.interactive:
        run_editor(result)

if __name__ == "__main__":
    main()
