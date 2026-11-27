"""
Database Seeding Script
Executes schema creation and initial data population.
"""
from backend.database.db import seed_default_data, verify_audit_log_integrity, get_db_connection

def main():
    print("Initializing Secure License System Database...")
    seed_default_data()
    print("Database schema created and default data seeded successfully!")
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, role FROM users;")
        users = cursor.fetchall()
        print("\n--- Seeded Users ---")
        for u in users:
            print(f"ID: {u['id']} | User: {u['username']:<10} | Email: {u['email']:<24} | Role: {u['role']}")
            
        cursor.execute("SELECT id, name, code_name, version FROM software;")
        software = cursor.fetchall()
        print("\n--- Seeded Software Products ---")
        for s in software:
            print(f"ID: {s['id']} | Name: {s['name']:<15} | Code: {s['code_name']:<12} | Ver: {s['version']}")

    # Verify audit log integrity chain
    integrity = verify_audit_log_integrity()
    print("\n--- Audit Log Cryptographic Integrity Check ---")
    print(f"Status: {'VALID' if integrity['valid'] else 'TAMPERED'} | Records Verified: {integrity['verified_count']}")
    print(f"Message: {integrity['message']}")
    print("-------------------------------------------------")

if __name__ == "__main__":
    main()
