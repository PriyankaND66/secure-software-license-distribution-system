"""
Presentation Generator for CNS Capstone Project
Builds a professional, comprehensive 18-slide widescreen PowerPoint presentation
documenting the complete cryptographic architecture, workflows, flowcharts, and team division.
"""
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor

# ---------------------------------------------------------------------------
# Styling Constants (Professional Cybersecurity Palette)
# ---------------------------------------------------------------------------
COLOR_PRIMARY_NAVY = RGBColor(15, 30, 65)     # #0F1E41
COLOR_ACCENT_BLUE   = RGBColor(2, 132, 199)    # #0284C7
COLOR_ACCENT_INDIGO = RGBColor(79, 70, 229)    # #4F46E5
COLOR_SUCCESS_GREEN = RGBColor(16, 185, 129)   # #10B981
COLOR_DANGER_RED    = RGBColor(239, 68, 68)    # #EF4444
COLOR_BG_LIGHT      = RGBColor(248, 250, 252)  # #F8FAFC
COLOR_CARD_BG       = RGBColor(241, 245, 249)  # #F1F5F9
COLOR_CARD_BORDER   = RGBColor(203, 213, 225)  # #CBD5E1
COLOR_TEXT_DARK     = RGBColor(15, 23, 42)     # #0F172A
COLOR_TEXT_MUTED    = RGBColor(71, 85, 105)    # #475569
COLOR_WHITE         = RGBColor(255, 255, 255)

FONT_HEADING = "Calibri"
FONT_BODY    = "Calibri"

def apply_header(slide, title_text, category_text="CRYPTOGRAPHY & NETWORK SECURITY | TEAM 07"):
    """Adds a standard top bar with category subtitle and title."""
    # Top banner line
    banner = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.1))
    banner.fill.solid()
    banner.fill.fore_color.rgb = COLOR_ACCENT_BLUE
    banner.line.fill.background()

    # Category Text
    cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.35), Inches(11.7), Inches(0.3))
    tf_cat = cat_box.text_frame
    tf_cat.word_wrap = True
    p_cat = tf_cat.paragraphs[0]
    p_cat.text = category_text.upper()
    p_cat.font.name = FONT_BODY
    p_cat.font.size = Pt(10)
    p_cat.font.bold = True
    p_cat.font.color.rgb = COLOR_ACCENT_BLUE

    # Title Text
    title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.65), Inches(11.7), Inches(0.65))
    tf = title_box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = title_text
    p.font.name = FONT_HEADING
    p.font.size = Pt(24)
    p.font.bold = True
    p.font.color.rgb = COLOR_PRIMARY_NAVY

    # Bottom footer line
    foot_line = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(7.0), Inches(11.733), Inches(0.02))
    foot_line.fill.solid()
    foot_line.fill.fore_color.rgb = COLOR_CARD_BORDER
    foot_line.line.fill.background()

    # Footer Text
    foot_box = slide.shapes.add_textbox(Inches(0.8), Inches(7.05), Inches(11.7), Inches(0.3))
    p_foot = foot_box.text_frame.paragraphs[0]
    p_foot.text = "School of Computer Science & Engineering (SoCSE) | Capstone Project 2026"
    p_foot.font.name = FONT_BODY
    p_foot.font.size = Pt(9)
    p_foot.font.color.rgb = COLOR_TEXT_MUTED

def add_card(slide, left, top, width, height, title, body_bullets, border_color=COLOR_CARD_BORDER, bg_color=COLOR_CARD_BG):
    """Creates a structured rounded card box with a title and bullet points."""
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = bg_color
    card.line.color.rgb = border_color
    card.line.width = Pt(1.5)

    tf = card.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.TOP
    tf.margin_left = Inches(0.2)
    tf.margin_right = Inches(0.2)
    tf.margin_top = Inches(0.2)
    tf.margin_bottom = Inches(0.2)

    # Title
    p_title = tf.paragraphs[0]
    p_title.text = title
    p_title.font.name = FONT_HEADING
    p_title.font.size = Pt(14)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_PRIMARY_NAVY
    p_title.space_after = Pt(8)

    # Bullets
    for b in body_bullets:
        p = tf.add_paragraph()
        p.text = f"•  {b}"
        p.font.name = FONT_BODY
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_DARK
        p.space_after = Pt(4)

    return card

# ---------------------------------------------------------------------------
# Slide Builders
# ---------------------------------------------------------------------------

def create_presentation():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: Title Slide (Dark Executive Theme)
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    bg1 = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
    bg1.fill.solid()
    bg1.fill.fore_color.rgb = COLOR_PRIMARY_NAVY
    bg1.line.fill.background()

    # Title Card Accent
    accent = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1.0), Inches(1.2), Inches(0.15), Inches(1.8))
    accent.fill.solid()
    accent.fill.fore_color.rgb = COLOR_ACCENT_BLUE
    accent.line.fill.background()

    # Title Box
    tb1 = s1.shapes.add_textbox(Inches(1.3), Inches(1.0), Inches(10.5), Inches(2.2))
    tf1 = tb1.text_frame
    p1 = tf1.paragraphs[0]
    p1.text = "Secure Software License\nDistribution System"
    p1.font.name = FONT_HEADING
    p1.font.size = Pt(36)
    p1.font.bold = True
    p1.font.color.rgb = COLOR_WHITE

    p1_sub = tf1.add_paragraph()
    p1_sub.text = "A Cryptographically Enforced Licensing Framework Built on Ed25519, AES-256-GCM, and SHA-256"
    p1_sub.font.size = Pt(14)
    p1_sub.font.color.rgb = COLOR_ACCENT_BLUE
    p1_sub.space_before = Pt(8)

    # Team Box (4 Members)
    team_members = [
        ("Arudha Goudar", "250 | 01fe23bcs059", "Authentication & RBAC"),
        ("Harshavardhan Undodi", "258 | 01fe23bcs219", "Cryptography & Keys"),
        ("Sumit Rathod", "239 | 01fe23bcs167", "Validator & Demo Client"),
        ("Priyanka N D", "244 | 01fe23bcs184", "Web Portal & Admin UI")
    ]
    card_w = Inches(2.65)
    start_x = Inches(1.0)
    for i, (name, roll, role) in enumerate(team_members):
        box = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, start_x + (i * Inches(2.9)), Inches(4.3), card_w, Inches(1.8))
        box.fill.solid()
        box.fill.fore_color.rgb = RGBColor(26, 44, 84)
        box.line.color.rgb = COLOR_ACCENT_BLUE
        tf = box.text_frame
        tf.margin_top = Inches(0.2)
        p = tf.paragraphs[0]
        p.text = name
        p.font.bold = True
        p.font.size = Pt(13)
        p.font.color.rgb = COLOR_WHITE
        p2 = tf.add_paragraph()
        p2.text = roll
        p2.font.size = Pt(10)
        p2.font.color.rgb = RGBColor(148, 163, 184)
        p3 = tf.add_paragraph()
        p3.text = role
        p3.font.size = Pt(10)
        p3.font.bold = True
        p3.font.color.rgb = COLOR_ACCENT_BLUE
        p3.space_before = Pt(6)

    # University Footer
    tb_u = s1.shapes.add_textbox(Inches(1.0), Inches(6.4), Inches(11.333), Inches(0.5))
    pu = tb_u.text_frame.paragraphs[0]
    pu.text = "School of Computer Science & Engineering (SoCSE) | Team 07 | Course: Cryptography and Network Security"
    pu.font.size = Pt(11)
    pu.font.color.rgb = RGBColor(203, 213, 225)

    # =========================================================================
    # SLIDE 2: Abstract & Executive Summary
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    apply_header(s2, "Abstract & Executive Summary")

    add_card(s2, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "The Modern Licensing Dilemma", [
        "Software piracy, unauthorized key sharing, and binary tampering result in billions of dollars in revenue leakage annually.",
        "Traditional serial numbers and plaintext license files can be trivially copied across multiple machines or forged using reverse-engineered algorithms.",
        "Vendors lack real-time revocation capabilities: once a serial key is distributed, cancelling access for refunded or rogue clients is nearly impossible.",
        "Offline clients often have zero defense against tamper attacks if symmetric keys are embedded within the client binary."
    ])

    add_card(s2, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Our Proposed Cryptographic Solution", [
        "Centralized Asymmetric Licensing: Private signing key remains strictly isolated on the License Server. Clients hold only the public key.",
        "7-Stage Verification Pipeline: Enforces digital signature authenticity, canonical SHA-256 integrity, expiry dates, and hardware binding.",
        "Dynamic Feature Authorization: Controls granular application capabilities (Basic Editing, PDF Export, Cloud Sync, Analytics).",
        "Tamper-Evident Audit Ledger: Implements blockchain-like linear SHA-256 hash chaining to detect any unauthorized database alteration.",
        "Working Prototype: Fully implemented with FastAPI, SQLite, and an actual protected desktop client ('SecureEditor')."
    ], border_color=COLOR_ACCENT_BLUE)

    # =========================================================================
    # SLIDE 3: Problem Statement & Attack Vectors
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    apply_header(s3, "Problem Statement & Threat Landscape")

    threats = [
        ("Key Forgery & Counterfeiting", "Attacker synthesizes artificial license keys because the validation algorithm relies on symmetric secrets or weak math.", COLOR_DANGER_RED),
        ("License File Tampering", "Attacker edits a plaintext or weakly hashed config file to extend expiry dates from 30 days to 10 years or enable premium tiers.", COLOR_DANGER_RED),
        ("Unauthorized Multi-Seat Sharing", "A single legitimate license file is copied and distributed to dozens of unauthorized computers across the internet.", COLOR_DANGER_RED),
        ("Revocation Blindness", "Breached, refunded, or compromised licenses continue to function indefinitely because the software never checks status centrally.", COLOR_DANGER_RED)
    ]
    for idx, (title, desc, color) in enumerate(threats):
        row = idx // 2
        col = idx % 2
        add_card(s3, Inches(0.8 + col * 5.9), Inches(1.5 + row * 2.6), Inches(5.6), Inches(2.3), f"Attack Vector #{idx+1}: {title}", [
            desc,
            "Target: Commercial Desktop & Enterprise Software",
            "Impact: Complete loss of access control & financial fraud"
        ], border_color=color)

    # =========================================================================
    # SLIDE 4: Comprehensive Cryptographic Mapping (The Core CNS Slide)
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    apply_header(s4, "Cryptographic Primitive Architecture & Role Separation")

    # Table of Cryptographic Primitives
    rows = 7
    cols = 4
    table_shape = s4.shapes.add_table(rows, cols, Inches(0.8), Inches(1.5), Inches(11.733), Inches(5.0))
    table = table_shape.table
    table.columns[0].width = Inches(2.2)
    table.columns[1].width = Inches(2.2)
    table.columns[2].width = Inches(4.5)
    table.columns[3].width = Inches(2.833)

    headers = ["Security Goal", "Algorithm / Standard", "Specific Role in System", "Execution Boundary"]
    for i, h in enumerate(headers):
        cell = table.cell(0, i)
        cell.text = h
        cell.fill.solid()
        cell.fill.fore_color.rgb = COLOR_PRIMARY_NAVY
        p = cell.text_frame.paragraphs[0]
        p.font.bold = True
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_WHITE

    crypto_data = [
        ("Authentication", "Argon2id (Salted)", "Memory-hard password hashing (PHC Winner); GPU cracking defense", "Server-Side Only"),
        ("Session Security", "RFC 7519 HMAC-SHA256", "Stateless bearer token signing with constant-time equality checks", "Server & REST API"),
        ("Authenticity & Non-Repudiation", "Ed25519 (Curve25519)", "Asymmetric digital signatures; verifies genuine server issuance", "Server (Sign) / Client (Verify)"),
        ("Confidentiality & AEAD", "AES-256-GCM (12-byte IV)", "Encrypts proprietary feature flags & customer payloads with auth tag", "Server-Side Encryption"),
        ("Integrity Detection", "Deterministic SHA-256", "RFC 8785 Canonical JSON hashing; detects single-bit file modifications", "Server & Client Validation"),
        ("Audit Tamper-Evidence", "Linear Hash Chaining", "Prev_hash embedding ensures database logs cannot be altered unnoticed", "SQLite Database Engine")
    ]
    for row_idx, data in enumerate(crypto_data, start=1):
        for col_idx, text in enumerate(data):
            cell = table.cell(row_idx, col_idx)
            cell.text = text
            cell.fill.solid()
            cell.fill.fore_color.rgb = COLOR_WHITE if row_idx % 2 == 0 else COLOR_CARD_BG
            p = cell.text_frame.paragraphs[0]
            p.font.size = Pt(10)
            p.font.color.rgb = COLOR_TEXT_DARK
            if col_idx == 0:
                p.font.bold = True

    # =========================================================================
    # SLIDE 5: Asymmetric Key Management (Trust Boundary)
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    apply_header(s5, "Asymmetric Trust Model & Key Isolation")

    add_card(s5, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "License Server (Private Key)", [
        "Private Key Path: backend/keys/ed25519_private.pem",
        "Key Size: 256-bit Edwards-curve Digital Signature (Ed25519)",
        "Strict Security Boundary: Never distributed to users, never included in client installations, and excluded via .gitignore.",
        "Role: Signs canonical license digests and generates authentication tags.",
        "Master AES Key: Stored in aes_master.key for payload encryption."
    ], border_color=COLOR_DANGER_RED)

    add_card(s5, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Protected Client Application (Public Key)", [
        "Public Key Path: client/keys/ed25519_public.pem",
        "Key Format: Standard SubjectPublicKeyInfo (SPKI) PEM",
        "Distribution: Embedded directly within client software package.",
        "Mathematical Property: Public key can ONLY verify signatures; it is mathematically impossible to forge a valid signature using only the public key.",
        "Zero Exposure: Even if an attacker decompiles or debugs the client, they obtain only the public verification key."
    ], border_color=COLOR_SUCCESS_GREEN)

    # =========================================================================
    # SLIDE 6: 3-Tier System Architecture (Flowchart)
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    apply_header(s6, "End-to-End 3-Tier System Architecture")

    # Tier 1
    t1 = add_card(s6, Inches(0.8), Inches(1.5), Inches(3.6), Inches(5.0), "Tier 1: Presentation & Web UI", [
        "HTML5 / CSS3 / Vanilla JS",
        "User Portal (dashboard.html):",
        "  • View license status",
        "  • Self-service 30-day Trial",
        "  • Hardware activation trigger",
        "  • Direct .lic file download",
        "Admin Dashboard (admin.html):",
        "  • Central license registry",
        "  • Custom multi-tier issuance",
        "  • Immediate license revocation",
        "  • Live audit integrity checker"
    ])

    # Tier 2
    t2 = add_card(s6, Inches(4.8), Inches(1.5), Inches(3.7), Inches(5.0), "Tier 2: License Server (FastAPI)", [
        "RESTful API & Security Middleware",
        "Argon2id Authentication Service",
        "RFC 7519 Bearer Token Provider",
        "Cryptographic Engine:",
        "  • Canonical JSON serialization",
        "  • SHA-256 digest computation",
        "  • Ed25519 signature generator",
        "  • AES-256-GCM AEAD cipher",
        "SQLite Relational Engine:",
        "  • Foreign key enforcement",
        "  • Tamper-evident audit chain"
    ], border_color=COLOR_ACCENT_BLUE)

    # Tier 3
    t3 = add_card(s6, Inches(8.9), Inches(1.5), Inches(3.6), Inches(5.0), "Tier 3: Protected Client Software", [
        "Desktop Application: 'SecureEditor'",
        "Client License Validator Engine",
        "Public Verification Key Only",
        "Hardware Fingerprint Sensor:",
        "  • Platform, CPU, node, MAC",
        "  • Truncated SHA-256 digest",
        "7-Stage Security Pipeline",
        "Feature Authorization Gating:",
        "  • Basic Editing (Trial)",
        "  • PDF Export (Standard)",
        "  • Cloud Backup (Perpetual)",
        "  • Security Analytics (Enterprise)"
    ])

    # =========================================================================
    # SLIDE 7: License Generation & Signing Pipeline (Flowchart)
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    apply_header(s7, "License Generation & Cryptographic Packaging Pipeline")

    steps = [
        ("Step 1: License Request", "Admin or User submits User ID, Software Code, Tier (Trial/Standard/Perpetual), and feature list."),
        ("Step 2: Canonical Serialization", "Keys sorted alphabetically and whitespace stripped (RFC 8785) to produce deterministic bytes."),
        ("Step 3: SHA-256 Hashing", "Computes a fixed 256-bit hexadecimal digest representing the unalterable identity of the license."),
        ("Step 4: Ed25519 Signing", "Server signs canonical metadata with Private Key; outputs Base64 mathematical proof of authenticity."),
        ("Step 5: AES-256-GCM Encryption", "Generates unique 12-byte random nonce; encrypts sensitive features + 16-byte authentication tag."),
        ("Step 6: Packaging & Storage", "Stores record in SQLite licenses table, appends chained audit log, and outputs portable license.lic.")
    ]
    for idx, (stitle, sdesc) in enumerate(steps):
        row = idx // 2
        col = idx % 2
        add_card(s7, Inches(0.8 + col * 5.9), Inches(1.5 + row * 1.7), Inches(5.6), Inches(1.5), stitle, [sdesc], border_color=COLOR_ACCENT_BLUE)

    # =========================================================================
    # SLIDE 8: Structure of the Portable License File (.lic)
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    apply_header(s8, "Structured Anatomy of the Portable License File (.lic)")

    add_card(s8, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "JSON License Schema (license.lic)", [
        "\"license_id\": \"LIC-A72F-82C1\" (Unique random identifier)",
        "\"user_email\": \"testuser@licensing.local\"",
        "\"software_code\": \"SEC-EDIT-V1\"",
        "\"software_version\": \"1.0.0\"",
        "\"license_type\": \"STANDARD\" (or TRIAL / PERPETUAL)",
        "\"issue_date\": \"2026-11-17T14:43:15Z\"",
        "\"expiry_date\": \"2027-11-17T14:43:15Z\"",
        "\"device_id\": \"DEV-16F8-3A87\" (or null if unbound)",
        "\"features\": [\"basic_editing\", \"export_pdf\"]",
        "\"encrypted_payload\": \"<Base64 AES-256-GCM Ciphertext>\"",
        "\"integrity_hash\": \"<64-character SHA-256 Digest>\"",
        "\"signature\": \"<Base64 Ed25519 Digital Signature>\""
    ])

    add_card(s8, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Why This Format is Tamper-Proof", [
        "Dual Layer Defense: Even though metadata is human-readable JSON, it cannot be edited without invalidating the signature.",
        "Canonicalization: JSON key ordering differences between platforms do not affect verification.",
        "Zero Hardcoded Keys: Every license is uniquely generated and independently verifiable.",
        "Confidential Feature Flags: Sensitive proprietary tokens are encrypted inside encrypted_payload via AES-GCM.",
        "Portable Distribution: Transferred seamlessly via HTTPS REST APIs as a single downloadable file."
    ], border_color=COLOR_SUCCESS_GREEN)

    # =========================================================================
    # SLIDE 9: Client-Side 7-Stage Validation Pipeline (Flowchart)
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    apply_header(s9, "Client-Side 7-Stage Cryptographic Validation Pipeline")

    val_stages = [
        ("Stage 1: File Parsing", "Checks presence of license.lic and verifies well-formed JSON syntax."),
        ("Stage 2: Ed25519 Signature Check", "Reconstructs canonical metadata and verifies signature using public key. Mismatch = ACCESS DENIED."),
        ("Stage 3: SHA-256 Integrity Check", "Recalculates SHA-256 digest over canonical metadata and compares with integrity_hash."),
        ("Stage 4: Software Association Check", "Verifies software_code matches expected application ('SEC-EDIT-V1'). Prevents cross-app license reuse."),
        ("Stage 5: Expiration Check", "Compares UTC system timestamp against expiry_date. Expired = ACCESS DENIED."),
        ("Stage 6: Device Binding Check", "Reads local machine hardware fingerprint; compares against bound device_id. Mismatch = ACCESS DENIED."),
        ("Stage 7: Online Status Check", "Queries server to confirm license has not been REVOKED by administrator. Revoked = ACCESS DENIED.")
    ]
    for idx, (stitle, sdesc) in enumerate(val_stages):
        top_y = Inches(1.5 + (idx * 0.75))
        box = s9.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), top_y, Inches(11.733), Inches(0.65))
        box.fill.solid()
        box.fill.fore_color.rgb = COLOR_CARD_BG if idx % 2 == 0 else COLOR_WHITE
        box.line.color.rgb = COLOR_ACCENT_BLUE if idx in [1, 2, 5, 6] else COLOR_CARD_BORDER
        tf = box.text_frame
        tf.margin_top = Inches(0.1)
        p = tf.paragraphs[0]
        p.text = f"{stitle}:  {sdesc}"
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_TEXT_DARK

    # =========================================================================
    # SLIDE 10: Device Binding & Anti-Piracy Lifecycle (Crucial Workflow)
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    apply_header(s10, "Device Binding Lifecycle & Real-World Machine Fingerprinting")

    add_card(s10, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "Non-Invasive Hardware Fingerprinting", [
        "Privacy-Conscious Identification: Does not collect personal data, usernames, or telemetry.",
        "Derivation Attributes: Combines OS Platform, Network Node Name, CPU Machine Architecture, and Hardware MAC.",
        "Cryptographic Digest: Passes raw attributes through SHA-256 to create a one-way deterministic hash.",
        "User-Friendly Encoding: Formatted as an 8-character hex token (e.g., 'DEV-16F8-3A87').",
        "Deterministic Matching: Always resolves to the exact same identifier on the same physical machine."
    ])

    add_card(s10, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Real-World Activation & Re-Signing Workflow", [
        "Phase 1 (Purchase/Issuance): Admin issues license with device_id = null (unbound) because hardware is not yet known.",
        "Phase 2 (First Launch / Activation): Software sends local fingerprint to POST /licenses/{id}/activate.",
        "Phase 3 (Server Cryptographic Re-Signing): Server binds device ID, recomputes SHA-256 hash, and generates a NEW Ed25519 signature.",
        "Phase 4 (Execution on Machine A): Hardware matches → ACCESS GRANTED.",
        "Phase 5 (Illegitimate Copy to Machine B): Digital signature is authentic, but hardware fingerprint fails → ACCESS DENIED (DEVICE_MISMATCH)."
    ], border_color=COLOR_ACCENT_BLUE)

    # =========================================================================
    # SLIDE 11: Tamper-Evident Cryptographic Audit Logging (Blockchain Chaining)
    # =========================================================================
    s11 = prs.slides.add_slide(blank_layout)
    apply_header(s11, "Tamper-Evident Security Audit Ledger (SHA-256 Hash Chaining)")

    add_card(s11, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "Linear Cryptographic Chaining", [
        "Forensic Accountability: Every critical event (Registration, Login, License Generation, Activation, Revocation) is permanently recorded.",
        "Chain Math: Each log row embeds the hash of its predecessor:",
        "  Entry Hash = SHA-256(prev_hash || timestamp || event || result || details)",
        "Genesis Block: Row #1 binds to 64 zeroes ('0000...0000').",
        "Forward Dependency: Modifying any historical row breaks the cryptographic chain for all subsequent entries."
    ])

    add_card(s11, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Integrity Auditing & Viva Proof", [
        "Audit Traversal Algorithm: verify_audit_log_integrity() walks from Row 1 to N, recalculating all digests.",
        "Admin Dashboard Integration: One-click '🛡️ Verify Chain Integrity' button gives real-time visual proof to examiners.",
        "Tested Tamper Detection: Our automated test (test_tamper_detection_in_audit_logs) deliberately edits a database record via SQL and proves the system immediately catches tampering.",
        "Mitigates Rogue Admin Attacks: Even if an attacker gains direct SQLite access, they cannot forge historical logs without detection."
    ], border_color=COLOR_SUCCESS_GREEN)

    # =========================================================================
    # SLIDE 12: Role-Based Access Control (RBAC) Architecture
    # =========================================================================
    s12 = prs.slides.add_slide(blank_layout)
    apply_header(s12, "Role-Based Access Control & Privilege Boundary Enforcement")

    add_card(s12, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "Standard User Role ('USER')", [
        "Credential Security: Salted Argon2id hashing.",
        "Self-Service Capability: Authorized ONLY to request a 30-Day TRIAL license for software evaluation.",
        "Strict Restriction: Cannot self-issue paid Standard or Perpetual licenses (enforced via HTTP 403 Forbidden).",
        "License Management: View own licenses, download signed .lic packages, and activate on physical machine.",
        "Protected App Access: Operates with basic feature set (Basic Editing, PDF Export)."
    ])

    add_card(s12, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Administrator Role ('ADMIN')", [
        "Elevated Privileges: Governed by FastAPI require_admin dependency guard.",
        "Commercial License Provisioning: Sole authority to issue 1-Year Standard and Perpetual commercial licenses.",
        "Granular Feature Allocation: Ability to enable Enterprise modules (Cloud Sync, Advanced Analytics).",
        "Hardware Pre-Binding: Optional ability to pre-bind licenses to corporate hardware.",
        "Immediate Revocation: Instant license revocation override.",
        "Security Oversight: Complete visibility of system stats and the cryptographic audit trail."
    ], border_color=COLOR_ACCENT_INDIGO)

    # =========================================================================
    # SLIDE 13: Protected Demo Client: 'SecureEditor'
    # =========================================================================
    s13 = prs.slides.add_slide(blank_layout)
    apply_header(s13, "Protected Demo Client Application ('SecureEditor')")

    add_card(s13, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "Core Functional Proof", [
        "Practical Demonstration: Proves that the licensing engine actually enforces access control on real desktop software.",
        "Pre-Execution Gating: Application cannot boot without passing all 7 validation stages.",
        "Diagnostic Error Reporting: Explicitly displays reason for rejection (FILE_NOT_FOUND, INVALID_SIGNATURE, LICENSE_EXPIRED, DEVICE_MISMATCH, REVOKED).",
        "Zero Private Key Presence: Relies 100% on public-key cryptography."
    ])

    add_card(s13, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Dynamic Feature Licensing Demonstration", [
        "Basic Document Editing: Unlocked for Trial & Standard tiers.",
        "Document Export to PDF/Text: Unlocked for Standard & Perpetual tiers.",
        "Encrypted Cloud Vault Backup: Gated; requires Perpetual tier (locked in Trial/Standard).",
        "Security & Readability Analytics: Gated; requires Enterprise tier.",
        "Viva Value: Demonstrates both Authentication (valid user) and Authorization (feature permissions) in real time."
    ], border_color=COLOR_ACCENT_BLUE)

    # =========================================================================
    # SLIDE 14: Comprehensive Security Testing Matrix
    # =========================================================================
    s14 = prs.slides.add_slide(blank_layout)
    apply_header(s14, "Security Test Plan & Empirical Verification Results")

    test_table_shape = s14.shapes.add_table(8, 4, Inches(0.8), Inches(1.5), Inches(11.733), Inches(5.0))
    ttable = test_table_shape.table
    ttable.columns[0].width = Inches(2.2)
    ttable.columns[1].width = Inches(3.8)
    ttable.columns[2].width = Inches(3.2)
    ttable.columns[3].width = Inches(2.533)

    theaders = ["Test Scenario", "Simulated Attack Action", "Expected Cryptographic Result", "Observed Outcome"]
    for i, h in enumerate(theaders):
        cell = ttable.cell(0, i)
        cell.text = h
        cell.fill.solid()
        cell.fill.fore_color.rgb = COLOR_PRIMARY_NAVY
        p = cell.text_frame.paragraphs[0]
        p.font.bold = True
        p.font.size = Pt(11)
        p.font.color.rgb = COLOR_WHITE

    test_rows = [
        ("Legitimate License", "Run SecureEditor with authentic license.lic", "Ed25519 signature & hash valid", "ACCESS GRANTED (100% Pass)"),
        ("License Tampering", "Attacker modifies user_email in license.lic", "Ed25519 signature mismatch", "ACCESS DENIED (INVALID_SIGNATURE)"),
        ("Date Tampering", "Attacker extends expiry_date to year 2099", "Canonical hash & signature fail", "ACCESS DENIED (INVALID_SIGNATURE)"),
        ("License Expiration", "Software run after expiration timestamp", "Expiry validation failure", "ACCESS DENIED (LICENSE_EXPIRED)"),
        ("Multi-Device Piracy", "License copied to Machine B (unauthorized)", "Hardware fingerprint mismatch", "ACCESS DENIED (DEVICE_MISMATCH)"),
        ("Revocation Enforcement", "Admin revokes license on dashboard", "Online server status check fails", "ACCESS DENIED (REVOKED)"),
        ("Audit Tampering", "Attacker modifies audit log directly in SQL", "Linear hash chain broken", "TAMPER DETECTED (Alert Raised)")
    ]
    for row_idx, data in enumerate(test_rows, start=1):
        for col_idx, text in enumerate(data):
            cell = ttable.cell(row_idx, col_idx)
            cell.text = text
            cell.fill.solid()
            cell.fill.fore_color.rgb = COLOR_WHITE if row_idx % 2 == 0 else COLOR_CARD_BG
            p = cell.text_frame.paragraphs[0]
            p.font.size = Pt(10)
            p.font.color.rgb = COLOR_TEXT_DARK
            if col_idx == 3:
                p.font.bold = True
                p.font.color.rgb = COLOR_SUCCESS_GREEN if "GRANTED" in text or "Pass" in text or "TAMPER" in text else COLOR_DANGER_RED

    # =========================================================================
    # SLIDE 15: Team Division & Viva Demonstration Runbook
    # =========================================================================
    s15 = prs.slides.add_slide(blank_layout)
    apply_header(s15, "Team 07 Project Division & Rehearsal Flow")

    team_roles = [
        ("Arudha Goudar", "01fe23bcs059", "Authentication & User Backend", [
            "Argon2id password hashing implementation",
            "RFC 7519 HMAC-SHA256 Token Provider",
            "Role-Based Access Control dependencies",
            "Demonstrates: User Login & 403 Forbidden RBAC"
        ]),
        ("Harshavardhan Undodi", "01fe23bcs219", "Cryptography & Keys Engine", [
            "Ed25519 Asymmetric Keypair lifecycle",
            "AES-256-GCM AEAD encryption service",
            "Deterministic SHA-256 canonical hashing",
            "Demonstrates: Live License Tampering Attack"
        ]),
        ("Sumit Rathod", "01fe23bcs167", "Validator & Demo Client", [
            "Client-Side 7-stage validation engine",
            "Protected 'SecureEditor' application",
            "Privacy-conscious hardware fingerprinting",
            "Demonstrates: Software Execution & Device Mismatch"
        ]),
        ("Priyanka N D", "01fe23bcs184", "Web UI & Admin Dashboard", [
            "Responsive Web Interface (HTML5/CSS3/JS)",
            "Central License Registry & 1-Click Download",
            "Immediate administrative revocation",
            "Demonstrates: Revocation & Audit Chain Integrity"
        ])
    ]
    for idx, (m_name, m_roll, m_title, m_tasks) in enumerate(team_roles):
        row = idx // 2
        col = idx % 2
        add_card(s15, Inches(0.8 + col * 5.9), Inches(1.5 + row * 2.6), Inches(5.6), Inches(2.35), f"{m_name} ({m_roll})", [
            f"Focus: {m_title}"
        ] + m_tasks[:3], border_color=COLOR_ACCENT_BLUE)

    # =========================================================================
    # SLIDE 16: Security Threat Model & Defense Synthesis
    # =========================================================================
    s16 = prs.slides.add_slide(blank_layout)
    apply_header(s16, "Security Threat Model & Defense Synthesis")

    add_card(s16, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "Guaranteed Protections", [
        "Cryptographic Integrity: Mathematical impossibility of modifying license parameters without detection.",
        "Asymmetric Authenticity: Eliminates key forgery attacks by locking private keys to the vendor server.",
        "Anti-Piracy Device Binding: Eliminates casual multi-machine license copying.",
        "Centralized Revocation: Restricts rogue or refunded clients from ongoing authorization.",
        "Timing Attack Immunity: Constant-time comparison prevents side-channel signature harvesting."
    ], border_color=COLOR_SUCCESS_GREEN)

    add_card(s16, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Inherent Limitations & Trade-Offs", [
        "Air-Gapped Revocation Delay: A 100% offline machine cannot detect immediate administrative revocation until network synchronization occurs.",
        "Hardware Virtualization: Advanced attackers operating inside hypervisors could theoretically spoof hardware identifiers.",
        "Binary Patching (DRM Boundary): Without dedicated hardware security modules (TPMs) or code obfuscation, client binaries can be disassembled (standard commercial limitation).",
        "Clock Rollback Attacks: Mitigated by storing last-known-execution timestamps or requiring periodic online sync."
    ], border_color=COLOR_CARD_BORDER)

    # =========================================================================
    # SLIDE 17: Conclusion & References
    # =========================================================================
    s17 = prs.slides.add_slide(blank_layout)
    apply_header(s17, "Conclusion & Standards References")

    add_card(s17, Inches(0.8), Inches(1.5), Inches(5.6), Inches(5.0), "Project Conclusion", [
        "Successfully developed and verified a robust, production-grade Software License Distribution prototype.",
        "Integrated 6 major cryptographic primitives adhering strictly to modern CNS principles.",
        "Implemented a demonstrable client application proving that license enforcement directly gates software capabilities.",
        "Achieved 100% pass rate across 48 automated security and unit tests.",
        "Delivers an airtight, easily demonstrable capstone project ready for university evaluation."
    ], border_color=COLOR_ACCENT_BLUE)

    add_card(s17, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.0), "Academic & Cryptographic References", [
        "William Stallings, 'Cryptography and Network Security: Principles and Practice', 8th Edition, Pearson.",
        "RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA / Ed25519).",
        "NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM).",
        "RFC 7519: JSON Web Token (JWT) Standard.",
        "RFC 8785: JSON Canonicalization Scheme (JCS).",
        "OWASP Application Security Verification Standard (ASVS) v4.0."
    ])

    # =========================================================================
    # SLIDE 18: Thank You / Viva Q&A
    # =========================================================================
    s18 = prs.slides.add_slide(blank_layout)
    bg18 = s18.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
    bg18.fill.solid()
    bg18.fill.fore_color.rgb = COLOR_PRIMARY_NAVY
    bg18.line.fill.background()

    tb18 = s18.shapes.add_textbox(Inches(1.5), Inches(2.2), Inches(10.333), Inches(3.0))
    tf18 = tb18.text_frame
    p18 = tf18.paragraphs[0]
    p18.text = "Thank You!"
    p18.font.name = FONT_HEADING
    p18.font.size = Pt(44)
    p18.font.bold = True
    p18.font.color.rgb = COLOR_WHITE
    p18.alignment = PP_ALIGN.CENTER

    p18_sub = tf18.add_paragraph()
    p18_sub.text = "Secure Software License Distribution System\nQuestions & Viva Discussion"
    p18_sub.font.size = Pt(20)
    p18_sub.font.color.rgb = COLOR_ACCENT_BLUE
    p18_sub.alignment = PP_ALIGN.CENTER
    p18_sub.space_before = Pt(14)

    p18_team = tf18.add_paragraph()
    p18_team.text = "Presented by Team 07 (SoCSE): Arudha Goudar | Harshavardhan Undodi | Sumit Rathod | Priyanka N D"
    p18_team.font.size = Pt(13)
    p18_team.font.color.rgb = RGBColor(148, 163, 184)
    p18_team.alignment = PP_ALIGN.CENTER
    p18_team.space_before = Pt(20)

    # Save presentation
    output_path = "Secure_License_System_Presentation.pptx"
    prs.save(output_path)
    print(f"Presentation generated successfully: {output_path}")

if __name__ == "__main__":
    create_presentation()
