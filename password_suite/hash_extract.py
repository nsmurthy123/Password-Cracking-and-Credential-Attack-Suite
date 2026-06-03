# ============================================================
# hash_extract.py — Password Hash Extractor & Identifier
# Simulates reading from Linux shadow / Windows SAM
# Creates demo hashes.txt for cracking simulation
# For educational and authorised use ONLY
# ============================================================
 
import hashlib
import os
import sys
from config import HASHES_FILE, DEMO_ACCOUNTS
 
# Try to import passlib for bcrypt support
try:
    from passlib.hash import bcrypt as bcrypt_hash
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("[!] passlib not installed. bcrypt hashing disabled.")
    print("[!] Run: pip install passlib")
 
 
def hash_password(password, algorithm):
    """
    Hash a password using the specified algorithm.
 
    Args:
        password  : plain-text password string
        algorithm : "md5", "sha1", "sha256", "sha512", "bcrypt"
 
    Returns:
        hex digest string (or bcrypt hash string)
    """
    algorithm = algorithm.lower()
 
    if algorithm == "md5":
        return hashlib.md5(password.encode("utf-8")).hexdigest()
 
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode("utf-8")).hexdigest()
 
    elif algorithm == "sha256":
        return hashlib.sha256(password.encode("utf-8")).hexdigest()
 
    elif algorithm == "sha512":
        return hashlib.sha512(password.encode("utf-8")).hexdigest()
 
    elif algorithm == "bcrypt":
        if BCRYPT_AVAILABLE:
            return bcrypt_hash.using(rounds=12).hash(password)
        else:
            # Fall back to SHA-256 if bcrypt not available
            print("[!] bcrypt unavailable — using sha256 instead")
            return hashlib.sha256(password.encode("utf-8")).hexdigest()
 
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
 
 
def identify_hash(hash_string):
    """
    Identify the likely algorithm from hash characteristics.
 
    Returns a string describing the likely hash type.
    """
    length = len(hash_string)
 
    if hash_string.startswith("$2y$") or hash_string.startswith("$2b$"):
        return "bcrypt (cost 12) — STRONG"
    elif hash_string.startswith("$6$"):
        return "SHA-512crypt (Linux shadow) — Moderate"
    elif hash_string.startswith("$5$"):
        return "SHA-256crypt (Linux shadow) — Moderate"
    elif hash_string.startswith("$1$"):
        return "MD5crypt (Linux shadow) — WEAK"
    elif length == 32:
        return "MD5 (32 hex chars) — CRITICAL"
    elif length == 40:
        return "SHA-1 (40 hex chars) — WEAK"
    elif length == 64:
        return "SHA-256 (64 hex chars) — Moderate"
    elif length == 128:
        return "SHA-512 (128 hex chars) — Moderate"
    else:
        return f"Unknown — length {length}"
 
 
def create_demo_hash_file(output_file=None, verbose=True):
    """
    Create a demo hashes.txt file from DEMO_ACCOUNTS in config.py.
    Format: username:algorithm:hash
 
    This simulates what you would extract from /etc/shadow.
    In a real authorised test, you would use:
        sudo cat /etc/shadow > shadow_copy.txt
    """
    if output_file is None:
        output_file = HASHES_FILE
 
    records = []
    if verbose:
        print("[*] Creating demo hash file...")
        print(f"[*] Hashing {len(DEMO_ACCOUNTS)} demo accounts\n")
 
    for username, algorithm, plaintext in DEMO_ACCOUNTS:
        hashed = hash_password(plaintext, algorithm)
        identified = identify_hash(hashed)
        record = f"{username}:{algorithm}:{hashed}"
        records.append(record)
 
        if verbose:
            print(f"  User      : {username}")
            print(f"  Algorithm : {algorithm.upper()}")
            print(f"  Hash      : {hashed[:40]}...")
            print(f"  Identified: {identified}")
            print()
 
    # Write to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(records))
 
    if verbose:
        print(f"[+] Hash file saved: {output_file}")
        print(f"[+] Total records: {len(records)}")
 
    return records
 
 
def load_hashes(filepath=None):
    """
    Load hashes from file.
    Returns list of (username, algorithm, hash) tuples.
    """
    if filepath is None:
        filepath = HASHES_FILE
 
    if not os.path.exists(filepath):
        print(f"[-] Hash file not found: {filepath}")
        print("[-] Run create_demo_hash_file() first.")
        return []
 
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(":", 2)
            if len(parts) == 3:
                records.append(tuple(parts))
 
    print(f"[+] Loaded {len(records)} hash records from {filepath}")
    return records
 
 
# ── Run directly for testing ──────────────────────────────────
if __name__ == "__main__":
    # Step 1: Create the demo hash file
    records = create_demo_hash_file(verbose=True)
 
    # Step 2: Load it back and verify
    print("\n[*] Verifying loaded hashes:")
    loaded = load_hashes()
    for username, algo, h in loaded:
        print(f"  {username:10} | {algo:8} | {h[:30]}...")
 
    # Step 3: Show hash identification for each
    print("\n[*] Hash type identification summary:")
    for username, algo, h in loaded:
        ident = identify_hash(h)
        print(f"  {username:10} → {ident}")
