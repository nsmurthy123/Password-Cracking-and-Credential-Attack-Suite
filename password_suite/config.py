# ============================================================
# config.py — Global Configuration for Password Cracking Suite
# Unified Mentor Cybersecurity Project
# For educational and authorised use ONLY
# ============================================================
 
import os
 
# ── Folder paths ──────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
WORDLIST_FILE = os.path.join(BASE_DIR, "wordlist.txt")
HASHES_FILE   = os.path.join(BASE_DIR, "hashes.txt")
RESULTS_FILE  = os.path.join(BASE_DIR, "crack_results.txt")
STRENGTH_FILE = os.path.join(BASE_DIR, "strength_report.txt")
REPORT_FILE   = os.path.join(BASE_DIR, "audit_report.txt")
 
# ── Brute-force settings ──────────────────────────────────────
CHARSET_LOWER   = "abcdefghijklmnopqrstuvwxyz"
CHARSET_UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CHARSET_DIGITS  = "0123456789"
CHARSET_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
 
# Default charset for brute force (change as needed)
CHARSET_DEFAULT = CHARSET_LOWER + CHARSET_DIGITS
 
# Maximum password length to try in brute-force mode
MAX_BF_LENGTH = 6
 
# ── Dictionary attack settings ───────────────────────────────
HASH_TYPE = "md5"   # Options: "md5", "sha1", "sha256", "sha512"
 
# ── Password strength thresholds ─────────────────────────────
ENTROPY_CRITICAL  = 20   # bits — CRITICAL: cracked instantly
ENTROPY_VERY_WEAK = 40   # bits — VERY WEAK: cracked in seconds
ENTROPY_WEAK      = 55   # bits — WEAK: cracked in minutes
ENTROPY_MODERATE  = 70   # bits — MODERATE: hours to crack
ENTROPY_STRONG    = 85   # bits — STRONG: very hard
# > 85 bits = VERY STRONG
 
# ── Demo shadow file entries (for hash_extract.py demo) ──────
# Format: username:hash_type:plain_password
DEMO_ACCOUNTS = [
    ("bhuvanesh",   "md5",    "hello123"),
    ("sam",     "md5",    "password"),
    ("ruth", "sha256", "qwerty2024"),
    ("lucy",   "sha256", "P@ssw0rd!"),
    ("meowth",     "sha512", "Tr0ub4dor&3"),
    ("frank",   "bcrypt", "sam@123"),
]
 
# ── Mutation rules toggle ─────────────────────────────────────
RULES = {
    "original":       True,
    "capitalize":     True,
    "uppercase":      True,
    "lowercase":      True,
    "reverse":        True,
    "leet_speak":     True,
    "append_numbers": True,
    "append_symbols": True,
    "prepend_numbers":True,
}
 
# ── Common suffixes to append in mutation ────────────────────
COMMON_SUFFIXES = [
    "1","2","123","1234","12345","2023","2024",
    "!","@","#","!@#","@123","#1","01","99","007",
]
 
print("[config] Configuration loaded successfully.")
