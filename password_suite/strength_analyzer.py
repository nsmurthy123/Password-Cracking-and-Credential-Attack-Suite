# ============================================================
# strength_analyzer.py — Password Strength Analyzer
# Entropy, complexity, pattern detection, scoring
# For educational and authorised use ONLY
# ============================================================
 
import math
import re
import os
from config import (
    STRENGTH_FILE,
    ENTROPY_CRITICAL, ENTROPY_VERY_WEAK, ENTROPY_WEAK,
    ENTROPY_MODERATE, ENTROPY_STRONG,
)
 
# Top 20 most common passwords — fast dictionary check
COMMON_PASSWORDS = {
    "123456","password","123456789","12345678","12345",
    "1234567","qwerty","abc123","111111","123123",
    "admin","letmein","welcome","monkey","dragon",
    "master","login","passw0rd","password1","iloveyou",
}
 
 
def calculate_entropy(password):
    """
    Calculate password entropy in bits.
    Formula: entropy = log2(charset_size ^ length)
 
    A higher value means harder to brute-force.
    Target: >= 60 bits for good security.
    """
    charset_size = 0
    if re.search(r"[a-z]", password): charset_size += 26
    if re.search(r"[A-Z]", password): charset_size += 26
    if re.search(r"[0-9]", password): charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset_size += 32
 
    if charset_size == 0:
        return 0.0
 
    entropy = math.log2(charset_size ** len(password))
    return round(entropy, 2)
 
 
def check_complexity(password):
    """
    Check which complexity requirements the password meets.
    Returns a dict of requirement → True/False.
    """
    return {
        "length_8":   len(password) >= 8,
        "length_12":  len(password) >= 12,
        "length_16":  len(password) >= 16,
        "has_lower":  bool(re.search(r"[a-z]", password)),
        "has_upper":  bool(re.search(r"[A-Z]", password)),
        "has_digit":  bool(re.search(r"[0-9]", password)),
        "has_symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }
 
 
def detect_patterns(password):
    """
    Detect weak patterns that reduce effective security.
    Returns list of detected pattern names.
    """
    patterns_found = []
    lower = password.lower()
 
    # Keyboard walks
    walks = ["qwerty","qwert","asdfg","asdf","zxcvb","zxcv",
             "12345","23456","34567","98765","09876"]
    for walk in walks:
        if walk in lower:
            patterns_found.append(f"keyboard-walk: {walk}")
 
    # Year patterns (1900–2099)
    if re.search(r"(19|20)\d{2}", password):
        patterns_found.append("contains-year")
 
    # Repeated characters (3+)
    if re.search(r"(.)\1{2,}", password):
        patterns_found.append("repeated-chars")
 
    # All digits
    if password.isdigit():
        patterns_found.append("all-digits")
 
    # All letters
    if password.isalpha():
        patterns_found.append("all-letters")
 
    # Starts/ends with digit cluster
    if re.match(r"^\d+", password) or re.search(r"\d+$", password):
        patterns_found.append("digit-prefix-or-suffix")
 
    # Common words at start
    for word in ["pass","password","admin","user","login","welcome"]:
        if lower.startswith(word):
            patterns_found.append(f"starts-with-common: {word}")
            break
 
    return patterns_found
 
 
def calculate_score(password):
    """
    Calculate overall strength score 0–100.
    Combines entropy, complexity, patterns, length bonuses.
    """
    score = 0
 
    # Length scoring
    length = len(password)
    if length >= 6:  score += 10
    if length >= 8:  score += 10
    if length >= 10: score += 5
    if length >= 12: score += 10
    if length >= 16: score += 5
 
    # Complexity scoring
    comp = check_complexity(password)
    if comp["has_lower"]:  score += 10
    if comp["has_upper"]:  score += 10
    if comp["has_digit"]:  score += 10
    if comp["has_symbol"]: score += 15
 
    # Entropy bonus
    entropy = calculate_entropy(password)
    if entropy >= 40: score += 5
    if entropy >= 60: score += 10
    if entropy >= 80: score += 5
 
    # Pattern penalties
    patterns = detect_patterns(password)
    score -= len(patterns) * 5
 
    # Common password penalty
    if password.lower() in COMMON_PASSWORDS:
        score -= 40
 
    # Very short penalty
    if length < 6:
        score -= 20
 
    return max(0, min(score, 100))
 
 
def get_label(score):
    """Return severity label for a given score."""
    if score < 20: return "CRITICAL"
    if score < 40: return "VERY WEAK"
    if score < 55: return "WEAK"
    if score < 70: return "MODERATE"
    if score < 85: return "STRONG"
    return "VERY STRONG"
 
 
def get_recommendations(password):
    """Return actionable improvement tips based on weaknesses."""
    tips = []
    comp = check_complexity(password)
    if len(password) < 12:
        tips.append("Increase length to at least 12 characters")
    if not comp["has_upper"]:
        tips.append("Add uppercase letters (A–Z)")
    if not comp["has_digit"]:
        tips.append("Add at least one digit (0–9)")
    if not comp["has_symbol"]:
        tips.append("Add a symbol (!@#$%^&*)")
    if password.lower() in COMMON_PASSWORDS:
        tips.append("This password is in common breach lists — change it immediately")
    patterns = detect_patterns(password)
    if patterns:
        tips.append(f"Avoid patterns: {", ".join(patterns)}")
    if not tips:
        tips.append("Password meets all recommendations")
    return tips
 
 
def analyze_password(password, verbose=True):
    """
    Run full analysis on a single password.
    Returns dict with all metrics.
    """
    entropy  = calculate_entropy(password)
    comp     = check_complexity(password)
    patterns = detect_patterns(password)
    score    = calculate_score(password)
    label    = get_label(score)
    tips     = get_recommendations(password)
 
    result = {
        "password": password,
        "length":   len(password),
        "entropy":  entropy,
        "score":    score,
        "label":    label,
        "complexity": comp,
        "patterns": patterns,
        "tips":     tips,
    }
 
    if verbose:
        print(f"  Password   : {password}")
        print(f"  Length     : {len(password)} chars")
        print(f"  Entropy    : {entropy} bits")
        print(f"  Score      : {score}/100")
        print(f"  Label      : {label}")
        print(f"  Uppercase  : {comp['has_upper']}")
        print(f"  Digits     : {comp['has_digit']}")
        print(f"  Symbols    : {comp['has_symbol']}")
        if patterns:
            print(f"  Patterns   : {patterns}")
        print(f"  Tips       :")
        for tip in tips:
            print(f"    → {tip}")
        print()
 
    return result
 
 
def analyze_list(passwords, output_file=None, verbose=True):
    """Analyze a list of passwords and save strength report."""
    if output_file is None:
        output_file = STRENGTH_FILE
 
    print(f"[*] Analyzing {len(passwords)} passwords...\n")
    print("=" * 60)
 
    results = []
    for pw in passwords:
        results.append(analyze_password(pw, verbose=verbose))
 
    # Summary
    print("=" * 60)
    labels = [r["label"] for r in results]
    from collections import Counter
    counts = Counter(labels)
    print("[+] STRENGTH DISTRIBUTION:")
    for label in ["CRITICAL","VERY WEAK","WEAK","MODERATE","STRONG","VERY STRONG"]:
        if label in counts:
            print(f"    {label:12} : {counts[label]}")
 
    avg_score = sum(r["score"] for r in results) / len(results)
    print(f"[+] Average score: {avg_score:.1f}/100")
 
    # Save to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("PASSWORD|ENTROPY|SCORE|LABEL|TIPS\n")
        for r in results:
            tips_str = " | ".join(r["tips"])
            f.write(f"{r['password']}|{r['entropy']}|{r['score']}|{r['label']}|{tips_str}\n")
 
    print(f"[+] Strength report saved: {output_file}")
    return results
 
 
# ── Run directly for testing ──────────────────────────────────
if __name__ == "__main__":
    test_passwords = [
        "123456",
        "password",
        "hello123",
        "John1990",
        "P@ssw0rd!",
        "T#9kLmW!2xQr",
        "correct-horse-battery-staple",
    ]
    analyze_list(test_passwords, verbose=True)
