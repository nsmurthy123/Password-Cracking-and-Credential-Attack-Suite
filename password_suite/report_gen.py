# ============================================================
# report_gen.py — Security Audit Report Generator
# Compiles crack results and strength analysis into report
# For educational and authorised use ONLY
# ============================================================
 
import os
from datetime import datetime
from collections import Counter
from config import RESULTS_FILE, STRENGTH_FILE, REPORT_FILE
 
 
def load_crack_results(filepath=None):
    """Load crack_results.txt into list of dicts."""
    if filepath is None:
        filepath = RESULTS_FILE
    if not os.path.exists(filepath):
        print(f"[-] Results file not found: {filepath}")
        return []
 
    results = []
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
 
    # Skip header line
    for line in lines[1:]:
        parts = line.strip().split("|")
        if len(parts) >= 7:
            results.append({
                "username":  parts[0],
                "algorithm": parts[1],
                "cracked":   parts[2].lower() == "true",
                "password":  parts[3],
                "attempts":  int(parts[4]) if parts[4].isdigit() else 0,
                "time":      float(parts[5]) if parts[5] else 0,
                "method":    parts[6],
            })
    return results
 
 
def load_strength_results(filepath=None):
    """Load strength_report.txt into list of dicts."""
    if filepath is None:
        filepath = STRENGTH_FILE
    if not os.path.exists(filepath):
        print(f"[-] Strength file not found: {filepath}")
        return []
 
    results = []
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
 
    for line in lines[1:]:
        parts = line.strip().split("|")
        if len(parts) >= 4:
            results.append({
                "password": parts[0],
                "entropy":  float(parts[1]) if parts[1] else 0,
                "score":    int(parts[2]) if parts[2].isdigit() else 0,
                "label":    parts[3],
                "tips":     parts[4] if len(parts) > 4 else "",
            })
    return results
 
 
def generate_report(crack_results=None, strength_results=None,
                    output_file=None, verbose=True):
    """
    Generate the complete security audit report.
 
    Args:
        crack_results    : list from load_crack_results()
        strength_results : list from load_strength_results()
        output_file      : path to save the report
        verbose          : print report to terminal also
    """
    if crack_results    is None: crack_results    = load_crack_results()
    if strength_results is None: strength_results = load_strength_results()
    if output_file      is None: output_file      = REPORT_FILE
 
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    lines = []
 
    def w(text=""):
        lines.append(text)
        if verbose:
            print(text)
 
    # ── HEADER ───────────────────────────────────────────────
    w("=" * 65)
    w("  PASSWORD SECURITY AUDIT REPORT")
    w(f"  Generated : {now}")
    w("  Project   : Password Cracking & Credential Attack Suite")
    w("  Purpose   : Educational / Authorised Penetration Test")
    w("=" * 65)
    w()
 
    # ── EXECUTIVE SUMMARY ────────────────────────────────────
    w("SECTION 1 — EXECUTIVE SUMMARY")
    w("-" * 65)
 
    total   = len(crack_results)
    cracked = sum(1 for r in crack_results if r["cracked"])
    skipped = sum(1 for r in crack_results if r["method"] == "skipped-bcrypt")
    pct     = int(100 * cracked / total) if total else 0
 
    w(f"  Total accounts tested  : {total}")
    w(f"  Passwords cracked      : {cracked}  ({pct}%)")
    w(f"  Skipped (bcrypt/strong): {skipped}")
    w(f"  Resistant accounts     : {total - cracked - skipped}")
    w()
 
    if cracked > 0:
        cracked_times = [r["time"] for r in crack_results if r["cracked"]]
        avg_time = sum(cracked_times) / len(cracked_times)
        w(f"  Avg crack time         : {avg_time:.4f}s")
        w(f"  Fastest crack          : {min(cracked_times):.4f}s")
        w(f"  Slowest crack          : {max(cracked_times):.4f}s")
    w()
 
    # ── CRACKING RESULTS ─────────────────────────────────────
    w("SECTION 2 — CRACKING SIMULATION RESULTS")
    w("-" * 65)
    w(f"  {'USERNAME':<12} {'ALGORITHM':<10} {'RESULT':<10} {'TIME':<10} {'METHOD'}")
    w("  " + "-" * 60)
 
    for r in crack_results:
        result_str = f"CRACKED ({r['password']})" if r["cracked"] else "RESISTANT"
        w(f"  {r['username']:<12} {r['algorithm'].upper():<10} {result_str:<30} {str(r['time']):<10} {r['method']}")
    w()
 
    # ── HASH ALGORITHM AUDIT ─────────────────────────────────
    w("SECTION 3 — HASH ALGORITHM AUDIT")
    w("-" * 65)
 
    algo_counts = Counter(r["algorithm"] for r in crack_results)
    risk_map = {
        "md5":    "CRITICAL — cracked in seconds, never use for passwords",
        "sha1":   "HIGH     — deprecated, vulnerable to collision attacks",
        "sha256": "MODERATE — not designed for passwords, use bcrypt instead",
        "sha512": "MODERATE — better but still faster than bcrypt",
        "bcrypt": "STRONG   — slow by design, recommended",
        "argon2": "BEST     — memory-hard, strongest available",
    }
    for algo, count in algo_counts.items():
        risk = risk_map.get(algo.lower(), "Unknown")
        w(f"  {algo.upper():<10} : {count} account(s) — {risk}")
    w()
 
    # ── STRENGTH ANALYSIS SUMMARY ────────────────────────────
    if strength_results:
        w("SECTION 4 — PASSWORD STRENGTH ANALYSIS")
        w("-" * 65)
 
        label_counts = Counter(r["label"] for r in strength_results)
        avg_score = sum(r["score"] for r in strength_results) / len(strength_results)
        avg_entropy = sum(r["entropy"] for r in strength_results) / len(strength_results)
 
        w(f"  Passwords analyzed  : {len(strength_results)}")
        w(f"  Average score       : {avg_score:.1f} / 100")
        w(f"  Average entropy     : {avg_entropy:.1f} bits")
        w()
        w("  Strength Distribution:")
        for label in ["CRITICAL","VERY WEAK","WEAK","MODERATE","STRONG","VERY STRONG"]:
            count = label_counts.get(label, 0)
            bar   = "#" * count
            w(f"    {label:<12} : {count:>3}  {bar}")
        w()
 
    # ── RECOMMENDATIONS ──────────────────────────────────────
    w("SECTION 5 — RECOMMENDATIONS & MITIGATION STEPS")
    w("-" * 65)
    w("  CRITICAL — Immediate Action Required:")
    w("  1. Migrate ALL MD5/SHA-1 password hashes to bcrypt (cost 12)")
    w("     or Argon2id immediately.")
    w("  2. Force password reset for all cracked accounts.")
    w("  3. Enable Multi-Factor Authentication (MFA) for all users.")
    w()
    w("  HIGH — Complete Within 30 Days:")
    w("  4. Enforce minimum password policy:")
    w("       - Minimum 12 characters")
    w("       - Must contain: uppercase + lowercase + digit + symbol")
    w("       - Cannot match any of last 5 passwords")
    w("  5. Block passwords found in breach databases (HaveIBeenPwned API)")
    w("  6. Implement account lockout: 5 attempts → 15-minute lockout")
    w()
    w("  MEDIUM — Complete Within 90 Days:")
    w("  7. Rate limiting: max 3 login attempts per minute per IP")
    w("  8. Deploy CAPTCHA on all public login forms")
    w("  9. Run quarterly password audits using this toolkit")
    w("  10. Disable LLMNR/NBT-NS on Windows (prevents Responder attacks)")
    w()
    w("=" * 65)
    w("  END OF REPORT — For authorised use only")
    w("=" * 65)
 
    # Save to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
 
    if verbose:
        print(f"\n[+] Audit report saved: {output_file}")
 
    return lines
 
 
# ── Run directly for testing ──────────────────────────────────
if __name__ == "__main__":
    generate_report(verbose=True)
