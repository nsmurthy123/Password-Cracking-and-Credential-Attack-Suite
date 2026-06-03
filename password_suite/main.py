# ============================================================
# main.py — Password Cracking Suite Orchestrator
# Unified Mentor Cybersecurity Project
# Run: python main.py --help
# For educational and authorised use ONLY
# ============================================================
 
import argparse
import sys
import os
 
def print_banner():
    """Print the suite banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║   Password Cracking & Credential Attack Suite         ║
    ║   Unified Mentor Cybersecurity Project                ║
    ║   For Educational & Authorised Use ONLY               ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)
 
 
def run_full_pipeline(base_words=None, verbose=True):
    """
    Run the full pipeline in order:
    1. Generate wordlist
    2. Create demo hash file
    3. Run cracking simulation
    4. Analyze strength of demo passwords
    5. Generate audit report
    """
    print("\n[PIPELINE] Starting full pipeline...\n")
 
    # Step 1: Dictionary Generation
    print("[STEP 1/5] Dictionary Generation")
    print("-" * 40)
    from dictionary_gen import generate_wordlist
    if base_words is None:
        base_words = [
            "password","admin","user","welcome","letmein",
            "qwerty","monkey","dragon","master","login",
            "john","alice","charlie","company","office","sam","hello","bhuvanesh",
        ]
    generate_wordlist(base_words, verbose=verbose)
    print()
 
    # Step 2: Hash Extraction (Demo)
    print("[STEP 2/5] Hash Extraction Demo")
    print("-" * 40)
    from hash_extract import create_demo_hash_file
    create_demo_hash_file(verbose=verbose)
    print()
 
    # Step 3: Attack Simulation
    print("[STEP 3/5] Brute-Force & Dictionary Attack Simulation")
    print("-" * 40)
    from bruteforce_sim import run_simulation
    run_simulation(verbose=verbose)
    print()
 
    # Step 4: Password Strength Analysis
    print("[STEP 4/5] Password Strength Analysis")
    print("-" * 40)
    from config import DEMO_ACCOUNTS
    from strength_analyzer import analyze_list
    passwords = [plain for _, _, plain in DEMO_ACCOUNTS]
    analyze_list(passwords, verbose=verbose)
    print()
 
    # Step 5: Report Generation
    print("[STEP 5/5] Audit Report Generation")
    print("-" * 40)
    from report_gen import generate_report
    generate_report(verbose=verbose)
 
    print("\n[PIPELINE] All steps complete!")
    print("[PIPELINE] Check audit_report.txt for your deliverable.")
 
 
def main():
    """Parse CLI arguments and dispatch to correct module."""
    print_banner()
 
    parser = argparse.ArgumentParser(
        description="Password Cracking & Credential Attack Suite",
        epilog="Example: python main.py --all"
    )
 
    parser.add_argument("--all",      action="store_true",
        help="Run full pipeline (recommended first run)")
    parser.add_argument("--generate", action="store_true",
        help="Run dictionary wordlist generator only")
    parser.add_argument("--extract",  action="store_true",
        help="Create demo hash file only")
    parser.add_argument("--attack",   action="store_true",
        help="Run cracking simulation only (requires hashes.txt)")
    parser.add_argument("--report",   action="store_true",
        help="Generate audit report only")
    parser.add_argument("--analyze",  type=str, metavar="PASSWORD",
        help="Analyze strength of a single password")
    parser.add_argument("--quiet",    action="store_true",
        help="Suppress verbose output")
 
    args    = parser.parse_args()
    verbose = not args.quiet
 
    if args.all:
        run_full_pipeline(verbose=verbose)
 
    elif args.generate:
        from dictionary_gen import generate_wordlist
        base = ["password","admin","welcome","letmein","qwerty"]
        generate_wordlist(base, verbose=verbose)
 
    elif args.extract:
        from hash_extract import create_demo_hash_file
        create_demo_hash_file(verbose=verbose)
 
    elif args.attack:
        from bruteforce_sim import run_simulation
        run_simulation(verbose=verbose)
 
    elif args.report:
        from report_gen import generate_report
        generate_report(verbose=verbose)
 
    elif args.analyze:
        from strength_analyzer import analyze_password
        analyze_password(args.analyze, verbose=True)
 
    else:
        print("[!] No option specified. Running full pipeline by default...")
        print("[!] Use --help to see all options.\n")
        run_full_pipeline(verbose=verbose)
 
 
if __name__ == "__main__":
    main()
