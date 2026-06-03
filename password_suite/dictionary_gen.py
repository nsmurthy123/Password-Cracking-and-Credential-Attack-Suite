# ============================================================
# dictionary_gen.py — Custom Wordlist Generator
# Generates mutated password lists from base words
# For educational and authorised use ONLY
# ============================================================
 
import os
import sys
import time
from config import WORDLIST_FILE, COMMON_SUFFIXES, RULES
 
 
def leet_speak(word):
    """Apply leet-speak character substitutions."""
    table = {
        "a": "@", "e": "3", "i": "1",
        "o": "0", "s": "$", "t": "7",
        "l": "1", "g": "9", "b": "8",
    }
    result = ""
    for char in word.lower():
        result += table.get(char, char)
    return result
 
 
def apply_mutations(word):
    """Apply all enabled mutation rules to a single base word.
    Returns a set of unique password variants.
    """
    variants = set()
 
    if RULES["original"]:
        variants.add(word)
 
    if RULES["capitalize"]:
        variants.add(word.capitalize())
 
    if RULES["uppercase"]:
        variants.add(word.upper())
 
    if RULES["lowercase"]:
        variants.add(word.lower())
 
    if RULES["reverse"]:
        variants.add(word[::-1])
        variants.add(word[::-1].capitalize())
 
    leet = leet_speak(word)
    if RULES["leet_speak"]:
        variants.add(leet)
        variants.add(leet.capitalize())
 
    # Append common suffixes to original and capitalised versions
    bases_for_suffix = [word, word.capitalize(), leet]
    if RULES["append_numbers"] or RULES["append_symbols"]:
        for base in bases_for_suffix:
            for suffix in COMMON_SUFFIXES:
                variants.add(base + suffix)
 
    # Prepend numbers to original and capitalised
    if RULES["prepend_numbers"]:
        for base in [word, word.capitalize()]:
            for num in ["1","2","123","2024","007"]:
                variants.add(num + base)
 
    return variants
 
 
def generate_wordlist(base_words, output_file=None, verbose=True):
    """
    Generate a mutated wordlist from a list of base words.
 
    Args:
        base_words  : list of base words (names, keywords, etc.)
        output_file : path to save the wordlist (default: config path)
        verbose     : print progress to terminal
 
    Returns:
        list of all generated passwords
    """
    if output_file is None:
        output_file = WORDLIST_FILE
 
    if verbose:
        print("[*] Starting dictionary generation...")
        print(f"[*] Base words: {len(base_words)}")
 
    all_passwords = set()
    start = time.time()
 
    for word in base_words:
        if not word.strip():
            continue
        mutations = apply_mutations(word.strip())
        all_passwords.update(mutations)
 
    # Sort for reproducibility
    final_list = sorted(all_passwords)
 
    # Write to file
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(final_list))
 
    elapsed = time.time() - start
    if verbose:
        print(f"[+] Generated {len(final_list):,} password variants")
        print(f"[+] Wordlist saved: {output_file}")
        print(f"[+] Time taken: {elapsed:.3f}s")
 
    return final_list
 
 
def load_wordlist_from_file(filepath):
    """Load existing words from a file (e.g., rockyou.txt).
    Returns a list of words stripped of whitespace.
    """
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip()]
    print(f"[+] Loaded {len(words):,} words from {filepath}")
    return words
 
 
# ── Run directly for testing ──────────────────────────────────
if __name__ == "__main__":
    # Example: generate wordlist for a target named John Smith, born 1990
    base = [
        "john", "smith", "johnsmith", "john1990",
        "password", "admin", "welcome", "letmein",
        "qwerty", "monkey", "dragon", "master",
        "company", "office", "work", "login","sam@123","hello","sam",
                ]
 
    wordlist = generate_wordlist(base, verbose=True)
 
    # Show first 10 samples
    print("\n[*] Sample entries (first 10):")
    for w in wordlist[:10]:
        print(f"    {w}")
 
    print(f"\n[+] Total unique passwords: {len(wordlist):,}")
