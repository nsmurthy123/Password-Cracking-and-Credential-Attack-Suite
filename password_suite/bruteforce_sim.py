# ============================================================
# bruteforce_sim.py — Password Cracking Simulation Engine
# Dictionary attack + Brute-force simulation
# For educational and authorised use ONLY
# ============================================================

import hashlib
import itertools
import os
import time
from config import (
    WORDLIST_FILE, HASHES_FILE, RESULTS_FILE,
    CHARSET_DEFAULT, MAX_BF_LENGTH
)

from passlib.hash import bcrypt as bcrypt_hash


# ------------------------------------------------------------
# BCRYPT DICTIONARY ATTACK
# ------------------------------------------------------------
def bcrypt_dictionary_attack(target_hash, wordlist_path=None, verbose=True):
    if wordlist_path is None:
        wordlist_path = WORDLIST_FILE

    start = time.time()
    attempts = 0

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if not word:
                continue

            attempts += 1

            if bcrypt_hash.verify(word, target_hash):
                elapsed = time.time() - start
                return {
                    "cracked": True,
                    "password": word,
                    "attempts": attempts,
                    "time": round(elapsed, 4),
                    "method": "bcrypt-dictionary",
                }

            if verbose and attempts % 10 == 0:
                print(f"   [*] Tried {attempts} passwords...", end="\r")

    elapsed = time.time() - start
    return {
        "cracked": False,
        "password": None,
        "attempts": attempts,
        "time": round(elapsed, 4),
        "method": "bcrypt-dictionary",
    }


# ------------------------------------------------------------
# HASH FUNCTION
# ------------------------------------------------------------
def hash_password(password, algorithm):
    algorithm = algorithm.lower()
    encoded = password.encode("utf-8")

    if algorithm == "md5":
        return hashlib.md5(encoded).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(encoded).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(encoded).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(encoded).hexdigest()
    else:
        return hashlib.md5(encoded)


# ------------------------------------------------------------
# KEYSPACE CALCULATION
# ------------------------------------------------------------
def estimate_keyspace(charset, max_length):
    total = 0
    for length in range(1, max_length + 1):
        total += len(charset) ** length
    return total


# ------------------------------------------------------------
# DICTIONARY ATTACK
# ------------------------------------------------------------
def dictionary_attack(target_hash, algorithm, wordlist_path=None, verbose=True):

    if wordlist_path is None:
        wordlist_path = WORDLIST_FILE

    if not os.path.exists(wordlist_path):
        print(f"[-] Wordlist not found: {wordlist_path}")
        return {"cracked": False, "password": None, "attempts": 0, "time": 0}

    start = time.time()
    attempts = 0
    target_hash = target_hash.lower().strip()

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()

            if not word:
                continue

            attempts += 1
            candidate = hash_password(word, algorithm)

            if candidate == target_hash:
                elapsed = time.time() - start
                return {
                    "cracked": True,
                    "password": word,
                    "attempts": attempts,
                    "time": round(elapsed, 4),
                    "method": "dictionary",
                }

    elapsed = time.time() - start
    return {
        "cracked": False,
        "password": None,
        "attempts": attempts,
        "time": round(elapsed, 4),
        "method": "dictionary",
    }


# ------------------------------------------------------------
# BRUTE FORCE ATTACK
# ------------------------------------------------------------
def brute_force_attack(target_hash, algorithm, max_length=None,
                       charset=None, verbose=True):

    if max_length is None:
        max_length = MAX_BF_LENGTH

    if charset is None:
        charset = CHARSET_DEFAULT

    keyspace = estimate_keyspace(charset, max_length)
    target_hash = target_hash.lower().strip()

    if verbose:
        print(f"  [*] Charset: {len(charset)} chars | Max length: {max_length}")
        print(f"  [*] Keyspace: {keyspace:,} combinations")

    start = time.time()
    attempts = 0

    for length in range(1, max_length + 1):

        if verbose:
            print(f"  [*] Trying length {length}...")

        for combo in itertools.product(charset, repeat=length):

            guess = "".join(combo)
            attempts += 1

            candidate = hash_password(guess, algorithm)

            if candidate == target_hash:
                elapsed = time.time() - start

                return {
                    "cracked": True,
                    "password": guess,
                    "attempts": attempts,
                    "time": round(elapsed, 4),
                    "method": "brute-force",
                }

    elapsed = time.time() - start

    return {
        "cracked": False,
        "password": None,
        "attempts": attempts,
        "time": round(elapsed, 4),
        "method": "brute-force",
    }


# ------------------------------------------------------------
# MAIN SIMULATION ENGINE
# ------------------------------------------------------------
def run_simulation(hashes_file=None, wordlist_file=None,
                   results_file=None, verbose=True):

    if hashes_file is None:
        hashes_file = HASHES_FILE

    if wordlist_file is None:
        wordlist_file = WORDLIST_FILE

    if results_file is None:
        results_file = RESULTS_FILE

    if not os.path.exists(hashes_file):
        print(f"[-] Hash file not found: {hashes_file}")
        print("[-] Run hash_extract.py first.")
        return []

    records = []

    with open(hashes_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                parts = line.split(":", 2)

                if len(parts) == 3:
                    records.append(tuple(parts))

    print(f"[*] Loaded {len(records)} hash records")
    print(f"[*] Wordlist: {wordlist_file}")
    print("[*] Starting simulation...\n")
    print("=" * 60)

    all_results = []
    total_cracked = 0

    for username, algorithm, target_hash in records:

        # ----------------------------------------------------
        # BCRYPT HANDLING
        # ----------------------------------------------------
        if target_hash.startswith("$2"):

            print(f" [*] bcrypt detected for {username} — trying dictionary (slow)...")

            result = bcrypt_dictionary_attack(
                target_hash,
                wordlist_path=wordlist_file,
                verbose=True
            )

            result["username"] = username
            result["algorithm"] = algorithm

            if result["cracked"]:
                total_cracked += 1
                print(f" [+] CRACKED: {result['password']} | {result['attempts']} attempts")
            else:
                print(f" [-] NOT CRACKED | {result['attempts']} attempts | {result['time']}s")

            all_results.append(result)
            print()
            continue

        # ----------------------------------------------------
        # NORMAL HASH ATTACK
        # ----------------------------------------------------
        print(f"  [*] Attacking: {username} ({algorithm.upper()})")

        result = dictionary_attack(
            target_hash,
            algorithm,
            wordlist_path=wordlist_file,
            verbose=False
        )

        if not result["cracked"] and algorithm == "md5":

            print("  [-] Dictionary failed — trying brute-force...")

            result = brute_force_attack(
                target_hash,
                algorithm,
                max_length=5,
                charset="abcdefghijklmnopqrstuvwxyz0123456789",
                verbose=True
            )

        result["username"] = username
        result["algorithm"] = algorithm

        if result["cracked"]:
            total_cracked += 1
            print(f"  [+] CRACKED: {result['password']} | {result['attempts']:,} attempts | {result['time']}s")
        else:
            print(f"  [-] NOT CRACKED | {result['attempts']:,} attempts | {result['time']}s")

        all_results.append(result)
        print()

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------
    print("=" * 60)
    print("[+] SIMULATION COMPLETE")
    print(f"[+] Total hashes : {len(records)}")
    print(f"[+] Cracked      : {total_cracked}")
    print(f"[+] Resistant    : {len(records) - total_cracked}")

    pct = int(100 * total_cracked / len(records)) if records else 0
    print(f"[+] Success rate : {pct}%")

    # --------------------------------------------------------
    # SAVE RESULTS
    # --------------------------------------------------------
    with open(results_file, "w", encoding="utf-8") as f:

        f.write("USERNAME|ALGORITHM|CRACKED|PASSWORD|ATTEMPTS|TIME|METHOD\n")

        for r in all_results:

            f.write(
                f"{r.get('username','?')}|"
                f"{r.get('algorithm','?')}|"
                f"{r.get('cracked',False)}|"
                f"{r.get('password','')}|"
                f"{r.get('attempts',0)}|"
                f"{r.get('time',0)}|"
                f"{r.get('method','?')}\n"
            )

    print(f"[+] Results saved: {results_file}")

    return all_results


# ------------------------------------------------------------
# RUN SCRIPT
# ------------------------------------------------------------
if __name__ == "__main__":
    run_simulation(verbose=True)