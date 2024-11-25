# -*- coding: utf-8 -*-
import hashlib
import itertools
import time
from string import ascii_lowercase, ascii_uppercase, digits
from colorama import Fore, init
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

def hash_password(password, algorithm="sha256"):
    """Hash a password using the specified algorithm."""
    if algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported algorithm: use 'sha256' or 'md5'.")

def brute_force_worker(hash_to_crack, charset, length, algorithm):
    """Worker function to perform brute force."""
    for attempt in itertools.product(charset, repeat=length):
        password = ''.join(attempt)
        if hash_password(password, algorithm) == hash_to_crack:
            return password
    return None

def brute_force(hash_to_crack, charset, max_length, algorithm="sha256"):
    """Main brute force function with threading."""
    print(Fore.CYAN + "[*] Cracking is in progress...")

    start_time = time.time()  # Début du chronomètre
    found_password = None

    # Using ThreadPoolExecutor to limit number of threads
    with ThreadPoolExecutor(max_workers=8) as executor:  # Adjust the number of workers
        futures = []
        
        for length in range(1, max_length + 1):
            futures.append(executor.submit(brute_force_worker, hash_to_crack, charset, length, algorithm))

        # Wait for the first result to return
        for future in futures:
            result = future.result()
            if result:
                found_password = result
                break

    end_time = time.time()  # Fin du chronomètre
    elapsed_time = end_time - start_time

    if found_password:
        print(Fore.GREEN + f"[+] Password found: {found_password}")
        print(Fore.LIGHTMAGENTA_EX + f"[*] Time taken to crack the password: {elapsed_time:.2f} seconds")
    else:
        print(Fore.RED + "[!] No password found. Check your hash or parameters.")
        print(Fore.LIGHTMAGENTA_EX + f"[*] Time taken: {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    print(Fore.LIGHTBLUE_EX + """
  __  __       ____                _
 |  \/  |_ __ / ___|_ __ __ _  ___| | __
 | |\/| | '__| |   | '__/ _` |/ __| |/ /
 | |  | | |  | |___| | | (_| | (__|   <
 |_|  |_|_|   \____|_|  \__,_|\___|_|\_

Welcome to Mr Crack! Dev by MrBlue (Falshon)
    """)
    print(Fore.YELLOW + "Make sure you have permission before using this tool.\n")

    # Inputs
    hash_to_crack = input(Fore.LIGHTRED_EX + "Enter the hash to crack: ").strip()
    algorithm = input(Fore.LIGHTBLUE_EX + "Algorithm (sha256/md5, default: sha256): ").strip() or "sha256"
    max_length = int(input(Fore.LIGHTBLUE_EX + "Enter the maximum password length (recommend: 4-6): ").strip())

    # Auto-detect charset (including lowercase, uppercase letters, and digits)
    charset = ascii_lowercase + ascii_uppercase + digits  # Now includes lowercase, uppercase, and digits
    print(Fore.YELLOW + "[*] Using charset: " + charset)

    # Launch brute force
    brute_force(hash_to_crack, charset, max_length, algorithm)
