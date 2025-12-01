# verify_integrity.py
# Computes SHA-256 of decrypted_message.txt and compares to original_sha256.txt

import hashlib

DECRYPTED_FILE = "decrypted_message.txt"
ORIGINAL_HASH_FILE = "original_sha256.txt"

def main():
    with open(DECRYPTED_FILE, "rb") as f:
        decrypted = f.read()
    decrypted_hash_hex = hashlib.sha256(decrypted).hexdigest()

    with open(ORIGINAL_HASH_FILE, "r") as f:
        original_hash_hex = f.read().strip()

    print(f"Original hash:  {original_hash_hex}")
    print(f"Decrypted hash: {decrypted_hash_hex}")

    if decrypted_hash_hex == original_hash_hex:
        print("Integrity OK: hashes match.")
    else:
        print("Integrity FAIL: hashes do not match.")

if __name__ == "__main__":
    main()
