import hashlib
import json
import sys

def compute_hashes(filename):
    hashes = {"SHA256": "", "SHA1": "", "MD5": ""}
    with open(filename, "rb") as f:
        data = f.read()
        hashes["SHA256"] = hashlib.sha256(data).hexdigest()
        hashes["SHA1"] = hashlib.sha1(data).hexdigest()
        hashes["MD5"] = hashlib.md5(data).hexdigest()
    return hashes

def save_hashes(hashes, json_file):
    with open(json_file, "w") as f:
        json.dump(hashes, f, indent=4)

def load_hashes(json_file):
    with open(json_file, "r") as f:
        return json.load(f)

def integrity_check(filename, json_file):
    current = compute_hashes(filename)
    stored = load_hashes(json_file)
    if current == stored:
        print(f"[PASS] Integrity check passed for {filename}")
    else:
        print(f"[FAIL] Integrity check failed for {filename}")
        print("Stored:", stored)
        print("Current:", current)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 hash_util.py <mode> <file>")
        print("Modes: generate, check")
        sys.exit(1)

    mode = sys.argv[1]
    filename = sys.argv[2]
    json_file = "hashes.json"

    if mode == "generate":
        hashes = compute_hashes(filename)
        save_hashes(hashes, json_file)
        print(f"Hashes for {filename} saved to {json_file}")
    elif mode == "check":
        integrity_check(filename, json_file)
    else:
        print("Invalid mode. Use 'generate' or 'check'.")
