# alice_encrypt.py
# Encrypts alice_message.txt using AES-256-CBC and encrypts AES key using RSA-OAEP

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import hashlib

PLAINTEXT_FILE = "alice_message.txt"
ENCRYPTED_FILE = "encrypted_file.bin"
ENCRYPTED_AES_KEY_FILE = "aes_key_encrypted.bin"
PUBLIC_KEY_FILE = "public.pem"
IV_FILE = "iv.bin"
ORIGINAL_HASH_FILE = "original_sha256.txt"

def main():
    # 1) Read plaintext
    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    # 2) Generate AES-256 key and IV
    aes_key = get_random_bytes(32)  # 32 bytes == 256 bits
    iv = get_random_bytes(16)       # 16 bytes for AES block size

    # 3) AES-256-CBC encrypt (PKCS#7 padding)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))

    # 4) Save encrypted file and IV
    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(ciphertext)
    with open(IV_FILE, "wb") as f:
        f.write(iv)

    # 5) Encrypt AES key with Bob’s RSA public key using OAEP
    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    with open(ENCRYPTED_AES_KEY_FILE, "wb") as f:
        f.write(enc_aes_key)

    # 6) Compute original SHA-256 hash for integrity reference
    original_hash_hex = hashlib.sha256(plaintext).hexdigest()
    with open(ORIGINAL_HASH_FILE, "w") as f:
        f.write(original_hash_hex)

    print("Created:")
    print(f"- {ENCRYPTED_FILE}")
    print(f"- {ENCRYPTED_AES_KEY_FILE}")
    print(f"- iv.bin")
    print(f"- original_sha256.txt (hash of alice_message.txt)")

if __name__ == "__main__":
    main()
