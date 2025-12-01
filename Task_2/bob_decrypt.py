# bob_decrypt.py
# Decrypts aes_key_encrypted.bin using Bob’s RSA private key, then decrypts encrypted_file.bin with AES-256-CBC

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

ENCRYPTED_FILE = "encrypted_file.bin"
ENCRYPTED_AES_KEY_FILE = "aes_key_encrypted.bin"
IV_FILE = "iv.bin"
PRIVATE_KEY_FILE = "private.pem"
DECRYPTED_FILE = "decrypted_message.txt"

def main():
    # 1) Load RSA private key (Bob)
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = RSA.import_key(f.read())

    # 2) Decrypt AES key with RSA-OAEP
    with open(ENCRYPTED_AES_KEY_FILE, "rb") as f:
        enc_aes_key = f.read()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    # 3) Load IV and ciphertext
    with open(IV_FILE, "rb") as f:
        iv = f.read()
    with open(ENCRYPTED_FILE, "rb") as f:
        ciphertext = f.read()

    # 4) AES-256-CBC decrypt (PKCS#7 unpadding)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_padded = cipher_aes.decrypt(ciphertext)
    plaintext = unpad(plaintext_padded, AES.block_size)

    # 5) Write recovered plaintext
    with open(DECRYPTED_FILE, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted message written to: {DECRYPTED_FILE}")

if __name__ == "__main__":
    main()
