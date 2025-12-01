#!/usr/bin/env python3
# Task 1: Full RSA + AES workflow (User A & User B)
# - Generate RSA key pair (User A): public.pem, private.pem
# - Generate AES-256 key & IV (User B)
# - Encrypt message.txt with AES-CBC (PKCS#7 padding)
# - Encrypt AES key with RSA-OAEP and save
# - Decrypt AES key and ciphertext, verify equality

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from pathlib import Path

# ---------- Utils ----------
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(padded: bytes, block_size: int = 16) -> bytes:
    pad_len = padded[-1]
    return padded[:-pad_len]

# ---------- Paths ----------
private_pem = Path("private.pem")
public_pem = Path("public.pem")
message_txt = Path("message.txt")
encrypted_message_bin = Path("encrypted_message.bin")
aes_key_encrypted_bin = Path("aes_key_encrypted.bin")
decrypted_message_txt = Path("decrypted_message.txt")

# ---------- 1) RSA key pair (User A) ----------
key = RSA.generate(2048)
private_pem.write_bytes(key.export_key())
public_pem.write_bytes(key.publickey().export_key())
print("[✓] RSA key pair generated: public.pem, private.pem")

# ---------- 2) AES-256 key & IV (User B) ----------
aes_key = get_random_bytes(32)  # 256-bit AES key
iv = get_random_bytes(16)       # 128-bit IV for CBC
print("[✓] AES key and IV generated")

# ---------- 3) Load plaintext from file if exists ----------
if message_txt.exists():
    plaintext = message_txt.read_bytes()
    print("[✓] Loaded existing message.txt")
else:
    plaintext = b"Hello User A, this is a secret message!"
    message_txt.write_bytes(plaintext)
    print("[✓] Created default message.txt")

# ---------- 4) AES-CBC encrypt (User B) ----------
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = cipher_aes.encrypt(pkcs7_pad(plaintext))
encrypted_message_bin.write_bytes(iv + ciphertext)
print("[✓] Message encrypted with AES-CBC: encrypted_message.bin")

# ---------- 5) Encrypt AES key with RSA-OAEP ----------
rsa_public = RSA.import_key(public_pem.read_bytes())
cipher_rsa = PKCS1_OAEP.new(rsa_public)
encrypted_aes_key = cipher_rsa.encrypt(aes_key)
aes_key_encrypted_bin.write_bytes(encrypted_aes_key)
print("[✓] AES key encrypted with RSA-OAEP: aes_key_encrypted.bin")

# ---------- 6) Decrypt AES key with RSA private ----------
rsa_private = RSA.import_key(private_pem.read_bytes())
cipher_rsa_priv = PKCS1_OAEP.new(rsa_private)
aes_key_dec = cipher_rsa_priv.decrypt(aes_key_encrypted_bin.read_bytes())

# ---------- 7) Decrypt ciphertext with AES-CBC ----------
blob = encrypted_message_bin.read_bytes()
iv_dec, ct_dec = blob[:16], blob[16:]
cipher_aes_dec = AES.new(aes_key_dec, AES.MODE_CBC, iv_dec)
padded_plain = cipher_aes_dec.decrypt(ct_dec)
plain_dec = pkcs7_unpad(padded_plain)
decrypted_message_txt.write_bytes(plain_dec)
print("[✓] Message decrypted: decrypted_message.txt")

# ---------- 8) Verify ----------
if plain_dec == plaintext:
    print("[✓] Verification OK: decrypted message matches original")
else:
    print("[!] Verification FAILED: mismatch")

