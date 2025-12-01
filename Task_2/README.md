# Secure File Exchange Using RSA + AES (Hybrid Encryption)

## Objective
Demonstrate a hybrid encryption protocol where Alice encrypts a file using AES-256, and the AES key is securely delivered to Bob by encrypting it with Bob’s RSA public key. Bob uses his RSA private key to recover the AES key and decrypts the file. Finally, SHA-256 is used to verify integrity.

## Files
- `alice_message.txt` – Original plaintext file
- `encrypted_file.bin` – File encrypted with AES-256-CBC
- `aes_key_encrypted.bin` – AES key encrypted with Bob’s RSA public key (RSA-OAEP)
- `decrypted_message.txt` – Final output decrypted by Bob
- `public.pem`, `private.pem` – Bob’s RSA key pair (2048-bit)
- `iv.bin` – Random IV used for AES-256-CBC
- `original_sha256.txt` – SHA-256 of the original plaintext for integrity comparison

## Flow (Encryption and Decryption)
1. **Key generation (Bob):** Bob generates an RSA-2048 key pair and shares `public.pem` with Alice; he keeps `private.pem` secret.
2. **Alice’s plaintext:** Alice places her message in `alice_message.txt`.
3. **AES setup:** Alice generates a random 32-byte AES key and a 16-byte IV.
4. **AES encryption:** Alice encrypts `alice_message.txt` using AES-256-CBC with PKCS#7 padding, producing `encrypted_file.bin`. The IV is stored in `iv.bin`.
5. **RSA key wrapping:** Alice encrypts the AES key with Bob’s `public.pem` using RSA-OAEP, producing `aes_key_encrypted.bin`.
6. **Bob’s RSA decryption:** Bob decrypts `aes_key_encrypted.bin` with `private.pem` to recover the AES key.
7. **AES decryption:** Bob decrypts `encrypted_file.bin` using the recovered AES key and `iv.bin`, yielding `decrypted_message.txt`.
8. **Integrity check:** SHA-256 hashes of `alice_message.txt` and `decrypted_message.txt` are compared. Matching hashes confirm integrity.

## Commands (Ubuntu/Linux)
```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install pycryptodome cryptography

# Generate keys
python generate_keys.py

# Prepare plaintext
echo "This is a secret message from Alice to Bob." > alice_message.txt

# Alice encrypts and wraps AES key
python alice_encrypt.py

# Bob decrypts and recovers plaintext
python bob_decrypt.py

# Verify integrity
python verify_integrity.py





AES vs RSA: Speed, Use Case, and Security

    Speed:

        AES (symmetric): Very fast and efficient for bulk data encryption. Hardware acceleration (AES-NI) further boosts performance.

        RSA (asymmetric): Much slower and computationally expensive, especially for large data. Best used for small payloads like keys.

    Use case:

        AES: Encrypting large files/streams and real-time communications due to low latency and throughput.

        RSA: Secure key exchange, digital signatures, and establishing trust without pre-shared keys.

    Security:

        AES-256: Considered strong against brute-force; security depends on correct mode (e.g., CBC, GCM), random IVs/nonces, and safe key handling.

        RSA-2048: Secure when implemented with modern padding (OAEP) and protected private keys. Vulnerable if outdated padding (PKCS#1 v1.5) or weak key sizes are used.

Notes

    Use RSA-OAEP for key encryption to prevent padding oracle attacks.

    Store and transmit the IV alongside the ciphertext; it is not secret but must be unpredictable.

    Do not reuse the same AES key and IV pair across multiple messages.

    Protect private.pem with appropriate filesystem permissions (e.g., chmod 600 private.pem).




