# 🔐 Task 1 – RSA + AES Encrypted Messaging Workflow

## 📌 Objective

Implement a secure messaging system using a hybrid cryptosystem:
- **RSA (asymmetric)** for encrypting the AES key.
- **AES (symmetric)** for encrypting the actual message.

---

## 👥 Roles

- **User A**: Generates RSA key pair and shares the public key.
- **User B**: 
  - Generates AES key and IV.
  - Encrypts the message using AES-CBC.
  - Encrypts the AES key using RSA-OAEP with User A’s public key.
- **User A**: 
  - Decrypts the AES key using their private RSA key.
  - Decrypts the message using the recovered AES key and IV.
  - Verifies the decrypted message matches the original.

---

## 🔧 Algorithms Used

| Component      | Algorithm        | Purpose                            |
|----------------|------------------|------------------------------------|
| RSA (2048-bit) | Asymmetric       | Encrypt/decrypt AES key            |
| RSA-OAEP       | Padding for RSA  | Secure key wrapping                |
| AES-256-CBC    | Symmetric        | Encrypt/decrypt message            |
| PKCS#7         | Padding scheme   | Align plaintext to AES block size  |

---

## 📁 File Outputs

| Filename                  | Description                                      |
|---------------------------|--------------------------------------------------|
| `private.pem`             | RSA private key (User A)                         |
| `public.pem`              | RSA public key (User A)                          |
| `message.txt`             | Original plaintext message                       |
| `encrypted_message.bin`   | AES-encrypted message (IV + ciphertext)          |
| `aes_key_encrypted.bin`   | RSA-encrypted AES key                            |
| `decrypted_message.txt`   | Decrypted message (should match original)        |

---

## 🔄 Workflow Steps

### 1. RSA Key Generation (User A)
- Generates a 2048-bit RSA key pair.
- Saves `private.pem` and `public.pem`.

### 2. AES Key and IV Generation (User B)
- Creates a random 256-bit AES key and 128-bit IV.

### 3. Message Preparation
- Loads `message.txt` if it exists.
- Otherwise, creates a default message.

### 4. AES Encryption
- Pads the plaintext using PKCS#7.
- Encrypts with AES-CBC.
- Saves `encrypted_message.bin` as `IV || ciphertext`.

### 5. RSA Encryption of AES Key
- Loads `public.pem`.
- Encrypts AES key using RSA-OAEP.
- Saves to `aes_key_encrypted.bin`.

### 6. RSA Decryption of AES Key (User A)
- Loads `private.pem`.
- Decrypts AES key from `aes_key_encrypted.bin`.

### 7. AES Decryption of Message
- Extracts IV and ciphertext from `encrypted_message.bin`.
- Decrypts using AES-CBC and unpads.
- Saves to `decrypted_message.txt`.

### 8. Verification
- Compares `decrypted_message.txt` with `message.txt`.
- Prints verification result.

---

## 🖥️ Terminal Output Example

```bash
[✓] RSA key pair generated: public.pem, private.pem
[✓] AES key and IV generated
[✓] Message encrypted with AES-CBC: encrypted_message.bin
[✓] AES key encrypted with RSA-OAEP: aes_key_encrypted.bin
[✓] Message decrypted: decrypted_message.txt
[✓] Verification OK: decrypted message matches original
