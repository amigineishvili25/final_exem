# generate_keys.py
# Generates RSA key pair for Bob (PEM files)

from Crypto.PublicKey import RSA

def main():
    key = RSA.generate(2048)  # 2048-bit RSA
    private_pem = key.export_key()                      # PKCS#1 PEM
    public_pem = key.publickey().export_key()

    with open("private.pem", "wb") as f:
        f.write(private_pem)
    with open("public.pem", "wb") as f:
        f.write(public_pem)

    print("Generated: public.pem, private.pem")

if __name__ == "__main__":
    main()
