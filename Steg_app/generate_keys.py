from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# RSA Key Generation (Persistent storage for reuse)
def generate_keys():
    """Generates RSA private and public keys and saves them to files."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# Run the function
if __name__ == "__main__":
    generate_keys()
    print("🔑 RSA Key Pair Generated Successfully!")