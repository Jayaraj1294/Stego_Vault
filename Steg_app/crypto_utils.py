from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # Get absolute path
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "public_key.pem")

# Load RSA keys from PEM files
def load_keys():
    """ Loads public and privte keys from the files """
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    return private_key, public_key

# load existing keys
private_key, public_key = load_keys()

def encrypt_message(message:str):
    """ Enrypts the message using AES and encrypts the AES key using RSA. """
    key = os.urandom(32) # Randomly generate a 256-bit AES Key
    iv = os.urandom(12)  # Generate IV (Nonce)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv)) # Use AES-GCM mode
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message.encode()) +encryptor.finalize()

    # Encrypt AES key using RSA public key
    encrypted_aes_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key, cipher_text, iv, encryptor.tag

def decrypt_message(encrypted_aes_key, cipher_text, iv, tag):
    """ Decrypts an AES-encrypted message using the stored RSA private.key """

    # RSA private key decrypts the AES key
    decrypted_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label=None
        )
    )

    # Ensure values are in byte format (fixes memoryview issue)
    if isinstance(cipher_text, memoryview):
        cipher_text = bytes(cipher_text)
    if isinstance(encrypted_aes_key, memoryview):
        encrypted_aes_key = bytes(encrypted_aes_key)
    if isinstance(iv, memoryview):
        iv = bytes(iv)
    if isinstance(tag, memoryview):
        tag = bytes(tag)

    # Using the Decrypted AES Key for Decryption
    cipher = Cipher(algorithms.AES(decrypted_key), modes.GCM(iv,tag))
    decryptor = cipher.decryptor()

    try:
        decrypted_text = decryptor.update(cipher_text) + decryptor.finalize()
        return decrypted_text.decode() # Convert bytes to strings
    except Exception as e:
        return f"Decryption failed: {str(e)}"