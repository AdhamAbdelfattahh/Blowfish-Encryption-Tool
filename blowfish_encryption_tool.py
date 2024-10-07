from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import os
import base64

def generate_key():
    """Generate a random Blowfish key."""
    return os.urandom(16)  # Blowfish key size can be between 4 and 56 bytes

def encrypt(plain_text, key):
    """Encrypt the plain text using Blowfish."""
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    padded_text = pad(plain_text.encode('utf-8'), Blowfish.block_size)
    cipher_text = cipher.encrypt(padded_text)
    return base64.b64encode(iv + cipher_text).decode('utf-8')

def decrypt(cipher_text, key):
    """Decrypt the cipher text using Blowfish."""
    cipher_text_bytes = base64.b64decode(cipher_text.encode('utf-8'))
    iv = cipher_text_bytes[:Blowfish.block_size]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_padded_text = cipher.decrypt(cipher_text_bytes[Blowfish.block_size:])
    return unpad(decrypted_padded_text, Blowfish.block_size).decode('utf-8')

if __name__ == "__main__":
    # Generate a key for Blowfish
    key = generate_key()
    
    # Input message
    message = "This is a secret message."
    
    # Encrypt the message
    encrypted_message = encrypt(message, key)
    print(f"Ciphertext: {encrypted_message}")
    
    # Decrypt the message
    decrypted_message = decrypt(encrypted_message, key)
    print(f"Decrypted: {decrypted_message}")
