import unittest
import pickle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from typing import Tuple

def aes_encryption(plain_text) -> Tuple:
    # Generate a random symmetric key
    symmetric_key = get_random_bytes(16)
    cipher = AES.new(symmetric_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return pickle.dumps((ciphertext, nonce, tag, symmetric_key))

def aes_decryption(encrypted_data, symmetric_key):
    # Unpickle the encrypted data and retrieve the nonce, tag, and ciphertext
    encrypted_ciphertext, nonce, tag, _ = pickle.loads(encrypted_data)

    # Create a new cipher instance using the given symmetric key and nonce
    cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)

    # Decrypt the ciphertext and return the decrypted plaintext
    decrypted_data = cipher.decrypt_and_verify(encrypted_ciphertext, tag)
    return decrypted_data.decode('utf-8')

class TestAESEncryption(unittest.TestCase):

    def test_encryption_decryption(self):
        # Sample plaintext to test
        plain_text = "This is a test message"

        # Encrypt the plain_text using the aes_encryption function
        encrypted_data = aes_encryption(plain_text)

        # Unpickle the encrypted data and retrieve the symmetric key
        _, _, _, symmetric_key = pickle.loads(encrypted_data)

        # Decrypt the encrypted data to get back the original plaintext
        decrypted_data = aes_decryption(encrypted_data, symmetric_key)

        # Assert that the decrypted data is equal to the original plaintext
        self.assertEqual(decrypted_data, plain_text)

if __name__ == '__main__':
    unittest.main()
