import unittest
import os
import sys
import base64



project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src import pqc_utils

class TestPqcUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Generate keys once for all tests in this class."""
        cls.kem_algo = pqc_utils.ALGORITHMS["kem"]
        cls.sig_algo = pqc_utils.ALGORITHMS["sig"]

        print(f"\nGenerating test keys (KEM: {cls.kem_algo}, SIG: {cls.sig_algo})...")
        cls.client_kem_pk, cls.client_kem_sk = pqc_utils.generate_key_pair(cls.kem_algo)
        cls.server_kem_pk, cls.server_kem_sk = pqc_utils.generate_key_pair(cls.kem_algo)
        cls.client_sign_pk, cls.client_sign_sk = pqc_utils.generate_key_pair(cls.sig_algo)
        cls.server_sign_pk, cls.server_sign_sk = pqc_utils.generate_key_pair(cls.sig_algo)
        print("Test keys generated.")

    def test_01_generate_key_pair(self):
        """Test basic key generation for KEM and SIG algorithms."""
        self.assertIsNotNone(self.client_kem_pk)
        self.assertIsNotNone(self.client_kem_sk)
        self.assertIsNotNone(self.client_sign_pk)
        self.assertIsNotNone(self.client_sign_sk)
        self.assertIsInstance(self.client_kem_pk, bytes)
        self.assertIsInstance(self.client_kem_sk, bytes)
        self.assertIsInstance(self.client_sign_pk, bytes)
        self.assertIsInstance(self.client_sign_sk, bytes)
        self.assertGreater(len(self.client_kem_pk), 0)
        self.assertGreater(len(self.client_kem_sk), 0)
        self.assertGreater(len(self.client_sign_pk), 0)
        self.assertGreater(len(self.client_sign_sk), 0)

        
        with self.assertRaises(pqc_utils.PQCError):
            pqc_utils.generate_key_pair("NonExistentAlgo")

    def test_02_kem_encap_decap(self):
        """Test KEM encapsulation and decapsulation round trip."""
        
        ciphertext1, shared_secret1_client = pqc_utils.kem_encapsulate(self.kem_algo, self.server_kem_pk)
        self.assertIsNotNone(ciphertext1)
        self.assertIsNotNone(shared_secret1_client)
        self.assertIsInstance(ciphertext1, bytes)
        self.assertIsInstance(shared_secret1_client, bytes)
        self.assertGreater(len(ciphertext1), 0)
        self.assertGreater(len(shared_secret1_client), 0)

        
        shared_secret1_server = pqc_utils.kem_decapsulate(self.kem_algo, ciphertext1, self.server_kem_sk)
        self.assertIsNotNone(shared_secret1_server)
        self.assertIsInstance(shared_secret1_server, bytes)

        
        self.assertEqual(shared_secret1_client, shared_secret1_server)

        
        ciphertext2, shared_secret2_server = pqc_utils.kem_encapsulate(self.kem_algo, self.client_kem_pk)
        shared_secret2_client = pqc_utils.kem_decapsulate(self.kem_algo, ciphertext2, self.client_kem_sk)
        self.assertEqual(shared_secret2_server, shared_secret2_client)

        
        with self.assertRaises(pqc_utils.PQCError):
            pqc_utils.kem_decapsulate(self.kem_algo, ciphertext1, self.client_kem_sk) 

        
        tampered_ciphertext = ciphertext1[:-1] + bytes([(ciphertext1[-1] + 1) % 256])
        with self.assertRaises(pqc_utils.PQCError):
             pqc_utils.kem_decapsulate(self.kem_algo, tampered_ciphertext, self.server_kem_sk)

    def test_03_sign_verify(self):
        """Test SPHINCS+ signing and verification round trip."""
        message = b"This is a test message for SPHINCS+ signing."

        
        signature = pqc_utils.sign_message(message, self.client_sign_sk, self.sig_algo)
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 0)

        
        self.assertTrue(pqc_utils.verify_signature(message, signature, self.client_sign_pk, self.sig_algo))

        
        self.assertFalse(pqc_utils.verify_signature(message, signature, self.server_sign_pk, self.sig_algo))

        
        tampered_message = b"This is a different message."
        self.assertFalse(pqc_utils.verify_signature(tampered_message, signature, self.client_sign_pk, self.sig_algo))

        
        tampered_signature = signature[:-1] + bytes([(signature[-1] + 1) % 256])
        
        self.assertFalse(pqc_utils.verify_signature(message, tampered_signature, self.client_sign_pk, self.sig_algo))

    def test_04_derive_aes_key(self):
        """Test HKDF key derivation."""
        
        _, shared_secret = pqc_utils.kem_encapsulate(self.kem_algo, self.server_kem_pk)

        aes_key1 = pqc_utils.derive_aes_key(shared_secret)
        self.assertIsInstance(aes_key1, bytes)
        
        self.assertEqual(len(aes_key1), 32)

        
        aes_key2 = pqc_utils.derive_aes_key(shared_secret)
        self.assertEqual(aes_key1, aes_key2)

        
        _, shared_secret_other = pqc_utils.kem_encapsulate(self.kem_algo, self.client_kem_pk)
        
        if shared_secret != shared_secret_other:
            aes_key_other = pqc_utils.derive_aes_key(shared_secret_other)
            self.assertNotEqual(aes_key1, aes_key_other)

    def test_05_aes_gcm_encrypt_decrypt(self):
        """Test AES-GCM encryption and decryption round trip."""
        
        _, shared_secret = pqc_utils.kem_encapsulate(self.kem_algo, self.server_kem_pk)
        aes_key = pqc_utils.derive_aes_key(shared_secret)

        plaintext = b"This is the secret data to be encrypted."

        
        nonce, ciphertext = pqc_utils.aes_gcm_encrypt(aes_key, plaintext)
        self.assertIsInstance(nonce, bytes)
        self.assertIsInstance(ciphertext, bytes)
        
        self.assertEqual(len(nonce), 12)
        # Ciphertext includes the tag, so it's longer than plaintext
        self.assertGreater(len(ciphertext), len(plaintext))

        
        decrypted_plaintext = pqc_utils.aes_gcm_decrypt(aes_key, nonce, ciphertext)
        self.assertEqual(plaintext, decrypted_plaintext)

        
        _, shared_secret_wrong = pqc_utils.kem_encapsulate(self.kem_algo, self.client_kem_pk)
        aes_key_wrong = pqc_utils.derive_aes_key(shared_secret_wrong)
        if aes_key != aes_key_wrong:
            with self.assertRaises(pqc_utils.PQCError): 
                pqc_utils.aes_gcm_decrypt(aes_key_wrong, nonce, ciphertext)

        
        nonce_wrong = os.urandom(12)
        with self.assertRaises(pqc_utils.PQCError):
            pqc_utils.aes_gcm_decrypt(aes_key, nonce_wrong, ciphertext)

        
        tampered_ciphertext = ciphertext[:-1] + bytes([(ciphertext[-1] + 1) % 256])
        with self.assertRaises(pqc_utils.PQCError):
            pqc_utils.aes_gcm_decrypt(aes_key, nonce, tampered_ciphertext)

if __name__ == '__main__':
    unittest.main() 