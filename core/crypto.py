import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class QuantumForensicCrypto:
    def __init__(self):
        print("[*] Initializing cryptographic keypairs via liboqs...")
        
        # Initialize the ML-DSA-65 (Dilithium3 equivalent) Signer
        self.signer = oqs.Signature("ML-DSA-65")
        self.dsa_public_key = self.signer.generate_keypair()
        
        # Initialize the ML-KEM-768 (Kyber768 equivalent) Mechanism
        self.kem = oqs.KeyEncapsulation("ML-KEM-768")
        self.kem_public_key = self.kem.generate_keypair()

    def sign_log(self, log_data: bytes) -> bytes:
        """
        Signs the log payload using real ML-DSA-65 determinism.
        """
        # Generates a valid cryptographic signature confirming data source integrity
        return self.signer.sign(log_data)

    def encrypt_payload(self, payload: bytes) -> tuple[bytes, bytes]:
        """
        Executes an ML-KEM key encapsulation to safely derive an ephemeral symmetric key,
        then encrypts the underlying payload via AES-256-GCM.
        """
        # 1. Real ML-KEM Encapsulation using the configured public key
        kem_ciphertext, shared_secret = self.kem.encap_secret(self.kem_public_key)

        # 2. Use the derived 256-bit shared secret for high-speed symmetric AEAD encryption
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, payload, None)

        # Prepend the 12-byte nonce to the encrypted payload for decryption retrieval
        final_encrypted_payload = nonce + encrypted_data
        
        return kem_ciphertext, final_encrypted_payload

    def close(self):
        """Safely clear native structures from memory."""
        self.signer.free()
        self.kem.free()