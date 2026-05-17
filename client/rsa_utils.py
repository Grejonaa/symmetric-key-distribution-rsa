from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class RSAClientUtils:
    """RSA key generation, serialization, and OAEP encryption/decryption for the client."""

    @staticmethod
    def generate_keys():
        """Generate a 2048-bit RSA key pair. Returns (private_key, public_key)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_public_key(public_key) -> bytes:
        """Serialize public key to PEM bytes."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def decrypt(private_key, ciphertext: bytes) -> bytes:
        """Decrypt bytes with RSA-OAEP (SHA-256). Returns the raw plaintext bytes."""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )