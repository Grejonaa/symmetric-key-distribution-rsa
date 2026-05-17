from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class RSAUtils:
    """
    RSA utility class for:
    - key generation
    - serialization
    - encryption/decryption
    """

    @staticmethod
    def generate_keys():
        """
        Generate RSA 2048-bit key pair.

        Returns:
            tuple:
                (private_key, public_key)
        """

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key):
        """
        Serialize public key to PEM format.

        Args:
            public_key:
                RSA public key

        Returns:
            bytes:
                PEM encoded public key
        """

        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def serialize_private_key(private_key):
        """
        Serialize private key to PEM format.

        Args:
            private_key:
                RSA private key

        Returns:
            bytes:
                PEM encoded private key
        """

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @staticmethod
    def load_public_key(pem_data):
        """
        Load public key from PEM data.

        Args:
            pem_data (bytes):
                PEM encoded public key

        Returns:
            RSA public key object
        """

        return serialization.load_pem_public_key(pem_data)

    @staticmethod
    def load_private_key(pem_data):
        """
        Load private key from PEM data.

        Args:
            pem_data (bytes):
                PEM encoded private key

        Returns:
            RSA private key object
        """

        return serialization.load_pem_private_key(
            pem_data,
            password=None
        )

    @staticmethod
    def encrypt(public_key, message: bytes):
        """
        Encrypt message using RSA-OAEP SHA-256.

        Args:
            public_key:
                RSA public key

            message (bytes):
                Plaintext bytes

        Returns:
            bytes:
                Encrypted ciphertext
        """

        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt(private_key, ciphertext: bytes):
        """
        Decrypt RSA ciphertext using OAEP SHA-256.

        Args:
            private_key:
                RSA private key

            ciphertext (bytes):
                Encrypted ciphertext

        Returns:
            bytes:
                Decrypted plaintext
        """

        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )



# TEST

if __name__ == "__main__":

    try:
        private_key, public_key = RSAUtils.generate_keys()

        encrypted = RSAUtils.encrypt(
            public_key,
            b"test"
        )

        decrypted = RSAUtils.decrypt(
            private_key,
            encrypted
        )

        if decrypted == b"test":
            print("OK")

        else:
            print("GABIM")

    except Exception as e:
        print(f"Ndodhi një gabim gjatë testit: {e}")