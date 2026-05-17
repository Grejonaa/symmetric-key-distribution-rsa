import os

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes
)

from cryptography.hazmat.primitives import (
    padding as sym_padding
)


class SymmetricUtils:
    """
    AES-CBC symmetric encryption utility.
    """

    @staticmethod
    def generate_key():
        """
        Generate AES-256 key.

        Returns:
            bytes:
                32-byte AES key
        """

        return os.urandom(32)

    @staticmethod
    def encrypt(key: bytes, plaintext: str):
        """
        Encrypt plaintext using AES-CBC.

        Args:
            key (bytes):
                AES key

            plaintext (str):
                Message to encrypt

        Returns:
            tuple:
                (iv, ciphertext)
        """

        if len(key) not in [16, 24, 32]:
            raise ValueError(
                "AES key duhet të jetë 16, 24 ose 32 bytes."
            )

        iv = os.urandom(16)

        padder = sym_padding.PKCS7(128).padder()

        padded = (
            padder.update(
                plaintext.encode("utf-8")
            )
            + padder.finalize()
        )

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv)
        )

        encryptor = cipher.encryptor()

        ciphertext = (
            encryptor.update(padded)
            + encryptor.finalize()
        )

        return iv, ciphertext

    @staticmethod
    def decrypt(
        key: bytes,
        iv: bytes,
        ciphertext: bytes
    ):
        """
        Decrypt AES-CBC ciphertext.

        Args:
            key (bytes):
                AES key

            iv (bytes):
                Initialization vector

            ciphertext (bytes):
                Encrypted message

        Returns:
            str:
                Decrypted plaintext
        """

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv)
        )

        decryptor = cipher.decryptor()

        padded_plaintext = (
            decryptor.update(ciphertext)
            + decryptor.finalize()
        )

        unpadder = sym_padding.PKCS7(128).unpadder()

        plaintext = (
            unpadder.update(padded_plaintext)
            + unpadder.finalize()
        )

        return plaintext.decode("utf-8")


# =====================================================
# TEST
# =====================================================

if __name__ == "__main__":

    try:
        key = SymmetricUtils.generate_key()

        iv, encrypted = SymmetricUtils.encrypt(
            key,
            "test"
        )

        decrypted = SymmetricUtils.decrypt(
            key,
            iv,
            encrypted
        )

        if decrypted == "test":
            print("OK")

        else:
            print("GABIM")

    except Exception as e:
        print(
            f"Ndodhi një gabim gjatë testit: {e}"
        )