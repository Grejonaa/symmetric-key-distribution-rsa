import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


class SymmetricClientUtils:
    """AES-CBC encryption for the client, matching the server's decrypt logic."""

    @staticmethod
    def encrypt(key: bytes, plaintext: str) -> tuple[bytes, bytes]:
        """
        Encrypt a plaintext string with AES-CBC.

        Args:
            key:       Raw AES key bytes received from the server (16, 24, or 32 bytes).
            plaintext: The message to encrypt.

        Returns:
            (iv, ciphertext) — both as raw bytes; caller base64-encodes them before sending.
        """
        iv = os.urandom(16)

        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return iv, ciphertext