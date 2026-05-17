import base64

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def generate_symmetric_key() -> bytes:
    return get_random_bytes(32)


def decrypt_message(symmetric_key: bytes, iv_b64: str, ciphertext_b64: str) -> str:
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode("utf-8")