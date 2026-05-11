from cryptography.fernet import Fernet
print("OK")

class SymmetricUtils:

    @staticmethod
    def generate_key():
        return Fernet.generate_key()

    @staticmethod
    def create_cipher(key: bytes):
        return Fernet(key)

    @staticmethod
    def encrypt(cipher, message: str):
        return cipher.encrypt(message.encode())

    @staticmethod
    def decrypt(cipher, token: bytes):
        return cipher.decrypt(token).decode()