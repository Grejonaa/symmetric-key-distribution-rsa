import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def receive_public_key(msg: dict) -> RSA.RsaKey:
    if msg.get("type") != "public_key":
        raise ValueError(f"Lloj mesazhi i gabuar: '{msg.get('type')}'")

    if "public_key" not in msg:
        raise ValueError("Mungon fusha 'public_key' në mesazhin e klientit.")

    pem_data = msg["public_key"].encode("utf-8")

    return RSA.import_key(pem_data)


def encrypt_symmetric_key(symmetric_key: bytes, client_public_key: RSA.RsaKey) -> str:
    cipher_rsa = PKCS1_OAEP.new(client_public_key)
    encrypted_key = cipher_rsa.encrypt(symmetric_key)

    return base64.b64encode(encrypted_key).decode("utf-8")