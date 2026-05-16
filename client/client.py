import socket
import json
import base64
import os

from logger import setup_logger
from rsa_utils import RSAClientUtils
from symmetric_utils import SymmetricClientUtils

HOST = "127.0.0.1"
PORT = 65432

logger = setup_logger()



# Transport helpers (length-prefixed JSON)

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def recv_message(sock: socket.socket) -> dict:
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        raise ConnectionError("Lidhja u ndërpre papritur.")
    msg_len = int.from_bytes(raw_len, "big")
    data = _recv_exact(sock, msg_len)
    return json.loads(data.decode("utf-8"))


def send_message(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    msg_len = len(data).to_bytes(4, "big")
    sock.sendall(msg_len + data)



# Main client logjika


def main() -> None:
    print("=" * 50)
    print("   SYMMETRIC KEY DISTRIBUTION CLIENT")
    print("=" * 50)

    # – Gjenero RSA çelësat
    print("\n  [1/4] Duke gjeneruar çelësat RSA...")
    private_key, public_key = RSAClientUtils.generate_keys()
    public_key_pem = RSAClientUtils.serialize_public_key(public_key).decode("utf-8")
    logger.info("Çelësat RSA u gjeneruan (2048-bit).")
    print("  Çelësat RSA u gjeneruan me sukses.")

    # – Connect me serverin
    print(f"\n  [2/4] Duke u lidhur me serverin {HOST}:{PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, PORT))
            logger.info(f"U lidh me serverin {HOST}:{PORT}.")
            print("  Lidhja u krye me sukses.\n")
        except ConnectionRefusedError:
            print(f"  GABIM: Serveri nuk është aktiv në {HOST}:{PORT}.")
            logger.error("Lidhja u refuzua – serveri nuk është aktiv.")
            return

        # – Dergo public key
        print("  [3/4] Duke dërguar çelësin publik RSA te serveri...")
        send_message(sock, {
            "type": "public_key",
            "public_key": public_key_pem,
        })
        logger.info("Çelësi publik RSA u dërgua te serveri.")

        # – Prano encrypted symmetric key
        print("  Duke pritur çelësin simetrik AES të enkriptuar...\n")
        response = recv_message(sock)

        if response.get("type") != "encrypted_symmetric_key":
            print(f"  GABIM: Lloj mesazhi i papritur: {response.get('type')}")
            logger.error(f"Mesazh i papritur nga serveri: {response.get('type')}")
            return

        encrypted_key_bytes = base64.b64decode(response["encrypted_key"])
        symmetric_key = RSAClientUtils.decrypt(private_key, encrypted_key_bytes)
        logger.info("Çelësi simetrik AES u dekriptua me sukses me RSA-OAEP.")
        print("  [4/4] Çelësi simetrik AES u mor dhe u dekriptua me sukses!")
        print("\n" + "=" * 50)
        print("   SESIONI ËSHTË AKTIV – mund të dërgoni mesazhe")
        print("   Shkruani 'quit' për të dalë.")
        print("=" * 50 + "\n")

        # Message loop
        while True:
            try:
                user_input = input("  Mesazhi juaj: ").strip()
            except (EOFError, KeyboardInterrupt):
                user_input = "quit"

            if user_input.lower() == "quit":
                send_message(sock, {"type": "disconnect"})
                logger.info("Klienti dërgoi sinjal disconnect.")
                print("\n  Lidhja u mbyll. Mirupafshim!")
                break

            if not user_input:
                continue

            # Enkripto me AES-CBC
            iv, ciphertext = SymmetricClientUtils.encrypt(symmetric_key, user_input)

            send_message(sock, {
                "type": "encrypted_message",
                "iv": base64.b64encode(iv).decode("utf-8"),
                "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            })

            logger.info("Mesazh i enkriptuar u dërgua te serveri.")
            print("  Mesazhi u dërgua.\n")


if __name__ == "__main__":
    main()