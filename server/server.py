import socket
import json
import datetime
import base64

from server.logger import setup_logger

from crypto.rsa_utils import RSAUtils
from crypto.symmetric_utils import SymmetricUtils

HOST = "127.0.0.1"
PORT = 65432

logger = setup_logger()


# NETWORK HELPERS

def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    try:
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf
    except Exception as e:
        logger.exception(f"Recv error: {e}")
        return b""


def recv_message(conn: socket.socket) -> dict:
    try:
        raw_len = _recv_exact(conn, 4)
        if not raw_len:
            raise ConnectionError("Client disconnected")

        msg_len = int.from_bytes(raw_len, "big")
        data = _recv_exact(conn, msg_len)

        if not data:
            raise ConnectionError("No data received")

        return json.loads(data.decode("utf-8"))

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        raise
    except Exception as e:
        logger.exception(f"recv_message error: {e}")
        raise


def send_message(conn: socket.socket, payload: dict) -> None:
    try:
        data = json.dumps(payload).encode("utf-8")
        msg_len = len(data).to_bytes(4, "big")
        conn.sendall(msg_len + data)

    except Exception as e:
        logger.exception(f"send_message error: {e}")
        raise


# -----------------------------
# CLIENT HANDLER
# -----------------------------

def handle_client(conn: socket.socket, addr: tuple, client_id: str) -> None:
    logger.info(f"[{client_id}] Connected from {addr}")
    print(f"\nClient connected: {client_id} {addr}\n")

    try:
        # 1. RSA keypair (server side optional, log only)
        RSAUtils.generate_keys()
        logger.info(f"[{client_id}] RSA context ready")

        # 2. Receive client public key
        msg = recv_message(conn)

        if msg.get("type") != "public_key":
            raise ValueError("Expected public_key")

        client_public_key = RSAUtils.load_public_key(
            msg["public_key"].encode("utf-8")
        )

        logger.info(f"[{client_id}] Public key received")

        # 3. Generate AES key
        symmetric_key = SymmetricUtils.generate_key()
        logger.info(f"[{client_id}] AES key generated")

        # 4. Encrypt AES key with RSA
        encrypted_key = RSAUtils.encrypt(client_public_key, symmetric_key)

        encrypted_key_b64 = base64.b64encode(encrypted_key).decode("utf-8")

        send_message(conn, {
            "type": "encrypted_symmetric_key",
            "encrypted_key": encrypted_key_b64
        })

        logger.info(f"[{client_id}] AES key sent")

        # -----------------------------
        # MESSAGE LOOP
        # -----------------------------

        print(f"Listening to {client_id}...\n")

        while True:
            try:
                msg = recv_message(conn)

            except ConnectionError:
                logger.info(f"[{client_id}] Disconnected")
                break

            msg_type = msg.get("type")

            # ---------------- encrypted message
            if msg_type == "encrypted_message":

                try:
                    iv = base64.b64decode(msg["iv"])
                    ciphertext = base64.b64decode(msg["ciphertext"])

                    plaintext = SymmetricUtils.decrypt(
                        symmetric_key,
                        iv,
                        ciphertext
                    )

                    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

                    print(f"[{timestamp}] {client_id}: {plaintext}")

                    logger.info(f"[{client_id}] Message decrypted")

                except Exception as e:
                    logger.exception(f"[{client_id}] AES decrypt error: {e}")

            # ---------------- disconnect
            elif msg_type == "disconnect":
                logger.info(f"[{client_id}] Client requested disconnect")
                break

            else:
                logger.warning(f"[{client_id}] Unknown message type: {msg_type}")

    except Exception as e:
        logger.exception(f"[{client_id}] Fatal error: {e}")

    finally:
        conn.close()
        logger.info(f"[{client_id}] Connection closed")
        print(f"Client {client_id} closed connection\n")


# -----------------------------
# MAIN SERVER
# -----------------------------

def main():
    print("=" * 50)
    print(" SYMMETRIC KEY DISTRIBUTION SERVER ")
    print("=" * 50)

    logger.info("Server starting")

    client_counter = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        print(f"Listening on {HOST}:{PORT}\n")

        try:
            while True:
                conn, addr = server.accept()
                client_counter += 1
                client_id = f"Client-{client_counter}"

                handle_client(conn, addr, client_id)

        except KeyboardInterrupt:
            logger.info("Server stopped manually")
            print("\nServer stopped")


if __name__ == "__main__":
    main()