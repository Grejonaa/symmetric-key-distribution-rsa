import socket
import json
import datetime

from logger import setup_logger
from key_manager import generate_symmetric_key, decrypt_message
from rsa_utils import receive_public_key, encrypt_symmetric_key


HOST = "127.0.0.1"
PORT = 65432

logger = setup_logger()


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""

    while len(buf) < n:
        chunk = conn.recv(n - len(buf))

        if not chunk:
            return b""

        buf += chunk

    return buf


def recv_message(conn: socket.socket) -> dict:
    raw_len = _recv_exact(conn, 4)

    if not raw_len:
        raise ConnectionError("Klienti u shkëput papritur.")

    msg_len = int.from_bytes(raw_len, "big")
    data = _recv_exact(conn, msg_len)

    return json.loads(data.decode("utf-8"))


def send_message(conn: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    msg_len = len(data).to_bytes(4, "big")

    conn.sendall(msg_len + data)


def handle_client(conn: socket.socket, addr: tuple, client_id: str) -> None:
    logger.info(f"[{client_id}] U lidh nga {addr[0]}:{addr[1]}")
    print(f"\n  Klient i lidhur: {client_id} ({addr[0]}:{addr[1]})\n")

    try:
        symmetric_key = generate_symmetric_key()
        logger.info(f"[{client_id}] Çelës AES-256 u gjenerua.")

        logger.info(f"[{client_id}] Duke pritur çelësin publik RSA...")
        msg = recv_message(conn)

        client_public_key = receive_public_key(msg)
        logger.info(
            f"[{client_id}] Çelësi publik RSA u mor "
            f"({client_public_key.size_in_bits()} bit)."
        )

        encrypted_key_b64 = encrypt_symmetric_key(
            symmetric_key,
            client_public_key
        )

        send_message(conn, {
            "type": "encrypted_symmetric_key",
            "encrypted_key": encrypted_key_b64,
        })

        logger.info(
            f"[{client_id}] Çelësi simetrik u dërgua i enkriptuar me RSA-OAEP."
        )
        print(f"  Çelësi simetrik i enkriptuar u dërgua te {client_id}.\n")

        print(f"  Duke pritur mesazhe nga {client_id}...\n")
        print("-" * 50)

        while True:
            try:
                msg = recv_message(conn)

            except (ConnectionError, json.JSONDecodeError):
                logger.info(f"[{client_id}] Klienti u shkëput. Sesioni mbaroi.")
                break

            msg_type = msg.get("type")

            if msg_type == "encrypted_message":
                try:
                    plaintext = decrypt_message(
                        symmetric_key,
                        msg["iv"],
                        msg["ciphertext"]
                    )

                    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

                    print(f"  [{timestamp}] Mesazh nga {client_id}:")
                    print(f"  > {plaintext}\n")

                    logger.info(f"[{client_id}] Mesazh i dekriptuar me sukses.")

                except Exception as error:
                    logger.error(f"[{client_id}] Gabim në dekriptim: {error}")
                    print(f"  Gabim në dekriptim: {error}\n")

            elif msg_type == "disconnect":
                logger.info(f"[{client_id}] Klienti u shkëput me sinjal.")
                print(f"  {client_id} u shkëput.\n")
                break

            else:
                logger.warning(
                    f"[{client_id}] Lloj mesazhi i panjohur: {msg_type}"
                )

    except ValueError as error:
        logger.error(f"[{client_id}] Gabim protokolli: {error}")
        print(f"  Gabim protokolli: {error}")

    except ConnectionError as error:
        logger.error(f"[{client_id}] Lidhja u ndërpre: {error}")
        print(f"  Lidhja u ndërpre: {error}")

    except Exception as error:
        logger.error(f"[{client_id}] Gabim i papritur: {error}")
        print(f"  Gabim i papritur: {error}")

    finally:
        conn.close()
        logger.info(f"[{client_id}] Socket u mbyll.")
        print(f"  Lidhja me {client_id} u mbyll.\n")


def main() -> None:
    print("=" * 50)
    print("   SYMMETRIC KEY DISTRIBUTION SERVER")
    print("=" * 50)
    print(f"   Host : {HOST}")
    print(f"   Port : {PORT}")
    print("=" * 50)
    print(f"\n  Duke pritur lidhje në {HOST}:{PORT}...\n")

    client_counter = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(5)

        logger.info(f"Serveri është aktiv në {HOST}:{PORT}")

        try:
            while True:
                conn, addr = server_sock.accept()
                client_counter += 1
                client_id = f"Client-{client_counter}"

                handle_client(conn, addr, client_id)

        except KeyboardInterrupt:
            print("\nServeri u ndal nga përdoruesi.")
            logger.info("Serveri u ndal.")


if __name__ == "__main__":
    main()