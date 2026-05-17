import socket
import json
import base64

from client.logger import setup_logger

from crypto.rsa_utils import RSAUtils
from crypto.symmetric_utils import SymmetricUtils


HOST = "127.0.0.1"
PORT = 65432

logger = setup_logger()



# Transport helpers (length-prefixed JSON)

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""

    try:
        while len(buf) < n:

            chunk = sock.recv(n - len(buf))

            if not chunk:
                logger.error(
                    "Lidhja u ndërpre gjatë marrjes së të dhënave."
                )

                return b""

            buf += chunk

        return buf

    except Exception as e:

        logger.exception(
            f"Gabim gjatë pranimit të të dhënave: {e}"
        )

        return b""


def recv_message(sock: socket.socket) -> dict:

    try:
        raw_len = _recv_exact(sock, 4)

        if not raw_len:
            raise ConnectionError(
                "Lidhja u ndërpre papritur."
            )

        msg_len = int.from_bytes(raw_len, "big")

        data = _recv_exact(sock, msg_len)

        if not data:
            raise ConnectionError(
                "Nuk u morën të dhëna nga serveri."
            )

        logger.info("Mesazh u pranua nga serveri.")

        return json.loads(data.decode("utf-8"))

    except json.JSONDecodeError as e:

        logger.error(
            f"Gabim gjatë dekodimit JSON: {e}"
        )

        raise

    except Exception as e:

        logger.exception(
            f"Gabim gjatë pranimit të mesazhit: {e}"
        )

        raise


def send_message(sock: socket.socket, payload: dict) -> None:

    try:
        data = json.dumps(payload).encode("utf-8")

        msg_len = len(data).to_bytes(4, "big")

        sock.sendall(msg_len + data)

        logger.info("Mesazh u dërgua me sukses.")

    except Exception as e:

        logger.exception(
            f"Gabim gjatë dërgimit të mesazhit: {e}"
        )

        raise


# Main client logic


def main() -> None:

    logger.info("Klienti u startua.")

    print("=" * 50)
    print("   SYMMETRIC KEY DISTRIBUTION CLIENT")
    print("=" * 50)


    # Gjenero RSA çelesat

    print("\n  [1/4] Duke gjeneruar çelësat RSA...")

    try:
        private_key, public_key = RSAUtils.generate_keys()

        public_key_pem = RSAUtils.serialize_public_key(
            public_key
        ).decode("utf-8")

        logger.info(
            "Çelësat RSA u gjeneruan me sukses (2048-bit)."
        )

        print("  Çelësat RSA u gjeneruan me sukses.")

    except Exception as e:

        logger.exception(
            f"Gabim gjatë gjenerimit të çelësave RSA: {e}"
        )

        print(
            "  GABIM gjatë gjenerimit të çelësave RSA."
        )

        return

    # Lidhu me serverin

    print(
        f"\n  [2/4] Duke u lidhur me serverin "
        f"{HOST}:{PORT}..."
    )

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as sock:

        try:
            sock.connect((HOST, PORT))

            logger.info(
                f"U lidh me serverin {HOST}:{PORT}."
            )

            print("  Lidhja u krye me sukses.\n")

        except ConnectionRefusedError:

            logger.error(
                "Lidhja u refuzua – serveri nuk është aktiv."
            )

            print(
                f"  GABIM: Serveri nuk është aktiv "
                f"në {HOST}:{PORT}."
            )

            return

        except Exception as e:

            logger.exception(
                f"Gabim gjatë lidhjes me serverin: {e}"
            )

            print(
                "  GABIM gjatë lidhjes me serverin."
            )

            return

        # Dergo public key


        print(
            "  [3/4] Duke dërguar çelësin publik RSA "
            "te serveri..."
        )

        try:
            send_message(sock, {
                "type": "public_key",
                "public_key": public_key_pem,
            })

            logger.info(
                "Çelësi publik RSA u dërgua te serveri."
            )

        except Exception as e:

            logger.exception(
                f"Gabim gjatë dërgimit të public key: {e}"
            )

            print(
                "  GABIM gjatë dërgimit të public key."
            )

            return


        # Prano encrypted symmetric key

        print(
            "  Duke pritur çelësin simetrik AES "
            "të enkriptuar...\n"
        )

        try:
            response = recv_message(sock)

        except Exception as e:

            logger.exception(
                f"Gabim gjatë marrjes së symmetric key: {e}"
            )

            print(
                "  GABIM gjatë marrjes së symmetric key."
            )

            return

        if response.get("type") != "encrypted_symmetric_key":

            logger.error(
                f"Mesazh i papritur nga serveri: "
                f"{response.get('type')}"
            )

            print(
                f"  GABIM: Lloj mesazhi i papritur: "
                f"{response.get('type')}"
            )

            return

        # Dekripto symmetric key

        try:
            encrypted_key_bytes = base64.b64decode(
                response["encrypted_key"]
            )

            symmetric_key = RSAUtils.decrypt(
                private_key,
                encrypted_key_bytes
            )

            logger.info(
                "Çelësi simetrik AES u dekriptua me sukses."
            )

            print(
                "  [4/4] Çelësi simetrik AES u mor "
                "dhe u dekriptua me sukses!"
            )

        except Exception as e:

            logger.exception(
                f"Gabim gjatë dekriptimit të symmetric key: {e}"
            )

            print(
                "  GABIM gjatë dekriptimit të symmetric key."
            )

            return

        print("\n" + "=" * 50)
        print(
            "   SESIONI ËSHTË AKTIV – mund të dërgoni mesazhe"
        )

        print("   Shkruani 'quit' për të dalë.")

        print("=" * 50 + "\n")


        # Message loop

        while True:

            try:
                user_input = input(
                    "  Mesazhi juaj: "
                ).strip()

                logger.info(
                    "Përdoruesi shkroi një mesazh."
                )

            except (EOFError, KeyboardInterrupt):

                logger.warning(
                    "Klienti u mbyll nga përdoruesi."
                )

                user_input = "quit"

            except Exception as e:

                logger.exception(
                    f"Gabim gjatë input-it: {e}"
                )

                print(
                    "  GABIM gjatë leximit të input-it."
                )

                continue


            # Disconnect

            if user_input.lower() == "quit":

                try:
                    send_message(
                        sock,
                        {"type": "disconnect"}
                    )

                    logger.info(
                        "Klienti dërgoi disconnect."
                    )

                except Exception as e:

                    logger.exception(
                        f"Gabim gjatë disconnect: {e}"
                    )

                print(
                    "\n  Lidhja u mbyll. Mirupafshim!"
                )

                break

            if not user_input:

                logger.warning(
                    "Përdoruesi dërgoi input bosh."
                )

                continue


            # Encrypt message me AES

            try:
                iv, ciphertext = SymmetricUtils.encrypt(
                    symmetric_key,
                    user_input
                )

                logger.info(
                    "Mesazhi u enkriptua me AES."
                )

            except Exception as e:

                logger.exception(
                    f"Gabim gjatë enkriptimit AES: {e}"
                )

                print(
                    "  GABIM gjatë enkriptimit të mesazhit."
                )

                continue

            # Dergo encrypted message

            try:
                send_message(sock, {
                    "type": "encrypted_message",
                    "iv": base64.b64encode(iv).decode(
                        "utf-8"
                    ),
                    "ciphertext": base64.b64encode(
                        ciphertext
                    ).decode("utf-8"),
                })

                logger.info(
                    "Mesazh i enkriptuar u dërgua te serveri."
                )

                print("  Mesazhi u dërgua.\n")

            except Exception as e:

                logger.exception(
                    f"Gabim gjatë dërgimit të mesazhit: {e}"
                )

                print(
                    "  GABIM gjatë dërgimit të mesazhit."
                )



# Start application

if __name__ == "__main__":

    try:
        main()

    except Exception as e:

        logger.exception(
            f"Gabim kritik në client: {e}"
        )

        print(
            "\n  Ndodhi një gabim kritik në aplikacion."
        )