import logging
import socket
import threading

from .base import BaseHoneypot

logger = logging.getLogger(__name__)

_DEFAULT_PORT = 2121
_RECV_SIZE = 1024
_BANNER = b"220 FTP Server Ready\r\n"
_USER_OK = b"331 Password required\r\n"
_PASS_FAIL = b"530 Login incorrect\r\n"
_GENERIC_ERR = b"500 Command not understood\r\n"


class FTPHoneypot(BaseHoneypot):
    """TCP honeypot that mimics an FTP server to capture credential brute-force attempts."""

    def __init__(self, host: str = "0.0.0.0", port: int = _DEFAULT_PORT):
        super().__init__(host, port, "FTP")
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self._host, self._port))
        self._server_socket.listen(5)
        self._is_running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        logger.info("FTPHoneypot listening on %s:%d", self._host, self._port)

    def stop(self):
        super().stop()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _accept_loop(self):
        while self._is_running:
            try:
                client_sock, addr = self._server_socket.accept()
            except OSError:
                break
            t = threading.Thread(
                target=self._handle_client,
                args=(client_sock, addr),
                daemon=True,
            )
            t.start()

    def _handle_client(self, client_sock: socket.socket, addr: tuple):
        attacker_ip, attacker_port = addr[0], addr[1]
        username = ""
        password = ""
        try:
            client_sock.sendall(_BANNER)
            # Collect up to two commands (USER + PASS)
            for _ in range(4):
                data = client_sock.recv(_RECV_SIZE)
                if not data:
                    break
                line = data.decode("utf-8", errors="replace").strip()
                upper = line.upper()
                if upper.startswith("USER"):
                    username = line[4:].strip()
                    client_sock.sendall(_USER_OK)
                elif upper.startswith("PASS"):
                    password = line[4:].strip()
                    client_sock.sendall(_PASS_FAIL)
                    break
                else:
                    client_sock.sendall(_GENERIC_ERR)
        except OSError:
            pass
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

        raw_data = f"USER={username} PASS={password}"
        self.log_attack(attacker_ip, attacker_port, raw_data, "FTP_BRUTE_FORCE")
