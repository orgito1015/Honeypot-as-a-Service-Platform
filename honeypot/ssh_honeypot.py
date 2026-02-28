import logging
import socket
import threading

from .base import BaseHoneypot

logger = logging.getLogger(__name__)

_SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"
_DEFAULT_PORT = 2222
_RECV_SIZE = 1024


class SSHHoneypot(BaseHoneypot):
    """TCP honeypot that mimics an SSH server to capture brute-force attempts."""

    def __init__(self, host: str = "0.0.0.0", port: int = _DEFAULT_PORT):
        super().__init__(host, port, "SSH")
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Bind the socket and begin accepting connections in a daemon thread."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self._host, self._port))
        self._server_socket.listen(5)
        self._is_running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        logger.info("SSHHoneypot listening on %s:%d", self._host, self._port)

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
        raw_data = ""
        try:
            client_sock.settimeout(30)
            client_sock.sendall(_SSH_BANNER)
            data = client_sock.recv(_RECV_SIZE)
            raw_data = data.decode("utf-8", errors="replace").strip()
        except socket.timeout:
            pass
        except OSError:
            pass
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

        self.log_attack(attacker_ip, attacker_port, raw_data, "SSH_BRUTE_FORCE")
