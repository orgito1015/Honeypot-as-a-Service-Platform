import logging
import socket
import threading

from .base import BaseHoneypot

logger = logging.getLogger(__name__)

_DEFAULT_PORT = 8080
_RECV_SIZE = 4096

_FAKE_RESPONSE = (
    "HTTP/1.1 200 OK\r\n"
    "Server: Apache/2.4.41 (Ubuntu)\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Content-Length: 45\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<html><body><h1>It works!</h1></body></html>"
)

_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}


class HTTPHoneypot(BaseHoneypot):
    """TCP honeypot that mimics an HTTP server to detect web probes and scans."""

    def __init__(self, host: str = "0.0.0.0", port: int = _DEFAULT_PORT):
        super().__init__(host, port, "HTTP")
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self._host, self._port))
        self._server_socket.listen(10)
        self._is_running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        logger.info("HTTPHoneypot listening on %s:%d", self._host, self._port)

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
        raw_request = ""
        try:
            data = client_sock.recv(_RECV_SIZE)
            raw_request = data.decode("utf-8", errors="replace")
            client_sock.sendall(_FAKE_RESPONSE.encode())
        except OSError:
            pass
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

        attack_data = self._parse_request(raw_request)
        self.log_attack(attacker_ip, attacker_port, attack_data, "HTTP_PROBE")

    @staticmethod
    def _parse_request(raw: str) -> str:
        """Extract method, path and headers from a raw HTTP request string."""
        lines = raw.splitlines()
        if not lines:
            return raw
        request_line = lines[0]
        parts = request_line.split()
        method = parts[0] if parts else "UNKNOWN"
        if method not in _HTTP_METHODS:
            method = "UNKNOWN"
        path = parts[1] if len(parts) > 1 else "/"
        headers = {
            line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip()
            for line in lines[1:]
            if ":" in line
        }
        return f"method={method} path={path} headers={headers}"
