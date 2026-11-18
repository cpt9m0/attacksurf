"""A local HTTP server that answers too slowly, to test the call deadline on a real socket.

It serves one connection on 127.0.0.1: reads the request, sends `head`, then sends one `drip`
every `interval` seconds, the way a server can keep a request alive without ever tripping a
per-read timeout. It records whether a client connected and whether the client hung up.
"""

import socket
import threading
from time import monotonic
from types import TracebackType
from typing import Self

# Headers promising a long JSON body that only ever arrives one byte at a time.
TRICKLING_HEAD = (
    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 1000000\r\n\r\n"
)


class SlowServer:
    def __init__(
        self,
        head: bytes,
        drip: bytes | None = None,
        *,
        interval: float = 0.05,
        limit: float = 10.0,
    ) -> None:
        self._head = head
        self._drip = drip
        self._interval = interval
        self._limit = limit
        self._listener = socket.create_server(("127.0.0.1", 0))
        # Closing a socket doesn't wake an `accept()` blocked on it, so accept polls instead.
        self._listener.settimeout(0.1)
        self.url = f"http://127.0.0.1:{self._listener.getsockname()[1]}"
        self.connected = threading.Event()
        self.hung_up = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="slow-server", daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=5)

    def _serve(self) -> None:
        conn = self._accept()
        if conn is None:
            return
        self.connected.set()
        with conn:
            conn.settimeout(self._limit)
            try:
                conn.recv(65536)  # the request; what it says doesn't matter here
                conn.sendall(self._head)
                if self._drip is None:
                    if conn.recv(1) == b"":  # wait for the client to finish with it
                        self.hung_up.set()
                    return
                ends = monotonic() + self._limit
                while not self._stop.is_set() and monotonic() < ends:
                    conn.sendall(self._drip)
                    self._stop.wait(self._interval)
            except OSError:  # the client closed the connection mid-reply
                self.hung_up.set()

    def _accept(self) -> socket.socket | None:
        """The first client's connection, or None if none came before the limit or the end."""
        ends = monotonic() + self._limit
        while not self._stop.is_set() and monotonic() < ends:
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:  # the listener was closed: the test ended
                return None
            return conn
        return None
