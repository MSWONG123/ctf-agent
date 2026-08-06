"""Accuracy-fix tests for the netcat agent (response timing + lossless decode)."""

import socket
import threading
import time

from agents import netcat


def _start_slow_server(delay=2.0, banner=b"BANNER\n"):
    """Server that sends a banner, then waits `delay`s before echoing each line."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def handle():
        try:
            conn, _ = srv.accept()
            if banner:
                conn.sendall(banner)
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                time.sleep(delay)
                conn.sendall(b"RESPONSE:" + data)
            conn.close()
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def test_nc_send_waits_for_slow_response():
    """A server slower than the old 1.5s window must not be missed / desynced."""
    netcat._connections.clear()
    port = _start_slow_server(delay=2.0)
    try:
        netcat.tool_nc_connect("127.0.0.1", port)
        resp = netcat.tool_nc_send("127.0.0.1", port, "hello")
    finally:
        netcat.tool_nc_close("127.0.0.1", port)
        netcat._connections.clear()
    assert "RESPONSE:hello" in resp, f"slow response was missed: {resp!r}"


def test_nc_connect_preserves_non_utf8_bytes():
    """Non-UTF-8 bytes in a response must survive losslessly (not become U+FFFD)."""
    netcat._connections.clear()
    port = _start_slow_server(delay=0.0, banner=b"\xff\xfeFLAG\n")
    try:
        banner = netcat.tool_nc_connect("127.0.0.1", port)
    finally:
        netcat.tool_nc_close("127.0.0.1", port)
        netcat._connections.clear()
    assert "�" not in banner
    assert b"\xff\xfe" in banner.encode("latin-1")
