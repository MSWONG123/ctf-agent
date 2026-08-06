"""Accuracy-fix tests for the ai_ml agent."""

import socket
import threading

from agents import ai_ml


def _start_echo_server(banner=b""):
    """Start a one-shot TCP server that sends an optional banner then echoes input."""
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
                conn.sendall(b"echo:" + data)
            conn.close()
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


def test_probe_model_sends_data_on_first_call():
    """The first probe to a host:port must actually send the payload, not just read the banner."""
    ai_ml._connections.clear()
    port = _start_echo_server(banner=b"WELCOME\n")
    try:
        result = ai_ml.tool_probe_model(host="127.0.0.1", port=port, data="ping")
    finally:
        ai_ml._connections.clear()
    assert "ping" in result, f"payload was not sent on first call: {result!r}"


def test_classify_uses_digit_fallback():
    assert ai_ml._classify("1") == "1"
    assert ai_ml._classify("0") == "0"
    assert ai_ml._classify("fires") == "1"
    assert ai_ml._classify("quiet") == "0"
    assert ai_ml._classify("banana") == "?"


def test_grid_probe_2d_bad_format_does_not_crash():
    result = ai_ml.tool_grid_probe_2d(
        host="127.0.0.1", port=1, x_range=[0], y_range=[0], format_str="{z}"
    )
    assert "format" in result.lower() or "error" in result.lower()


def test_ascii_pattern_send_empty_group_does_not_crash():
    result = ai_ml.tool_ascii_pattern_send(target_bits="0", zero_values=[], one_values=[1])
    assert "error" in result.lower() or "empty" in result.lower()
