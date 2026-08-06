"""Netcat agent — interactive TCP sessions for CTF challenges."""

import socket
import time

import anthropic

from agents.base import BaseAgent


# Module-level connection store keyed by host:port
_connections: dict[str, socket.socket] = {}


def _get_conn(host: str, port: int) -> socket.socket | None:
    key = f"{host}:{port}"
    return _connections.get(key)


def _recv(sock: socket.socket, idle: float = 1.0, deadline: float = 8.0) -> str:
    """Read a response robustly.

    Wait up to `deadline` seconds for the first byte (so a slow server is not
    missed and its reply does not desync onto the next send), then keep reading
    until `idle` seconds pass with no more data. Decodes with latin-1 so binary
    responses/flags survive losslessly instead of turning into U+FFFD.
    """
    end = time.monotonic() + deadline
    data = b""
    got_any = False
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(idle if got_any else remaining)
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            got_any = True
        except socket.timeout:
            break
    return data.decode("latin-1")


def tool_nc_connect(host: str, port: int) -> str:
    """Open a TCP connection and return the banner."""
    key = f"{host}:{port}"
    # Close any existing connection to this target
    if key in _connections:
        try:
            _connections[key].close()
        except Exception:
            pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        _connections[key] = s
        banner = _recv(s, deadline=5.0)
        return f"Connected to {key}\n\n{banner}"
    except Exception as e:
        return f"ERROR connecting to {key}: {e}"


def tool_nc_send(host: str, port: int, data: str) -> str:
    """Send data over an existing TCP connection and return the response."""
    key = f"{host}:{port}"
    s = _connections.get(key)
    if not s:
        return f"ERROR: No open connection to {key}. Use nc_connect first."

    try:
        s.sendall((data + "\n").encode())
        resp = _recv(s, deadline=8.0)
        return resp if resp else "(no response)"
    except Exception as e:
        return f"ERROR sending to {key}: {e}"


def tool_nc_close(host: str, port: int) -> str:
    """Close a TCP connection."""
    key = f"{host}:{port}"
    s = _connections.get(key)
    if s:
        try:
            s.close()
        except Exception:
            pass
        del _connections[key]
        return f"Closed connection to {key}"
    return f"No open connection to {key}"


# --- Tool definitions ---

NETCAT_TOOLS = [
    {
        "name": "nc_connect",
        "description": "Open a TCP connection to host:port and read the banner. Returns the initial server output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP"},
                "port": {"type": "integer", "description": "TCP port number"},
            },
            "required": ["host", "port"],
        },
    },
    {
        "name": "nc_send",
        "description": "Send a line of text over an open TCP connection and return the server's response. Appends a newline automatically.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP of open connection"},
                "port": {"type": "integer", "description": "TCP port of open connection"},
                "data": {"type": "string", "description": "Data to send (newline is appended)"},
            },
            "required": ["host", "port", "data"],
        },
    },
    {
        "name": "nc_close",
        "description": "Close an open TCP connection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP"},
                "port": {"type": "integer", "description": "TCP port"},
            },
            "required": ["host", "port"],
        },
    },
]

NETCAT_DISPATCH = {
    "nc_connect": lambda **kw: tool_nc_connect(**kw),
    "nc_send": lambda **kw: tool_nc_send(**kw),
    "nc_close": lambda **kw: tool_nc_close(**kw),
}

NETCAT_SYSTEM_PROMPT = """You are a netcat agent for CTF challenges and authorized security testing.
Your job is to interact with TCP services — connect, send data, read responses, and solve interactive challenges.

You have three tools:
- nc_connect: Open a TCP connection and read the banner
- nc_send: Send a line of text and read the response
- nc_close: Close the connection

Strategy:
1. Connect to the target and carefully read the banner/instructions.
2. Understand what the service expects (format, bounds, rules).
3. Interact methodically — probe, gather information, then execute a solution.
4. For binary search / threshold finding: probe endpoints first, then narrow down.
5. Report any flags, secrets, or key findings you discover.

Be precise with your inputs. Read responses carefully. Track your state (what you've sent, what outputs you've seen).
When you find a flag or the service reveals a secret, include it verbatim in your final response."""


def create_netcat_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a netcat agent instance."""
    return BaseAgent(
        name="netcat",
        system_prompt=NETCAT_SYSTEM_PROMPT,
        tools=NETCAT_TOOLS,
        tool_dispatch=NETCAT_DISPATCH,
        client=client,
    )
