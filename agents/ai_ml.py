"""AI/ML agent — model probing, boundary finding, weight recovery, adversarial search."""

import socket
import time
import urllib.request
import json

import anthropic

from agents.base import BaseAgent


# --- Persistent connection store ---
_connections: dict[str, socket.socket] = {}


def _recv(sock, timeout=2.0):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data.decode(errors="replace")


# --- Tool implementations ---

def tool_probe_model(
    host: str = "", port: int = 0, url: str = "",
    data: str = "", method: str = "tcp"
) -> str:
    """Send input to a model and get output. Supports TCP and HTTP."""
    if method == "http" or url:
        if method == "http" and not url:
            return "ERROR: url is required for HTTP mode"
        try:
            if url:
                payload = json.dumps({"input": data}).encode()
                req = urllib.request.Request(
                    url, data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.read().decode(errors="replace")
        except Exception as e:
            return f"ERROR: {e}"

    # TCP mode
    key = f"{host}:{port}"
    if key not in _connections:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((host, port))
            _connections[key] = s
            time.sleep(0.5)
            banner = _recv(s, timeout=3.0)
            return f"Connected.\n{banner}"
        except Exception as e:
            return f"ERROR: {e}"

    s = _connections[key]
    try:
        s.sendall((data + "\n").encode())
        time.sleep(0.3)
        return _recv(s, timeout=1.5) or "(no response)"
    except Exception as e:
        if key in _connections:
            del _connections[key]
        return f"ERROR: {e}"


def tool_binary_search_boundary(observations: list) -> str:
    """Analyze observations to find the decision boundary.

    Each observation: {"input": <number>, "output": <0 or 1>}
    """
    zeros = sorted([o["input"] for o in observations if o["output"] == 0])
    ones = sorted([o["input"] for o in observations if o["output"] == 1])

    if not zeros or not ones:
        return "Cannot determine boundary: need both 0 and 1 outputs."

    max_zero = max(zeros)
    min_one = min(ones)

    if max_zero < min_one:
        return (f"Boundary between {max_zero} (last 0) and {min_one} (first 1)\n"
                f"Threshold ~ {(max_zero + min_one) / 2}\n"
                f"The model fires (1) when input >= ~{min_one}")
    else:
        min_zero = min(zeros)
        max_one = max(ones)
        return (f"Boundary between {max_one} (last 1) and {min_zero} (first 0)\n"
                f"Threshold ~ {(max_one + min_zero) / 2}\n"
                f"The model fires (1) when input <= ~{max_one}")


def tool_grid_probe_2d(
    host: str, port: int,
    x_range: list, y_range: list,
    format_str: str = "{x},{y}"
) -> str:
    """Probe a 2D model over a grid and return the output map."""
    results = []
    for x in x_range:
        row = []
        for y in y_range:
            data = format_str.format(x=x, y=y)
            resp = tool_probe_model(host=host, port=port, data=data)
            if "fires" in resp.lower() or "1" in resp.split()[-1:]:
                row.append("1")
            elif "quiet" in resp.lower() or "0" in resp.split()[-1:]:
                row.append("0")
            else:
                row.append("?")
            results.append({"x": x, "y": y, "output": row[-1], "raw": resp.strip()[:80]})
        # Small delay between rows
        time.sleep(0.1)

    # Format as grid
    lines = [f"Grid probe results ({len(x_range)}x{len(y_range)}):"]
    header = "    " + " ".join(f"{y:3d}" for y in y_range)
    lines.append(header)
    idx = 0
    for x in x_range:
        row_str = f"{x:3d} "
        for y in y_range:
            row_str += f"  {results[idx]['output']}"
            idx += 1
        lines.append(row_str)

    return "\n".join(lines)


def tool_linear_solve(equations: list) -> str:
    """Solve Ax = b using Gaussian elimination.

    Each equation is a list: [a1, a2, ..., an, b] representing a1*x1 + a2*x2 + ... = b
    """
    n = len(equations)
    if n == 0:
        return "No equations provided."

    # Build augmented matrix
    m = [row[:] for row in equations]
    cols = len(m[0]) - 1

    if cols != n:
        return f"System is {'over' if n > cols else 'under'}determined ({n} equations, {cols} unknowns)"

    # Forward elimination
    for col in range(cols):
        # Find pivot
        max_row = col
        for row in range(col + 1, n):
            if abs(m[row][col]) > abs(m[max_row][col]):
                max_row = row
        m[col], m[max_row] = m[max_row], m[col]

        if abs(m[col][col]) < 1e-12:
            return "Singular matrix — no unique solution."

        for row in range(col + 1, n):
            factor = m[row][col] / m[col][col]
            for j in range(col, cols + 1):
                m[row][j] -= factor * m[col][j]

    # Back substitution
    x = [0.0] * cols
    for i in range(cols - 1, -1, -1):
        x[i] = m[i][cols]
        for j in range(i + 1, cols):
            x[i] -= m[i][j] * x[j]
        x[i] /= m[i][i]

    lines = ["Solution:"]
    for i, val in enumerate(x):
        if abs(val - round(val)) < 1e-6:
            lines.append(f"  x{i + 1} = {int(round(val))}")
        else:
            lines.append(f"  x{i + 1} = {val:.6f}")

    return "\n".join(lines)


def tool_confusion_matrix(data: list) -> str:
    """Build confusion matrix from classification results.

    Each entry: {"input": <any>, "expected": <0 or 1>, "actual": <0 or 1>}
    """
    tp = fp = tn = fn = 0
    for d in data:
        exp, act = d["expected"], d["actual"]
        if exp == 1 and act == 1:
            tp += 1
        elif exp == 0 and act == 0:
            tn += 1
        elif exp == 0 and act == 1:
            fp += 1
        else:
            fn += 1

    total = len(data)
    accuracy = (tp + tn) / total if total else 0

    return (f"Confusion Matrix:\n"
            f"  TP={tp} FP={fp}\n"
            f"  FN={fn} TN={tn}\n"
            f"Total: {total}, Accuracy: {accuracy:.2%}")


def tool_adversarial_search(
    host: str, port: int,
    boundary_value: float,
    epsilon: float = 0.01,
    num_steps: int = 20,
) -> str:
    """Search for adversarial inputs near the decision boundary."""
    results = []
    for i in range(num_steps):
        val = boundary_value + (i - num_steps // 2) * epsilon
        resp = tool_probe_model(host=host, port=port, data=str(val))
        output = "1" if "fires" in resp.lower() else "0"
        results.append(f"  x={val:.6f}: output={output}")

    return "Adversarial search results:\n" + "\n".join(results)


def tool_ascii_pattern_send(
    target_bits: str,
    zero_values: list,
    one_values: list,
) -> str:
    """Compute a sequence of values that produces a target bit pattern.

    Returns a string representation of the list of values to send
    (avoids back-to-back repeats).

    Note: if a group has only one value, back-to-back repeat avoidance
    cannot be applied for consecutive bits in that group and the single
    value will be repeated — this is an accepted edge-case limitation.
    """
    sequence = []
    for bit in target_bits:
        if bit == "0":
            vals = zero_values
        else:
            vals = one_values

        if sequence and sequence[-1] in vals:
            # Pick a different value from the same group.
            # If the group has only one value, the for-else falls through and
            # vals[0] is appended anyway (repeat unavoidable — edge case).
            for v in vals:
                if v != sequence[-1]:
                    sequence.append(v)
                    break
            else:
                sequence.append(vals[0])
        else:
            sequence.append(vals[0])

    return str(sequence)


# --- Tool definitions ---

AI_ML_TOOLS = [
    {
        "name": "probe_model",
        "description": "Send input to a model endpoint (TCP or HTTP) and get the response. Maintains persistent TCP connections.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname for TCP connection"},
                "port": {"type": "integer", "description": "Port for TCP connection"},
                "url": {"type": "string", "description": "URL for HTTP API endpoint"},
                "data": {"type": "string", "description": "Data to send to the model"},
                "method": {"type": "string", "enum": ["tcp", "http"], "default": "tcp"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "binary_search_boundary",
        "description": "Analyze observation data to find the 1D decision boundary. Input: list of {input, output} observations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "observations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "input": {"type": "number"},
                            "output": {"type": "integer"},
                        },
                    },
                    "description": "List of {input: number, output: 0 or 1} observations",
                },
            },
            "required": ["observations"],
        },
    },
    {
        "name": "grid_probe_2d",
        "description": "Probe a 2D model over a grid of (x,y) values. Returns output map.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname"},
                "port": {"type": "integer", "description": "Port"},
                "x_range": {"type": "array", "items": {"type": "integer"}, "description": "List of x values"},
                "y_range": {"type": "array", "items": {"type": "integer"}, "description": "List of y values"},
                "format_str": {"type": "string", "description": "Format string for input, e.g. '{x},{y}'", "default": "{x},{y}"},
            },
            "required": ["host", "port", "x_range", "y_range"],
        },
    },
    {
        "name": "linear_solve",
        "description": "Solve a system of linear equations using Gaussian elimination. Each equation is [a1, a2, ..., an, b] for a1*x1 + a2*x2 + ... = b.",
        "input_schema": {
            "type": "object",
            "properties": {
                "equations": {
                    "type": "array",
                    "items": {"type": "array", "items": {"type": "number"}},
                    "description": "List of equations, each as [coefficients..., constant]",
                },
            },
            "required": ["equations"],
        },
    },
    {
        "name": "confusion_matrix",
        "description": "Build a confusion matrix from classification results: TP, FP, TN, FN, accuracy.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "input": {},
                            "expected": {"type": "integer"},
                            "actual": {"type": "integer"},
                        },
                    },
                    "description": "List of {input, expected, actual} entries",
                },
            },
            "required": ["data"],
        },
    },
    {
        "name": "adversarial_search",
        "description": "Search for inputs near the decision boundary that flip the model's output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "boundary_value": {"type": "number", "description": "Approximate boundary value"},
                "epsilon": {"type": "number", "description": "Step size for perturbation", "default": 0.01},
                "num_steps": {"type": "integer", "description": "Number of probes", "default": 20},
            },
            "required": ["host", "port", "boundary_value"],
        },
    },
    {
        "name": "ascii_pattern_send",
        "description": "Compute a sequence of values that produces a target bit pattern (e.g. '01110000' for ASCII 'p'), avoiding back-to-back repeats.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_bits": {"type": "string", "description": "Target bit string, e.g. '01110000'"},
                "zero_values": {"type": "array", "items": {"type": "number"}, "description": "Values that produce output 0"},
                "one_values": {"type": "array", "items": {"type": "number"}, "description": "Values that produce output 1"},
            },
            "required": ["target_bits", "zero_values", "one_values"],
        },
    },
]

AI_ML_DISPATCH = {
    "probe_model": lambda **kw: tool_probe_model(**kw),
    "binary_search_boundary": lambda **kw: tool_binary_search_boundary(**kw),
    "grid_probe_2d": lambda **kw: tool_grid_probe_2d(**kw),
    "linear_solve": lambda **kw: tool_linear_solve(**kw),
    "confusion_matrix": lambda **kw: tool_confusion_matrix(**kw),
    "adversarial_search": lambda **kw: tool_adversarial_search(**kw),
    "ascii_pattern_send": lambda **kw: tool_ascii_pattern_send(**kw),
}

AI_ML_SYSTEM_PROMPT = """You are an AI/ML security agent for CTF challenges.

Strategy:
1. Connect to the service with probe_model and read the rules carefully.
2. Probe the model systematically to map its behavior.
3. For 1D models: probe endpoints of the input range, then use binary_search_boundary.
4. For 2D models: use grid_probe_2d to map the decision surface.
5. Use linear_solve to recover integer weights and bias from boundary observations.
6. For ASCII pattern challenges: use ascii_pattern_send to compute the value sequence.
7. Track your query count — CTF services usually limit queries.

Common CTF AI challenges:
- 1D/2D perceptron: find decision boundary, recover weights w1, w2, bias b
- Neural network probing: map inputs to outputs, find hidden logic
- Adversarial examples: craft inputs near the boundary that flip classification
- ASCII encoding: produce bit patterns by choosing inputs on correct side of boundary

Always report found weights, boundaries, and flags verbatim."""


def create_ai_ml_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create an AI/ML agent."""
    return BaseAgent(
        name="ai_ml",
        system_prompt=AI_ML_SYSTEM_PROMPT,
        tools=AI_ML_TOOLS,
        tool_dispatch=AI_ML_DISPATCH,
        client=client,
    )
