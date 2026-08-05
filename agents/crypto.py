"""Crypto agent — decoding, hash ID, cipher brute-force, frequency analysis."""

import base64
import binascii
import hashlib
import string
from collections import Counter

import anthropic

from agents.base import BaseAgent


# --- Tool implementations ---

def tool_base64_decode(data: str) -> str:
    """Decode a base64-encoded string."""
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="replace")
        return f"Decoded: {decoded}"
    except Exception as e:
        return f"ERROR decoding base64: {e}"


def tool_base64_encode(data: str) -> str:
    """Encode a string to base64."""
    encoded = base64.b64encode(data.encode()).decode()
    return f"Encoded: {encoded}"


def tool_hex_decode(data: str) -> str:
    """Decode a hex-encoded string."""
    try:
        clean = data.replace(" ", "").replace("0x", "").replace("\\x", "")
        decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
        return f"Decoded: {decoded}"
    except Exception as e:
        return f"ERROR decoding hex: {e}"


def tool_hash_identify(hash_str: str) -> str:
    """Identify the likely hash type based on length and character set."""
    h = hash_str.strip()
    length = len(h)
    results = []

    hash_types = {
        32: ["MD5", "NTLM"],
        40: ["SHA-1"],
        56: ["SHA-224"],
        64: ["SHA-256"],
        96: ["SHA-384"],
        128: ["SHA-512"],
    }

    if length in hash_types:
        try:
            int(h, 16)
            results.extend(hash_types[length])
        except ValueError:
            pass

    if h.startswith("$2b$") or h.startswith("$2a$") or h.startswith("$2y$"):
        results.append("bcrypt")
    elif h.startswith("$6$"):
        results.append("SHA-512 crypt")
    elif h.startswith("$5$"):
        results.append("SHA-256 crypt")
    elif h.startswith("$1$"):
        results.append("MD5 crypt")

    if not results:
        results.append(f"Unknown (length={length})")

    return f"Hash: {h}\nLength: {length}\nPossible types: {', '.join(results)}"


def tool_rot_bruteforce(text: str) -> str:
    """Try all ROT-N (Caesar cipher) rotations (1-25)."""
    results = []
    for n in range(1, 26):
        decoded = ""
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decoded += chr((ord(c) - base + n) % 26 + base)
            else:
                decoded += c
        results.append(f"ROT-{n:2d}: {decoded}")
    return "\n".join(results)


def tool_xor_bruteforce(data: str, max_key_len: int = 1) -> str:
    """XOR brute-force with single-byte keys (0x00-0xFF)."""
    try:
        raw = bytes.fromhex(data.replace(" ", ""))
    except ValueError:
        raw = data.encode()

    results = []
    for key in range(256):
        decoded = bytes([b ^ key for b in raw])
        try:
            text = decoded.decode("ascii")
            if all(c in string.printable for c in text):
                results.append(f"Key 0x{key:02x}: {text}")
        except UnicodeDecodeError:
            continue

    if not results:
        return "No printable ASCII results found for any single-byte XOR key."
    return "\n".join(results[:50])


def tool_frequency_analysis(text: str) -> str:
    """Perform character frequency analysis on text."""
    letters = [c.lower() for c in text if c.isalpha()]
    total = len(letters)
    if total == 0:
        return "No alphabetic characters found."

    counter = Counter(letters)
    lines = [f"Total letters: {total}\n"]
    lines.append("Frequency (descending):")
    for char, count in counter.most_common():
        pct = count / total * 100
        bar = "#" * int(pct / 2)
        lines.append(f"  {char}: {count:4d} ({pct:5.1f}%) {bar}")

    english_freq = "etaoinshrdlcumwfgypbvkjxqz"
    sorted_chars = "".join(c for c, _ in counter.most_common())
    lines.append(f"\nYour text order:  {sorted_chars}")
    lines.append(f"English expected: {english_freq}")

    return "\n".join(lines)


# --- Tool definitions ---

CRYPTO_TOOLS = [
    {
        "name": "base64_decode",
        "description": "Decode a base64-encoded string.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Base64-encoded string to decode"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "base64_encode",
        "description": "Encode a string to base64.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "String to encode"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "hex_decode",
        "description": "Decode a hex-encoded string to text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Hex string (e.g. '48656c6c6f' or '0x48 0x65')"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "hash_identify",
        "description": "Identify the likely type of a hash based on its length and format.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_str": {"type": "string", "description": "The hash string to identify"},
            },
            "required": ["hash_str"],
        },
    },
    {
        "name": "rot_bruteforce",
        "description": "Try all 25 ROT-N (Caesar cipher) rotations on a string. Useful for simple substitution ciphers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Ciphertext to brute-force"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "xor_bruteforce",
        "description": "XOR brute-force with all single-byte keys (0x00-0xFF). Input can be hex or ASCII.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Data to XOR (hex string or raw text)"},
                "max_key_len": {"type": "integer", "description": "Max key length (default 1)", "default": 1},
            },
            "required": ["data"],
        },
    },
    {
        "name": "frequency_analysis",
        "description": "Perform character frequency analysis. Compares letter distribution to English language frequencies.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to analyze"},
            },
            "required": ["text"],
        },
    },
]

CRYPTO_DISPATCH = {
    "base64_decode": lambda **kw: tool_base64_decode(**kw),
    "base64_encode": lambda **kw: tool_base64_encode(**kw),
    "hex_decode": lambda **kw: tool_hex_decode(**kw),
    "hash_identify": lambda **kw: tool_hash_identify(**kw),
    "rot_bruteforce": lambda **kw: tool_rot_bruteforce(**kw),
    "xor_bruteforce": lambda **kw: tool_xor_bruteforce(**kw),
    "frequency_analysis": lambda **kw: tool_frequency_analysis(**kw),
}

CRYPTO_SYSTEM_PROMPT = """You are a cryptography agent for CTF challenges and authorized security testing.
Your job is to analyze, decode, and crack encoded or encrypted data.

Strategy:
1. Examine the input data — look at length, character set, patterns, and structure.
2. Try common encodings first: base64, hex.
3. If it looks like a hash, identify it with hash_identify.
4. If it looks like a substitution cipher, try rot_bruteforce.
5. If it might be XOR-encrypted, try xor_bruteforce.
6. Use frequency_analysis to compare letter distributions to English.
7. Combine techniques — data may be multi-layered (e.g., base64 wrapping hex wrapping ROT13).

Report clearly:
- What encoding/encryption was identified
- The decoded/decrypted result
- Confidence level and reasoning
- If unable to crack, describe what was tried and suggest next steps"""


def create_crypto_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a crypto agent instance."""
    return BaseAgent(
        name="crypto",
        system_prompt=CRYPTO_SYSTEM_PROMPT,
        tools=CRYPTO_TOOLS,
        tool_dispatch=CRYPTO_DISPATCH,
        client=client,
    )
