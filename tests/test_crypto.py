from unittest.mock import MagicMock
from agents.crypto import (
    create_crypto_agent, CRYPTO_TOOLS, CRYPTO_DISPATCH,
    tool_base64_decode, tool_base64_encode, tool_hex_decode,
    tool_hash_identify, tool_rot_bruteforce, tool_frequency_analysis,
)


def test_crypto_tools_defined():
    names = [t["name"] for t in CRYPTO_TOOLS]
    assert "base64_decode" in names
    assert "base64_encode" in names
    assert "hex_decode" in names
    assert "hash_identify" in names
    assert "rot_bruteforce" in names
    assert "frequency_analysis" in names


def test_dispatch_matches_tools():
    tool_names = {t["name"] for t in CRYPTO_TOOLS}
    dispatch_names = set(CRYPTO_DISPATCH.keys())
    assert tool_names == dispatch_names


def test_create_crypto_agent():
    client = MagicMock()
    agent = create_crypto_agent(client)
    assert agent.name == "crypto"


def test_base64_decode():
    result = tool_base64_decode("SGVsbG8gV29ybGQ=")
    assert "Hello World" in result


def test_base64_encode():
    result = tool_base64_encode("Hello World")
    assert "SGVsbG8gV29ybGQ=" in result


def test_hex_decode():
    result = tool_hex_decode("48656c6c6f")
    assert "Hello" in result


def test_hash_identify_md5():
    result = tool_hash_identify("5d41402abc4b2a76b9719d911017c592")
    assert "MD5" in result


def test_hash_identify_sha256():
    result = tool_hash_identify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert "SHA-256" in result or "SHA256" in result


def test_rot_bruteforce():
    result = tool_rot_bruteforce("Uryyb Jbeyq")
    assert "Hello World" in result


def test_frequency_analysis():
    result = tool_frequency_analysis("aaabbbcccddd")
    assert "a" in result
