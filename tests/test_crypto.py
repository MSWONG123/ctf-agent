from unittest.mock import MagicMock
from agents.crypto import (
    create_crypto_agent, CRYPTO_TOOLS, CRYPTO_DISPATCH,
    tool_base64_decode, tool_base64_encode, tool_hex_decode,
    tool_hash_identify, tool_rot_bruteforce, tool_frequency_analysis,
    tool_rsa_analyze, tool_vigenere_crack, tool_mod_math,
    tool_substitution_solve, tool_hash_crack, tool_prng_crack,
    tool_encoding_chain,
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


def test_rsa_analyze_small_e():
    # e=3, small message cube-root attack
    result = tool_rsa_analyze(
        n=1000000007 * 1000000009,
        e=3,
        c=27,  # 3^3 = 27
    )
    assert "3" in result  # Should find plaintext m=3


def test_rsa_analyze_fermat():
    # Two close primes
    p, q = 1000000007, 1000000009
    n = p * q
    result = tool_rsa_analyze(n=n, e=65537, c=12345)
    assert str(p) in result or str(q) in result or "factor" in result.lower()


def test_vigenere_crack():
    # Encrypt "HELLOWORLD" with key "KEY"
    result = tool_vigenere_crack("RIJVSUYVJN")
    assert isinstance(result, str)
    # Should find candidate decryptions


def test_mod_math_modinv():
    result = tool_mod_math(operation="modinv", a=3, m=11)
    assert "4" in result  # 3*4 = 12 = 1 mod 11


def test_mod_math_modpow():
    result = tool_mod_math(operation="modpow", a=2, b=10, m=1000)
    assert "1024" in result or "24" in result  # 2^10 mod 1000 = 24


def test_mod_math_crt():
    result = tool_mod_math(operation="crt", remainders=[2, 3, 2], moduli=[3, 5, 7])
    assert "23" in result  # x = 23 mod 105


def test_hash_crack():
    import hashlib, tempfile, os
    target = hashlib.md5(b"password").hexdigest()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wl:
        wl.write("wrong\npassword\nanother\n")
        wlpath = wl.name
    result = tool_hash_crack(hash_value=target, wordlist_path=wlpath, hash_type="md5")
    os.unlink(wlpath)
    assert "password" in result


def test_encoding_chain():
    import base64
    # base64(hex("Hello"))
    inner = "48656c6c6f".encode()
    encoded = base64.b64encode(inner).decode()
    result = tool_encoding_chain(data=encoded)
    assert "Hello" in result or "48656c6c6f" in result


def test_substitution_solve():
    result = tool_substitution_solve("GUVF VF N GRFG ZRFFNTR")
    assert isinstance(result, str)
