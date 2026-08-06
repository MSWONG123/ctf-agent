"""Accuracy-fix tests for the crypto agent (MT19937 untemper, RSA small-e root)."""

import random

from agents.crypto import tool_prng_crack, tool_rsa_analyze


def test_prng_crack_predicts_real_mt19937_sequence():
    """Untemper must reconstruct state so predictions match Python's MT19937."""
    rng = random.Random(0xC0FFEE)
    observed = [rng.getrandbits(32) for _ in range(624)]
    expected_next = [rng.getrandbits(32) for _ in range(5)]

    result = tool_prng_crack(observed, predict_count=5)

    for value in expected_next:
        assert str(value) in result, f"missing predicted value {value}"


def test_rsa_small_e_recovers_large_message():
    """Small-e cube-root attack must recover a message larger than the brute range."""
    m = int.from_bytes(b"flag{sm4ll_e_cube_root_recovery}", "big")  # ~256-bit
    e = 3
    c = pow(m, e)               # unreduced (m**e < n) — classic small-e CTF
    n = c + 12345               # modulus is irrelevant to the root attack

    result = tool_rsa_analyze(n, e, c)

    assert str(m) in result, "did not recover the plaintext integer"
    assert "flag{sm4ll_e_cube_root_recovery}" in result


def test_rsa_small_e_huge_modulus_does_not_crash():
    """c larger than the float range must not raise OverflowError."""
    m = int.from_bytes(b"A" * 200, "big")  # ~1600-bit message
    e = 3
    c = pow(m, e)                            # c far exceeds 1.8e308
    n = c + 7

    result = tool_rsa_analyze(n, e, c)  # must not raise

    assert str(m) in result
