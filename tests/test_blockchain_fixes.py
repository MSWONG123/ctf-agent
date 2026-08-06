"""Accuracy-fix tests for the blockchain agent abi_decode."""

from agents.blockchain import tool_abi_decode


def test_abi_decode_signed_negative_int():
    """int256 must be decoded as two's complement, not a huge positive."""
    word = (-12345) & ((1 << 256) - 1)
    data = "0x" + f"{word:064x}"

    result = tool_abi_decode(data, "int256")

    assert "-12345" in result


def test_abi_decode_signed_small_width():
    """int8 = -1 (ABI sign-extended) must decode to -1."""
    data = "0x" + "f" * 64  # all ones -> -1 for any signed width

    result = tool_abi_decode(data, "int8")

    assert "-1" in result


def test_abi_decode_unsigned_still_positive():
    data = "0x" + f"{42:064x}"
    result = tool_abi_decode(data, "uint256")
    assert "42" in result


def test_abi_decode_dynamic_string():
    """A dynamic `string` argument must be decoded via its offset, not as a raw word."""
    head = f"{32:064x}"                    # offset to the tail
    length = f"{2:064x}"                   # length = 2
    data_word = b"hi".hex().ljust(64, "0")  # "hi" right-padded
    encoded = "0x" + head + length + data_word

    result = tool_abi_decode(encoded, "string")

    assert "hi" in result
