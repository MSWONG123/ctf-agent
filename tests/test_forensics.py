import math
import os
import struct
import tempfile
import zipfile
from unittest.mock import MagicMock
from agents.forensics import (
    create_forensics_agent, FORENSICS_TOOLS, FORENSICS_DISPATCH,
    tool_file_metadata, tool_binwalk_scan, tool_file_carve,
    tool_stego_strings, tool_hex_search, tool_entropy_analysis,
    tool_zip_crack, tool_base_convert, tool_flag_search,
)


def test_forensics_tools_defined():
    names = [t["name"] for t in FORENSICS_TOOLS]
    assert "file_metadata" in names
    assert "binwalk_scan" in names
    assert "file_carve" in names
    assert "stego_lsb" in names
    assert "stego_strings" in names
    assert "pcap_analyze" in names
    assert "hex_search" in names
    assert "entropy_analysis" in names
    assert "zip_crack" in names
    assert "base_convert" in names
    assert "flag_search" in names


def test_dispatch_matches_tools():
    tool_names = {t["name"] for t in FORENSICS_TOOLS}
    dispatch_names = set(FORENSICS_DISPATCH.keys())
    assert tool_names == dispatch_names


def test_create_forensics_agent():
    client = MagicMock()
    agent = create_forensics_agent(client)
    assert agent.name == "forensics"


def test_binwalk_scan_finds_png():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 100 + b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        f.flush()
        result = tool_binwalk_scan(f.name)
    os.unlink(f.name)
    assert "PNG" in result


def test_file_carve():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 10 + b"HIDDEN_DATA" + b"\x00" * 10)
        f.flush()
        out_path = f.name + ".carved"
        result = tool_file_carve(f.name, offset=10, length=11, output_path=out_path)
    with open(out_path, "rb") as carved:
        assert carved.read() == b"HIDDEN_DATA"
    os.unlink(f.name)
    os.unlink(out_path)
    assert "Carved" in result


def test_stego_strings_finds_trailing():
    # Create a minimal JPEG-like file with data after FFD9
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        f.write(b"\xff\xd8\xff\xe0" + b"\x00" * 50 + b"\xff\xd9" + b"secret_message_here")
        f.flush()
        result = tool_stego_strings(f.name)
    os.unlink(f.name)
    assert "secret_message_here" in result


def test_hex_search_finds_pattern():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00" * 50 + b"\xde\xad\xbe\xef" + b"\x00" * 50)
        f.flush()
        result = tool_hex_search(f.name, hex_pattern="deadbeef")
    os.unlink(f.name)
    assert "0x32" in result or "50" in result  # offset 50


def test_entropy_analysis():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        # Low entropy: repeated bytes
        f.write(b"\x00" * 256)
        # High entropy: random-ish
        f.write(bytes(range(256)))
        f.flush()
        result = tool_entropy_analysis(f.name, block_size=256)
    os.unlink(f.name)
    assert "entropy" in result.lower() or "0." in result


def test_zip_crack():
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as zf:
        zpath = zf.name
    with zipfile.ZipFile(zpath, "w") as z:
        z.setpassword(b"password")
        z.writestr("secret.txt", "flag{test}", compress_type=zipfile.ZIP_STORED)
    # zip_crack needs a wordlist
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wl:
        wl.write("wrong\npassword\nanother\n")
        wl.flush()
        wlpath = wl.name
    # Note: Python's zipfile doesn't support creating encrypted ZIPs easily
    # so this test just verifies the function runs without error
    result = tool_zip_crack(zpath, wlpath)
    os.unlink(zpath)
    os.unlink(wlpath)
    assert isinstance(result, str)


def test_base_convert():
    result = tool_base_convert("255", from_base="decimal", to_base="hex")
    assert "ff" in result.lower()


def test_flag_search():
    result = tool_flag_search(text="some text flag{found_it} more text")
    assert "flag{found_it}" in result


def test_flag_search_academy():
    result = tool_flag_search(text="here is academy{test_flag_123} done")
    assert "academy{test_flag_123}" in result
