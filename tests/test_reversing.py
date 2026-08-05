import os
import struct
import tempfile
from unittest.mock import MagicMock
from agents.reversing import (
    create_reversing_agent, REVERSING_TOOLS, REVERSING_DISPATCH,
    tool_file_identify, tool_strings_extract, tool_checksec,
    tool_elf_sections, tool_elf_symbols, tool_hexdump, tool_patch_bytes,
    tool_run_binary, tool_cyclic_pattern, tool_shellcode_gen,
)


def test_reversing_tools_defined():
    names = [t["name"] for t in REVERSING_TOOLS]
    assert "file_identify" in names
    assert "strings_extract" in names
    assert "checksec" in names
    assert "disassemble" in names
    assert "elf_sections" in names
    assert "elf_symbols" in names
    assert "hexdump" in names
    assert "patch_bytes" in names
    assert "run_binary" in names
    assert "cyclic_pattern" in names
    assert "shellcode_gen" in names


def test_dispatch_matches_tools():
    tool_names = {t["name"] for t in REVERSING_TOOLS}
    dispatch_names = set(REVERSING_DISPATCH.keys())
    assert tool_names == dispatch_names


def test_create_reversing_agent():
    client = MagicMock()
    agent = create_reversing_agent(client)
    assert agent.name == "reversing"


def test_file_identify_elf():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        # ELF magic bytes
        f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)
        f.flush()
        result = tool_file_identify(f.name)
    os.unlink(f.name)
    assert "ELF" in result


def test_file_identify_pe():
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 62)
        f.flush()
        result = tool_file_identify(f.name)
    os.unlink(f.name)
    assert "PE" in result or "MZ" in result


def test_strings_extract():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00\x00hello_world\x00\x00\x01\x02flag{test}\x00")
        f.flush()
        result = tool_strings_extract(f.name)
    os.unlink(f.name)
    assert "hello_world" in result
    assert "flag{test}" in result


def test_hexdump():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x41\x42\x43\x44\x45\x46")
        f.flush()
        result = tool_hexdump(f.name, offset=0, length=6)
    os.unlink(f.name)
    assert "41 42 43 44 45 46" in result or "ABCDEF" in result


def test_patch_bytes():
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\x00\x00\x00\x00")
        f.flush()
        result = tool_patch_bytes(f.name, offset=1, hex_bytes="41 42")
    with open(f.name, "rb") as f2:
        data = f2.read()
    os.unlink(f.name)
    assert data == b"\x00\x41\x42\x00"
    assert "Patched" in result


def test_cyclic_pattern_generate():
    result = tool_cyclic_pattern(action="generate", length=100)
    assert len(result) >= 100


def test_cyclic_pattern_find():
    result = tool_cyclic_pattern(action="find", pattern="aaab")
    assert isinstance(result, str)


def test_shellcode_gen():
    result = tool_shellcode_gen(arch="x64", payload="execve_bin_sh")
    assert "\\x" in result or "0x" in result.lower()
