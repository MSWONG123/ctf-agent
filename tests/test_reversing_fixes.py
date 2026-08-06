"""Accuracy-fix tests for the reversing agent ELF vaddr->offset mapping."""

import struct

from agents import reversing


def _make_elf64(seg_vaddr=0x400000, seg_offset=0x1000, seg_filesz=0x3000):
    """Minimal 64-bit ELF header + one PT_LOAD program header."""
    data = bytearray(64 + 56)
    data[0:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # little-endian
    struct.pack_into("<Q", data, 32, 64)   # e_phoff
    struct.pack_into("<H", data, 54, 56)   # e_phentsize
    struct.pack_into("<H", data, 56, 1)    # e_phnum
    ph = 64
    struct.pack_into("<I", data, ph + 0, 1)           # p_type = PT_LOAD
    struct.pack_into("<Q", data, ph + 8, seg_offset)  # p_offset
    struct.pack_into("<Q", data, ph + 16, seg_vaddr)  # p_vaddr
    struct.pack_into("<Q", data, ph + 32, seg_filesz) # p_filesz
    return bytes(data)


def test_elf_vaddr_to_offset_maps_load_segment():
    data = _make_elf64(seg_vaddr=0x400000, seg_offset=0x1000, seg_filesz=0x3000)
    # entry virtual address 0x400050 lives at file offset 0x1050
    assert reversing._elf_vaddr_to_offset(data, 0x400050) == 0x1050


def test_elf_vaddr_to_offset_out_of_range_returns_none():
    data = _make_elf64(seg_vaddr=0x400000, seg_offset=0x1000, seg_filesz=0x3000)
    assert reversing._elf_vaddr_to_offset(data, 0x999999) is None
