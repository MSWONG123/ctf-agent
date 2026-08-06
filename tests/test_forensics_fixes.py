"""Accuracy-fix tests for the forensics agent (PNG LSB unfiltering, zip_crack)."""

import struct
import zipfile
import zlib

from agents import forensics


def _png_chunk(ctype, data):
    return (struct.pack(">I", len(data)) + ctype + data
            + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF))


def _make_png_lsb(message: bytes) -> bytes:
    """Grayscale 8-bit PNG whose pixel LSBs encode `message`, stored Sub-filtered."""
    bits = []
    for byte in message:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    pixels = bytes(0x80 | b for b in bits)  # one channel, LSB carries the bit
    width, height = len(pixels), 1

    # Encode with Sub filter (type 1) so a naive reader of the filtered stream
    # gets the wrong bytes.
    filtered = bytearray()
    for i, px in enumerate(pixels):
        a = pixels[i - 1] if i >= 1 else 0
        filtered.append((px - a) & 0xFF)
    scanline = bytes([1]) + bytes(filtered)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
    idat = _png_chunk(b"IDAT", zlib.compress(scanline))
    iend = _png_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def test_stego_lsb_png_reverses_filters(tmp_path):
    png = _make_png_lsb(b"Hey")
    path = tmp_path / "stego.png"
    path.write_bytes(png)

    result = forensics.tool_stego_lsb(str(path))

    assert "Hey" in result


def test_zip_crack_reports_unencrypted(tmp_path):
    zpath = tmp_path / "plain.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("a.txt", "hello world")
    wl = tmp_path / "wl.txt"
    wl.write_text("password\n123456\n")

    result = forensics.tool_zip_crack(str(zpath), str(wl))

    assert "not encrypted" in result.lower()
