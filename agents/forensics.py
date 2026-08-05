"""Forensics agent — file analysis, steganography, pcap, entropy, carving."""

import math
import os
import re
import shutil
import struct
import subprocess
import zipfile

import anthropic

from agents.base import BaseAgent


# --- Tool implementations ---

SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF87a image"),
    (b"GIF89a", "GIF89a image"),
    (b"PK\x03\x04", "ZIP/JAR/APK/DOCX archive"),
    (b"PK\x05\x06", "ZIP (empty archive)"),
    (b"\x1f\x8b", "GZIP compressed"),
    (b"BZh", "BZIP2 compressed"),
    (b"\xfd7zXZ\x00", "XZ compressed"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "PE/MZ executable"),
    (b"%PDF", "PDF document"),
    (b"\xd0\xcf\x11\xe0", "MS Office / OLE2"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x00\x00\x00\x1cftyp", "MP4/MOV video"),
    (b"\x00\x00\x00\x20ftyp", "MP4/MOV video"),
    (b"RIFF", "RIFF (WAV/AVI)"),
    (b"OggS", "OGG audio/video"),
    (b"\x52\x49\x46\x46", "RIFF container"),
]


def tool_file_metadata(file_path: str) -> str:
    """Extract file metadata."""
    # Try exiftool first
    if shutil.which("exiftool"):
        try:
            result = subprocess.run(
                ["exiftool", file_path], capture_output=True, text=True, timeout=15
            )
            if result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

    # Pure Python fallback
    try:
        with open(file_path, "rb") as f:
            data = f.read(65536)  # Read first 64KB
    except Exception as e:
        return f"ERROR: {e}"

    info = [f"File: {file_path}", f"Size: {os.path.getsize(file_path)} bytes"]

    # Detect type
    for sig, label in SIGNATURES:
        if data[:len(sig)] == sig:
            info.append(f"Type: {label}")
            break

    # JPEG EXIF
    if data[:2] == b"\xff\xd8":
        i = 2
        while i < len(data) - 4:
            if data[i] != 0xff:
                break
            marker = data[i + 1]
            seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
            if marker == 0xe1:  # APP1 (EXIF)
                exif_data = data[i + 4:i + 2 + seg_len]
                if exif_data[:4] == b"Exif":
                    info.append("EXIF data present")
                    # Extract readable strings from EXIF
                    strings = []
                    current = []
                    for b in exif_data:
                        if 32 <= b <= 126:
                            current.append(chr(b))
                        else:
                            if len(current) >= 4:
                                strings.append("".join(current))
                            current = []
                    for s in strings[:20]:
                        info.append(f"  EXIF string: {s}")
            i += 2 + seg_len

    # PDF info
    if data[:4] == b"%PDF":
        version = data[:8].decode(errors="replace").strip()
        info.append(f"PDF version: {version}")
        if b"/Encrypt" in data:
            info.append("PDF is encrypted")
        # Count pages
        page_count = data.count(b"/Type /Page")
        if page_count:
            info.append(f"Approximate pages: {page_count}")

    return "\n".join(info)


def tool_binwalk_scan(file_path: str) -> str:
    """Scan file for embedded file signatures."""
    # Try binwalk command first
    if shutil.which("binwalk"):
        try:
            result = subprocess.run(
                ["binwalk", file_path], capture_output=True, text=True, timeout=30
            )
            if result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

    # Pure Python signature scan
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    findings = []
    for sig, label in SIGNATURES:
        offset = 0
        while True:
            idx = data.find(sig, offset)
            if idx == -1:
                break
            findings.append(f"0x{idx:08x}  {label}")
            offset = idx + 1
            if len(findings) > 100:
                break

    if not findings:
        return "No known signatures found."
    return f"Found {len(findings)} signatures:\n" + "\n".join(findings)


def tool_file_carve(file_path: str, offset: int, length: int, output_path: str = "") -> str:
    """Extract bytes from a file at a given offset."""
    if not output_path:
        output_path = file_path + f".carved_0x{offset:x}"
    try:
        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(length)
        with open(output_path, "wb") as out:
            out.write(data)
        return f"Carved {len(data)} bytes from offset 0x{offset:x} to {output_path}"
    except Exception as e:
        return f"ERROR: {e}"


def tool_stego_lsb(file_path: str, num_bits: int = 1, num_bytes: int = 256) -> str:
    """Extract LSB steganography from a PNG/BMP image."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    # Simple BMP LSB extraction
    if data[:2] == b"BM":
        pixel_offset = struct.unpack_from("<I", data, 10)[0]
        pixels = data[pixel_offset:]
        bits = []
        for i in range(min(len(pixels), num_bytes * 8)):
            bits.append(str(pixels[i] & 1))
        # Convert bits to bytes
        result_bytes = []
        for i in range(0, len(bits) - 7, 8):
            byte = int("".join(bits[i:i + 8]), 2)
            result_bytes.append(byte)
        decoded = bytes(result_bytes)
        printable = decoded.decode(errors="replace")
        return f"LSB extraction ({len(result_bytes)} bytes):\nHex: {decoded[:64].hex()}\nASCII: {printable[:256]}"

    # PNG: extract from IDAT pixel data (simplified)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        # Find IDAT chunks
        idat_data = b""
        i = 8
        while i < len(data) - 8:
            chunk_len = struct.unpack(">I", data[i:i + 4])[0]
            chunk_type = data[i + 4:i + 8]
            if chunk_type == b"IDAT":
                idat_data += data[i + 8:i + 8 + chunk_len]
            i += 12 + chunk_len

        if idat_data:
            # Decompress
            import zlib
            try:
                raw = zlib.decompress(idat_data)
                bits = []
                for byte in raw[:num_bytes * 8]:
                    bits.append(str(byte & 1))
                result_bytes = []
                for j in range(0, len(bits) - 7, 8):
                    b = int("".join(bits[j:j + 8]), 2)
                    result_bytes.append(b)
                decoded = bytes(result_bytes)
                printable = decoded.decode(errors="replace")
                return f"LSB extraction ({len(result_bytes)} bytes):\nHex: {decoded[:64].hex()}\nASCII: {printable[:256]}"
            except Exception as e:
                return f"PNG decompression error: {e}"

    return "Unsupported image format for LSB extraction. Use BMP or PNG."


def tool_stego_strings(file_path: str) -> str:
    """Look for data hidden after file EOF markers."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    eof_markers = {
        b"\xff\xd9": "JPEG",       # JPEG EOI
        b"%%EOF": "PDF",           # PDF
        b"IEND": "PNG",            # PNG IEND chunk
    }

    for marker, ftype in eof_markers.items():
        idx = data.rfind(marker)
        if idx != -1:
            trailing_start = idx + len(marker)
            # For PNG, skip the CRC after IEND
            if ftype == "PNG":
                trailing_start += 4
            trailing = data[trailing_start:]
            if trailing and trailing != b"\x00" * len(trailing):
                printable = trailing.decode(errors="replace")
                return (f"Found {len(trailing)} bytes after {ftype} EOF marker at 0x{idx:x}:\n"
                        f"Hex: {trailing[:64].hex()}\n"
                        f"ASCII: {printable[:256]}")

    return "No hidden data found after EOF markers."


def tool_pcap_analyze(file_path: str) -> str:
    """Parse a pcap file and summarize network flows."""
    # Try tshark first
    if shutil.which("tshark"):
        try:
            result = subprocess.run(
                ["tshark", "-r", file_path, "-q", "-z", "conv,tcp"],
                capture_output=True, text=True, timeout=30,
            )
            if result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

    # Pure Python pcap parser
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    # Check pcap magic
    if len(data) < 24:
        return "File too small for pcap."

    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xa1b2c3d4:
        endian = "<"
    elif magic == 0xd4c3b2a1:
        endian = ">"
    else:
        return f"Not a pcap file (magic: 0x{data[:4].hex()})"

    # Parse global header
    snaplen = struct.unpack(endian + "I", data[16:20])[0]
    link_type = struct.unpack(endian + "I", data[20:24])[0]

    info = [f"PCAP file, link type: {link_type}, snaplen: {snaplen}"]
    flows = {}
    payloads = []

    offset = 24
    pkt_count = 0
    while offset + 16 <= len(data):
        ts_sec = struct.unpack(endian + "I", data[offset:offset + 4])[0]
        ts_usec = struct.unpack(endian + "I", data[offset + 4:offset + 8])[0]
        incl_len = struct.unpack(endian + "I", data[offset + 8:offset + 12])[0]
        orig_len = struct.unpack(endian + "I", data[offset + 12:offset + 16])[0]

        if incl_len > snaplen or offset + 16 + incl_len > len(data):
            break

        pkt_data = data[offset + 16:offset + 16 + incl_len]
        pkt_count += 1

        # Parse Ethernet (link_type 1)
        if link_type == 1 and len(pkt_data) >= 34:
            eth_type = struct.unpack(">H", pkt_data[12:14])[0]
            if eth_type == 0x0800:  # IPv4
                ip_header = pkt_data[14:]
                ihl = (ip_header[0] & 0x0f) * 4
                protocol = ip_header[9]
                src_ip = ".".join(str(b) for b in ip_header[12:16])
                dst_ip = ".".join(str(b) for b in ip_header[16:20])

                if protocol == 6 and len(ip_header) >= ihl + 20:  # TCP
                    tcp = ip_header[ihl:]
                    src_port = struct.unpack(">H", tcp[0:2])[0]
                    dst_port = struct.unpack(">H", tcp[2:4])[0]
                    tcp_hdr_len = ((tcp[12] >> 4) & 0xf) * 4
                    payload = tcp[tcp_hdr_len:]
                    flow = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    flows[flow] = flows.get(flow, 0) + 1
                    if payload:
                        payloads.append((flow, payload[:200]))

                elif protocol == 17 and len(ip_header) >= ihl + 8:  # UDP
                    udp = ip_header[ihl:]
                    src_port = struct.unpack(">H", udp[0:2])[0]
                    dst_port = struct.unpack(">H", udp[2:4])[0]
                    payload = udp[8:]
                    flow = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} (UDP)"
                    flows[flow] = flows.get(flow, 0) + 1
                    if payload:
                        payloads.append((flow, payload[:200]))

        offset += 16 + incl_len

    info.append(f"Total packets: {pkt_count}")
    if flows:
        info.append(f"\nFlows ({len(flows)}):")
        for flow, count in sorted(flows.items(), key=lambda x: -x[1])[:30]:
            info.append(f"  {flow} — {count} packets")

    if payloads:
        info.append(f"\nPayload samples ({min(len(payloads), 10)}):")
        for flow, payload in payloads[:10]:
            printable = payload.decode(errors="replace")[:100]
            info.append(f"  [{flow}] {printable}")

    return "\n".join(info)


def tool_hex_search(file_path: str, hex_pattern: str = "", ascii_pattern: str = "") -> str:
    """Search a file for a hex or ASCII byte pattern."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    if hex_pattern:
        try:
            needle = bytes.fromhex(hex_pattern.replace(" ", ""))
        except ValueError as e:
            return f"ERROR parsing hex: {e}"
    elif ascii_pattern:
        needle = ascii_pattern.encode()
    else:
        return "Provide hex_pattern or ascii_pattern."

    results = []
    offset = 0
    while True:
        idx = data.find(needle, offset)
        if idx == -1:
            break
        context = data[max(0, idx - 8):idx + len(needle) + 8]
        results.append(f"Found at 0x{idx:x} (offset {idx}): {context.hex()}")
        offset = idx + 1
        if len(results) >= 50:
            break

    if not results:
        return "Pattern not found."
    return "\n".join(results)


def tool_entropy_analysis(file_path: str, block_size: int = 256) -> str:
    """Calculate per-block Shannon entropy."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    def shannon_entropy(block):
        if not block:
            return 0.0
        freq = [0] * 256
        for b in block:
            freq[b] += 1
        length = len(block)
        ent = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                ent -= p * math.log2(p)
        return ent

    lines = [f"File size: {len(data)} bytes, block size: {block_size}"]
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        ent = shannon_entropy(block)
        blocks.append((i, ent))
        if len(blocks) <= 50 or ent > 7.5 or ent < 0.5:
            bar = "#" * int(ent * 4)
            lines.append(f"0x{i:08x}: {ent:.2f} {bar}")

    avg_ent = sum(e for _, e in blocks) / len(blocks) if blocks else 0
    high_ent = sum(1 for _, e in blocks if e > 7.0)
    lines.insert(1, f"Average entropy: {avg_ent:.2f}")
    lines.insert(2, f"High-entropy blocks (>7.0): {high_ent}/{len(blocks)}")
    if high_ent > len(blocks) * 0.8:
        lines.insert(3, "NOTE: Mostly high entropy — likely encrypted or compressed")
    return "\n".join(lines)


def tool_zip_crack(zip_path: str, wordlist_path: str) -> str:
    """Brute-force a password-protected ZIP file."""
    try:
        zf = zipfile.ZipFile(zip_path)
    except Exception as e:
        return f"ERROR opening ZIP: {e}"

    try:
        with open(wordlist_path, "r", errors="replace") as wl:
            words = wl.read().splitlines()
    except Exception as e:
        return f"ERROR reading wordlist: {e}"

    for i, pwd in enumerate(words):
        try:
            zf.extractall(pwd=pwd.encode())
            return f"Password found: {pwd} (attempt {i + 1}/{len(words)})\nFiles: {zf.namelist()}"
        except (RuntimeError, zipfile.BadZipFile):
            continue
        except Exception:
            continue

    return f"Password not found. Tried {len(words)} words from {wordlist_path}"


def tool_base_convert(value: str, from_base: str = "decimal", to_base: str = "hex") -> str:
    """Convert between number bases."""
    base_map = {
        "binary": 2, "bin": 2,
        "octal": 8, "oct": 8,
        "decimal": 10, "dec": 10,
        "hex": 16, "hexadecimal": 16,
    }

    from_b = base_map.get(from_base.lower())
    to_b = base_map.get(to_base.lower())

    if from_b is None or to_b is None:
        # Handle base32/58/64 as string encodings
        import base64 as b64mod
        try:
            if from_base.lower() == "base64":
                raw = b64mod.b64decode(value)
            elif from_base.lower() == "base32":
                raw = b64mod.b32decode(value)
            else:
                raw = value.encode()

            if to_base.lower() == "base64":
                return f"Result: {b64mod.b64encode(raw).decode()}"
            elif to_base.lower() == "base32":
                return f"Result: {b64mod.b32encode(raw).decode()}"
            elif to_base.lower() == "hex":
                return f"Result: {raw.hex()}"
            elif to_base.lower() == "decimal":
                return f"Result: {int.from_bytes(raw, 'big')}"
            return f"Unsupported to_base: {to_base}"
        except Exception as e:
            return f"ERROR: {e}"

    try:
        num = int(value, from_b)
    except ValueError as e:
        return f"ERROR parsing value: {e}"

    if to_b == 2:
        return f"Result: {bin(num)}"
    elif to_b == 8:
        return f"Result: {oct(num)}"
    elif to_b == 10:
        return f"Result: {num}"
    elif to_b == 16:
        return f"Result: {hex(num)}"
    return f"Result: {num}"


def tool_flag_search(file_path: str = "", text: str = "") -> str:
    """Search for CTF flag patterns."""
    patterns = [
        r'flag\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'academy\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'FLAG\{[^}]+\}',
    ]

    if file_path:
        try:
            with open(file_path, "rb") as f:
                text = f.read().decode(errors="replace")
        except Exception as e:
            return f"ERROR: {e}"

    if not text:
        return "Provide file_path or text to search."

    found = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        found.extend(matches)

    if not found:
        return "No flag patterns found."
    return f"Found {len(found)} flag(s):\n" + "\n".join(f"  {f}" for f in found)


# --- Tool definitions ---

FORENSICS_TOOLS = [
    {
        "name": "file_metadata",
        "description": "Extract file metadata (EXIF, PDF info, size, type). Uses exiftool if available, else pure Python.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "binwalk_scan",
        "description": "Scan a file for embedded file signatures (PNG, ZIP, ELF, PDF, etc.).",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file to scan"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "file_carve",
        "description": "Extract (carve) bytes from a file at a given offset and length.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Source file path"},
                "offset": {"type": "integer", "description": "Start offset"},
                "length": {"type": "integer", "description": "Number of bytes to extract"},
                "output_path": {"type": "string", "description": "Output file path (optional)"},
            },
            "required": ["file_path", "offset", "length"],
        },
    },
    {
        "name": "stego_lsb",
        "description": "Extract LSB (least significant bit) steganography from PNG or BMP images.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the image file"},
                "num_bits": {"type": "integer", "description": "Bits per channel to extract (default 1)", "default": 1},
                "num_bytes": {"type": "integer", "description": "Max bytes to extract (default 256)", "default": 256},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "stego_strings",
        "description": "Search for hidden data appended after a file's EOF marker (JPEG FFD9, PDF %%EOF, PNG IEND).",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "pcap_analyze",
        "description": "Parse a pcap file, summarize TCP/UDP flows, and extract payload samples.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the pcap file"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "hex_search",
        "description": "Search a file for a hex byte pattern or ASCII string.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file"},
                "hex_pattern": {"type": "string", "description": "Hex pattern to find (e.g. 'deadbeef')"},
                "ascii_pattern": {"type": "string", "description": "ASCII string to find"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "entropy_analysis",
        "description": "Calculate Shannon entropy per block. High entropy (>7.0) suggests encryption/compression.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file"},
                "block_size": {"type": "integer", "description": "Block size in bytes (default 256)", "default": 256},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "zip_crack",
        "description": "Brute-force a password-protected ZIP file with a wordlist.",
        "input_schema": {
            "type": "object",
            "properties": {
                "zip_path": {"type": "string", "description": "Path to the ZIP file"},
                "wordlist_path": {"type": "string", "description": "Path to the password wordlist"},
            },
            "required": ["zip_path", "wordlist_path"],
        },
    },
    {
        "name": "base_convert",
        "description": "Convert a value between bases: binary, octal, decimal, hex, base32, base64.",
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "The value to convert"},
                "from_base": {"type": "string", "description": "Source base (binary, octal, decimal, hex, base32, base64)"},
                "to_base": {"type": "string", "description": "Target base"},
            },
            "required": ["value", "from_base", "to_base"],
        },
    },
    {
        "name": "flag_search",
        "description": "Search a file or text for CTF flag patterns (flag{}, CTF{}, academy{}, picoCTF{}, etc.).",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to file to search"},
                "text": {"type": "string", "description": "Text string to search"},
            },
            "required": [],
        },
    },
]

FORENSICS_DISPATCH = {
    "file_metadata": lambda **kw: tool_file_metadata(**kw),
    "binwalk_scan": lambda **kw: tool_binwalk_scan(**kw),
    "file_carve": lambda **kw: tool_file_carve(**kw),
    "stego_lsb": lambda **kw: tool_stego_lsb(**kw),
    "stego_strings": lambda **kw: tool_stego_strings(**kw),
    "pcap_analyze": lambda **kw: tool_pcap_analyze(**kw),
    "hex_search": lambda **kw: tool_hex_search(**kw),
    "entropy_analysis": lambda **kw: tool_entropy_analysis(**kw),
    "zip_crack": lambda **kw: tool_zip_crack(**kw),
    "base_convert": lambda **kw: tool_base_convert(**kw),
    "flag_search": lambda **kw: tool_flag_search(**kw),
}

FORENSICS_SYSTEM_PROMPT = """You are a forensics agent for CTF challenges and authorized security testing.

Strategy:
1. Start with file_metadata to understand the file type, size, and embedded metadata.
2. Run binwalk_scan to detect embedded files or appended data.
3. Use entropy_analysis to identify encrypted or compressed regions.
4. Check stego_strings for data hidden after EOF markers.
5. For images, try stego_lsb to extract hidden messages.
6. Use file_carve to extract embedded files found by binwalk_scan.
7. For pcap files, use pcap_analyze to summarize flows and extract payloads.
8. Use hex_search to find specific patterns in files.
9. For password-protected ZIPs, try zip_crack with available wordlists.
10. Always run flag_search on extracted data to find flag patterns.

Report:
- File type and metadata
- Embedded or hidden content found
- Entropy profile (encrypted/compressed regions)
- Extracted files and their contents
- Any flags or secrets discovered"""


def create_forensics_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a forensics agent instance."""
    return BaseAgent(
        name="forensics",
        system_prompt=FORENSICS_SYSTEM_PROMPT,
        tools=FORENSICS_TOOLS,
        tool_dispatch=FORENSICS_DISPATCH,
        client=client,
    )
