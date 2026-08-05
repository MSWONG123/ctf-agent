"""Reverse engineering + binary exploitation agent."""

import os
import shutil
import struct
import subprocess
import tempfile

import anthropic

from agents.base import BaseAgent


# --- Tool implementations ---

MAGIC_BYTES = {
    b"\x7fELF": "ELF",
    b"MZ": "PE/MZ (Windows executable)",
    b"\xfe\xed\xfa\xce": "Mach-O (32-bit)",
    b"\xfe\xed\xfa\xcf": "Mach-O (64-bit)",
    b"\xcf\xfa\xed\xfe": "Mach-O (64-bit, reversed)",
    b"\xca\xfe\xba\xbe": "Mach-O (Universal)",
    b"\x89PNG": "PNG image",
    b"PK\x03\x04": "ZIP/JAR/APK archive",
    b"\x1f\x8b": "GZIP compressed",
    b"#!": "Script (shebang)",
    b"\x7fCGC": "CGC (Cyber Grand Challenge) binary",
    b"\xd0\xcf\x11\xe0": "MS Office / OLE2",
    b"%PDF": "PDF document",
}


def tool_file_identify(file_path: str) -> str:
    """Identify file type from magic bytes."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(64)
    except Exception as e:
        return f"ERROR: {e}"

    if not header:
        return "Empty file"

    for magic, label in MAGIC_BYTES.items():
        if header[:len(magic)] == magic:
            size = os.path.getsize(file_path)
            info = f"Type: {label}\nSize: {size} bytes"

            # ELF-specific info
            if label == "ELF" and len(header) >= 20:
                bits = "64-bit" if header[4] == 2 else "32-bit"
                endian = "little-endian" if header[5] == 1 else "big-endian"
                elf_types = {2: "executable", 3: "shared object", 1: "relocatable"}
                e_type = struct.unpack_from("<H" if header[5] == 1 else ">H", header, 16)[0]
                type_str = elf_types.get(e_type, f"unknown({e_type})")
                info += f"\nArch: {bits} {endian}\nELF type: {type_str}"

            return info

    # Fallback to file command
    if shutil.which("file"):
        try:
            result = subprocess.run(
                ["file", file_path], capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception:
            pass

    return f"Unknown file type. First 16 bytes: {header[:16].hex()}"


def tool_strings_extract(file_path: str, min_length: int = 4) -> str:
    """Extract printable strings from a binary file."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    strings = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))

    if not strings:
        return "No printable strings found."

    result = f"Found {len(strings)} strings (min length {min_length}):\n"
    for s in strings[:200]:
        result += f"  {s}\n"
    if len(strings) > 200:
        result += f"  ... and {len(strings) - 200} more"
    return result


def tool_checksec(file_path: str) -> str:
    """Check binary security protections by parsing ELF headers."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    if data[:4] != b"\x7fELF":
        # Try external checksec
        if shutil.which("checksec"):
            try:
                result = subprocess.run(
                    ["checksec", "--file=" + file_path],
                    capture_output=True, text=True, timeout=10,
                )
                return result.stdout.strip() or result.stderr.strip()
            except Exception:
                pass
        return "Not an ELF file. Cannot check protections."

    is_64 = data[4] == 2
    le = data[5] == 1
    fmt = "<" if le else ">"

    results = []

    # Check PIE: ELF type == ET_DYN (3) suggests PIE
    e_type = struct.unpack_from(fmt + "H", data, 16)[0]
    results.append(f"PIE: {'Yes (ET_DYN)' if e_type == 3 else 'No (ET_EXEC)'}")

    # Parse program headers for NX (PT_GNU_STACK)
    if is_64:
        e_phoff = struct.unpack_from(fmt + "Q", data, 32)[0]
        e_phentsize = struct.unpack_from(fmt + "H", data, 54)[0]
        e_phnum = struct.unpack_from(fmt + "H", data, 56)[0]
    else:
        e_phoff = struct.unpack_from(fmt + "I", data, 28)[0]
        e_phentsize = struct.unpack_from(fmt + "H", data, 42)[0]
        e_phnum = struct.unpack_from(fmt + "H", data, 44)[0]

    nx = "Unknown"
    relro = "No"
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 8 > len(data):
            break
        p_type = struct.unpack_from(fmt + "I", data, off)[0]
        if p_type == 0x6474e551:  # PT_GNU_STACK
            if is_64:
                p_flags = struct.unpack_from(fmt + "I", data, off + 4)[0]
            else:
                p_flags = struct.unpack_from(fmt + "I", data, off + 24)[0]
            nx = "Yes (NX enabled)" if not (p_flags & 0x1) else "No (stack executable)"
        if p_type == 0x6474e552:  # PT_GNU_RELRO
            relro = "Partial"

    results.append(f"NX: {nx}")
    results.append(f"RELRO: {relro}")

    # Check for stack canary: search for __stack_chk_fail in symtab
    canary = "Yes" if b"__stack_chk_fail" in data else "No"
    results.append(f"Stack Canary: {canary}")

    return "\n".join(results)


def tool_disassemble(file_path: str, function: str = "", start_addr: str = "", num_instructions: int = 50) -> str:
    """Disassemble binary. Tries objdump, then capstone, else error."""
    if shutil.which("objdump"):
        cmd = ["objdump", "-d", "--no-show-raw-insn"]
        if function:
            cmd = ["objdump", "-d", f"--disassemble={function}"]
        cmd.append(file_path)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            lines = output.split("\n")
            if len(lines) > num_instructions + 20:
                lines = lines[:num_instructions + 20]
            return "\n".join(lines)
        except Exception as e:
            return f"ERROR running objdump: {e}"

    try:
        import capstone
        with open(file_path, "rb") as f:
            data = f.read()
        if data[:4] == b"\x7fELF":
            is_64 = data[4] == 2
            if is_64:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                entry = struct.unpack_from("<Q", data, 24)[0]
            else:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                entry = struct.unpack_from("<I", data, 24)[0]
            lines = []
            for i, (addr, size, mnem, op_str) in enumerate(md.disasm_lite(data[entry:], entry)):
                lines.append(f"  0x{addr:x}:  {mnem} {op_str}")
                if i >= num_instructions:
                    break
            return "\n".join(lines) if lines else "No instructions decoded."
        return "Cannot determine architecture for disassembly."
    except ImportError:
        return "ERROR: No disassembler available. Install objdump (binutils) or capstone (pip install capstone)."


def tool_elf_sections(file_path: str) -> str:
    """List ELF sections with names, sizes, and flags."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    if data[:4] != b"\x7fELF":
        return "Not an ELF file."

    is_64 = data[4] == 2
    le = data[5] == 1
    fmt = "<" if le else ">"

    if is_64:
        e_shoff = struct.unpack_from(fmt + "Q", data, 40)[0]
        e_shentsize = struct.unpack_from(fmt + "H", data, 58)[0]
        e_shnum = struct.unpack_from(fmt + "H", data, 60)[0]
        e_shstrndx = struct.unpack_from(fmt + "H", data, 62)[0]
    else:
        e_shoff = struct.unpack_from(fmt + "I", data, 32)[0]
        e_shentsize = struct.unpack_from(fmt + "H", data, 46)[0]
        e_shnum = struct.unpack_from(fmt + "H", data, 48)[0]
        e_shstrndx = struct.unpack_from(fmt + "H", data, 50)[0]

    if e_shoff == 0 or e_shnum == 0:
        return "No section headers found."

    # Get shstrtab
    shstr_off = e_shoff + e_shstrndx * e_shentsize
    if is_64:
        shstr_offset = struct.unpack_from(fmt + "Q", data, shstr_off + 24)[0]
        shstr_size = struct.unpack_from(fmt + "Q", data, shstr_off + 32)[0]
    else:
        shstr_offset = struct.unpack_from(fmt + "I", data, shstr_off + 16)[0]
        shstr_size = struct.unpack_from(fmt + "I", data, shstr_off + 20)[0]
    shstrtab = data[shstr_offset:shstr_offset + shstr_size]

    def get_name(name_off):
        end = shstrtab.find(b"\x00", name_off)
        if end == -1:
            return "<unknown>"
        return shstrtab[name_off:end].decode(errors="replace")

    flag_map = {1: "W", 2: "A", 4: "X"}
    lines = [f"{'Name':20s} {'Size':>10s} {'Offset':>10s} {'Flags':6s}"]
    lines.append("-" * 50)

    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if is_64:
            sh_name = struct.unpack_from(fmt + "I", data, off)[0]
            sh_flags = struct.unpack_from(fmt + "Q", data, off + 8)[0]
            sh_offset = struct.unpack_from(fmt + "Q", data, off + 24)[0]
            sh_size = struct.unpack_from(fmt + "Q", data, off + 32)[0]
        else:
            sh_name = struct.unpack_from(fmt + "I", data, off)[0]
            sh_flags = struct.unpack_from(fmt + "I", data, off + 8)[0]
            sh_offset = struct.unpack_from(fmt + "I", data, off + 16)[0]
            sh_size = struct.unpack_from(fmt + "I", data, off + 20)[0]

        name = get_name(sh_name)
        flags_str = "".join(v for k, v in flag_map.items() if sh_flags & k)
        lines.append(f"{name:20s} {sh_size:10d} 0x{sh_offset:08x} {flags_str:6s}")

    return "\n".join(lines)


def tool_elf_symbols(file_path: str) -> str:
    """List symbols from ELF symtab/dynsym."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return f"ERROR: {e}"

    if data[:4] != b"\x7fELF":
        return "Not an ELF file."

    is_64 = data[4] == 2
    le = data[5] == 1
    fmt = "<" if le else ">"

    if is_64:
        e_shoff = struct.unpack_from(fmt + "Q", data, 40)[0]
        e_shentsize = struct.unpack_from(fmt + "H", data, 58)[0]
        e_shnum = struct.unpack_from(fmt + "H", data, 60)[0]
    else:
        e_shoff = struct.unpack_from(fmt + "I", data, 32)[0]
        e_shentsize = struct.unpack_from(fmt + "H", data, 46)[0]
        e_shnum = struct.unpack_from(fmt + "H", data, 48)[0]

    SHT_SYMTAB = 2
    SHT_DYNSYM = 11

    symbols = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + e_shentsize > len(data):
            break
        sh_type = struct.unpack_from(fmt + "I", data, off + 4)[0]
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue

        if is_64:
            sh_offset = struct.unpack_from(fmt + "Q", data, off + 24)[0]
            sh_size = struct.unpack_from(fmt + "Q", data, off + 32)[0]
            sh_link = struct.unpack_from(fmt + "I", data, off + 40)[0]
            entry_size = 24
        else:
            sh_offset = struct.unpack_from(fmt + "I", data, off + 16)[0]
            sh_size = struct.unpack_from(fmt + "I", data, off + 20)[0]
            sh_link = struct.unpack_from(fmt + "I", data, off + 24)[0]
            entry_size = 16

        # Get linked string table
        strtab_hdr_off = e_shoff + sh_link * e_shentsize
        if is_64:
            strtab_off = struct.unpack_from(fmt + "Q", data, strtab_hdr_off + 24)[0]
            strtab_sz = struct.unpack_from(fmt + "Q", data, strtab_hdr_off + 32)[0]
        else:
            strtab_off = struct.unpack_from(fmt + "I", data, strtab_hdr_off + 16)[0]
            strtab_sz = struct.unpack_from(fmt + "I", data, strtab_hdr_off + 20)[0]
        strtab = data[strtab_off:strtab_off + strtab_sz]

        num_syms = sh_size // entry_size
        tab_name = "symtab" if sh_type == SHT_SYMTAB else "dynsym"
        for j in range(min(num_syms, 500)):
            sym_off = sh_offset + j * entry_size
            if is_64:
                st_name = struct.unpack_from(fmt + "I", data, sym_off)[0]
                st_value = struct.unpack_from(fmt + "Q", data, sym_off + 8)[0]
            else:
                st_name = struct.unpack_from(fmt + "I", data, sym_off)[0]
                st_value = struct.unpack_from(fmt + "I", data, sym_off + 4)[0]

            end = strtab.find(b"\x00", st_name)
            name = strtab[st_name:end].decode(errors="replace") if end != -1 else ""
            if name:
                symbols.append(f"  [{tab_name}] 0x{st_value:08x} {name}")

    if not symbols:
        return "No symbols found (binary may be stripped)."
    return f"Found {len(symbols)} symbols:\n" + "\n".join(symbols[:200])


def tool_hexdump(file_path: str, offset: int = 0, length: int = 256) -> str:
    """Hex dump a range from a file."""
    try:
        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(length)
    except Exception as e:
        return f"ERROR: {e}"

    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"0x{offset + i:08x}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines) if lines else "No data at this offset."


def tool_patch_bytes(file_path: str, offset: int, hex_bytes: str) -> str:
    """Patch bytes at an offset in a file."""
    try:
        raw = bytes.fromhex(hex_bytes.replace(" ", "").replace("0x", ""))
    except ValueError as e:
        return f"ERROR parsing hex: {e}"

    try:
        with open(file_path, "r+b") as f:
            f.seek(offset)
            f.write(raw)
        return f"Patched {len(raw)} bytes at offset 0x{offset:x}"
    except Exception as e:
        return f"ERROR: {e}"


def tool_run_binary(file_path: str, args: str = "", stdin_data: str = "") -> str:
    """Run a binary with given args and stdin, capture output."""
    cmd = [file_path] + (args.split() if args else [])
    try:
        result = subprocess.run(
            cmd,
            input=stdin_data.encode() if stdin_data else None,
            capture_output=True,
            timeout=10,
        )
        output = f"Exit code: {result.returncode}\n"
        if result.stdout:
            output += f"stdout:\n{result.stdout.decode(errors='replace')}\n"
        if result.stderr:
            output += f"stderr:\n{result.stderr.decode(errors='replace')}\n"
        return output.strip()
    except subprocess.TimeoutExpired:
        return "ERROR: Binary timed out after 10 seconds"
    except Exception as e:
        return f"ERROR: {e}"


def _de_bruijn(k, n):
    """Generate De Bruijn sequence for alphabet size k and subsequence length n."""
    alphabet = [chr(ord('a') + i) for i in range(k)]
    a = [0] * (k * n)
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(alphabet[i] for i in sequence)


def tool_cyclic_pattern(action: str = "generate", length: int = 200, pattern: str = "") -> str:
    """Generate or find offset in a De Bruijn cyclic pattern."""
    seq = _de_bruijn(26, 4)
    # Extend if needed
    while len(seq) < max(length, 8192):
        seq = seq + seq

    if action == "generate":
        return seq[:length]
    elif action == "find":
        idx = seq.find(pattern)
        if idx == -1:
            return f"Pattern '{pattern}' not found in cyclic sequence"
        return f"Pattern '{pattern}' found at offset: {idx}"
    return "Unknown action. Use 'generate' or 'find'."


SHELLCODE_DB = {
    ("x64", "execve_bin_sh"): (
        "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e"
        "\\x2f\\x2f\\x73\\x68\\x57\\x54\\x5f\\x6a\\x3b\\x58"
        "\\x99\\x0f\\x05"
    ),
    ("x86", "execve_bin_sh"): (
        "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f"
        "\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0"
        "\\x0b\\xcd\\x80"
    ),
    ("x64", "nop_sled"): "\\x90" * 32,
    ("x86", "nop_sled"): "\\x90" * 32,
}


def tool_shellcode_gen(arch: str = "x64", payload: str = "execve_bin_sh") -> str:
    """Generate common shellcode snippets."""
    key = (arch.lower(), payload.lower())
    if key in SHELLCODE_DB:
        sc = SHELLCODE_DB[key]
        raw = bytes(int(sc[i + 2:i + 4], 16) for i in range(0, len(sc), 4))
        return f"Shellcode ({arch}, {payload}):\n{sc}\nLength: {len(raw)} bytes\nPython: {raw!r}"
    available = [f"{a}/{p}" for a, p in SHELLCODE_DB.keys()]
    return f"Unknown payload. Available: {', '.join(available)}"


# --- Tool definitions ---

REVERSING_TOOLS = [
    {
        "name": "file_identify",
        "description": "Identify file type from magic bytes (ELF, PE, Mach-O, script, etc.).",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "strings_extract",
        "description": "Extract printable ASCII strings from a binary file.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the binary"},
                "min_length": {"type": "integer", "description": "Minimum string length (default 4)", "default": 4},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "checksec",
        "description": "Check ELF binary security protections: PIE, NX, RELRO, stack canary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the ELF binary"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "disassemble",
        "description": "Disassemble a binary. Optionally specify a function name or limit instruction count.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the binary"},
                "function": {"type": "string", "description": "Function name to disassemble"},
                "start_addr": {"type": "string", "description": "Start address (hex)"},
                "num_instructions": {"type": "integer", "description": "Max instructions to show", "default": 50},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "elf_sections",
        "description": "List ELF sections with names, sizes, offsets, and flags (W/A/X).",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the ELF file"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "elf_symbols",
        "description": "List symbols from ELF symtab and dynsym sections.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the ELF file"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "hexdump",
        "description": "Hex dump a byte range from a file with ASCII column.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file"},
                "offset": {"type": "integer", "description": "Start offset in bytes", "default": 0},
                "length": {"type": "integer", "description": "Number of bytes to dump", "default": 256},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "patch_bytes",
        "description": "Overwrite bytes at a given offset in a file. Hex input, e.g. '90 90 90'.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the file to patch"},
                "offset": {"type": "integer", "description": "Byte offset to start writing"},
                "hex_bytes": {"type": "string", "description": "Hex string of bytes to write, e.g. '41 42 43'"},
            },
            "required": ["file_path", "offset", "hex_bytes"],
        },
    },
    {
        "name": "run_binary",
        "description": "Execute a binary with arguments and optional stdin. Returns stdout, stderr, exit code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the executable"},
                "args": {"type": "string", "description": "Command-line arguments (space-separated)"},
                "stdin_data": {"type": "string", "description": "Data to send to stdin"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "cyclic_pattern",
        "description": "Generate a De Bruijn cyclic pattern or find a substring's offset. Used for buffer overflow offset detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["generate", "find"], "description": "'generate' or 'find'"},
                "length": {"type": "integer", "description": "Length of pattern to generate", "default": 200},
                "pattern": {"type": "string", "description": "Substring to find (for action='find')"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "shellcode_gen",
        "description": "Generate common shellcode snippets. Available: x86/x64 execve_bin_sh, nop_sled.",
        "input_schema": {
            "type": "object",
            "properties": {
                "arch": {"type": "string", "enum": ["x86", "x64"], "description": "Target architecture", "default": "x64"},
                "payload": {"type": "string", "description": "Payload name: execve_bin_sh, nop_sled", "default": "execve_bin_sh"},
            },
            "required": [],
        },
    },
]

REVERSING_DISPATCH = {
    "file_identify": lambda **kw: tool_file_identify(**kw),
    "strings_extract": lambda **kw: tool_strings_extract(**kw),
    "checksec": lambda **kw: tool_checksec(**kw),
    "disassemble": lambda **kw: tool_disassemble(**kw),
    "elf_sections": lambda **kw: tool_elf_sections(**kw),
    "elf_symbols": lambda **kw: tool_elf_symbols(**kw),
    "hexdump": lambda **kw: tool_hexdump(**kw),
    "patch_bytes": lambda **kw: tool_patch_bytes(**kw),
    "run_binary": lambda **kw: tool_run_binary(**kw),
    "cyclic_pattern": lambda **kw: tool_cyclic_pattern(**kw),
    "shellcode_gen": lambda **kw: tool_shellcode_gen(**kw),
}

REVERSING_SYSTEM_PROMPT = """You are a reverse engineering and binary exploitation agent for CTF challenges.

Strategy:
1. Start with file_identify to determine the binary format.
2. Run checksec to understand security protections (PIE, NX, canary, RELRO).
3. Use elf_sections and elf_symbols to map the binary structure.
4. Extract strings_extract to find hardcoded secrets, flag patterns, and function names.
5. Use disassemble to analyze specific functions (especially main, win, or flag-related).
6. Use hexdump to inspect specific data regions.

For exploitation:
7. Use cyclic_pattern to generate overflow payloads and find offsets.
8. Use run_binary to test inputs and observe behavior.
9. Use shellcode_gen for common payloads.
10. Use patch_bytes to modify binaries for RE challenges.

Report:
- Binary type, architecture, protections
- Key functions and their behavior
- Vulnerabilities found (buffer overflow, format string, use-after-free)
- Exploitation strategy with offsets and payload"""


def create_reversing_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a reverse engineering + binary exploitation agent."""
    return BaseAgent(
        name="reversing",
        system_prompt=REVERSING_SYSTEM_PROMPT,
        tools=REVERSING_TOOLS,
        tool_dispatch=REVERSING_DISPATCH,
        client=client,
    )
