"""Crypto agent — decoding, hash ID, cipher brute-force, frequency analysis, RSA, AES, Vigenere, mod math."""

import base64
import binascii
import hashlib
import math
import string
from collections import Counter

import anthropic

from agents.base import BaseAgent


# --- Tool implementations ---

def tool_base64_decode(data: str) -> str:
    """Decode a base64-encoded string."""
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="replace")
        return f"Decoded: {decoded}"
    except Exception as e:
        return f"ERROR decoding base64: {e}"


def tool_base64_encode(data: str) -> str:
    """Encode a string to base64."""
    encoded = base64.b64encode(data.encode()).decode()
    return f"Encoded: {encoded}"


def tool_hex_decode(data: str) -> str:
    """Decode a hex-encoded string."""
    try:
        clean = data.replace(" ", "").replace("0x", "").replace("\\x", "")
        decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
        return f"Decoded: {decoded}"
    except Exception as e:
        return f"ERROR decoding hex: {e}"


def tool_hash_identify(hash_str: str) -> str:
    """Identify the likely hash type based on length and character set."""
    h = hash_str.strip()
    length = len(h)
    results = []

    hash_types = {
        32: ["MD5", "NTLM"],
        40: ["SHA-1"],
        56: ["SHA-224"],
        64: ["SHA-256"],
        96: ["SHA-384"],
        128: ["SHA-512"],
    }

    if length in hash_types:
        try:
            int(h, 16)
            results.extend(hash_types[length])
        except ValueError:
            pass

    if h.startswith("$2b$") or h.startswith("$2a$") or h.startswith("$2y$"):
        results.append("bcrypt")
    elif h.startswith("$6$"):
        results.append("SHA-512 crypt")
    elif h.startswith("$5$"):
        results.append("SHA-256 crypt")
    elif h.startswith("$1$"):
        results.append("MD5 crypt")

    if not results:
        results.append(f"Unknown (length={length})")

    return f"Hash: {h}\nLength: {length}\nPossible types: {', '.join(results)}"


def tool_rot_bruteforce(text: str) -> str:
    """Try all ROT-N (Caesar cipher) rotations (1-25)."""
    results = []
    for n in range(1, 26):
        decoded = ""
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decoded += chr((ord(c) - base + n) % 26 + base)
            else:
                decoded += c
        results.append(f"ROT-{n:2d}: {decoded}")
    return "\n".join(results)


def tool_xor_bruteforce(data: str, max_key_len: int = 1) -> str:
    """XOR brute-force with single-byte keys (0x00-0xFF)."""
    try:
        raw = bytes.fromhex(data.replace(" ", ""))
    except ValueError:
        raw = data.encode()

    results = []
    for key in range(256):
        decoded = bytes([b ^ key for b in raw])
        try:
            text = decoded.decode("ascii")
            if all(c in string.printable for c in text):
                results.append(f"Key 0x{key:02x}: {text}")
        except UnicodeDecodeError:
            continue

    if not results:
        return "No printable ASCII results found for any single-byte XOR key."
    return "\n".join(results[:50])


def tool_frequency_analysis(text: str) -> str:
    """Perform character frequency analysis on text."""
    letters = [c.lower() for c in text if c.isalpha()]
    total = len(letters)
    if total == 0:
        return "No alphabetic characters found."

    counter = Counter(letters)
    lines = [f"Total letters: {total}\n"]
    lines.append("Frequency (descending):")
    for char, count in counter.most_common():
        pct = count / total * 100
        bar = "#" * int(pct / 2)
        lines.append(f"  {char}: {count:4d} ({pct:5.1f}%) {bar}")

    english_freq = "etaoinshrdlcumwfgypbvkjxqz"
    sorted_chars = "".join(c for c, _ in counter.most_common())
    lines.append(f"\nYour text order:  {sorted_chars}")
    lines.append(f"English expected: {english_freq}")

    return "\n".join(lines)


def _iroot(x: int, n: int) -> int:
    """Return floor(x ** (1/n)) using integer binary search (no float overflow)."""
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return 0
    hi = 1
    while hi ** n <= x:
        hi <<= 1
    lo = hi >> 1
    while lo < hi:
        mid = (lo + hi + 1) >> 1
        if mid ** n <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def tool_rsa_analyze(n: int, e: int, c: int, p: int = 0, q: int = 0) -> str:
    """Analyze RSA parameters and attempt common attacks."""
    results = [f"RSA Analysis: n={n}, e={e}, c={c}"]

    # If p and q given, just decrypt
    if p and q:
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        try:
            plaintext = m.to_bytes((m.bit_length() + 7) // 8, "big").decode(errors="replace")
        except Exception:
            plaintext = str(m)
        results.append(f"Factors given: p={p}, q={q}")
        results.append(f"d = {d}")
        results.append(f"Plaintext (int): {m}")
        results.append(f"Plaintext (str): {plaintext}")
        return "\n".join(results)

    # Attack 1: Small e (cube root)
    if e <= 5:
        results.append(f"\n[Attack] Small e={e} — trying integer root")
        for m_candidate in range(2, 100000):
            if pow(m_candidate, e) == c:
                results.append(f"SUCCESS: m = {m_candidate}")
                try:
                    plaintext = m_candidate.to_bytes((m_candidate.bit_length() + 7) // 8, "big").decode(errors="replace")
                    results.append(f"Plaintext: {plaintext}")
                except Exception:
                    pass
                return "\n".join(results)
        # Try exact integer e-th root (works for any size, unlike float **).
        m_root = _iroot(c, e)
        for m_test in (m_root - 1, m_root, m_root + 1):
            if m_test > 0 and pow(m_test, e) == c:
                results.append(f"SUCCESS: m = {m_test}")
                try:
                    plaintext = m_test.to_bytes((m_test.bit_length() + 7) // 8, "big").decode(errors="replace")
                    results.append(f"Plaintext: {plaintext}")
                except Exception:
                    pass
                return "\n".join(results)
        results.append("Small-e root attack: no exact root found (c may be reduced mod n)")

    # Attack 2: Fermat factorization (works when p and q are close)
    results.append("\n[Attack] Fermat factorization")
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for i in range(100000):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p_found = a + b
            q_found = a - b
            if p_found * q_found == n and p_found > 1 and q_found > 1:
                results.append(f"SUCCESS: p={p_found}, q={q_found}")
                phi = (p_found - 1) * (q_found - 1)
                try:
                    d = pow(e, -1, phi)
                    m = pow(c, d, n)
                    results.append(f"d = {d}")
                    results.append(f"Plaintext (int): {m}")
                    try:
                        plaintext = m.to_bytes((m.bit_length() + 7) // 8, "big").decode(errors="replace")
                        results.append(f"Plaintext (str): {plaintext}")
                    except Exception:
                        pass
                except Exception as ex:
                    results.append(f"Decryption failed: {ex}")
                return "\n".join(results)
        a += 1

    results.append("Fermat: no close factors found in 100k iterations")

    # Attack 3: Wiener's (large e)
    if e > n // 3:
        results.append("\n[Attack] Wiener's attack (large e)")

        def continued_fraction(num, den):
            cf = []
            while den:
                q_val = num // den
                cf.append(q_val)
                num, den = den, num - q_val * den
            return cf

        def convergents(cf):
            convs = []
            h_prev, h_curr = 0, 1
            k_prev, k_curr = 1, 0
            for a_val in cf:
                h_prev, h_curr = h_curr, a_val * h_curr + h_prev
                k_prev, k_curr = k_curr, a_val * k_curr + k_prev
                convs.append((h_curr, k_curr))
            return convs

        cf = continued_fraction(e, n)
        for k, d in convergents(cf):
            if k == 0:
                continue
            phi_candidate = (e * d - 1) // k
            s = n - phi_candidate + 1
            disc = s * s - 4 * n
            if disc >= 0:
                sqrt_disc = math.isqrt(disc)
                if sqrt_disc * sqrt_disc == disc:
                    p_w = (s + sqrt_disc) // 2
                    q_w = (s - sqrt_disc) // 2
                    if p_w * q_w == n:
                        results.append(f"SUCCESS: p={p_w}, q={q_w}, d={d}")
                        m = pow(c, d, n)
                        results.append(f"Plaintext (int): {m}")
                        return "\n".join(results)
        results.append("Wiener's: no valid convergent found")

    return "\n".join(results)


def tool_aes_decrypt(ciphertext: str, key: str, iv: str = "", mode: str = "ECB") -> str:
    """Decrypt AES-ECB or AES-CBC."""
    try:
        ct = bytes.fromhex(ciphertext.replace(" ", "").replace("0x", ""))
        k = bytes.fromhex(key.replace(" ", "").replace("0x", ""))
    except ValueError as ex:
        return f"ERROR parsing hex: {ex}"

    # Try PyCryptodome
    try:
        from Crypto.Cipher import AES as AES_Crypto
        if mode.upper() == "CBC":
            iv_bytes = bytes.fromhex(iv.replace(" ", "").replace("0x", "")) if iv else b"\x00" * 16
            cipher = AES_Crypto.new(k, AES_Crypto.MODE_CBC, iv_bytes)
        else:
            cipher = AES_Crypto.new(k, AES_Crypto.MODE_ECB)
        plaintext = cipher.decrypt(ct)
        # Remove PKCS7 padding
        pad_len = plaintext[-1]
        if 1 <= pad_len <= 16 and plaintext[-pad_len:] == bytes([pad_len]) * pad_len:
            plaintext = plaintext[:-pad_len]
        return f"Decrypted: {plaintext.decode(errors='replace')}\nHex: {plaintext.hex()}"
    except ImportError:
        pass

    # Pure-Python AES fallback (supports AES-128/192/256, ECB and CBC)
    def _aes_decrypt_pure(ciphertext_bytes: bytes, key_bytes: bytes, iv_bytes: bytes = None, use_cbc: bool = False) -> bytes:
        # AES S-box (inverse)
        _SBOX = [
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
        ]

        def _xtime(a):
            return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff

        def _gmul(a, b):
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                hi = a & 0x80
                a = (a << 1) & 0xff
                if hi:
                    a ^= 0x1b
                b >>= 1
            return p

        def _inv_sub_bytes(state):
            return [_SBOX[b] for b in state]

        def _inv_shift_rows(state):
            # state is 16 bytes in column-major order: state[row + 4*col]
            # InvShiftRows: row i shifts right by i
            s = list(state)
            # Row 1: shift right 1
            s[1], s[5], s[9], s[13] = state[13], state[1], state[5], state[9]
            # Row 2: shift right 2
            s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]
            # Row 3: shift right 3
            s[3], s[7], s[11], s[15] = state[7], state[11], state[15], state[3]
            return s

        def _inv_mix_columns(state):
            result = list(state)
            for col in range(4):
                c = col * 4
                s0, s1, s2, s3 = state[c], state[c+1], state[c+2], state[c+3]
                result[c]   = _gmul(s0,0x0e)^_gmul(s1,0x0b)^_gmul(s2,0x0d)^_gmul(s3,0x09)
                result[c+1] = _gmul(s0,0x09)^_gmul(s1,0x0e)^_gmul(s2,0x0b)^_gmul(s3,0x0d)
                result[c+2] = _gmul(s0,0x0d)^_gmul(s1,0x09)^_gmul(s2,0x0e)^_gmul(s3,0x0b)
                result[c+3] = _gmul(s0,0x0b)^_gmul(s1,0x0d)^_gmul(s2,0x09)^_gmul(s3,0x0e)
            return result

        def _add_round_key(state, round_key):
            return [state[i] ^ round_key[i] for i in range(16)]

        # Key expansion
        _RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
        _SBOX_ENC = [
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
        ]

        key_len = len(key_bytes)
        if key_len == 16:
            nk, nr = 4, 10
        elif key_len == 24:
            nk, nr = 6, 12
        elif key_len == 32:
            nk, nr = 8, 14
        else:
            raise ValueError(f"Invalid key length: {key_len}")

        # Expand key into round keys (each 16 bytes = 4 words)
        w = list(key_bytes)
        for i in range(nk, 4 * (nr + 1)):
            temp = w[(i-1)*4:i*4]
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [_SBOX_ENC[b] for b in temp]
                temp[0] ^= _RCON[(i // nk) - 1]
            elif nk > 6 and i % nk == 4:
                temp = [_SBOX_ENC[b] for b in temp]
            prev = w[(i-nk)*4:(i-nk+1)*4]
            w += [prev[j] ^ temp[j] for j in range(4)]

        def _get_round_key(round_num):
            return w[round_num*16:(round_num+1)*16]

        def _decrypt_block(block_bytes):
            # Convert to column-major state
            state = list(block_bytes)
            state = _add_round_key(state, _get_round_key(nr))
            for rnd in range(nr - 1, 0, -1):
                state = _inv_shift_rows(state)
                state = _inv_sub_bytes(state)
                state = _add_round_key(state, _get_round_key(rnd))
                state = _inv_mix_columns(state)
            state = _inv_shift_rows(state)
            state = _inv_sub_bytes(state)
            state = _add_round_key(state, _get_round_key(0))
            return bytes(state)

        result = b""
        prev_block = iv_bytes if iv_bytes else None
        for block_start in range(0, len(ciphertext_bytes), 16):
            block = ciphertext_bytes[block_start:block_start + 16]
            decrypted = _decrypt_block(block)
            if use_cbc and prev_block is not None:
                decrypted = bytes(decrypted[i] ^ prev_block[i] for i in range(16))
            result += decrypted
            prev_block = block
        return result

    try:
        use_cbc = mode.upper() == "CBC"
        iv_bytes = bytes.fromhex(iv.replace(" ", "").replace("0x", "")) if iv else b"\x00" * 16
        plaintext = _aes_decrypt_pure(ct, k, iv_bytes if use_cbc else None, use_cbc=use_cbc)
        # Remove PKCS7 padding
        pad_len = plaintext[-1]
        if 1 <= pad_len <= 16 and plaintext[-pad_len:] == bytes([pad_len]) * pad_len:
            plaintext = plaintext[:-pad_len]
        return f"Decrypted (pure-Python AES): {plaintext.decode(errors='replace')}\nHex: {plaintext.hex()}"
    except Exception as e:
        return f"ERROR in pure-Python AES: {e}"


def tool_vigenere_crack(ciphertext: str, max_key_len: int = 20) -> str:
    """Crack a Vigenere cipher using Kasiski/frequency analysis."""
    ct = "".join(c.upper() for c in ciphertext if c.isalpha())
    if not ct:
        return "No alphabetic characters in ciphertext."

    def ic(text):
        n = len(text)
        if n < 2:
            return 0
        freq = [0] * 26
        for c in text:
            freq[ord(c) - ord('A')] += 1
        return sum(f * (f - 1) for f in freq) / (n * (n - 1))

    results = ["Vigenere analysis:"]

    best_key_len = 1
    best_ic = 0
    for kl in range(1, min(max_key_len + 1, len(ct) // 2)):
        groups = [ct[i::kl] for i in range(kl)]
        avg_ic = sum(ic(g) for g in groups) / kl
        if avg_ic > best_ic:
            best_ic = avg_ic
            best_key_len = kl

    results.append(f"Most likely key length: {best_key_len} (IC={best_ic:.4f})")

    english_freq = [0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061,
                    0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019,
                    0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.002,
                    0.020, 0.001]

    key = []
    for pos in range(best_key_len):
        group = ct[pos::best_key_len]
        best_shift = 0
        best_score = -1
        for shift in range(26):
            score = 0
            for c in group:
                decrypted_idx = (ord(c) - ord('A') - shift) % 26
                score += english_freq[decrypted_idx]
            if score > best_score:
                best_score = score
                best_shift = shift
        key.append(chr(best_shift + ord('A')))

    key_str = "".join(key)
    results.append(f"Key: {key_str}")

    plaintext = []
    for i, c in enumerate(ct):
        shift = ord(key[i % len(key)]) - ord('A')
        plaintext.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
    results.append(f"Decrypted: {''.join(plaintext)}")

    return "\n".join(results)


def tool_mod_math(operation: str, a: int = 0, b: int = 0, m: int = 0,
                  remainders: list = None, moduli: list = None) -> str:
    """Modular arithmetic operations: modpow, modinv, crt, discrete_log."""
    if operation == "modpow":
        result = pow(a, b, m)
        return f"{a}^{b} mod {m} = {result}"

    elif operation == "modinv":
        try:
            result = pow(a, -1, m)
            return f"{a}^(-1) mod {m} = {result}"
        except ValueError:
            return f"No modular inverse: gcd({a}, {m}) != 1"

    elif operation == "crt":
        if not remainders or not moduli or len(remainders) != len(moduli):
            return "CRT requires equal-length remainders and moduli lists."

        M = 1
        for mi in moduli:
            M *= mi

        x = 0
        for ri, mi in zip(remainders, moduli):
            Mi = M // mi
            yi = pow(Mi, -1, mi)
            x += ri * Mi * yi

        x = x % M
        return f"CRT solution: x = {x} (mod {M})"

    elif operation == "discrete_log":
        # Baby-step giant-step for small groups
        n = math.isqrt(m) + 1
        table = {}
        val = 1
        for j in range(n + 1):
            table[val] = j
            val = (val * a) % m

        try:
            factor = pow(a, -n, m)
        except ValueError:
            return f"Discrete log: a={a} has no inverse mod {m}"
        gamma = b
        for i in range(n + 1):
            if gamma in table:
                result = i * n + table[gamma]
                return f"Discrete log: log_{a}({b}) mod {m} = {result}"
            gamma = (gamma * factor) % m
        return "Discrete log not found (group may be too large)"

    return f"Unknown operation: {operation}. Use: modpow, modinv, crt, discrete_log"


def tool_padding_oracle(oracle_url: str, ciphertext: str, block_size: int = 16) -> str:
    """Padding oracle attack description and simulation (CBC mode)."""
    import json
    import urllib.request
    import urllib.error

    try:
        ct = bytes.fromhex(ciphertext.replace(" ", "").replace("0x", ""))
    except ValueError as ex:
        return f"ERROR parsing ciphertext hex: {ex}"

    if len(ct) % block_size != 0:
        return f"ERROR: ciphertext length ({len(ct)}) not multiple of block size ({block_size})"

    blocks = [ct[i:i + block_size] for i in range(0, len(ct), block_size)]
    if len(blocks) < 2:
        return "Need at least 2 blocks (IV + ciphertext)."

    def check_padding(modified_ct):
        try:
            req = urllib.request.Request(
                oracle_url,
                data=json.dumps({"ciphertext": modified_ct.hex()}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode()
                return "valid" in body.lower() or resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code != 400 and e.code != 403
        except Exception:
            return False

    plaintext = b""
    for block_idx in range(1, len(blocks)):
        decrypted_block = bytearray(block_size)
        for byte_pos in range(block_size - 1, -1, -1):
            pad_val = block_size - byte_pos
            prefix = b"".join(blocks[:block_idx - 1])
            for guess in range(256):
                modified = bytearray(blocks[block_idx - 1])
                modified[byte_pos] = guess
                for k in range(byte_pos + 1, block_size):
                    modified[k] = decrypted_block[k] ^ pad_val
                test = prefix + bytes(modified) + blocks[block_idx]
                if check_padding(test):
                    decrypted_block[byte_pos] = guess ^ pad_val
                    break

        plain_block = bytes(x ^ y for x, y in zip(decrypted_block, blocks[block_idx - 1]))
        plaintext += plain_block

    # Remove padding
    pad_len = plaintext[-1]
    if 1 <= pad_len <= block_size:
        plaintext = plaintext[:-pad_len]

    return f"Decrypted: {plaintext.decode(errors='replace')}\nHex: {plaintext.hex()}"


def tool_substitution_solve(ciphertext: str) -> str:
    """Attempt to solve a simple substitution cipher using frequency analysis."""
    ct = ciphertext.upper()
    freq = Counter(c for c in ct if c.isalpha())
    sorted_chars = [c for c, _ in freq.most_common()]
    english_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

    mapping = {}
    for i, c in enumerate(sorted_chars):
        if i < len(english_order):
            mapping[c] = english_order[i]

    decoded = ""
    for c in ct:
        if c.isalpha():
            decoded += mapping.get(c, "?")
        else:
            decoded += c

    # Also try ROT-13 (common in CTFs)
    rot13 = ""
    for c in ct:
        if c.isalpha():
            base = ord('A')
            rot13 += chr((ord(c) - base + 13) % 26 + base)
        else:
            rot13 += c

    return (f"Frequency-based substitution:\n{decoded}\n\n"
            f"ROT-13 (common in CTF):\n{rot13}\n\n"
            f"Frequency map: {mapping}")


def tool_hash_crack(hash_value: str, wordlist_path: str, hash_type: str = "auto") -> str:
    """Crack a hash against a wordlist."""
    h = hash_value.strip().lower()

    # Auto-detect hash type
    if hash_type == "auto":
        if len(h) == 32:
            hash_type = "md5"
        elif len(h) == 40:
            hash_type = "sha1"
        elif len(h) == 64:
            hash_type = "sha256"
        elif len(h) == 128:
            hash_type = "sha512"
        else:
            return f"Cannot auto-detect hash type for length {len(h)}"

    try:
        with open(wordlist_path, "r", errors="replace") as f:
            words = f.read().splitlines()
    except Exception as e:
        return f"ERROR reading wordlist: {e}"

    for i, word in enumerate(words):
        computed = hashlib.new(hash_type, word.encode()).hexdigest()
        if computed == h:
            return f"CRACKED: {hash_value} = {word} ({hash_type}, attempt {i + 1}/{len(words)})"

    return f"Not cracked. Tried {len(words)} words with {hash_type}."


def tool_prng_crack(outputs: list, predict_count: int = 10) -> str:
    """Crack Mersenne Twister (MT19937) from 624 consecutive 32-bit outputs."""
    if len(outputs) < 624:
        return f"Need 624 outputs, got {len(outputs)}. Collect more data."

    def _undo_right(value, shift):
        # Invert value = x ^ (x >> shift). XOR the constant `value` each pass
        # (NOT the running result) so it converges to x.
        result = value
        for _ in range(0, 32, shift):
            result = value ^ (result >> shift)
        return result & 0xFFFFFFFF

    def _undo_left(value, shift, mask):
        # Invert value = x ^ ((x << shift) & mask).
        result = value
        for _ in range(0, 32, shift):
            result = value ^ ((result << shift) & mask)
        return result & 0xFFFFFFFF

    def untemper(y):
        # Reverse the tempering transform of MT19937, in reverse order.
        y = _undo_right(y, 18)
        y = _undo_left(y, 15, 0xEFC60000)
        y = _undo_left(y, 7, 0x9D2C5680)
        y = _undo_right(y, 11)
        return y & 0xFFFFFFFF

    state = [untemper(o & 0xFFFFFFFF) for o in outputs[:624]]

    def generate(st, index):
        if index >= 624:
            for i in range(624):
                y = (st[i] & 0x80000000) | (st[(i + 1) % 624] & 0x7FFFFFFF)
                st[i] = st[(i + 397) % 624] ^ (y >> 1)
                if y & 1:
                    st[i] ^= 0x9908B0DF
            index = 0

        y = st[index]
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF, index + 1

    predictions = []
    idx = 624
    for _ in range(predict_count):
        val, idx = generate(state, idx)
        predictions.append(val)

    return (f"MT19937 state recovered from {len(outputs)} outputs.\n"
            f"Next {predict_count} predicted values:\n" +
            "\n".join(f"  {i + 1}: {v}" for i, v in enumerate(predictions)))


def tool_encoding_chain(data: str, max_depth: int = 10) -> str:
    """Auto-detect and decode stacked encodings (base64, hex, ROT13)."""
    results = [f"Input: {data[:100]}{'...' if len(data) > 100 else ''}"]
    current = data

    for depth in range(max_depth):
        decoded = None
        method = None

        # Try base64
        try:
            raw = base64.b64decode(current, validate=True)
            if len(raw) > 0 and all(b < 128 for b in raw):
                decoded = raw.decode()
                method = "base64"
        except Exception:
            pass

        # Try hex
        if not decoded:
            clean = current.strip().replace(" ", "").replace("0x", "")
            if len(clean) % 2 == 0 and len(clean) >= 2 and all(c in "0123456789abcdefABCDEF" for c in clean):
                try:
                    raw = bytes.fromhex(clean)
                    if all(32 <= b < 127 for b in raw):
                        decoded = raw.decode()
                        method = "hex"
                except Exception:
                    pass

        # Try ROT13
        if not decoded:
            rot = tool_rot_bruteforce(current)
            for line in rot.split("\n"):
                if "ROT-13:" in line:
                    candidate = line.split(":", 1)[1].strip()
                    common = sum(1 for c in candidate.lower() if c in "etaoinshrdl")
                    orig_common = sum(1 for c in current.lower() if c in "etaoinshrdl")
                    if common > orig_common + 3:
                        decoded = candidate
                        method = "ROT-13"
                    break

        if decoded and decoded != current:
            results.append(f"  Layer {depth + 1} ({method}): {decoded[:100]}")
            current = decoded
        else:
            break

    results.append(f"\nFinal result: {current}")
    return "\n".join(results)


# --- Tool definitions ---

CRYPTO_TOOLS = [
    {
        "name": "base64_decode",
        "description": "Decode a base64-encoded string.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Base64-encoded string to decode"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "base64_encode",
        "description": "Encode a string to base64.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "String to encode"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "hex_decode",
        "description": "Decode a hex-encoded string to text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Hex string (e.g. '48656c6c6f' or '0x48 0x65')"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "hash_identify",
        "description": "Identify the likely type of a hash based on its length and format.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_str": {"type": "string", "description": "The hash string to identify"},
            },
            "required": ["hash_str"],
        },
    },
    {
        "name": "rot_bruteforce",
        "description": "Try all 25 ROT-N (Caesar cipher) rotations on a string. Useful for simple substitution ciphers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Ciphertext to brute-force"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "xor_bruteforce",
        "description": "XOR brute-force with all single-byte keys (0x00-0xFF). Input can be hex or ASCII.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Data to XOR (hex string or raw text)"},
                "max_key_len": {"type": "integer", "description": "Max key length (default 1)", "default": 1},
            },
            "required": ["data"],
        },
    },
    {
        "name": "frequency_analysis",
        "description": "Perform character frequency analysis. Compares letter distribution to English language frequencies.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to analyze"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "rsa_analyze",
        "description": "Analyze RSA parameters and attempt common attacks: small-e cube-root, Fermat factorization, Wiener's attack. Provide n, e, c; optionally p and q for direct decryption.",
        "input_schema": {
            "type": "object",
            "properties": {
                "n": {"type": "integer", "description": "RSA modulus"},
                "e": {"type": "integer", "description": "RSA public exponent"},
                "c": {"type": "integer", "description": "Ciphertext (integer)"},
                "p": {"type": "integer", "description": "Prime factor p (optional)", "default": 0},
                "q": {"type": "integer", "description": "Prime factor q (optional)", "default": 0},
            },
            "required": ["n", "e", "c"],
        },
    },
    {
        "name": "aes_decrypt",
        "description": "Decrypt AES-ECB or AES-CBC given hex ciphertext and hex key. Uses PyCryptodome if available.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ciphertext": {"type": "string", "description": "Hex-encoded ciphertext"},
                "key": {"type": "string", "description": "Hex-encoded AES key (16, 24, or 32 bytes)"},
                "iv": {"type": "string", "description": "Hex-encoded IV for CBC mode (optional)", "default": ""},
                "mode": {"type": "string", "description": "AES mode: ECB or CBC (default ECB)", "default": "ECB"},
            },
            "required": ["ciphertext", "key"],
        },
    },
    {
        "name": "vigenere_crack",
        "description": "Crack a Vigenere cipher using index-of-coincidence key-length estimation and frequency analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ciphertext": {"type": "string", "description": "Vigenere-encrypted ciphertext (alphabetic)"},
                "max_key_len": {"type": "integer", "description": "Maximum key length to try (default 20)", "default": 20},
            },
            "required": ["ciphertext"],
        },
    },
    {
        "name": "mod_math",
        "description": "Modular arithmetic: modpow (a^b mod m), modinv (a^-1 mod m), crt (Chinese Remainder Theorem), discrete_log (baby-step giant-step).",
        "input_schema": {
            "type": "object",
            "properties": {
                "operation": {"type": "string", "description": "Operation: modpow | modinv | crt | discrete_log"},
                "a": {"type": "integer", "description": "Base / value a", "default": 0},
                "b": {"type": "integer", "description": "Exponent / value b (modpow, discrete_log)", "default": 0},
                "m": {"type": "integer", "description": "Modulus", "default": 0},
                "remainders": {"type": "array", "items": {"type": "integer"}, "description": "Remainders list (crt only)"},
                "moduli": {"type": "array", "items": {"type": "integer"}, "description": "Moduli list (crt only)"},
            },
            "required": ["operation"],
        },
    },
    {
        "name": "padding_oracle",
        "description": "Perform a CBC padding oracle attack against a remote oracle endpoint. Sends modified ciphertexts and reads valid/invalid responses.",
        "input_schema": {
            "type": "object",
            "properties": {
                "oracle_url": {"type": "string", "description": "URL of the padding oracle endpoint"},
                "ciphertext": {"type": "string", "description": "Hex-encoded ciphertext (IV prepended)"},
                "block_size": {"type": "integer", "description": "Block size in bytes (default 16)", "default": 16},
            },
            "required": ["oracle_url", "ciphertext"],
        },
    },
    {
        "name": "substitution_solve",
        "description": "Attempt to solve a simple substitution cipher. Tries frequency-based mapping and ROT-13.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ciphertext": {"type": "string", "description": "Substitution-encrypted ciphertext"},
            },
            "required": ["ciphertext"],
        },
    },
    {
        "name": "hash_crack",
        "description": "Crack a hash (MD5/SHA1/SHA256/SHA512) against a wordlist file. Auto-detects hash type from length.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash_value": {"type": "string", "description": "The hash to crack (hex string)"},
                "wordlist_path": {"type": "string", "description": "Absolute path to a wordlist file"},
                "hash_type": {"type": "string", "description": "Hash type: auto | md5 | sha1 | sha256 | sha512", "default": "auto"},
            },
            "required": ["hash_value", "wordlist_path"],
        },
    },
    {
        "name": "prng_crack",
        "description": "Recover Mersenne Twister (MT19937) internal state from 624 consecutive 32-bit outputs and predict future values.",
        "input_schema": {
            "type": "object",
            "properties": {
                "outputs": {"type": "array", "items": {"type": "integer"}, "description": "List of 624+ consecutive 32-bit MT19937 outputs"},
                "predict_count": {"type": "integer", "description": "Number of future values to predict (default 10)", "default": 10},
            },
            "required": ["outputs"],
        },
    },
    {
        "name": "encoding_chain",
        "description": "Auto-detect and peel stacked encodings (base64, hex, ROT-13) layer by layer.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Potentially multi-encoded data string"},
                "max_depth": {"type": "integer", "description": "Maximum decoding layers to attempt (default 10)", "default": 10},
            },
            "required": ["data"],
        },
    },
]

CRYPTO_DISPATCH = {
    "base64_decode": lambda **kw: tool_base64_decode(**kw),
    "base64_encode": lambda **kw: tool_base64_encode(**kw),
    "hex_decode": lambda **kw: tool_hex_decode(**kw),
    "hash_identify": lambda **kw: tool_hash_identify(**kw),
    "rot_bruteforce": lambda **kw: tool_rot_bruteforce(**kw),
    "xor_bruteforce": lambda **kw: tool_xor_bruteforce(**kw),
    "frequency_analysis": lambda **kw: tool_frequency_analysis(**kw),
    "rsa_analyze": lambda **kw: tool_rsa_analyze(**kw),
    "aes_decrypt": lambda **kw: tool_aes_decrypt(**kw),
    "vigenere_crack": lambda **kw: tool_vigenere_crack(**kw),
    "mod_math": lambda **kw: tool_mod_math(**kw),
    "padding_oracle": lambda **kw: tool_padding_oracle(**kw),
    "substitution_solve": lambda **kw: tool_substitution_solve(**kw),
    "hash_crack": lambda **kw: tool_hash_crack(**kw),
    "prng_crack": lambda **kw: tool_prng_crack(**kw),
    "encoding_chain": lambda **kw: tool_encoding_chain(**kw),
}

CRYPTO_SYSTEM_PROMPT = """You are a cryptography agent for CTF challenges and authorized security testing.
Your job is to analyze, decode, and crack encoded or encrypted data.

Strategy:
1. Examine the input data — look at length, character set, patterns, and structure.
2. Try common encodings first: base64, hex. For stacked encodings use encoding_chain.
3. If it looks like a hash, identify it with hash_identify; crack it with hash_crack.
4. If it looks like a substitution cipher, try rot_bruteforce or substitution_solve.
5. If it might be XOR-encrypted, try xor_bruteforce.
6. Use frequency_analysis to compare letter distributions to English.
7. For Vigenere ciphers, use vigenere_crack.
8. For RSA challenges: use rsa_analyze — try small-e root, Fermat factorization, Wiener's attack.
9. For AES challenges: use aes_decrypt with the key and IV.
10. For modular arithmetic (CTF math puzzles): use mod_math (modpow, modinv, crt, discrete_log).
11. For CBC padding oracle challenges: use padding_oracle with the oracle URL.
12. For Python random() predictions: use prng_crack with 624 consecutive MT19937 outputs.
13. Combine techniques — data may be multi-layered.

Report clearly:
- What encoding/encryption was identified
- The decoded/decrypted result
- Confidence level and reasoning
- If unable to crack, describe what was tried and suggest next steps"""


def create_crypto_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a crypto agent instance."""
    return BaseAgent(
        name="crypto",
        system_prompt=CRYPTO_SYSTEM_PROMPT,
        tools=CRYPTO_TOOLS,
        tool_dispatch=CRYPTO_DISPATCH,
        client=client,
    )
