"""Blockchain agent — smart contract analysis, ABI/tx decoding, EVM bytecode."""

import hashlib
import json
import re
import struct
import urllib.request
import urllib.error

import anthropic

from agents.base import BaseAgent


# --- Pure Python Keccak-256 (Ethereum uses original Keccak, not NIST SHA3) ---

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROTATIONS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _keccak_f(state):
    """Apply Keccak-f[1600] permutation."""
    for rc in _KECCAK_RC:
        # Theta
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ ((C[(x + 1) % 5] << 1 | C[(x + 1) % 5] >> 63) & 0xFFFFFFFFFFFFFFFF)
             for x in range(5)]
        state = [[state[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        # Rho and Pi
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _KECCAK_ROTATIONS[x][y]
                B[y][(2 * x + 3 * y) % 5] = (
                    (state[x][y] << r | state[x][y] >> (64 - r)) & 0xFFFFFFFFFFFFFFFF
                )
        # Chi
        state = [
            [(B[x][y] ^ (~B[(x + 1) % 5][y] & B[(x + 2) % 5][y])) & 0xFFFFFFFFFFFFFFFF
             for y in range(5)]
            for x in range(5)
        ]
        # Iota
        state[0][0] ^= rc
    return state


def _keccak256(data: bytes) -> bytes:
    """Pure-Python Keccak-256 (Ethereum variant, not NIST SHA3-256)."""
    rate = 136  # (1600 - 512) / 8 bits = 136 bytes
    msg = bytearray(data)
    # Keccak padding: 0x01 ... 0x80
    msg += b'\x01'
    while len(msg) % rate != 0:
        msg += b'\x00'
    msg[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for block_start in range(0, len(msg), rate):
        block = msg[block_start:block_start + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            word = int.from_bytes(block[i * 8:(i + 1) * 8], 'little')
            state[x][y] ^= word
        state = _keccak_f(state)

    result = b''
    for i in range(4):
        x, y = i % 5, i // 5
        result += state[x][y].to_bytes(8, 'little')
    return result


# --- Tool implementations ---

VULN_PATTERNS = [
    {
        "name": "Reentrancy",
        "pattern": r'\.call\{?\s*value\s*[:=]',
        "description": "External call with value before state update — possible reentrancy",
        "severity": "HIGH",
    },
    {
        "name": "tx.origin authentication",
        "pattern": r'tx\.origin',
        "description": "Using tx.origin for auth — vulnerable to phishing attacks",
        "severity": "HIGH",
    },
    {
        "name": "Unchecked low-level call",
        "pattern": r'\.call\(|\.delegatecall\(|\.staticcall\(',
        "description": "Low-level call — check return value",
        "severity": "MEDIUM",
    },
    {
        "name": "selfdestruct",
        "pattern": r'selfdestruct\(|suicide\(',
        "description": "Contract can be destroyed — check access control",
        "severity": "HIGH",
    },
    {
        "name": "Block timestamp dependence",
        "pattern": r'block\.timestamp|now\b',
        "description": "Using block.timestamp — can be manipulated by miners",
        "severity": "LOW",
    },
    {
        "name": "Unchecked math (pre-0.8)",
        "pattern": r'pragma\s+solidity\s+[<^]?\s*0\.[0-7]\.',
        "description": "Solidity < 0.8.0 without SafeMath — integer overflow/underflow risk",
        "severity": "HIGH",
    },
    {
        "name": "delegatecall to variable",
        "pattern": r'\.delegatecall\(',
        "description": "delegatecall — if target is user-controlled, can hijack storage",
        "severity": "HIGH",
    },
    {
        "name": "Hardcoded private key/secret",
        "pattern": r'(?:private|secret|key)\s*=\s*["\']?0x[0-9a-fA-F]{64}',
        "description": "Hardcoded secret in contract — visible on-chain",
        "severity": "CRITICAL",
    },
]


def tool_solidity_analyze(source_code: str = "", file_path: str = "") -> str:
    """Static analysis of Solidity source for common vulnerabilities."""
    if file_path:
        try:
            with open(file_path, "r") as f:
                source_code = f.read()
        except Exception as e:
            return f"ERROR: {e}"

    if not source_code:
        return "Provide source_code or file_path."

    findings = []
    for vuln in VULN_PATTERNS:
        matches = list(re.finditer(vuln["pattern"], source_code))
        if matches:
            lines = []
            for m in matches:
                line_num = source_code[:m.start()].count("\n") + 1
                context = source_code[max(0, m.start() - 30):m.end() + 30].strip()
                lines.append(f"    Line {line_num}: ...{context}...")
            findings.append(
                f"[{vuln['severity']}] {vuln['name']}: {vuln['description']}\n"
                + "\n".join(lines)
            )

    if not findings:
        return "No common vulnerability patterns detected."
    return f"Found {len(findings)} potential issues:\n\n" + "\n\n".join(findings)


def tool_abi_decode(data: str, types: str, includes_selector: bool = False) -> str:
    """Decode ABI-encoded data given type list."""
    clean = data.replace("0x", "").replace(" ", "")
    selector = None
    if includes_selector:
        selector = clean[:8]
        clean = clean[8:]

    type_list = [t.strip() for t in types.split(",")]
    results = []
    offset = 0

    for t in type_list:
        if offset + 64 > len(clean):
            results.append(f"{t}: <insufficient data>")
            break
        word = clean[offset:offset + 64]
        if t.startswith("uint") or t.startswith("int"):
            val = int(word, 16)
            results.append(f"{t}: {val} (0x{val:x})")
        elif t == "address":
            addr = "0x" + word[24:]
            results.append(f"{t}: {addr}")
        elif t == "bool":
            val = int(word, 16)
            results.append(f"{t}: {bool(val)}")
        elif t.startswith("bytes"):
            results.append(f"{t}: 0x{word}")
        else:
            results.append(f"{t}: 0x{word} (raw)")
        offset += 64

    prefix = f"Selector: 0x{selector}\n" if selector is not None else ""
    return prefix + "\n".join(results)


KNOWN_SELECTORS = {
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "70a08231": "balanceOf(address)",
    "18160ddd": "totalSupply()",
    "dd62ed3e": "allowance(address,address)",
    "06fdde03": "name()",
    "95d89b41": "symbol()",
    "313ce567": "decimals()",
    "a0712d68": "mint(uint256)",
    "42966c68": "burn(uint256)",
    "8da5cb5b": "owner()",
    "715018a6": "renounceOwnership()",
    "f2fde38b": "transferOwnership(address)",
    "3ccfd60b": "withdraw()",
    "d0e30db0": "deposit()",
    "e8e33700": "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    "38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
}


def tool_selector_lookup(selector: str) -> str:
    """Look up a 4-byte function selector."""
    clean = selector.replace("0x", "").lower()[:8]
    if clean in KNOWN_SELECTORS:
        return f"0x{clean} -> {KNOWN_SELECTORS[clean]}"
    return f"0x{clean} -> Unknown selector (not in built-in database of {len(KNOWN_SELECTORS)} signatures)"


EVM_OPCODES = {
    0x00: ("STOP", 0), 0x01: ("ADD", 0), 0x02: ("MUL", 0), 0x03: ("SUB", 0),
    0x04: ("DIV", 0), 0x05: ("SDIV", 0), 0x06: ("MOD", 0), 0x07: ("SMOD", 0),
    0x08: ("ADDMOD", 0), 0x09: ("MULMOD", 0), 0x0a: ("EXP", 0), 0x10: ("LT", 0),
    0x11: ("GT", 0), 0x14: ("EQ", 0), 0x15: ("ISZERO", 0), 0x16: ("AND", 0),
    0x17: ("OR", 0), 0x18: ("XOR", 0), 0x19: ("NOT", 0), 0x1a: ("BYTE", 0),
    0x20: ("SHA3", 0), 0x30: ("ADDRESS", 0), 0x31: ("BALANCE", 0),
    0x32: ("ORIGIN", 0), 0x33: ("CALLER", 0), 0x34: ("CALLVALUE", 0),
    0x35: ("CALLDATALOAD", 0), 0x36: ("CALLDATASIZE", 0), 0x37: ("CALLDATACOPY", 0),
    0x38: ("CODESIZE", 0), 0x39: ("CODECOPY", 0), 0x3a: ("GASPRICE", 0),
    0x3b: ("EXTCODESIZE", 0), 0x40: ("BLOCKHASH", 0), 0x41: ("COINBASE", 0),
    0x42: ("TIMESTAMP", 0), 0x43: ("NUMBER", 0), 0x44: ("DIFFICULTY", 0),
    0x45: ("GASLIMIT", 0), 0x50: ("POP", 0), 0x51: ("MLOAD", 0),
    0x52: ("MSTORE", 0), 0x53: ("MSTORE8", 0), 0x54: ("SLOAD", 0),
    0x55: ("SSTORE", 0), 0x56: ("JUMP", 0), 0x57: ("JUMPI", 0),
    0x58: ("PC", 0), 0x59: ("MSIZE", 0), 0x5a: ("GAS", 0),
    0x5b: ("JUMPDEST", 0), 0xf0: ("CREATE", 0), 0xf1: ("CALL", 0),
    0xf2: ("CALLCODE", 0), 0xf3: ("RETURN", 0), 0xf4: ("DELEGATECALL", 0),
    0xf5: ("CREATE2", 0), 0xfa: ("STATICCALL", 0), 0xfd: ("REVERT", 0),
    0xff: ("SELFDESTRUCT", 0),
}
# Add PUSH1-PUSH32, DUP1-DUP16, SWAP1-SWAP16, LOG0-LOG4
for _i in range(32):
    EVM_OPCODES[0x60 + _i] = (f"PUSH{_i + 1}", _i + 1)
for _i in range(16):
    EVM_OPCODES[0x80 + _i] = (f"DUP{_i + 1}", 0)
    EVM_OPCODES[0x90 + _i] = (f"SWAP{_i + 1}", 0)
for _i in range(5):
    EVM_OPCODES[0xa0 + _i] = (f"LOG{_i}", 0)


def tool_bytecode_analyze(bytecode: str) -> str:
    """Disassemble EVM bytecode."""
    clean = bytecode.replace("0x", "").replace(" ", "")
    try:
        raw = bytes.fromhex(clean)
    except ValueError as e:
        return f"ERROR: {e}"

    lines = []
    i = 0
    while i < len(raw):
        opcode = raw[i]
        if opcode in EVM_OPCODES:
            name, extra = EVM_OPCODES[opcode]
            if extra > 0:
                operand = raw[i + 1:i + 1 + extra].hex()
                lines.append(f"0x{i:04x}: {name} 0x{operand}")
                i += 1 + extra
            else:
                lines.append(f"0x{i:04x}: {name}")
                i += 1
        else:
            lines.append(f"0x{i:04x}: UNKNOWN(0x{opcode:02x})")
            i += 1

        if len(lines) >= 200:
            lines.append(f"... truncated ({len(raw) - i} bytes remaining)")
            break

    return "\n".join(lines)


def tool_tx_decode(raw_tx: str) -> str:
    """Decode an RLP-encoded Ethereum transaction."""
    clean = raw_tx.replace("0x", "").replace(" ", "")
    try:
        data = bytes.fromhex(clean)
    except ValueError as e:
        return f"ERROR: {e}"

    def rlp_decode(data, pos=0):
        if pos >= len(data):
            return None, pos
        prefix = data[pos]
        if prefix <= 0x7f:
            return bytes([prefix]), pos + 1
        elif prefix <= 0xb7:
            str_len = prefix - 0x80
            return data[pos + 1:pos + 1 + str_len], pos + 1 + str_len
        elif prefix <= 0xbf:
            len_of_len = prefix - 0xb7
            str_len = int.from_bytes(data[pos + 1:pos + 1 + len_of_len], "big")
            start = pos + 1 + len_of_len
            return data[start:start + str_len], start + str_len
        elif prefix <= 0xf7:
            list_len = prefix - 0xc0
            items = []
            end = pos + 1 + list_len
            p = pos + 1
            while p < end:
                item, p = rlp_decode(data, p)
                items.append(item)
            return items, end
        else:
            len_of_len = prefix - 0xf7
            list_len = int.from_bytes(data[pos + 1:pos + 1 + len_of_len], "big")
            items = []
            start = pos + 1 + len_of_len
            end = start + list_len
            p = start
            while p < end:
                item, p = rlp_decode(data, p)
                items.append(item)
            return items, end

    try:
        decoded, _ = rlp_decode(data)
    except Exception as e:
        return f"ERROR decoding RLP: {e}"

    if not isinstance(decoded, list) or len(decoded) < 6:
        return f"Decoded RLP (not standard tx format): {decoded}"

    fields = ["nonce", "gasPrice", "gasLimit", "to", "value", "data"]
    if len(decoded) >= 9:
        fields += ["v", "r", "s"]

    lines = []
    for i, name in enumerate(fields):
        if i < len(decoded):
            val = decoded[i]
            if isinstance(val, bytes):
                if name in ("to",):
                    lines.append(f"{name}: 0x{val.hex()}")
                elif name in ("data",):
                    lines.append(f"{name}: 0x{val.hex()[:100]}{'...' if len(val) > 50 else ''}")
                else:
                    int_val = int.from_bytes(val, "big") if val else 0
                    lines.append(f"{name}: {int_val} (0x{val.hex()})")
            else:
                lines.append(f"{name}: {val}")

    return "\n".join(lines)


def tool_keccak256(data: str) -> str:
    """Compute Keccak-256 hash (Ethereum's original Keccak, not NIST SHA3)."""
    h = _keccak256(data.encode()).hex()
    selector = h[:8]
    return f"Hash: 0x{h}\nSelector (first 4 bytes): 0x{selector}"


def tool_address_checksum(address: str) -> str:
    """Validate and compute EIP-55 checksum for an Ethereum address."""
    clean = address.lower().replace("0x", "")
    if len(clean) != 40:
        return f"ERROR: Invalid address length ({len(clean)} chars, expected 40)"

    addr_hash = _keccak256(clean.encode()).hex()

    checksummed = "0x"
    for i, c in enumerate(clean):
        if c in "0123456789":
            checksummed += c
        elif int(addr_hash[i], 16) >= 8:
            checksummed += c.upper()
        else:
            checksummed += c.lower()

    return f"Checksummed: {checksummed}"


def tool_contract_interact(rpc_url: str, to: str, data: str, block: str = "latest") -> str:
    """Call a read-only contract function via JSON-RPC eth_call."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": to, "data": data}, block],
        "id": 1,
    }
    try:
        req = urllib.request.Request(
            rpc_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
        if "error" in result:
            return f"RPC error: {result['error']}"
        return f"Result: {result.get('result', 'null')}"
    except Exception as e:
        return f"ERROR: {e}"


# --- Tool definitions ---

BLOCKCHAIN_TOOLS = [
    {
        "name": "solidity_analyze",
        "description": "Static analysis of Solidity source for vulnerabilities: reentrancy, tx.origin, unchecked calls, selfdestruct, integer overflow.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_code": {"type": "string", "description": "Solidity source code to analyze"},
                "file_path": {"type": "string", "description": "Path to a .sol file"},
            },
            "required": [],
        },
    },
    {
        "name": "abi_decode",
        "description": "Decode ABI-encoded calldata or return data given type list (e.g. 'uint256,address').",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Hex-encoded ABI data"},
                "types": {"type": "string", "description": "Comma-separated types: uint256,address,bool,bytes32"},
                "includes_selector": {"type": "boolean", "description": "Whether data starts with 4-byte selector", "default": False},
            },
            "required": ["data", "types"],
        },
    },
    {
        "name": "selector_lookup",
        "description": "Look up a 4-byte function selector against known function signatures.",
        "input_schema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "4-byte hex selector (e.g. 'a9059cbb')"},
            },
            "required": ["selector"],
        },
    },
    {
        "name": "bytecode_analyze",
        "description": "Disassemble EVM bytecode into opcodes. Identifies PUSH values, CALL, DELEGATECALL, SELFDESTRUCT.",
        "input_schema": {
            "type": "object",
            "properties": {
                "bytecode": {"type": "string", "description": "Hex-encoded EVM bytecode"},
            },
            "required": ["bytecode"],
        },
    },
    {
        "name": "tx_decode",
        "description": "Decode a raw RLP-encoded Ethereum transaction into nonce, gas, to, value, data, v/r/s.",
        "input_schema": {
            "type": "object",
            "properties": {
                "raw_tx": {"type": "string", "description": "Hex-encoded raw transaction"},
            },
            "required": ["raw_tx"],
        },
    },
    {
        "name": "keccak256",
        "description": "Compute Keccak-256 hash (Ethereum's hash function). Returns full hash and 4-byte selector.",
        "input_schema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "String to hash (e.g. 'transfer(address,uint256)')"},
            },
            "required": ["data"],
        },
    },
    {
        "name": "address_checksum",
        "description": "Validate and compute EIP-55 checksum for an Ethereum address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Ethereum address (with or without 0x prefix)"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "contract_interact",
        "description": "Call a read-only smart contract function via JSON-RPC eth_call.",
        "input_schema": {
            "type": "object",
            "properties": {
                "rpc_url": {"type": "string", "description": "JSON-RPC endpoint URL"},
                "to": {"type": "string", "description": "Contract address"},
                "data": {"type": "string", "description": "ABI-encoded calldata"},
                "block": {"type": "string", "description": "Block number or 'latest'", "default": "latest"},
            },
            "required": ["rpc_url", "to", "data"],
        },
    },
]

BLOCKCHAIN_DISPATCH = {
    "solidity_analyze": lambda **kw: tool_solidity_analyze(**kw),
    "abi_decode": lambda **kw: tool_abi_decode(**kw),
    "selector_lookup": lambda **kw: tool_selector_lookup(**kw),
    "bytecode_analyze": lambda **kw: tool_bytecode_analyze(**kw),
    "tx_decode": lambda **kw: tool_tx_decode(**kw),
    "keccak256": lambda **kw: tool_keccak256(**kw),
    "address_checksum": lambda **kw: tool_address_checksum(**kw),
    "contract_interact": lambda **kw: tool_contract_interact(**kw),
}

BLOCKCHAIN_SYSTEM_PROMPT = """You are a blockchain security agent for CTF challenges.

Strategy:
1. For Solidity source: run solidity_analyze to flag vulnerability patterns.
2. For unknown calldata: use first 4 bytes with selector_lookup, then abi_decode.
3. For raw transactions: use tx_decode to extract fields.
4. For bytecode: use bytecode_analyze to disassemble and identify key operations.
5. For on-chain interaction: use contract_interact with eth_call.
6. Use keccak256 to compute function selectors from signatures.

Common CTF patterns:
- Reentrancy: external call before state update
- Access control: tx.origin, missing onlyOwner
- Integer overflow: Solidity < 0.8 without SafeMath
- selfdestruct: force-send ether to break balance checks
- delegatecall: storage collision with proxy contracts
- Hardcoded secrets: private variables are readable on-chain

Report all findings with severity, evidence, and exploitation strategy."""


def create_blockchain_agent(client: anthropic.Anthropic) -> BaseAgent:
    """Create a blockchain security agent."""
    return BaseAgent(
        name="blockchain",
        system_prompt=BLOCKCHAIN_SYSTEM_PROMPT,
        tools=BLOCKCHAIN_TOOLS,
        tool_dispatch=BLOCKCHAIN_DISPATCH,
        client=client,
    )
