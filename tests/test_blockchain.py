import hashlib
from unittest.mock import MagicMock
from agents.blockchain import (
    create_blockchain_agent, BLOCKCHAIN_TOOLS, BLOCKCHAIN_DISPATCH,
    tool_solidity_analyze, tool_abi_decode, tool_selector_lookup,
    tool_bytecode_analyze, tool_tx_decode, tool_keccak256,
    tool_address_checksum,
)


def test_blockchain_tools_defined():
    names = [t["name"] for t in BLOCKCHAIN_TOOLS]
    assert "solidity_analyze" in names
    assert "abi_decode" in names
    assert "selector_lookup" in names
    assert "bytecode_analyze" in names
    assert "tx_decode" in names
    assert "keccak256" in names
    assert "address_checksum" in names
    assert "contract_interact" in names


def test_dispatch_matches_tools():
    tool_names = {t["name"] for t in BLOCKCHAIN_TOOLS}
    dispatch_names = set(BLOCKCHAIN_DISPATCH.keys())
    assert tool_names == dispatch_names


def test_create_blockchain_agent():
    client = MagicMock()
    agent = create_blockchain_agent(client)
    assert agent.name == "blockchain"


def test_solidity_analyze_reentrancy():
    code = """
    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
    """
    result = tool_solidity_analyze(source_code=code)
    assert "reentrancy" in result.lower()


def test_solidity_analyze_tx_origin():
    code = """
    function transfer(address to) public {
        require(tx.origin == owner);
        // transfer logic
    }
    """
    result = tool_solidity_analyze(source_code=code)
    assert "tx.origin" in result


def test_keccak256():
    result = tool_keccak256("transfer(address,uint256)")
    assert "a9059cbb" in result.lower()


def test_selector_lookup():
    result = tool_selector_lookup("a9059cbb")
    assert "transfer" in result.lower()


def test_address_checksum():
    result = tool_address_checksum("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae")
    assert "0x" in result


def test_abi_decode_uint():
    # ABI-encoded uint256 value 42
    data = "000000000000000000000000000000000000000000000000000000000000002a"
    result = tool_abi_decode(data=data, types="uint256")
    assert "42" in result


def test_bytecode_analyze():
    # Simple bytecode: PUSH1 0x60 PUSH1 0x40 MSTORE
    bytecode = "6060604052"
    result = tool_bytecode_analyze(bytecode=bytecode)
    assert "PUSH1" in result or "push1" in result.lower()
