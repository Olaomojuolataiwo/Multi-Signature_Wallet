// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title RevertingTarget
 * @notice A minimal contract designed to always revert when a proposal calls its function.
 * This is used to test how the MultiSig wallet handles internal call failures within a batch.
 */
contract RevertingTarget {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice This function is designed to be called by a MultiSig's executeTransaction.
     * It immediately reverts, testing the MultiSig's ability to handle nested call failures.
     */
    function failImmediately() public {
        // Explicitly revert execution with a custom message
        revert("RevertAttack: Deliberate failure");
    }
}
