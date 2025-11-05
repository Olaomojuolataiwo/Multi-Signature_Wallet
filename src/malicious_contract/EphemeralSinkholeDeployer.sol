pragma solidity ^0.8.20;

import "src/malicious_contract/Sinkhole.sol"; // Adjust path as needed

contract EphemeralSinkholeDeployer {
    // This function creates the Sinkhole and immediately destroys it in the same transaction.
    // This is the ONLY way to guarantee the contract code is cleared post-Dencun.
    function deployAndImplode(address payable destructionRecipient)
        external
        payable
        returns (address destroyedAddress)
    {
        // 1. Create the Sinkhole contract
        // The Deployer becomes the Sinkhole's 'owner'.
        Sinkhole newSinkhole = new Sinkhole{value: msg.value}();

        // Return the address of the new contract
        return address(newSinkhole);

        // 2. The Deployer calls implode (which uses suicide/selfdestruct)
        // Since the Deployer is the owner, this succeeds.
        newSinkhole.implode(destructionRecipient);
    }
}
