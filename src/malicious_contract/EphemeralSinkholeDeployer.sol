pragma solidity ^0.8.20;

import "src/malicious_contract/Sinkhole.sol";

contract EphemeralSinkholeDeployer {
    function deployAndImplode(address payable destructionRecipient)
        external
        payable
        returns (address destroyedAddress, uint256 capturedBalance)
    {
        Sinkhole newSinkhole = new Sinkhole{value: msg.value}();

        destroyedAddress = address(newSinkhole);
        capturedBalance = address(newSinkhole).balance;

        newSinkhole.implode(destructionRecipient);
    }
}
