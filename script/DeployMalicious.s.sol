// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/malicious_contract/ReentrancyAttacker.sol";
import "../src/malicious_contract/Sinkhole.sol";

contract DeployMalicious is Script {

    function run() public {
        // Optional: total wei forwarded to both contracts (split inside script)
        uint256 valueWei = vm.envUint("DEPLOY_VALUE_WEI"); // set to 0 if not needed
        address vulnerable = vm.envAddress("VULNERABLE_ADDRESS"); // required for ReentrancyAttacker

        // start broadcasting transactions using the private key you pass via CLI (--private-key)
        vm.startBroadcast();

        address reentrancyAddr;
        address sinkAddr;

        if (valueWei > 0) {
            // split value to two parts (half and remainder)
            uint256 half = valueWei / 2;
            ReentrancyAttacker re = (new ReentrancyAttacker){value: half}(vulnerable);
            Sinkhole s = (new Sinkhole){value: valueWei - half}();
            reentrancyAddr = address(re);
            sinkAddr = address(s);
        } else {
            // no value forwarded
            ReentrancyAttacker re = new ReentrancyAttacker(vulnerable);
            Sinkhole s = new Sinkhole();
            reentrancyAddr = address(re);
            sinkAddr = address(s);
        }

        vm.stopBroadcast();

        // Print resulting addresses so they appear in forge output
        console.log("ReentrancyAttacker:", reentrancyAddr);
        console.log("Sinkhole:", sinkAddr);
    }
}
