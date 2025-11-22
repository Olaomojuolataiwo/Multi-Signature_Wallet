// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/VulnerableMultiSig.sol";
import "../src/SecureMultiSig.sol";

contract DeployAll is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");

        // read owners from env if present; otherwise use hardcoded placeholders
        address owner1 =
            address(uint160(vm.envOr("OWNER1", uint256(uint160(address(0xcc7a3706Df7FCcFbF99f577382BC62C0e565FcF0))))));
        address owner2 =
            address(uint160(vm.envOr("OWNER2", uint256(uint160(address(0x513B1d92C2CA2d364B9d99ABabA485D298bdCbea))))));
        address owner3 =
            address(uint160(vm.envOr("OWNER3", uint256(uint160(address(0xAB168F094e0037eDA6562da1d4784bD44B1860A1))))));

        uint256 threshold = vm.envOr("THRESHOLD", uint256(2));
        uint256 timelock = vm.envOr("TIMELOCK", uint256(120)); // 2 minutes

        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;

        // Start broadcast using deployer key
        vm.startBroadcast(deployerKey);

        // Deploy VulnerableMultiSig
        VulnerableMultiSig vulnerable = new VulnerableMultiSig(owners, threshold);
        console.log("VulnerableMultiSig deployed at:", address(vulnerable));

        // Deploy SecureMultiSig
        SecureMultiSig secure = new SecureMultiSig(owners, threshold, timelock);
        console.log("SecureMultiSig deployed at:", address(secure));

        vm.stopBroadcast();
    }
}
