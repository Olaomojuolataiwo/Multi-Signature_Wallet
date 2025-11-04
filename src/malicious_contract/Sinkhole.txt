// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Sinkhole {
    address public owner;
    bool public locked;

    event Locked(address sender, uint256 amount);
    event Killed(address to, uint256 amount);

    constructor() payable {
        owner = msg.sender;
        locked = false;
    }

    receive() external payable {
        // Simply accept funds and flip locked to demonstrate unreachable funds if self-destructed later.
        locked = true;
        emit Locked(msg.sender, msg.value);
    }

    // Self-destruct and send funds to a destination controlled by owner (optional)
    function implode(address payable to) external {
        require(msg.sender == owner, "not owner");
        uint256 bal = address(this).balance;
        emit Killed(to, bal);
        selfdestruct(to);
    }

    // kill without sending to anyone (send to zero address) - illustrative
    function implodeBurn() external {
        require(msg.sender == owner, "not owner");
        uint256 bal = address(this).balance;
        emit Killed(address(0), bal);
        selfdestruct(payable(address(0)));
    }
}
