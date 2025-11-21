// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title VulnerableMultiSig
 * @notice Educational/insecure multi-signature wallet used to demonstrate common mistakes.
 *
 * Each intentional vulnerability is annotated with a comment like `// T-03:` (ticket reference).
 * Tests/exploits should reference these ticket IDs.
 */
contract VulnerableMultiSig {
    // --- Ownership ---
    address[] public owners; // enumeration (unbounded)
    mapping(address => bool) public isOwner; // quick lookup
    uint256 public threshold; // confirmations required

    // --- Proposals ---
    uint256 public proposalCount;

    struct Proposal {
        address proposer;
        address to;
        uint256 value;
        bytes data;
        uint256 confirmations;
        bool executed;
        uint256 createdAt;
        // NOTE: mapping inside struct (works in storage) but complicates enumeration/testing.
        mapping(address => bool) confirmed;
    }

    mapping(uint256 => Proposal) public proposals; // unbounded mapping
        // T-04: no caps / no deposit protection

    // --- Events ---
    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, address indexed to, uint256 value);
    event Confirmed(uint256 indexed proposalId, address indexed confirmer);
    event Executed(uint256 indexed proposalId, address indexed executor, bool success, bytes result);
    event Cancelled(uint256 indexed proposalId, address indexed canceller);
    event OwnerAdded(address indexed newOwner);
    event OwnerRemoved(address indexed removedOwner);
    event ThresholdChanged(uint256 newThreshold);

    // --- Constructor ---
    constructor(address[] memory _owners, uint256 _threshold) payable {
        require(_owners.length >= _threshold && _threshold > 0, "invalid owners/threshold");
        for (uint256 i = 0; i < _owners.length; i++) {
            address o = _owners[i];
            isOwner[o] = true;
        }
        owners = _owners;
        threshold = _threshold;
    }

    // -----------------------
    // Core flows (insecure)
    // -----------------------

    /// @notice Propose a transaction
    function proposeTransaction(address to, uint256 value, bytes calldata data) external returns (uint256) {
        uint256 id = ++proposalCount;

        // create storage slot and set primitive fields
        Proposal storage p = proposals[id];
        p.proposer = msg.sender;
        p.to = to;
        p.value = value;
        p.data = data;
        p.confirmations = 0;
        p.executed = false;
        p.createdAt = block.timestamp; // T-06: uses timestamp (and used elsewhere maybe)

        emit ProposalCreated(id, msg.sender, to, value);
        return id;
    }

    /// @notice Confirm a proposal
    function confirmTransaction(uint256 proposalId) public {
        Proposal storage p = proposals[proposalId];
        require(!p.executed, "already executed");
        // T-01: no check that confirmer is owner — this is a deliberate access control bypass
        // (should be: require(isOwner[msg.sender], ...))
        if (!p.confirmed[msg.sender]) {
            p.confirmed[msg.sender] = true;
            p.confirmations += 1;
            emit Confirmed(proposalId, msg.sender);
        }
    }

    /// @notice Execute a proposal (very insecure)
    function executeTransaction(uint256 proposalId) public {
        Proposal storage p = proposals[proposalId];
        require(!p.executed, "already executed");

        // T-02: no nonce or domain binding for on-chain execution flow (signature-less flow)
        // T-06: naive timelock example: allow fast execution if timestamp older than some window
        // (here we do not require any timelock, intentionally)
        require(p.confirmations >= threshold, "not enough confirmations");

        // T-05: Reentrancy vulnerability — external call BEFORE state update
        // (we update executed *after* the external call)
        (bool success, bytes memory result) = p.to.call{value: p.value}(p.data);

        // T-03: unchecked external call handling — we DON'T revert or handle partial failures properly.
        // We still emit an event with the result but leave state inconsistent (execute flag set after).
        // A better pattern is CEI: set executed = true BEFORE calling external (and/or check return).
        emit Executed(proposalId, msg.sender, success, result);

        // mark executed AFTER external call — vulnerable to reentrancy.
        p.executed = true;
    }

    /// @notice Create many proposals in one transaction (danger: unbounded loop)
    function batchPropose(address[] calldata tos, uint256[] calldata values, bytes[] calldata datas) external {
        require(tos.length == values.length && tos.length == datas.length, "length mismatch");
        for (uint256 i = 0; i < tos.length; ++i) {
            // call the existing external function (so the same logic runs, including events)
            // We call internal creation function if you have one, otherwise call external:
            this.proposeTransaction(tos[i], values[i], datas[i]);
        }
    }

    /// @notice Confirm multiple proposals in one transaction (danger: unbounded loop)
    function batchConfirm(uint256[] calldata ids) external {
        for (uint256 i = 0; i < ids.length; ++i) {
            confirmTransaction(ids[i]);
        }
    }

    /// @notice Batch execute many proposals (gas exhaustion danger)
    function batchExecute(uint256[] calldata ids) external {
        // T-11: unbounded loop over user-supplied array — gas exhaustion risk.
        for (uint256 i = 0; i < ids.length; i++) {
            executeTransaction(ids[i]);
        }
    }

    /// @notice Cancel a proposal (anyone can cancel)
    function cancelTransaction(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        // T-13: insecure cancellation — no proper privileges or timelock; anyone can cancel
        require(!p.executed, "already executed");
        delete proposals[proposalId];
        emit Cancelled(proposalId, msg.sender);
    }

    // -----------------------
    // Governance (insecure)
    // -----------------------

    /// @notice Add owner (no access controls)
    function addOwner(address newOwner) external {
        // T-01: missing access control entirely - any caller can add an owner
        if (!isOwner[newOwner]) {
            owners.push(newOwner);
            isOwner[newOwner] = true;
            emit OwnerAdded(newOwner);
        }
    }

    /// @notice Remove owner (no proper checks)
    function removeOwner(address owner) external {
        // T-01: missing access control entirely - any caller can remove an owner
        if (isOwner[owner]) {
            isOwner[owner] = false;
            // naive removal from array (can leave holes / duplicated state)
            for (uint256 i = 0; i < owners.length; i++) {
                if (owners[i] == owner) {
                    owners[i] = owners[owners.length - 1];
                    owners.pop();
                    break;
                }
            }
            emit OwnerRemoved(owner);
        }
    }

    /// @notice Change threshold (callable by anyone)
    function changeThreshold(uint256 newThreshold) external {
        // T-01 / T-06: missing governance timelock and access control
        require(newThreshold > 0 && newThreshold <= owners.length, "invalid threshold");
        threshold = newThreshold;
        emit ThresholdChanged(newThreshold);
    }

    // -----------------------
    // Signature / meta-tx helpers (naive)
    // -----------------------

    /**
     * @notice Execute a single transaction authorized by an off-chain signature.
     * This intentionally demonstrates a naive, vulnerable signature flow:
     *  - no nonce included (T-02)
     *  - no domain separator / chainId / contract binding (T-02)
     *  - simple signature on (to,value,keccak(data)) — naive packing (T-12)
     */
    function executeWithSignature(address to, uint256 value, bytes calldata data, bytes calldata signature) external {
        // Recover signer from naive message hash
        bytes32 h = keccak256(abi.encodePacked(to, value, keccak256(data)));
        bytes32 ethSigned = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        address signer = ecrecover(ethSigned, v, r, s);

        require(signer != address(0), "invalid signature");

        // T-09: signature forgery / invalid signer handling — this function does NOT check that signer is an owner
        // (should be: require(isOwner[signer], ...)). As written, any recovered address can be used to execute.
        // This is an intentional vulnerability.
        // Execute the call (again, executed BEFORE marking any internal state).
        (bool success, bytes memory result) = to.call{value: value}(data);
        emit Executed(0, msg.sender, success, result); // proposalId = 0 for direct signature execution
    }

    // -----------------------
    // Emergency / misc (insecure)
    // -----------------------

    /// @notice Emergency withdraw that can be time-manipulated (timestamp dependence)
    function emergencyWithdraw(address payable to) external {
        // T-06: Uses timestamp to allow withdraw if contract older than X seconds
        // but there is no multi-sig confirmation or guardian — a very unsafe pattern.
        require(block.timestamp > 0, "never"); // nonsense guard; left intentionally weak
        to.transfer(address(this).balance); // may revert if gas stipends insufficient / fallback attack
    }

    // -----------------------
    // Helpers / Views
    // -----------------------

    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function getProposal(uint256 proposalId)
        external
        view
        returns (
            address proposer,
            address to,
            uint256 value,
            bytes memory data,
            uint256 confirmations,
            bool executed,
            uint256 createdAt
        )
    {
        Proposal storage p = proposals[proposalId];
        return (p.proposer, p.to, p.value, p.data, p.confirmations, p.executed, p.createdAt);
    }

    /// @notice naive signature splitter
    function splitSignature(bytes memory sig) public pure returns (uint8 v, bytes32 r, bytes32 s) {
        // T-02/T-12: This code assumes 65-byte signatures and doesn't validate lengths carefully
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    // Fallback/receive
    receive() external payable {}

    // -----------------------
    // --- Intentional arithmetic quirk (T-08) ---
    // -----------------------
    // Demonstrate an unchecked block to simulate overflow possibility in older compilers.
    // In Solidity >=0.8 overflow reverts by default but developers can use `unchecked` to bypass.
    function dangerousAdd(uint256 a, uint256 b) public pure returns (uint256) {
        unchecked {
            // T-08: unchecked arithmetic intentionally present for tests
            return a + b;
        }
    }

    // -----------------------
    // Storage collision / abi packing example (T-12)
    // -----------------------
    // naiveHash uses abi.encodePacked which can collide if not careful
    function naiveHash(address a, uint256 b, string calldata s) public pure returns (bytes32) {
        // T-12: abi.encodePacked may cause collisions — used intentionally to show risk
        return keccak256(abi.encodePacked(a, b, s));
    }

    // Emit a richer snapshot event for debug / artifact reconstruction.
    event ProposalSnapshot(
        uint256 indexed proposalId,
        address proposer,
        address to,
        uint256 value,
        uint256 confirmations,
        bool executed,
        uint256 createdAt
    );

    // Return the list of owners and the current threshold in a single call.
    function getGovernanceState() external view returns (address[] memory, uint256) {
        return (owners, threshold);
    }

    // This function iterates owner list and checks the proposal.confirmed map.
    // NOTE: reading mapping inside struct is supported in view context.
    function getProposalConfirmations(uint256 proposalId) external view returns (address[] memory) {
        Proposal storage p = proposals[proposalId];

        // pre-allocate using the stored confirmations count as an upper bound
        uint256 count = p.confirmations;
        address[] memory confirmers = new address[](count);
        uint256 idx = 0;

        // iterate owners and collect those who have confirmed
        for (uint256 i = 0; i < owners.length; i++) {
            if (p.confirmed[owners[i]]) {
                // guard to avoid out-of-bounds if stored count is stale for some reason
                if (idx < count) {
                    confirmers[idx] = owners[i];
                    idx++;
                }
            }
        }

        // If we somehow filled fewer than count (defensive), shrink array:
        if (idx < count) {
            address[] memory trimmed = new address[](idx);
            for (uint256 j = 0; j < idx; j++) {
                trimmed[j] = confirmers[j];
            }
            return trimmed;
        }

        return confirmers;
    }

    // Emit a proposal snapshot event (helpful after deletes/cancellations to reconstruct).
    function emitProposalSnapshot(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        emit ProposalSnapshot(proposalId, p.proposer, p.to, p.value, p.confirmations, p.executed, p.createdAt);
    }
}
