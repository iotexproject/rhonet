// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PrizeVault - one round's prize pool and credit ledger (RhoWalkers MVP)
/// @notice Minimal settlement contract for the "one unit of work = one credit" scheme.
///   - The operator pre-funds the pool in an ERC-20 (USDC on an L2).
///   - Every epoch the coordinator posts the Merkle root of (payout address, credited steps).
///     Roots only ever grow a miner's balance; the latest root is the one claims use.
///   - After the round is solved the operator calls `settle` with the final root and the
///     total credited steps. Miners claim pool * mine / total with a Merkle proof.
///   - If the round is aborted (external solve, timeout, coordinator silence) the operator
///     calls `refund` and the depositor takes the pool back; credits stay recorded.
///   Leaf and node hashing match rhowalkers/merkle.py: leaf = sha256(addr20 || uint256 steps),
///   node = sha256(min || max).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PrizeVault {
    IERC20 public immutable token;
    address public immutable operator;
    bytes32 public immutable roundId;

    uint256 public pool;
    bytes32 public root;          // latest posted ledger root
    uint64 public epoch;          // epoch index of `root`
    uint256 public totalSteps;    // set at settle
    bool public settled;
    bool public aborted;
    mapping(address => bool) public claimed;

    event RootPosted(uint64 indexed epoch, bytes32 root, uint256 totalSteps);
    event Settled(bytes32 root, uint256 totalSteps, uint256 pool);
    event Claimed(address indexed miner, uint256 steps, uint256 amount);
    event Aborted(uint256 refunded);

    modifier onlyOperator() { require(msg.sender == operator, "not operator"); _; }

    constructor(IERC20 _token, bytes32 _roundId) {
        token = _token;
        operator = msg.sender;
        roundId = _roundId;
    }

    /// @notice Anyone can add to the pool before settlement (community top-ups, sponsor prizes).
    function fund(uint256 amount) external {
        require(!settled && !aborted, "closed");
        require(token.transferFrom(msg.sender, address(this), amount), "transfer");
        pool += amount;
    }

    /// @notice Hourly (epoch) checkpoint. Cheap: one storage write per epoch, DPs stay off-chain.
    function postRoot(uint64 _epoch, bytes32 _root, uint256 _totalSteps) external onlyOperator {
        require(!settled && !aborted, "closed");
        require(_epoch > epoch || root == bytes32(0), "stale epoch");
        epoch = _epoch;
        root = _root;
        emit RootPosted(_epoch, _root, _totalSteps);
    }

    /// @notice Final root after the collision. From here on the pool is divided once, pro rata.
    function settle(uint64 _epoch, bytes32 _root, uint256 _totalSteps) external onlyOperator {
        require(!settled && !aborted, "closed");
        require(_totalSteps > 0, "no work");
        epoch = _epoch;
        root = _root;
        totalSteps = _totalSteps;
        settled = true;
        emit Settled(_root, _totalSteps, pool);
    }

    function abort() external onlyOperator {
        require(!settled && !aborted, "closed");
        aborted = true;
        uint256 amt = pool;
        pool = 0;
        require(token.transfer(operator, amt), "transfer");
        emit Aborted(amt);
    }

    function leaf(address miner, uint256 steps) public pure returns (bytes32) {
        return sha256(abi.encodePacked(miner, steps));
    }

    function verify(bytes32 _root, bytes32 node, bytes32[] calldata proof) public pure returns (bool) {
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 s = proof[i];
            node = node < s ? sha256(abi.encodePacked(node, s)) : sha256(abi.encodePacked(s, node));
        }
        return node == _root;
    }

    function payout(uint256 steps) public view returns (uint256) {
        return pool * steps / totalSteps;
    }

    /// @notice Pull-based claim: one transaction per miner, no operator gas per miner.
    function claim(uint256 steps, bytes32[] calldata proof) external {
        require(settled, "not settled");
        require(!claimed[msg.sender], "claimed");
        require(verify(root, leaf(msg.sender, steps), proof), "bad proof");
        claimed[msg.sender] = true;
        uint256 amt = payout(steps);
        require(token.transfer(msg.sender, amt), "transfer");
        emit Claimed(msg.sender, steps, amt);
    }
}
