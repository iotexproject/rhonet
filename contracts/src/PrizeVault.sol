// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EcMath} from "./EcMath.sol";

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title PrizeVault - one round's streaming prize shares
/// @notice Only standard, non-rebasing ERC-20 tokens are supported. A rebasing or
/// fee-on-transfer token breaks the cumulativeDeposits accounting; fund() reverts on a measured shortfall.
/// @dev Epoch indices are strictly increasing, but a miner's credited steps are NOT monotone:
/// coordinator slashing reduces them, including to zero. Only the final settled root is payable.
/// Roots have a challenge window before settlement, allowing observers to inspect them and invoke
/// an eligible stall, deadline, or external-solve abort. Leaf totals are verified when posting each root.
/// Merkle leaves are sha256(addr20 || uint256 steps), nodes sha256(min || max); odd nodes are promoted.
contract PrizeVault {
    struct Curve {
        uint256 p;
        uint256 a;
        uint256 b;
        uint256 n;
        uint256 gx;
        uint256 gy;
        uint256 qx;
        uint256 qy;
    }
    struct Timing {
        uint64 deadline;
        uint64 stallWindow;
        uint64 revealDelay;
        uint64 commitExpiry;
        uint64 settleDelay;
        uint64 claimWindow;
    }

    IERC20 public immutable token;
    bytes32 public immutable roundId;
    address public immutable operator;
    uint256 public immutable p;
    uint256 public immutable a;
    uint256 public immutable b;
    uint256 public immutable n;
    uint256 public immutable gx;
    uint256 public immutable gy;
    uint256 public immutable qx;
    uint256 public immutable qy;
    uint64 public immutable deadline;
    uint64 public immutable stallWindow;
    uint64 public immutable revealDelay;
    uint64 public immutable commitExpiry;
    uint64 public immutable settleDelay;
    uint64 public immutable claimWindow;

    mapping(address => uint256) public deposits;
    uint256 public cumulativeDeposits;
    uint256 public refunded;
    uint256 public totalSteps;
    uint256 public claimedSteps;
    mapping(address => uint256) public registeredSteps;
    mapping(address => uint256) public withdrawn;
    uint256 public totalWithdrawn;
    mapping(address => uint256) public accountedDeposits; // Deposits level already settled for this claimant.

    bytes32 public root;
    uint64 public epoch;
    mapping(uint64 => bytes32) public rootAt;
    mapping(uint64 => uint256) public rootLeafCountAt;
    mapping(uint64 => uint256) public rootStepsAt;
    uint256 public rootPostedAt;
    uint256 public lastRootAt;
    uint256 public settledAt;
    bool public settled;
    bool public aborted;
    uint256 public sweptDeposits;
    uint256 public sweptToOperator;
    uint256 public lastSweepAt;
    uint256 public lastDepositAt;
    uint256 public immutable externalRevealDelay;
    mapping(address => bytes32) public externalCommitment;
    mapping(address => uint256) public externalCommitAt;
    bool public solutionCommitted;
    bytes32 public solutionCommitment;
    uint256 public commitAt;
    bool public solved;
    uint256 public solutionK;
    bool private hasRoot;
    bool private entered;

    event Funded(address indexed depositor, uint256 amount, uint256 cumulativeDeposits);
    event RootPosted(uint64 indexed epoch, bytes32 root, uint256 leafCount, uint256 totalSteps);
    event ExternalSolveCommitted(address indexed claimant, bytes32 commitment, uint256 committedAt);
    event SolutionCommitted(bytes32 commitment, uint256 commitAt);
    event CommitmentCleared();
    event SolutionRevealed(uint256 k);
    event Settled(uint64 indexed epoch, bytes32 root, uint256 totalSteps);
    event Registered(address indexed miner, uint256 steps);
    event Withdrawn(address indexed miner, uint256 amount);
    /// @dev Reasons: 1 = deadline, 2 = stall, 3 = external solve.
    event Aborted(uint8 reason);
    event Refunded(address indexed depositor, uint256 amount);
    event Swept(uint256 amount, uint256 sweptDeposits);
    event ExcessRecovered(uint256 amount);

    modifier onlyOperator() {
        require(msg.sender == operator, "not operator");
        _;
    }
    modifier nonReentrant() {
        require(!entered, "reentrant");
        entered = true;
        _;
        entered = false;
    }
    modifier openRound() {
        require(!settled && !aborted, "closed");
        _;
    }

    /// @dev p must be prime and n must be the intended subgroup order; primality/order are not tested.
    /// Infinity is represented by Z == 0 in EcMath, never by an affine coordinate sentinel.
    constructor(IERC20 _token, bytes32 _roundId, Curve memory c, Timing memory t) {
        require(address(_token) != address(0), "zero token");
        require(c.p > 3 && (c.p & 1) == 1, "bad p");
        require(c.n > 1, "bad n");
        require(EcMath.isOnCurve(c.p, c.a, c.b, c.gx, c.gy), "bad G");
        require(EcMath.isOnCurve(c.p, c.a, c.b, c.qx, c.qy), "bad Q");
        require(t.deadline > block.timestamp, "bad deadline");
        require(t.commitExpiry > t.revealDelay, "bad commit expiry");
        token = _token;
        roundId = _roundId;
        operator = msg.sender;
        p = c.p; a = c.a; b = c.b; n = c.n;
        gx = c.gx; gy = c.gy; qx = c.qx; qy = c.qy;
        deadline = t.deadline;
        stallWindow = t.stallWindow;
        revealDelay = t.revealDelay;
        externalRevealDelay = uint256(t.revealDelay) + 1;
        commitExpiry = t.commitExpiry;
        settleDelay = t.settleDelay;
        claimWindow = t.claimWindow;
        lastRootAt = block.timestamp;
    }

    /// @notice Deposits accrue to fixed shares even after settlement and earlier sweeps.
    function fund(uint256 amount) external nonReentrant {
        require(!aborted, "aborted");
        uint256 beforeBalance = token.balanceOf(address(this));
        _safeTransferFrom(msg.sender, amount);
        uint256 afterBalance = token.balanceOf(address(this));
        require(afterBalance >= beforeBalance && afterBalance - beforeBalance == amount,
            "fee-on-transfer token not supported");
        deposits[msg.sender] += amount;
        cumulativeDeposits += amount;
        if (amount != 0) lastDepositAt = block.timestamp;
        emit Funded(msg.sender, amount, cumulativeDeposits);
    }

    /// @notice Post a checkpoint with all leaves, in strictly increasing address order.
    /// @dev Reconstructing the root binds its exact count and sum on chain while preserving
    /// existing SHA-256 proofs. Unique addresses ensure no valid positive leaf is excluded
    /// by another registration. Posting costs O(leaf count) calldata, memory and hashing.
    function postRoot(uint64 _epoch, bytes32 _root, address[] calldata miners, uint256[] calldata steps)
        external onlyOperator openRound
    {
        require(_epoch > epoch || (epoch == 0 && root == bytes32(0)), "stale epoch");
        // Even a first checkpoint of (0, 0) consumes epoch zero.
        require(!hasRoot || _epoch > epoch, "stale epoch");
        require(miners.length == steps.length, "leaf lengths");
        bytes32[] memory nodes = new bytes32[](miners.length);
        uint256 sum;
        for (uint256 i; i < miners.length; ++i) {
            require(miners[i] != address(0) && (i == 0 || miners[i] > miners[i - 1]), "leaf order");
            nodes[i] = leaf(miners[i], steps[i]);
            sum += steps[i]; // Checked addition rejects a sum that cannot fit uint256.
        }
        uint256 width = nodes.length;
        while (width > 1) {
            uint256 next;
            for (uint256 i; i < width; i += 2) {
                if (i + 1 == width) {
                    nodes[next++] = nodes[i];
                } else {
                    bytes32 x = nodes[i];
                    bytes32 y = nodes[i + 1];
                    nodes[next++] = x < y ? sha256(abi.encodePacked(x, y)) : sha256(abi.encodePacked(y, x));
                }
            }
            width = next;
        }
        require(_root == (nodes.length == 0 ? bytes32(0) : nodes[0]), "bad leaves");
        rootLeafCountAt[_epoch] = miners.length;
        rootStepsAt[_epoch] = sum;
        hasRoot = true;
        rootAt[_epoch] = _root;
        rootPostedAt = block.timestamp;
        lastRootAt = block.timestamp;
        epoch = _epoch;
        root = _root;
        emit RootPosted(_epoch, _root, miners.length, sum);
    }

    /// @notice Commit keccak256(abi.encode(k, salt, msg.sender)) before exposing the solution.
    function commitSolution(bytes32 commitment) external onlyOperator openRound {
        require(!solutionCommitted, "already committed");
        solutionCommitted = true;
        solutionCommitment = commitment;
        commitAt = block.timestamp;
        emit SolutionCommitted(commitment, commitAt);
    }

    /// @notice Anyone may clear an expired, unrevealed commitment so the operator can retry.
    function clearCommitment() external openRound {
        require(solutionCommitted, "not committed");
        require(!solved, "solved");
        require(block.timestamp >= commitAt + commitExpiry, "too early");
        solutionCommitted = false;
        solutionCommitment = bytes32(0);
        commitAt = 0;
        emit CommitmentCleared();
    }

    /// @notice The operator should secure any external prize before broadcasting this reveal.
    /// @dev The delay enforces ordering; this vault cannot verify an external prize was secured.
    function revealSolution(uint256 k, bytes32 salt) external onlyOperator {
        require(solutionCommitted, "not committed");
        require(!solved, "already solved");
        require(!aborted, "aborted");
        require(block.timestamp >= commitAt + revealDelay, "too early");
        require(solutionCommitment == keccak256(abi.encode(k, salt, msg.sender)), "bad commitment");
        require(EcMath.verifyDlog(p, a, n, gx, gy, qx, qy, k), "bad k");
        solved = true;
        solutionK = k;
        emit SolutionRevealed(k);
    }

    function settle(uint64 _epoch, bytes32 _root, uint256 _totalSteps) external onlyOperator openRound {
        require(solved, "not solved");
        require(_totalSteps > 0, "no work");
        require(hasRoot && _epoch == epoch && _root == rootAt[_epoch] && _root == root, "bad root");
        require(_totalSteps == rootStepsAt[_epoch], "denominator");
        require(block.timestamp >= rootPostedAt + settleDelay, "too early");
        totalSteps = _totalSteps;
        settledAt = block.timestamp;
        settled = true;
        emit Settled(_epoch, _root, _totalSteps);
    }

    function register(uint256 steps, bytes32[] calldata proof) public {
        require(settled, "not settled");
        require(registeredSteps[msg.sender] == 0, "registered");
        require(steps > 0, "no work");
        require(verify(root, leaf(msg.sender, steps), proof), "bad proof");
        require(steps <= totalSteps - claimedSteps, "denominator");
        claimedSteps += steps;
        registeredSteps[msg.sender] = steps;
        emit Registered(msg.sender, steps);
    }

    /// @notice Lifetime share if never swept and withdrawn in a single call.
    /// @dev This is not a promise about the sum of multiple claimable amounts.
    function entitlement(address who) public view returns (uint256) {
        if (totalSteps == 0) return 0;
        return _mulDiv(registeredSteps[who], cumulativeDeposits, totalSteps);
    }

    function swept() public view returns (bool) {
        return sweptDeposits > 0;
    }

    function _watermark(address who) internal view returns (uint256) {
        uint256 w = accountedDeposits[who];
        return w > sweptDeposits ? w : sweptDeposits;
    }

    // Never subtract lifetime floors: floor(s*C/T) - floor(s*S/T) can exceed
    // floor(s*(C-S)/T) by 1. With m claimants, a late tranche can be overallocated
    // by up to m wei. Round each claimant's tranche down independently instead.
    function claimable(address who) public view returns (uint256) {
        if (totalSteps == 0) return 0;
        uint256 w = _watermark(who);
        if (cumulativeDeposits <= w) return 0;
        return _mulDiv(registeredSteps[who], cumulativeDeposits - w, totalSteps);
    }

    /// @notice Withdraw the current tranche's share, closing it even if its floor is zero.
    /// @dev Each extra withdrawal can lose up to 1 wei relative to one withdrawal at
    /// the end: each tranche is rounded strictly downward and can never over-pay.
    /// The residue is recovered by sweep, so nothing is locked (L-1).
    /// Invariant: for any tranche D = cumulativeDeposits - w,
    /// sum_i floor(steps_i * D / totalSteps) <= D * (sum_i steps_i) / totalSteps <= D,
    /// because register enforces sum_i registeredSteps_i <= totalSteps. Each tranche
    /// is rounded down once, so outstanding claims against it cannot exceed it.
    /// Thus totalWithdrawn + refunded + sweptToOperator <= cumulativeDeposits exactly;
    /// at rest, token.balanceOf(vault) >= cumulativeDeposits - totalWithdrawn - refunded - sweptToOperator.
    /// Equality holds only without untracked direct transfers; excess is separately recoverable.
    function withdraw() public nonReentrant {
        require(settled, "not settled");
        if (registeredSteps[msg.sender] == 0) return;
        uint256 amount = claimable(msg.sender);
        accountedDeposits[msg.sender] = cumulativeDeposits;
        withdrawn[msg.sender] += amount;
        totalWithdrawn += amount;
        if (amount != 0) _safeTransfer(msg.sender, amount);
        emit Withdrawn(msg.sender, amount);
    }

    function claim(uint256 steps, bytes32[] calldata proof) external {
        register(steps, proof);
        withdraw();
    }

    function abortOnDeadline() external openRound {
        require(block.timestamp >= deadline, "too early");
        aborted = true;
        emit Aborted(1);
    }

    function abortOnStall() external openRound {
        require(block.timestamp - lastRootAt > stallWindow, "not stalled");
        aborted = true;
        emit Aborted(2);
    }

    /// @notice Commit keccak256(abi.encode(k, salt, msg.sender)) before exposing an external solve.
    /// @dev Independent of operator commitments, including garbage commitments.
    function commitExternalSolve(bytes32 commitment) external openRound {
        require(!solved, "solved");
        require(commitment != bytes32(0), "empty commitment");
        externalCommitment[msg.sender] = commitment;
        externalCommitAt[msg.sender] = block.timestamp;
        emit ExternalSolveCommitted(msg.sender, commitment, block.timestamp);
    }

    /// @notice An independently committed solve can abort after a longer delay than the operator's.
    /// @dev A copied pending reveal cannot immediately abort. Timely operator inclusion is
    /// still required: no timestamp delay can guarantee inclusion against censorship.
    function abortOnExternalSolve(uint256 k, bytes32 salt) external openRound {
        require(!solved, "solved");
        require(externalCommitment[msg.sender] != bytes32(0), "not committed");
        require(block.timestamp >= externalCommitAt[msg.sender] + externalRevealDelay, "too early");
        require(externalCommitment[msg.sender] == keccak256(abi.encode(k, salt, msg.sender)),
            "bad commitment");
        require(EcMath.verifyDlog(p, a, n, gx, gy, qx, qy, k), "bad k");
        aborted = true;
        emit Aborted(3);
    }

    function refundClaim() external nonReentrant {
        require(aborted, "not aborted");
        uint256 d = deposits[msg.sender];
        require(d > 0, "no deposit");
        deposits[msg.sender] = 0;
        refunded += d;
        _safeTransfer(msg.sender, d);
        emit Refunded(msg.sender, d);
    }

    /// @notice Sweep the current tranche's entire residue to the operator after its claim window.
    /// @dev Sweeps close the entire unswept batch, so even its newest deposit must
    /// have aged a full window. New funding extends the batch's window; zero funding does not.
    /// This conservatively gives every deposit at least its own full claim window.
    function sweep() external nonReentrant {
        require(settled, "not settled");
        require(block.timestamp >= settledAt + claimWindow, "too early");
        require(block.timestamp >= lastSweepAt + claimWindow, "too early");
        require(block.timestamp >= lastDepositAt + claimWindow, "too early");
        require(cumulativeDeposits > sweptDeposits, "nothing to sweep");
        sweptDeposits = cumulativeDeposits;
        lastSweepAt = block.timestamp;
        uint256 amount = _trackedBalance();
        sweptToOperator += amount;
        if (amount != 0) _safeTransfer(operator, amount);
        emit Swept(amount, sweptDeposits);
    }

    function _trackedBalance() internal view returns (uint256) {
        return cumulativeDeposits - totalWithdrawn - refunded - sweptToOperator;
    }

    /// @notice Recover untracked direct transfers once the round is settled or aborted.
    /// @dev Anyone may trigger recovery, but only the fixed operator receives the excess.
    /// Tracked sponsor refunds and miner claims remain reserved, including late deposits.
    function recoverExcess() external nonReentrant {
        require(settled || aborted, "not finished");
        uint256 amount = token.balanceOf(address(this)) - _trackedBalance();
        require(amount != 0, "no excess");
        _safeTransfer(operator, amount);
        emit ExcessRecovered(amount);
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

    function _safeTransfer(address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(abi.encodeCall(IERC20.transfer, (to, amount)));
        require(ok && (data.length == 0 || (data.length == 32 && abi.decode(data, (bool)))), "transfer");
    }

    function _safeTransferFrom(address from, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeCall(IERC20.transferFrom, (from, address(this), amount)));
        require(ok && (data.length == 0 || (data.length == 32 && abi.decode(data, (bool)))), "transferFrom");
    }

    /// @dev Full-width floor(x*y/d): divide the exact 512-bit product using a modular inverse.
    /// Here x <= d, so the result fits uint256. Caller guarantees d > 0.
    function _mulDiv(uint256 x, uint256 y, uint256 d) private pure returns (uint256 result) {
        unchecked {
            uint256 lo;
            uint256 hi;
            assembly ("memory-safe") {
                let mm := mulmod(x, y, not(0))
                lo := mul(x, y)
                hi := sub(sub(mm, lo), lt(mm, lo))
            }
            if (hi == 0) return lo / d;
            require(d > hi, "share overflow");
            uint256 rem = mulmod(x, y, d);
            assembly ("memory-safe") {
                hi := sub(hi, gt(rem, lo))
                lo := sub(lo, rem)
            }
            uint256 twos = d & (0 - d);
            assembly ("memory-safe") {
                d := div(d, twos)
                lo := div(lo, twos)
                twos := add(div(sub(0, twos), twos), 1)
            }
            lo |= hi * twos;
            uint256 inv = (3 * d) ^ 2;
            // Newton iteration doubles correct inverse bits: 4 -> 8 -> ... -> 256.
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            return lo * inv;
        }
    }
}
