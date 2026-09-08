// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, stdError} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {PrizeVault, IERC20} from "../src/PrizeVault.sol";
import {EcMath} from "../src/EcMath.sol";
import {MockToken, NoReturnToken, FeeOnTransferToken} from "./MockToken.sol";
import {Fixture} from "./Fixture.sol";
import {RoundFixture as R} from "./RoundFixture.sol";
import {Curve131Fixture as C} from "./Curve131Fixture.sol";

contract EcMathHarness {
    function verify(PrizeVault.Curve calldata c, uint256 k) external view returns (bool) {
        return EcMath.verifyDlog(c.p, c.a, c.n, c.gx, c.gy, c.qx, c.qy, k);
    }
}

contract PrizeVaultTest is Test {
    PrizeVault internal vault;
    MockToken internal tok;
    address internal constant SPONSOR = address(0xA11CE);
    address internal constant SPONSOR2 = address(0xB0B);
    address internal constant STRANGER = address(0xCAFE);
    bytes32 internal constant SALT = keccak256("stage two salt");
    uint256 internal constant POOL = 1_050_000 ether;

    function setUp() public {
        vm.warp(1_800_000_000);
        tok = new MockToken();
        vault = _deploy(IERC20(address(tok)), _roundCurve());
    }

    function _roundCurve() internal pure returns (PrizeVault.Curve memory) {
        return PrizeVault.Curve(R.P, R.A, R.B, R.N, R.GX, R.GY, R.QX, R.QY);
    }

    function _curve131() internal pure returns (PrizeVault.Curve memory) {
        return PrizeVault.Curve(C.P, C.A, C.B, C.N, C.GX, C.GY, C.QX, C.QY);
    }

    function _deploy(IERC20 token, PrizeVault.Curve memory curve) internal returns (PrizeVault) {
        return new PrizeVault(token, keccak256("stage two round"), curve,
            PrizeVault.Timing(uint64(block.timestamp + 30 days), 1 days, 10 minutes, 1 days, 1 hours, 90 days));
    }

    function _fund(address sponsor, uint256 amount) internal {
        tok.mint(sponsor, amount);
        vm.startPrank(sponsor);
        tok.approve(address(vault), amount);
        vault.fund(amount);
        vm.stopPrank();
    }

    function _commit(uint256 k) internal {
        vault.commitSolution(keccak256(abi.encode(k, SALT, address(this))));
    }

    function _solve() internal {
        _commit(R.K);
        vm.warp(vault.commitAt() + vault.revealDelay());
        vault.revealSolution(R.K, SALT);
    }

    function _fixtureLeaves() internal pure returns (address[] memory miners, uint256[] memory steps) {
        miners = new address[](5);
        steps = new uint256[](5);
        for (uint256 i; i < 5; ++i) (miners[i], steps[i],) = _fixture(i);
    }

    function _postRoot(uint64 epoch, bytes32 root) internal {
        if (root == bytes32(0)) {
            vault.postRoot(epoch, root, new address[](0), new uint256[](0));
        } else {
            (address[] memory miners, uint256[] memory steps) = _fixtureLeaves();
            vault.postRoot(epoch, root, miners, steps);
        }
    }

    function _solveAndSettle(uint256 totalSteps) internal {
        _solve();
        _postRoot(1, Fixture.ROOT);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        vault.settle(1, Fixture.ROOT, totalSteps);
    }

    function _fixture(uint256 i) internal pure returns (address, uint256, bytes32[] memory) {
        if (i == 0) return Fixture.leaf0();
        if (i == 1) return Fixture.leaf1();
        if (i == 2) return Fixture.leaf2();
        if (i == 3) return Fixture.leaf3();
        require(i == 4, "fixture index");
        return Fixture.leaf4();
    }

    function _claim(uint256 i) internal {
        (address who, uint256 steps, bytes32[] memory proof) = _fixture(i);
        vm.prank(who);
        vault.claim(steps, proof);
    }

    function _assertConservation() internal view {
        uint256 deposits = vault.cumulativeDeposits();
        assertLe(vault.totalWithdrawn(), deposits);
        uint256 outflows = vault.totalWithdrawn() + vault.refunded() + vault.sweptToOperator();
        assertLe(outflows, deposits);
        assertEq(tok.balanceOf(address(vault)), deposits - outflows);
        uint256 paid;
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps,) = _fixture(i);
            assertLe(vault.withdrawn(who), vault.totalSteps() == 0 ? 0 : steps * deposits / vault.totalSteps());
            assertEq(tok.balanceOf(who), vault.withdrawn(who));
            paid += vault.withdrawn(who);
        }
        assertEq(paid, vault.totalWithdrawn());
    }

    function _sendDirect(uint256 amount) internal {
        tok.mint(STRANGER, amount);
        vm.prank(STRANGER);
        tok.transfer(address(vault), amount);
    }

    function testDirectTransferExcessRecoverableAfterAbort() public {
        _fundTwoDepositors();
        _sendDirect(123);
        vm.expectRevert("not finished");
        vault.recoverExcess();
        vm.warp(vault.deadline());
        vault.abortOnDeadline();
        // Recover before refunds: every tracked sponsor token must stay reserved.
        vm.prank(STRANGER);
        vault.recoverExcess();
        assertEq(tok.balanceOf(address(this)), 123);
        assertEq(tok.balanceOf(address(vault)), POOL + POOL / 2);
        assertEq(vault.refunded(), 0);
        assertEq(vault.sweptToOperator(), 0);
        _assertAbortClosedAndRefunds();
        _sendDirect(17);
        vault.recoverExcess();
        assertEq(tok.balanceOf(address(this)), 140);
        assertEq(tok.balanceOf(address(vault)), 0);
        vm.expectRevert("no excess");
        vault.recoverExcess();
        _assertConservation();
    }

    function testDirectTransferRecoveryAndSweepPreserveTrackedClaims() public {
        _fund(SPONSOR, POOL);
        _solveAndSettle(Fixture.TOTAL);
        _sendDirect(123);
        _claim(0);
        uint256 tracked = POOL - vault.totalWithdrawn();
        vm.prank(STRANGER);
        vault.recoverExcess();
        assertEq(tok.balanceOf(address(this)), 123);
        assertEq(tok.balanceOf(address(vault)), tracked);
        assertEq(vault.sweptToOperator(), 0);
        vm.expectRevert("no excess");
        vault.recoverExcess();
        _sendDirect(17);
        vm.warp(vault.settledAt() + vault.claimWindow());
        vault.sweep();
        assertEq(vault.sweptToOperator(), tracked);
        assertEq(tok.balanceOf(address(vault)), 17);
        _fund(SPONSOR2, POOL);
        vault.recoverExcess();
        assertEq(tok.balanceOf(address(vault)), POOL);
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps,) = _fixture(i);
            if (i == 0) {
                vm.prank(who);
                vault.withdraw();
            } else {
                _claim(i);
            }
            assertEq(tok.balanceOf(who), steps * POOL / Fixture.TOTAL * (i == 0 ? 2 : 1));
        }
        assertEq(tok.balanceOf(address(vault)), 0);
        _assertConservation();
    }

    function testT3_OperatorCannotTakeSponsorDepositAndStrangerEnablesRefund() public {
        uint256 operatorBefore = tok.balanceOf(address(this));
        _fund(SPONSOR, POOL);
        vm.expectRevert("too early");
        vault.abortOnDeadline();
        vm.expectRevert("not stalled");
        vault.abortOnStall();
        vm.expectRevert("not settled");
        vault.sweep();
        // The removed legacy abort() is intentionally absent from the typed API.
        assertEq(tok.balanceOf(address(this)), operatorBefore);
        assertEq(tok.balanceOf(address(vault)), POOL);
        vm.warp(uint256(vault.deadline()) + 1);
        vm.prank(STRANGER);
        vault.abortOnDeadline();
        vm.prank(STRANGER);
        vm.expectRevert("no deposit");
        vault.refundClaim();
        uint256 beforeRefund = tok.balanceOf(SPONSOR);
        vm.prank(SPONSOR);
        vault.refundClaim();
        assertEq(tok.balanceOf(SPONSOR) - beforeRefund, POOL);
        assertEq(vault.deposits(SPONSOR), 0);
        vm.prank(SPONSOR);
        vm.expectRevert("no deposit");
        vault.refundClaim();
        assertEq(vault.refunded(), POOL);
        assertEq(tok.balanceOf(address(vault)), 0);
        assertEq(tok.balanceOf(address(this)), operatorBefore);
    }

    function testDenominatorHalf_RejectsAtSettleAndAllLeavesReceiveExactShares() public {
        _fund(SPONSOR, POOL);
        _solve();
        _postRoot(1, Fixture.ROOT);
        assertEq(vault.rootLeafCountAt(1), 5);
        assertEq(vault.rootStepsAt(1), Fixture.TOTAL);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        vm.expectRevert("denominator");
        vault.settle(1, Fixture.ROOT, Fixture.TOTAL / 2);
        assertFalse(vault.settled());
        vault.settle(1, Fixture.ROOT, Fixture.TOTAL);
        for (uint256 i; i < 5; ++i) {
            _claim(i);
            (address who, uint256 steps,) = _fixture(i);
            assertEq(tok.balanceOf(who), steps * POOL / Fixture.TOTAL);
            _assertConservation();
        }
        assertEq(vault.claimedSteps(), Fixture.TOTAL);
        assertEq(vault.totalWithdrawn(), POOL);
        _fund(SPONSOR2, POOL);
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps,) = _fixture(i);
            vm.prank(who);
            vault.withdraw();
            assertEq(tok.balanceOf(who), 2 * steps * POOL / Fixture.TOTAL);
        }
        _assertConservation();
    }

    function testDenominatorDouble_RejectsAtSettleAndSweepRecoversExactResidue() public {
        _fund(SPONSOR, POOL);
        _solve();
        _postRoot(1, Fixture.ROOT);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        vm.expectRevert("denominator");
        vault.settle(1, Fixture.ROOT, Fixture.TOTAL * 2);
        assertFalse(vault.settled());
        vault.settle(1, Fixture.ROOT, Fixture.TOTAL);
        // First three leaves sum to 40%; remaining 60% is swept after the window.
        for (uint256 i; i < 3; ++i) {
            _claim(i);
            (address who, uint256 steps,) = _fixture(i);
            assertEq(tok.balanceOf(who), steps * POOL / Fixture.TOTAL);
            _assertConservation();
        }
        uint256 residue = tok.balanceOf(address(vault));
        assertEq(residue, POOL * 3 / 5);
        vm.expectRevert("too early");
        vault.sweep();
        vm.warp(vault.settledAt() + vault.claimWindow() + 1);
        uint256 beforeBalance = tok.balanceOf(address(this));
        vault.sweep();
        assertEq(tok.balanceOf(address(this)) - beforeBalance, residue);
        assertEq(tok.balanceOf(address(vault)), 0);
        assertTrue(vault.swept());
        _assertConservation();
    }

    function testSweepIsTrancheBased_LatePrizeStillClaimable() public {
        _fund(SPONSOR, POOL);
        _solveAndSettle(Fixture.TOTAL);
        _claim(0);
        uint256 residue = tok.balanceOf(address(vault));
        uint256 operatorBefore = tok.balanceOf(address(this));
        vm.warp(vault.settledAt() + vault.claimWindow());
        vm.prank(STRANGER);
        vm.expectEmit(address(vault));
        emit PrizeVault.Swept(residue, POOL);
        vault.sweep();
        assertEq(tok.balanceOf(address(this)) - operatorBefore, residue);
        assertEq(tok.balanceOf(address(vault)), 0);
        assertEq(vault.sweptDeposits(), POOL);
        assertEq(vault.sweptToOperator(), residue);
        assertEq(vault.lastSweepAt(), block.timestamp);
        _assertConservation();

        uint256 late = 2 * POOL + 1; // One base unit of late-tranche rounding residue.
        _fund(SPONSOR2, late);
        assertEq(vault.cumulativeDeposits(), POOL + late);
        vm.expectRevert("too early");
        vault.sweep();
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps, bytes32[] memory proof) = _fixture(i);
            if (i != 0) {
                vm.prank(who);
                vault.register(steps, proof);
            }
            uint256 beforeBalance = tok.balanceOf(who);
            assertEq(vault.claimable(who), steps * late / Fixture.TOTAL);
            assertEq(vault.accountedDeposits(who), i == 0 ? POOL : 0); // Registration and views leave it unchanged.
            vm.prank(who);
            vault.withdraw();
            assertEq(tok.balanceOf(who) - beforeBalance, steps * late / Fixture.TOTAL);
            assertEq(vault.accountedDeposits(who), POOL + late);
            assertEq(vault.claimable(who), 0);
            vm.prank(who);
            vault.withdraw();
            assertEq(tok.balanceOf(who) - beforeBalance, steps * late / Fixture.TOTAL);
            _assertConservation();
        }
        assertEq(tok.balanceOf(address(vault)), 1);
        vm.warp(vault.lastSweepAt() + vault.claimWindow() - 1);
        vm.expectRevert("too early");
        vault.sweep();
        vm.warp(vault.lastSweepAt() + vault.claimWindow());
        operatorBefore = tok.balanceOf(address(this));
        vm.prank(STRANGER);
        vault.sweep();
        assertEq(tok.balanceOf(address(this)) - operatorBefore, 1);
        assertEq(vault.sweptToOperator(), residue + 1);
        assertEq(vault.sweptDeposits(), POOL + late);
        _assertConservation();
    }

    function testSweep_RejectsNothingToSweep() public {
        _solveAndSettle(Fixture.TOTAL);
        vm.warp(vault.settledAt() + vault.claimWindow());
        vm.expectRevert("nothing to sweep");
        vault.sweep();
        _fund(SPONSOR, POOL);
        vm.expectRevert("too early");
        vault.sweep();
        vm.warp(vault.lastDepositAt() + vault.claimWindow());
        vault.sweep();
        vm.warp(vault.lastSweepAt() + vault.claimWindow());
        vm.expectRevert("nothing to sweep");
        vault.sweep();
        _assertConservation();
    }

    function testSweep_LateTrancheOutstandingClaimsAreBounded() public {
        _fund(SPONSOR, 14);
        _solveAndSettle(Fixture.TOTAL);
        vm.warp(vault.settledAt() + vault.claimWindow());
        vault.sweep();
        _fund(SPONSOR2, 1);
        uint256 outstanding;
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps, bytes32[] memory proof) = _fixture(i);
            vm.prank(who);
            vault.register(steps, proof);
            outstanding += vault.claimable(who);
        }
        assertLe(outstanding, tok.balanceOf(address(vault)));
        for (uint256 i; i < 5; ++i) {
            (address who,,) = _fixture(i);
            vm.prank(who);
            vault.withdraw();
            _assertConservation();
        }
    }

    function testWithdrawBeforeRegisterPreservesPriorDeposits() public {
        _fund(SPONSOR, POOL);
        _solveAndSettle(Fixture.TOTAL);
        (address who, uint256 steps, bytes32[] memory proof) = _fixture(0);
        vm.prank(who);
        vault.withdraw();
        assertEq(vault.accountedDeposits(who), 0);
        assertEq(vault.withdrawn(who), 0);
        assertEq(vault.totalWithdrawn(), 0);
        _fund(SPONSOR2, POOL);
        vm.prank(who);
        vault.withdraw();
        assertEq(vault.accountedDeposits(who), 0);
        vm.prank(who);
        vault.claim(steps, proof);
        assertEq(tok.balanceOf(who), steps * (2 * POOL) / Fixture.TOTAL);
        assertEq(vault.claimable(who), 0);
        _assertConservation();
    }

    function testH2_LatePrizesAccrueUnderSameRootForExistingAndLateClaimants() public {
        _fund(SPONSOR, POOL);
        _solveAndSettle(Fixture.TOTAL);
        _claim(0);
        (address first, uint256 steps,) = Fixture.leaf0();
        uint256 beforeBalance = tok.balanceOf(first);
        _fund(SPONSOR2, 2 * POOL);
        assertTrue(vault.settled());
        assertEq(vault.cumulativeDeposits(), 3 * POOL);
        vm.prank(first);
        vault.withdraw();
        assertEq(tok.balanceOf(first) - beforeBalance, steps * (2 * POOL) / Fixture.TOTAL);
        _assertConservation();
        vm.warp(vault.settledAt() + 5 weeks);
        _fund(SPONSOR, 3 * POOL);
        assertEq(vault.root(), Fixture.ROOT);
        assertEq(vault.cumulativeDeposits(), 6 * POOL);
        _claim(1);
        (address late, uint256 lateSteps,) = Fixture.leaf1();
        assertEq(tok.balanceOf(late), lateSteps * (6 * POOL) / Fixture.TOTAL);
        vm.prank(first);
        vault.withdraw();
        assertEq(tok.balanceOf(first), steps * (6 * POOL) / Fixture.TOTAL);
        for (uint256 i = 2; i < 5; ++i) _claim(i);
        _assertConservation();
        assertEq(vault.totalWithdrawn(), 6 * POOL);
        assertEq(tok.balanceOf(address(vault)), 0);
    }

    function testPythonRootVerifiesOnChain() public view {
        uint256 sum;
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps, bytes32[] memory proof) = _fixture(i);
            bytes32 leafHash = vault.leaf(who, steps);
            assertEq(leafHash, sha256(abi.encodePacked(who, steps)));
            assertTrue(vault.verify(Fixture.ROOT, leafHash, proof));
            assertFalse(vault.verify(Fixture.ROOT, vault.leaf(who, steps + 1), proof));
            sum += steps;
        }
        assertEq(sum, Fixture.TOTAL);
    }

    function testSolutionGate_CorrectScalarAfterDelay() public {
        _solve();
        assertTrue(vault.solved());
        assertEq(vault.solutionK(), R.K);
    }

    function testSolutionGate_WrongScalarWithMatchingCommitment() public {
        _commit(R.K + 1);
        vm.warp(vault.commitAt() + vault.revealDelay());
        vm.expectRevert("bad k");
        vault.revealSolution(R.K + 1, SALT);
        assertFalse(vault.solved());
    }

    function testSolutionGate_RevealBeforeDelay() public {
        _commit(R.K);
        vm.warp(vault.commitAt() + vault.revealDelay() - 1);
        vm.expectRevert("too early");
        vault.revealSolution(R.K, SALT);
        assertFalse(vault.solved());
    }

    function testSolutionGate_MismatchedCommitment() public {
        _commit(R.K);
        vm.warp(vault.commitAt() + vault.revealDelay());
        vm.expectRevert("bad commitment");
        vault.revealSolution(R.K, bytes32(uint256(123)));
        vm.expectRevert("bad commitment");
        vault.revealSolution(R.K + 1, SALT);
        assertFalse(vault.solved());
    }

    function testSolutionGate_SettleWithoutReveal() public {
        _postRoot(1, Fixture.ROOT);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        vm.expectRevert("not solved");
        vault.settle(1, Fixture.ROOT, Fixture.TOTAL);
        _commit(R.K);
        vm.expectRevert("not solved");
        vault.settle(1, Fixture.ROOT, Fixture.TOTAL);
    }

    function testEcMath_VerifyDlogRejectsWrongAndOutOfRangeScalars() public {
        EcMathHarness ec = new EcMathHarness();
        PrizeVault.Curve memory c = _roundCurve();
        assertTrue(ec.verify(c, R.K));
        assertFalse(ec.verify(c, R.K + 1));
        assertFalse(ec.verify(c, R.K - 1));
        assertFalse(ec.verify(c, 0));
        assertFalse(ec.verify(c, R.N));
    }

    function _fundTwoDepositors() internal {
        _fund(SPONSOR, POOL);
        _fund(SPONSOR2, POOL / 2);
    }

    function _assertAbortClosedAndRefunds() internal {
        assertTrue(vault.aborted());
        vm.expectRevert("closed");
        vault.settle(1, Fixture.ROOT, Fixture.TOTAL);
        vm.expectRevert("closed");
        _postRoot(2, Fixture.ROOT);
        uint256 operatorBefore = tok.balanceOf(address(this));
        vm.prank(SPONSOR);
        vault.refundClaim();
        vm.prank(SPONSOR2);
        vault.refundClaim();
        assertEq(tok.balanceOf(SPONSOR), POOL);
        assertEq(tok.balanceOf(SPONSOR2), POOL / 2);
        assertEq(vault.deposits(SPONSOR), 0);
        assertEq(vault.deposits(SPONSOR2), 0);
        assertEq(vault.refunded(), vault.cumulativeDeposits());
        assertEq(tok.balanceOf(address(vault)), 0);
        assertEq(tok.balanceOf(address(this)), operatorBefore);
    }

    function testAbortOnStall_StrangerAndLastRootResetsClock() public {
        _fundTwoDepositors();
        vm.warp(block.timestamp + 12 hours);
        _postRoot(1, Fixture.ROOT);
        uint256 lastRoot = vault.lastRootAt();
        vm.warp(lastRoot + vault.stallWindow() - 1);
        vm.prank(STRANGER);
        vm.expectRevert("not stalled");
        vault.abortOnStall();
        vm.warp(lastRoot + vault.stallWindow());
        vm.prank(STRANGER);
        vm.expectRevert("not stalled");
        vault.abortOnStall();
        vm.warp(lastRoot + vault.stallWindow() + 1);
        vm.prank(STRANGER);
        vault.abortOnStall();
        _assertAbortClosedAndRefunds();
    }

    function testAbortOnDeadline_Stranger() public {
        _fundTwoDepositors();
        vm.warp(uint256(vault.deadline()) - 1);
        vm.prank(STRANGER);
        vm.expectRevert("too early");
        vault.abortOnDeadline();
        vm.warp(uint256(vault.deadline()) + 1);
        vm.prank(STRANGER);
        vault.abortOnDeadline();
        _assertAbortClosedAndRefunds();
    }

    function _externalCommit(address claimant, uint256 k) internal {
        vm.prank(claimant);
        vault.commitExternalSolve(keccak256(abi.encode(k, SALT, claimant)));
    }

    function testExternalSolve_MempoolRevealCannotBeFrontRun() public {
        _fundTwoDepositors();
        _commit(R.K);
        vm.warp(vault.commitAt() + vault.revealDelay());
        vm.prank(STRANGER);
        vm.expectRevert("not committed");
        vault.abortOnExternalSolve(R.K, SALT);
        _externalCommit(STRANGER, R.K);
        assertGt(vault.externalRevealDelay(), vault.revealDelay());
        vm.prank(STRANGER);
        vm.expectRevert("too early");
        vault.abortOnExternalSolve(R.K, SALT);
        vault.revealSolution(R.K, SALT);
        vm.warp(block.timestamp + vault.externalRevealDelay());
        vm.prank(STRANGER);
        vm.expectRevert("solved");
        vault.abortOnExternalSolve(R.K, SALT);
        assertFalse(vault.aborted());
        _postRoot(1, Fixture.ROOT);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        vault.settle(1, Fixture.ROOT, Fixture.TOTAL);
        for (uint256 i; i < 5; ++i) _claim(i);
        assertEq(vault.totalWithdrawn(), POOL + POOL / 2);
    }

    function testExternalSolve_CommitmentIsSenderBoundAndReplacementRestartsDelay() public {
        _externalCommit(STRANGER, R.K);
        vm.warp(block.timestamp + vault.externalRevealDelay());
        vault.commitExternalSolve(keccak256(abi.encode(R.K, SALT, STRANGER)));
        vm.warp(block.timestamp + vault.externalRevealDelay());
        vm.expectRevert("bad commitment");
        vault.abortOnExternalSolve(R.K, SALT);
        _externalCommit(STRANGER, R.K);
        vm.prank(STRANGER);
        vm.expectRevert("too early");
        vault.abortOnExternalSolve(R.K, SALT);
        vm.warp(block.timestamp + vault.externalRevealDelay());
        vm.prank(STRANGER);
        vm.expectRevert("bad commitment");
        vault.abortOnExternalSolve(R.K, bytes32(0));
        vm.prank(STRANGER);
        vault.abortOnExternalSolve(R.K, SALT);
        assertTrue(vault.aborted());
    }

    function testAbortOnExternalSolve_StrangerBeforeCommit() public {
        _fundTwoDepositors();
        _externalCommit(STRANGER, R.K);
        vm.warp(block.timestamp + 1);
        _commit(R.K);
        vm.warp(vault.externalCommitAt(STRANGER) + vault.externalRevealDelay());
        vm.prank(STRANGER);
        vault.abortOnExternalSolve(R.K, SALT);
        _assertAbortClosedAndRefunds();
    }

    function testAbortOnExternalSolve_RejectsAfterCommit() public {
        _commit(R.K);
        vm.warp(vault.commitAt() + vault.revealDelay());
        vault.revealSolution(R.K, SALT);
        vm.prank(STRANGER);
        vm.expectRevert("solved");
        vault.abortOnExternalSolve(R.K, SALT);
        assertFalse(vault.aborted());
    }

    function testAbortOnExternalSolve_GarbageCommitmentStillRefundsEveryone() public {
        uint256 operatorBefore = tok.balanceOf(address(this));
        _fundTwoDepositors();
        vault.commitSolution(keccak256("garbage"));
        _externalCommit(STRANGER, R.K);
        vm.warp(block.timestamp + vault.externalRevealDelay());
        vm.prank(STRANGER);
        vault.abortOnExternalSolve(R.K, SALT);
        _assertAbortClosedAndRefunds();
        assertEq(tok.balanceOf(address(this)), operatorBefore);
    }

    function testClearCommitment_StrangerClearsAtExpiryAndOperatorRetries() public {
        _fund(SPONSOR, POOL);
        vault.commitSolution(keccak256("garbage"));
        uint256 expires = vault.commitAt() + vault.commitExpiry();
        vm.warp(expires - 1);
        vm.prank(STRANGER);
        vm.expectRevert("too early");
        vault.clearCommitment();
        vm.warp(expires);
        vm.prank(STRANGER);
        vm.expectEmit(address(vault));
        emit PrizeVault.CommitmentCleared();
        vault.clearCommitment();
        assertFalse(vault.solutionCommitted());
        assertEq(vault.solutionCommitment(), bytes32(0));
        assertEq(vault.commitAt(), 0);
        _solveAndSettle(Fixture.TOTAL);
        for (uint256 i; i < 5; ++i) _claim(i);
        _assertConservation();
    }

    function testClearCommitment_RejectsSolvedRound() public {
        _solve();
        vm.warp(vault.commitAt() + vault.commitExpiry());
        vm.prank(STRANGER);
        vm.expectRevert("solved");
        vault.clearCommitment();
        assertTrue(vault.solutionCommitted());
        assertTrue(vault.solved());
    }

    function testClearCommitment_RejectsMissingOrClosedCommitment() public {
        vm.expectRevert("not committed");
        vault.clearCommitment();
        _commit(R.K);
        vm.warp(vault.commitAt() + vault.commitExpiry());
        _externalCommit(address(this), R.K);
        vm.warp(block.timestamp + vault.externalRevealDelay());
        vault.abortOnExternalSolve(R.K, SALT);
        vm.expectRevert("closed");
        vault.clearCommitment();
    }

    function testCommitExpiry_MustExceedRevealDelay() public {
        PrizeVault.Timing memory timing = PrizeVault.Timing(
            uint64(block.timestamp + 30 days), 1 days, 10 minutes, 10 minutes, 1 hours, 90 days
        );
        vm.expectRevert("bad commit expiry");
        new PrizeVault(IERC20(address(tok)), bytes32(0), _roundCurve(), timing);
        timing.commitExpiry = 9 minutes;
        vm.expectRevert("bad commit expiry");
        new PrizeVault(IERC20(address(tok)), bytes32(0), _roundCurve(), timing);
    }

    function testLatePrizeCannotBeSweptOnArrival() public {
        _fund(SPONSOR, POOL);
        _solveAndSettle(Fixture.TOTAL);
        vm.warp(vault.settledAt() + vault.claimWindow());
        vault.sweep();
        // An old sweep must not let newly arrived money be swept immediately.
        vm.warp(block.timestamp + vault.claimWindow());
        _fund(SPONSOR2, POOL);
        vm.expectRevert("too early");
        vault.sweep();
        (address alice, uint256 aliceSteps,) = _fixture(0);
        _claim(0);
        assertEq(tok.balanceOf(alice), aliceSteps * POOL / Fixture.TOTAL);
        vm.warp(vault.lastDepositAt() + vault.claimWindow() - 1);
        vm.expectRevert("too early");
        vault.sweep();
        (address bob, uint256 bobSteps,) = _fixture(1);
        _claim(1);
        assertEq(tok.balanceOf(bob), bobSteps * POOL / Fixture.TOTAL);
        uint256 residue = POOL - tok.balanceOf(alice) - tok.balanceOf(bob);
        vm.warp(vault.lastDepositAt() + vault.claimWindow());
        // A zero deposit must not postpone a sweep.
        _fund(SPONSOR2, 0);
        vault.sweep();
        assertEq(tok.balanceOf(address(this)), POOL + residue);
        assertEq(tok.balanceOf(address(vault)), 0);
        _assertConservation();
        // Funding immediately after a sweep also gets a full window.
        _fund(SPONSOR2, POOL);
        vm.expectRevert("too early");
        vault.sweep();
        vm.prank(alice);
        vault.withdraw();
        vm.warp(vault.lastDepositAt() + vault.claimWindow());
        vault.sweep();
        assertEq(tok.balanceOf(alice), 2 * aliceSteps * POOL / Fixture.TOTAL);
        _assertConservation();
    }

    function testSweepLifetimeFloorDifference_Counterexample() public {
        // Same fixture and 14 + 1 deposits: lifetime-floor subtraction owed 5 wei
        // against a 1 wei balance. Independently rounded tranches owe zero here.
        uint256 sweptDeposit = 14;
        uint256 lateDeposit = 1;
        _fund(SPONSOR, sweptDeposit);
        _solveAndSettle(Fixture.TOTAL);
        vm.warp(vault.settledAt() + vault.claimWindow());
        vault.sweep();
        _fund(SPONSOR2, lateDeposit);
        uint256 outstanding;
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps, bytes32[] memory proof) = _fixture(i);
            vm.prank(who);
            vault.register(steps, proof);
            assertEq(vault.accountedDeposits(who), 0);
            assertEq(vault.claimable(who), steps * lateDeposit / Fixture.TOTAL);
            outstanding += vault.claimable(who);
        }
        assertEq(outstanding, 0);
        assertLe(outstanding, lateDeposit);
        for (uint256 i; i < 5; ++i) {
            (address who,,) = _fixture(i);
            assertLe(vault.claimable(who), tok.balanceOf(address(vault)));
            vm.prank(who);
            vault.withdraw();
            assertEq(vault.accountedDeposits(who), sweptDeposit + lateDeposit);
            assertEq(vault.claimable(who), 0);
            assertEq(tok.balanceOf(address(vault)), lateDeposit);
            _assertConservation();
        }
        vm.warp(vault.lastSweepAt() + vault.claimWindow());
        vault.sweep();
        assertEq(vault.sweptToOperator(), sweptDeposit + lateDeposit);
        assertEq(tok.balanceOf(address(vault)), 0);
        _assertConservation();
    }

    function testAbortOnExternalSolve_RejectsWrongScalar() public {
        _externalCommit(STRANGER, R.K + 1);
        vm.warp(block.timestamp + vault.externalRevealDelay());
        vm.prank(STRANGER);
        vm.expectRevert("bad k");
        vault.abortOnExternalSolve(R.K + 1, SALT);
        assertFalse(vault.aborted());
    }

    function testRootTotals_RejectsFalseLeavesDuplicatesAndOverflow() public {
        (address[] memory miners, uint256[] memory steps) = _fixtureLeaves();
        steps[0] /= 2;
        vm.expectRevert("bad leaves");
        vault.postRoot(1, Fixture.ROOT, miners, steps);
        assertEq(vault.rootStepsAt(1), 0);
        (miners, steps) = _fixtureLeaves();
        miners[1] = miners[0];
        vm.expectRevert("leaf order");
        vault.postRoot(1, Fixture.ROOT, miners, steps);
        (miners, steps) = _fixtureLeaves();
        vm.expectRevert("leaf lengths");
        vault.postRoot(1, Fixture.ROOT, miners, new uint256[](1));
        steps[0] = type(uint256).max;
        vm.expectRevert(stdError.arithmeticError);
        vault.postRoot(1, Fixture.ROOT, miners, steps);
        _postRoot(1, Fixture.ROOT);
        assertEq(vault.rootStepsAt(1), Fixture.TOTAL);
    }

    function testRootTotals_TwoEqualLeavesBothRegisterInEitherOrder() public {
        address[] memory miners = new address[](2);
        uint256[] memory steps = new uint256[](2);
        miners[0] = address(1);
        miners[1] = address(2);
        steps[0] = 50;
        steps[1] = 50;
        bytes32 aLeaf = vault.leaf(miners[0], 50);
        bytes32 bLeaf = vault.leaf(miners[1], 50);
        bytes32 pairRoot = aLeaf < bLeaf
            ? sha256(abi.encodePacked(aLeaf, bLeaf)) : sha256(abi.encodePacked(bLeaf, aLeaf));
        _fund(SPONSOR, 100);
        _solve();
        vault.postRoot(1, pairRoot, miners, steps);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        vm.expectRevert("denominator");
        vault.settle(1, pairRoot, 50);
        vault.settle(1, pairRoot, 100);
        uint256 snapshot = vm.snapshotState();
        for (uint256 order; order < 2; ++order) {
            bytes32[] memory proof = new bytes32[](1);
            for (uint256 i; i < 2; ++i) {
                uint256 index = order == 0 ? i : 1 - i;
                proof[0] = index == 0 ? bLeaf : aLeaf;
                vm.prank(miners[index]);
                vault.claim(50, proof);
                assertEq(tok.balanceOf(miners[index]), 50);
            }
            assertEq(vault.claimedSteps(), 100);
            assertEq(vault.totalWithdrawn(), 100);
            if (order == 0) assertTrue(vm.revertToState(snapshot));
        }
    }

    function testRootMonotonicity_RejectsEqualAndEarlierEpochs() public {
        _postRoot(2, Fixture.ROOT);
        vm.expectRevert("stale epoch");
        _postRoot(2, Fixture.ROOT);
        vm.expectRevert("stale epoch");
        _postRoot(1, Fixture.ROOT);
        _postRoot(3, Fixture.ROOT);
        assertEq(vault.epoch(), 3);
    }

    function testRootMonotonicity_ZeroEpochAndZeroRootAreConsumed() public {
        _postRoot(0, bytes32(0));
        vm.expectRevert("stale epoch");
        _postRoot(0, bytes32(0));
        _postRoot(1, Fixture.ROOT);
    }

    function testChallengeWindow_RejectsOldOrMismatchedRoot() public {
        _solve();
        bytes32 oldRoot = bytes32(0);
        _postRoot(1, oldRoot);
        _postRoot(2, Fixture.ROOT);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        vm.expectRevert("bad root");
        vault.settle(1, oldRoot, Fixture.TOTAL);
        vm.expectRevert("bad root");
        vault.settle(2, oldRoot, Fixture.TOTAL);
        vault.settle(2, Fixture.ROOT, Fixture.TOTAL);
        assertTrue(vault.settled());
    }

    function testChallengeWindow_SettleDelayRestartsOnNewRoot() public {
        _solve();
        _postRoot(1, Fixture.ROOT);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        _postRoot(2, Fixture.ROOT);
        vm.warp(vault.rootPostedAt() + vault.settleDelay() - 1);
        vm.expectRevert("too early");
        vault.settle(2, Fixture.ROOT, Fixture.TOTAL);
        vm.warp(vault.rootPostedAt() + vault.settleDelay());
        vault.settle(2, Fixture.ROOT, Fixture.TOTAL);
        assertTrue(vault.settled());
    }

    struct ClaimAccounting {
        uint256[5] depositLevel;
        uint256[5] eligibleDeposits;
        uint256[5] withdrawals;
    }

    function _recordWithdrawal(ClaimAccounting memory accounting, uint256 index) internal view {
        (address who,,) = _fixture(index);
        uint256 deposits = vault.cumulativeDeposits();
        if (vault.registeredSteps(who) == 0) return;
        accounting.eligibleDeposits[index] += deposits - accounting.depositLevel[index];
        accounting.depositLevel[index] = deposits;
        ++accounting.withdrawals[index];
    }

    function testFuzz_Conservation(uint256 initial, uint256 extra, uint256 seed, uint8 count) public {
        initial = bound(initial, 1, 1e24);
        extra = bound(extra, 1, 1e24);
        uint256 claimantCount = bound(uint256(count), 0, 5);
        _fund(SPONSOR, initial);
        _solveAndSettle(Fixture.TOTAL);
        uint256[5] memory order = [uint256(0), 1, 2, 3, 4];
        for (uint256 i = 5; i > 1; --i) {
            seed = uint256(keccak256(abi.encode(seed, i)));
            uint256 j = seed % i;
            (order[i - 1], order[j]) = (order[j], order[i - 1]);
        }
        ClaimAccounting memory accounting;
        uint256 registered;
        uint256 sweepTurn = seed % 20;
        for (uint256 turn; turn < 20; ++turn) {
            seed = uint256(keccak256(abi.encode(seed, turn)));
            if (turn == sweepTurn) {
                vm.warp(vault.settledAt() + vault.claimWindow());
                vm.prank(STRANGER);
                vault.sweep();
                for (uint256 i; i < 5; ++i) accounting.depositLevel[i] = vault.cumulativeDeposits();
                _assertConservation();
            }
            uint256 action = seed % 3;
            if (action == 0) {
                _fund(SPONSOR2, bound(seed >> 8, 1, extra));
            } else if (action == 1 && registered < claimantCount) {
                (address who, uint256 steps, bytes32[] memory proof) = _fixture(order[registered++]);
                vm.prank(who);
                vault.register(steps, proof);
            } else {
                uint256 index = order[(seed >> 8) % 5];
                (address who,,) = _fixture(index);
                _recordWithdrawal(accounting, index);
                vm.prank(who);
                vault.withdraw();
            }
            _assertConservation();
        }
        // Ensure every run includes post-settlement funding and exactly the chosen
        // number of registrations, even if the random schedule omits an action.
        _fund(SPONSOR2, extra);
        _assertConservation();
        while (registered < claimantCount) {
            uint256 index = order[registered++];
            (address who, uint256 steps, bytes32[] memory proof) = _fixture(index);
            vm.prank(who);
            vault.register(steps, proof);
            _recordWithdrawal(accounting, index);
            vm.prank(who);
            vault.withdraw();
            _assertConservation();
        }
        for (uint256 i; i < claimantCount; ++i) {
            (address who, uint256 steps,) = _fixture(order[i]);
            _recordWithdrawal(accounting, order[i]);
            vm.prank(who);
            vault.withdraw();
            assertLe(vault.withdrawn(who), steps * vault.cumulativeDeposits() / Fixture.TOTAL);
            // Only sweeps close unpaid deposits. Pre-registration withdrawals are
            // no-ops, so the rounding bound includes all unswept prior funding.
            uint256 share = steps * accounting.eligibleDeposits[order[i]] / Fixture.TOTAL;
            uint256 withdrawals = accounting.withdrawals[order[i]];
            assertGe(vault.withdrawn(who), share > withdrawals ? share - withdrawals : 0);
            _assertConservation();
        }
    }

    function testFuzz_NoSweepWithdrawalRoundingBounds(uint256 initial, uint256 extra, uint8 count) public {
        initial = bound(initial, 1, 1e24);
        extra = bound(extra, 1, 1e24);
        uint256 rounds = bound(uint256(count), 1, 20);
        _fund(SPONSOR, initial);
        _solveAndSettle(Fixture.TOTAL);
        uint256[5] memory withdrawals;
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps, bytes32[] memory proof) = _fixture(i);
            vm.prank(who);
            vault.register(steps, proof);
        }
        for (uint256 turn; turn < rounds; ++turn) {
            _fund(SPONSOR2, extra);
            for (uint256 i; i < 5; ++i) {
                (address who, uint256 steps,) = _fixture(i);
                vm.prank(who);
                vault.withdraw();
                ++withdrawals[i];
                uint256 lifetimeShare = steps * vault.cumulativeDeposits() / Fixture.TOTAL;
                assertLe(vault.withdrawn(who), lifetimeShare);
                assertGe(vault.withdrawn(who), lifetimeShare > withdrawals[i] ? lifetimeShare - withdrawals[i] : 0);
            }
            _assertConservation();
        }
        vm.warp(vault.settledAt() + vault.claimWindow());
        vault.sweep();
        assertEq(tok.balanceOf(address(vault)), 0);
        _assertConservation();
    }

    function testFuzz_SingleWithdrawalAtEndIsExact(uint256 initial, uint256 extra) public {
        initial = bound(initial, 1, 1e24);
        extra = bound(extra, 1, 1e24);
        _fund(SPONSOR, initial);
        _solveAndSettle(Fixture.TOTAL);
        _fund(SPONSOR2, extra);
        for (uint256 i; i < 5; ++i) {
            _claim(i);
            (address who, uint256 steps,) = _fixture(i);
            assertEq(vault.withdrawn(who), steps * vault.cumulativeDeposits() / Fixture.TOTAL);
            assertEq(vault.accountedDeposits(who), vault.cumulativeDeposits());
            _assertConservation();
        }
    }

    function testNoReturnToken_FundAndWithdraw() public {
        NoReturnToken token = new NoReturnToken();
        vault = _deploy(IERC20(address(token)), _roundCurve());
        token.mint(SPONSOR, POOL);
        vm.startPrank(SPONSOR);
        token.approve(address(vault), POOL);
        vault.fund(POOL);
        vm.stopPrank();
        assertEq(vault.cumulativeDeposits(), POOL);
        _solveAndSettle(Fixture.TOTAL);
        for (uint256 i; i < 5; ++i) {
            _claim(i);
            (address who, uint256 steps,) = _fixture(i);
            assertEq(token.balanceOf(who), steps * POOL / Fixture.TOTAL);
        }
        assertEq(vault.totalWithdrawn(), POOL);
        assertEq(token.balanceOf(address(vault)), 0);
    }

    function testFeeOnTransferToken_FundingRejectedWithoutAccountingChanges() public {
        FeeOnTransferToken token = new FeeOnTransferToken();
        vault = _deploy(IERC20(address(token)), _roundCurve());
        token.mint(SPONSOR, POOL);
        vm.startPrank(SPONSOR);
        token.approve(address(vault), POOL);
        vm.expectRevert("fee-on-transfer token not supported");
        vault.fund(POOL);
        vm.stopPrank();
        assertEq(vault.cumulativeDeposits(), 0);
        assertEq(vault.deposits(SPONSOR), 0);
        assertEq(token.balanceOf(address(vault)), 0);
        assertEq(token.balanceOf(SPONSOR), POOL);
        assertEq(token.allowance(SPONSOR, address(vault)), POOL);
    }

    function testGasRevealSolution131Bit() public {
        PrizeVault.Curve memory c = _curve131();
        assertGe(c.p, uint256(1) << 130);
        assertLt(c.p, uint256(1) << 131);
        vault = _deploy(IERC20(address(tok)), c);
        EcMathHarness ec = new EcMathHarness();
        _commit(C.K);
        vm.warp(vault.commitAt() + vault.revealDelay());
        uint256 beforeGas = gasleft();
        vault.revealSolution(C.K, SALT);
        uint256 revealGas = beforeGas - gasleft();
        beforeGas = gasleft();
        bool valid = ec.verify(c, C.K);
        uint256 ecGas = beforeGas - gasleft();
        console2.log("reveal gas (131-bit modulus)", revealGas);
        console2.log("EcMath.verifyDlog gas (131-bit modulus)", ecGas);
        assertTrue(valid);
        assertTrue(vault.solved());
        assertEq(vault.solutionK(), C.K);
        assertLt(revealGas, 5_000_000);
        assertLt(ecGas, 5_000_000);
    }
}
