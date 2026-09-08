# PrizeVault adversarial fixes

All five listed defects were reproduced in tests before their respective fixes. Baseline: 35 passing tests. Full-suite results after defects 1–5: 37, 38, 40, 41, and 43 passing tests, respectively, with no failures or skipped tests in those successful runs. The original 35 scenarios are retained; both denominator tests now require rejection at settlement, and existing external-solve tests use the required claim commitment. The nothing-to-sweep test now additionally rejects sweeping fresh deposits.

Tools: Foundry 1.5.1-stable (b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2), solc 0.8.24. The compiler's existing EcMath.sol mutability warning remains.

## Changes and reproduction evidence

1. External solve: reproduced a successful attacker abort immediately before operator reveal, followed by the operator's reveal reverting. External abort now requires a sender-bound commitment and waits revealDelay + 1 second. Tests cover pending-reveal copying, independent prior knowledge, garbage operator commitments, sender binding, replacement delays, and invalid salts/scalars. As with any timestamp-based scheme, timely operator transaction inclusion is assumed; the delay cannot guarantee inclusion under censorship.
2. Late prize: reproduced an immediate sweep of a newly arrived prize after an old sweep, leaving the claimant zero. Sweeps now require the newest nonzero deposit to age a full claim window. Since a sweep closes the whole unswept batch, this conservatively protects every included deposit. New funding extends older deposits' sweep eligibility too; mature deposits are not swept separately. Tests cover same-block attempts, one second before expiry, withdrawals during the window, exact residue at expiry, and zero-value funding.
3. Denominator: the original half-denominator test reproduced successful settlement followed by exclusion of valid claimants. postRoot now receives all leaf addresses and values, reconstructs the existing SHA-256 tree, checks unique ordered nonzero addresses, and records exact leaf count and sum per epoch. settle requires that sum. Unlike merely accepting operator-supplied metadata, this makes a falsely low sum impossible for the supplied root (assuming SHA-256 collision resistance). Existing proofs and odd-node promotion remain compatible. Posting requires O(number of leaves) calldata, memory, and hashing, so large checkpoints are limited by block gas. Tests cover both Alice/Bob registration orders, all fixture leaves receiving exact initial and future shares, false leaves, duplicates, length mismatch, sum overflow, and both understated and overstated settlement totals.
4. Unregistered withdrawal: reproduced the watermark advancing and the claimant receiving zero on subsequent registration. withdraw now returns without changing accounting for addresses with zero registered steps. The regression and fuzz reference model include prior deposits in the miner's share.
5. Direct transfers: reproduced tokens remaining after abort and all refunds, with sweep reverting and no recovery selector. recoverExcess is callable only after settlement or abort, sends only balance above tracked obligations to the fixed operator, and preserves claims/refunds. sweep transfers only tracked residue. The balance invariant comment now allows untracked excess. Tests exercise recovery before/after refunds, after withdrawals, alongside sweeps and late funding, and reject recovery before completion or without excess.

## API changes

- postRoot(uint64 epoch, bytes32 root, address[] miners, uint256[] steps), with strictly increasing addresses; count and sum are derived and emitted in RootPosted.
- commitExternalSolve(bytes32 commitment), where commitment = keccak256(abi.encode(k, salt, claimant)).
- abortOnExternalSolve(uint256 k, bytes32 salt).
- recoverExcess().

Only contracts/src/PrizeVault.sol, contracts/test/PrizeVault.t.sol, and artifacts under contracts/review-results/ were edited/created intentionally. No git mutation commands were used. External coordinator callers need to adopt the new ABI.

The pre-fix test source snapshots below assert the vulnerable behavior; those assertions were replaced by the fixed regression expectations. An initial defect-2 full run identified the existing testSweep_RejectsNothingToSweep test's dependence on immediate sweeping (37 passed, 1 failed). Its original empty-sweep checks were retained and a fresh-deposit rejection plus a full-window wait were added; the successful rerun is recorded below.

## 00-baseline.txt

```text
No files changed, compilation skipped

Ran 35 tests for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testAbortOnDeadline_Stranger() (gas: 346773)
[PASS] testAbortOnExternalSolve_GarbageCommitmentStillRefundsEveryone() (gas: 519123)
[PASS] testAbortOnExternalSolve_RejectsAfterCommit() (gas: 281179)
[PASS] testAbortOnExternalSolve_RejectsWrongScalar() (gas: 160784)
[PASS] testAbortOnExternalSolve_StrangerBeforeCommit() (gas: 460599)
[PASS] testAbortOnStall_StrangerAndLastRootResetsClock() (gas: 415081)
[PASS] testChallengeWindow_RejectsOldOrMismatchedRoot() (gas: 505051)
[PASS] testChallengeWindow_SettleDelayRestartsOnNewRoot() (gas: 508031)
[PASS] testClearCommitment_RejectsMissingOrClosedCommitment() (gas: 261656)
[PASS] testClearCommitment_RejectsSolvedRound() (gas: 285076)
[PASS] testClearCommitment_StrangerClearsAtExpiryAndOperatorRetries() (gas: 1221216)
[PASS] testCommitExpiry_MustExceedRevealDelay() (gas: 97509)
[PASS] testDenominatorDouble_AllReceiveHalfAndSweepRecoversExactResidue() (gas: 1642360)
[PASS] testDenominatorHalf_RejectsLaterClaimantsBeforeOverdraw() (gas: 1324393)
[PASS] testEcMath_VerifyDlogRejectsWrongAndOutOfRangeScalars() (gas: 952709)
[PASS] testFeeOnTransferToken_FundingRejectedWithoutAccountingChanges() (gas: 4734830)
[PASS] testFuzz_Conservation(uint256,uint256,uint256,uint8) (runs: 257, μ: 2881951, ~: 2888746)
[PASS] testFuzz_NoSweepWithdrawalRoundingBounds(uint256,uint256,uint8) (runs: 256, μ: 2435672, ~: 2142248)
[PASS] testFuzz_SingleWithdrawalAtEndIsExact(uint256,uint256) (runs: 256, μ: 1553893, ~: 1556511)
[PASS] testGasRevealSolution131Bit() (gas: 5757612)
[PASS] testH2_LatePrizesAccrueUnderSameRootForExistingAndLateClaimants() (gas: 1366767)
[PASS] testNoReturnToken_FundAndWithdraw() (gas: 5728498)
[PASS] testPythonRootVerifiesOnChain() (gas: 123973)
[PASS] testRootMonotonicity_RejectsEqualAndEarlierEpochs() (gas: 161188)
[PASS] testRootMonotonicity_ZeroEpochAndZeroRootAreConsumed() (gas: 137349)
[PASS] testSolutionGate_CorrectScalarAfterDelay() (gas: 279242)
[PASS] testSolutionGate_MismatchedCommitment() (gas: 97633)
[PASS] testSolutionGate_RevealBeforeDelay() (gas: 91212)
[PASS] testSolutionGate_SettleWithoutReveal() (gas: 209930)
[PASS] testSolutionGate_WrongScalarWithMatchingCommitment() (gas: 234947)
[PASS] testSweepIsTrancheBased_LatePrizeStillClaimable() (gas: 1894888)
[PASS] testSweepLifetimeFloorDifference_Counterexample() (gas: 1548328)
[PASS] testSweep_LateTrancheOutstandingClaimsAreBounded() (gas: 1406687)
[PASS] testSweep_RejectsNothingToSweep() (gas: 745272)
[PASS] testT3_OperatorCannotTakeSponsorDepositAndStrangerEnablesRefund() (gas: 277697)
Suite result: ok. 35 passed; 0 failed; 0 skipped; finished in 972.22ms (2.09s CPU time)

Ran 1 test suite in 979.22ms (972.22ms CPU time): 35 tests passed, 0 failed, 0 skipped (35 total tests)
```

## 01-fixed.txt

```text
Compiling 2 files with Solc 0.8.24
Solc 0.8.24 finished in 520.22ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 37 tests for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testAbortOnDeadline_Stranger() (gas: 346811)
[PASS] testAbortOnExternalSolve_GarbageCommitmentStillRefundsEveryone() (gas: 561002)
[PASS] testAbortOnExternalSolve_RejectsAfterCommit() (gas: 281295)
[PASS] testAbortOnExternalSolve_RejectsWrongScalar() (gas: 211381)
[PASS] testAbortOnExternalSolve_StrangerBeforeCommit() (gas: 560678)
[PASS] testAbortOnStall_StrangerAndLastRootResetsClock() (gas: 415189)
[PASS] testChallengeWindow_RejectsOldOrMismatchedRoot() (gas: 504941)
[PASS] testChallengeWindow_SettleDelayRestartsOnNewRoot() (gas: 507787)
[PASS] testClearCommitment_RejectsMissingOrClosedCommitment() (gas: 313982)
[PASS] testClearCommitment_RejectsSolvedRound() (gas: 285120)
[PASS] testClearCommitment_StrangerClearsAtExpiryAndOperatorRetries() (gas: 1221144)
[PASS] testCommitExpiry_MustExceedRevealDelay() (gas: 98267)
[PASS] testDenominatorDouble_AllReceiveHalfAndSweepRecoversExactResidue() (gas: 1642313)
[PASS] testDenominatorHalf_RejectsLaterClaimantsBeforeOverdraw() (gas: 1324458)
[PASS] testEcMath_VerifyDlogRejectsWrongAndOutOfRangeScalars() (gas: 952709)
[PASS] testExternalSolve_CommitmentIsSenderBoundAndReplacementRestartsDelay() (gas: 304325)
[PASS] testExternalSolve_MempoolRevealCannotBeFrontRun() (gas: 1246745)
[PASS] testFeeOnTransferToken_FundingRejectedWithoutAccountingChanges() (gas: 4999248)
[PASS] testFuzz_Conservation(uint256,uint256,uint256,uint8) (runs: 257, μ: 2907581, ~: 2896564)
[PASS] testFuzz_NoSweepWithdrawalRoundingBounds(uint256,uint256,uint8) (runs: 256, μ: 2461851, ~: 2104818)
[PASS] testFuzz_SingleWithdrawalAtEndIsExact(uint256,uint256) (runs: 256, μ: 1554948, ~: 1556781)
[PASS] testGasRevealSolution131Bit() (gas: 6021942)
[PASS] testH2_LatePrizesAccrueUnderSameRootForExistingAndLateClaimants() (gas: 1366914)
[PASS] testNoReturnToken_FundAndWithdraw() (gas: 5992783)
[PASS] testPythonRootVerifiesOnChain() (gas: 123049)
[PASS] testRootMonotonicity_RejectsEqualAndEarlierEpochs() (gas: 161035)
[PASS] testRootMonotonicity_ZeroEpochAndZeroRootAreConsumed() (gas: 137195)
[PASS] testSolutionGate_CorrectScalarAfterDelay() (gas: 279265)
[PASS] testSolutionGate_MismatchedCommitment() (gas: 97634)
[PASS] testSolutionGate_RevealBeforeDelay() (gas: 91213)
[PASS] testSolutionGate_SettleWithoutReveal() (gas: 209907)
[PASS] testSolutionGate_WrongScalarWithMatchingCommitment() (gas: 234948)
[PASS] testSweepIsTrancheBased_LatePrizeStillClaimable() (gas: 1896114)
[PASS] testSweepLifetimeFloorDifference_Counterexample() (gas: 1549689)
[PASS] testSweep_LateTrancheOutstandingClaimsAreBounded() (gas: 1407216)
[PASS] testSweep_RejectsNothingToSweep() (gas: 745113)
[PASS] testT3_OperatorCannotTakeSponsorDepositAndStrangerEnablesRefund() (gas: 277558)
Suite result: ok. 37 passed; 0 failed; 0 skipped; finished in 874.40ms (1.80s CPU time)

Ran 1 test suite in 878.00ms (874.40ms CPU time): 37 tests passed, 0 failed, 0 skipped (37 total tests)
```

## 01-pre-fix-test.txt

```text
    function testExternalSolve_MempoolRevealCannotBeFrontRun() public {
        _fundTwoDepositors();
        _commit(R.K);
        vm.warp(vault.commitAt() + vault.revealDelay());
        // Attacker sees k in the pending reveal and executes first.
        vm.prank(STRANGER);
        vault.abortOnExternalSolve(R.K);
        assertTrue(vault.aborted());
        vm.expectRevert("aborted");
        vault.revealSolution(R.K, SALT);
        _assertAbortClosedAndRefunds();
    }

```

## 01-pre-fix.txt

```text
Compiling 1 files with Solc 0.8.24
Solc 0.8.24 finished in 500.50ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 1 test for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testExternalSolve_MempoolRevealCannotBeFrontRun() (gas: 522592)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.14ms (1.63ms CPU time)

Ran 1 test suite in 113.20ms (5.14ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## 02-fixed.txt

```text
Compiling 1 files with Solc 0.8.24
Solc 0.8.24 finished in 581.84ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 38 tests for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testAbortOnDeadline_Stranger() (gas: 364646)
[PASS] testAbortOnExternalSolve_GarbageCommitmentStillRefundsEveryone() (gas: 578907)
[PASS] testAbortOnExternalSolve_RejectsAfterCommit() (gas: 281273)
[PASS] testAbortOnExternalSolve_RejectsWrongScalar() (gas: 211425)
[PASS] testAbortOnExternalSolve_StrangerBeforeCommit() (gas: 578565)
[PASS] testAbortOnStall_StrangerAndLastRootResetsClock() (gas: 433060)
[PASS] testChallengeWindow_RejectsOldOrMismatchedRoot() (gas: 504986)
[PASS] testChallengeWindow_SettleDelayRestartsOnNewRoot() (gas: 507966)
[PASS] testClearCommitment_RejectsMissingOrClosedCommitment() (gas: 314159)
[PASS] testClearCommitment_RejectsSolvedRound() (gas: 285121)
[PASS] testClearCommitment_StrangerClearsAtExpiryAndOperatorRetries() (gas: 1243966)
[PASS] testCommitExpiry_MustExceedRevealDelay() (gas: 98365)
[PASS] testDenominatorDouble_AllReceiveHalfAndSweepRecoversExactResidue() (gas: 1667902)
[PASS] testDenominatorHalf_RejectsLaterClaimantsBeforeOverdraw() (gas: 1349112)
[PASS] testEcMath_VerifyDlogRejectsWrongAndOutOfRangeScalars() (gas: 952709)
[PASS] testExternalSolve_CommitmentIsSenderBoundAndReplacementRestartsDelay() (gas: 304455)
[PASS] testExternalSolve_MempoolRevealCannotBeFrontRun() (gas: 1269124)
[PASS] testFeeOnTransferToken_FundingRejectedWithoutAccountingChanges() (gas: 5036153)
[PASS] testFuzz_Conservation(uint256,uint256,uint256,uint8) (runs: 257, μ: 2935506, ~: 2931082)
[PASS] testFuzz_NoSweepWithdrawalRoundingBounds(uint256,uint256,uint8) (runs: 256, μ: 2518989, ~: 2293237)
[PASS] testFuzz_SingleWithdrawalAtEndIsExact(uint256,uint256) (runs: 256, μ: 1580411, ~: 1581394)
[PASS] testGasRevealSolution131Bit() (gas: 6058847)
[PASS] testH2_LatePrizesAccrueUnderSameRootForExistingAndLateClaimants() (gas: 1390270)
[PASS] testLatePrizeCannotBeSweptOnArrival() (gas: 1217089)
[PASS] testNoReturnToken_FundAndWithdraw() (gas: 6051890)
[PASS] testPythonRootVerifiesOnChain() (gas: 123709)
[PASS] testRootMonotonicity_RejectsEqualAndEarlierEpochs() (gas: 161013)
[PASS] testRootMonotonicity_ZeroEpochAndZeroRootAreConsumed() (gas: 137195)
[PASS] testSolutionGate_CorrectScalarAfterDelay() (gas: 279243)
[PASS] testSolutionGate_MismatchedCommitment() (gas: 97612)
[PASS] testSolutionGate_RevealBeforeDelay() (gas: 91191)
[PASS] testSolutionGate_SettleWithoutReveal() (gas: 209930)
[PASS] testSolutionGate_WrongScalarWithMatchingCommitment() (gas: 234926)
[PASS] testSweepIsTrancheBased_LatePrizeStillClaimable() (gas: 1922400)
[PASS] testSweepLifetimeFloorDifference_Counterexample() (gas: 1575510)
[PASS] testSweep_LateTrancheOutstandingClaimsAreBounded() (gas: 1432410)
[PASS] testSweep_RejectsNothingToSweep() (gas: 779074)
[PASS] testT3_OperatorCannotTakeSponsorDepositAndStrangerEnablesRefund() (gas: 295374)
Suite result: ok. 38 passed; 0 failed; 0 skipped; finished in 888.86ms (1.84s CPU time)

Ran 1 test suite in 893.85ms (888.86ms CPU time): 38 tests passed, 0 failed, 0 skipped (38 total tests)
```

## 02-pre-fix-test.txt

```text
    function testLatePrizeCannotBeSweptOnArrival() public {
        _fund(SPONSOR, POOL);
        _solveAndSettle(Fixture.TOTAL);
        vm.warp(vault.settledAt() + vault.claimWindow());
        vault.sweep();
        vm.warp(block.timestamp + vault.claimWindow());
        _fund(SPONSOR2, POOL);
        vault.sweep();
        assertEq(tok.balanceOf(address(this)), 2 * POOL);
        (address who,,) = _fixture(0);
        _claim(0);
        assertEq(tok.balanceOf(who), 0);
    }

```

## 02-pre-fix.txt

```text
Compiling 1 files with Solc 0.8.24
Solc 0.8.24 finished in 499.41ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 1 test for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testLatePrizeCannotBeSweptOnArrival() (gas: 791472)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.03ms (1.28ms CPU time)

Ran 1 test suite in 115.39ms (5.03ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## 03-fixed.txt

```text
Compiling 2 files with Solc 0.8.24
Solc 0.8.24 finished in 609.82ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 40 tests for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testAbortOnDeadline_Stranger() (gas: 371213)
[PASS] testAbortOnExternalSolve_GarbageCommitmentStillRefundsEveryone() (gas: 585402)
[PASS] testAbortOnExternalSolve_RejectsAfterCommit() (gas: 281384)
[PASS] testAbortOnExternalSolve_RejectsWrongScalar() (gas: 211603)
[PASS] testAbortOnExternalSolve_StrangerBeforeCommit() (gas: 585028)
[PASS] testAbortOnStall_StrangerAndLastRootResetsClock() (gas: 505068)
[PASS] testChallengeWindow_RejectsOldOrMismatchedRoot() (gas: 574337)
[PASS] testChallengeWindow_SettleDelayRestartsOnNewRoot() (gas: 672500)
[PASS] testClearCommitment_RejectsMissingOrClosedCommitment() (gas: 314116)
[PASS] testClearCommitment_RejectsSolvedRound() (gas: 285034)
[PASS] testClearCommitment_StrangerClearsAtExpiryAndOperatorRetries() (gas: 1325409)
[PASS] testCommitExpiry_MustExceedRevealDelay() (gas: 99552)
[PASS] testDenominatorDouble_RejectsAtSettleAndSweepRecoversExactResidue() (gas: 1410767)
[PASS] testDenominatorHalf_RejectsAtSettleAndAllLeavesReceiveExactShares() (gas: 1758236)
[PASS] testEcMath_VerifyDlogRejectsWrongAndOutOfRangeScalars() (gas: 952709)
[PASS] testExternalSolve_CommitmentIsSenderBoundAndReplacementRestartsDelay() (gas: 304613)
[PASS] testExternalSolve_MempoolRevealCannotBeFrontRun() (gas: 1351247)
[PASS] testFeeOnTransferToken_FundingRejectedWithoutAccountingChanges() (gas: 5508426)
[PASS] testFuzz_Conservation(uint256,uint256,uint256,uint8) (runs: 257, μ: 3035912, ~: 3020935)
[PASS] testFuzz_NoSweepWithdrawalRoundingBounds(uint256,uint256,uint8) (runs: 256, μ: 2661249, ~: 2373903)
[PASS] testFuzz_SingleWithdrawalAtEndIsExact(uint256,uint256) (runs: 256, μ: 1658757, ~: 1660664)
[PASS] testGasRevealSolution131Bit() (gas: 6531163)
[PASS] testH2_LatePrizesAccrueUnderSameRootForExistingAndLateClaimants() (gas: 1471258)
[PASS] testLatePrizeCannotBeSweptOnArrival() (gas: 1298033)
[PASS] testNoReturnToken_FundAndWithdraw() (gas: 6606188)
[PASS] testPythonRootVerifiesOnChain() (gas: 123687)
[PASS] testRootMonotonicity_RejectsEqualAndEarlierEpochs() (gas: 341324)
[PASS] testRootMonotonicity_ZeroEpochAndZeroRootAreConsumed() (gas: 227447)
[PASS] testRootTotals_RejectsFalseLeavesDuplicatesAndOverflow() (gas: 316780)
[PASS] testRootTotals_TwoEqualLeavesBothRegisterInEitherOrder() (gas: 1142821)
[PASS] testSolutionGate_CorrectScalarAfterDelay() (gas: 279287)
[PASS] testSolutionGate_MismatchedCommitment() (gas: 97568)
[PASS] testSolutionGate_RevealBeforeDelay() (gas: 91147)
[PASS] testSolutionGate_SettleWithoutReveal() (gas: 292036)
[PASS] testSolutionGate_WrongScalarWithMatchingCommitment() (gas: 234860)
[PASS] testSweepIsTrancheBased_LatePrizeStillClaimable() (gas: 2000844)
[PASS] testSweepLifetimeFloorDifference_Counterexample() (gas: 1654589)
[PASS] testSweep_LateTrancheOutstandingClaimsAreBounded() (gas: 1511964)
[PASS] testSweep_RejectsNothingToSweep() (gas: 860735)
[PASS] testT3_OperatorCannotTakeSponsorDepositAndStrangerEnablesRefund() (gas: 295392)
Suite result: ok. 40 passed; 0 failed; 0 skipped; finished in 931.73ms (1.97s CPU time)

Ran 1 test suite in 934.82ms (931.73ms CPU time): 40 tests passed, 0 failed, 0 skipped (40 total tests)
```

## 03-pre-fix-test.txt

```text
    function testDenominatorHalf_RejectsLaterClaimantsBeforeOverdraw() public {
        _fund(SPONSOR, POOL);
        _solveAndSettle(Fixture.TOTAL / 2);
        for (uint256 i; i < 5; ++i) {
            (address who, uint256 steps, bytes32[] memory proof) = _fixture(i);
            uint256 beforeBalance = tok.balanceOf(address(vault));
            vm.prank(who);
            if (i >= 3) vm.expectRevert("denominator");
            vault.claim(steps, proof);
            if (i >= 3) {
                assertEq(tok.balanceOf(address(vault)), beforeBalance);
                assertEq(vault.registeredSteps(who), 0);
                assertEq(tok.balanceOf(who), 0);
            } else {
                assertEq(tok.balanceOf(who), steps * POOL / (Fixture.TOTAL / 2));
            }
            _assertConservation();
        }
        assertEq(vault.claimedSteps(), 42_000_000);
    }

```

## 03-pre-fix.txt

```text
No files changed, compilation skipped

Ran 1 test for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testDenominatorHalf_RejectsLaterClaimantsBeforeOverdraw() (gas: 1349112)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 3.34ms (1.18ms CPU time)

Ran 1 test suite in 110.74ms (3.34ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## 04-fixed.txt

```text
Compiling 2 files with Solc 0.8.24
Solc 0.8.24 finished in 608.46ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 41 tests for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testAbortOnDeadline_Stranger() (gas: 371213)
[PASS] testAbortOnExternalSolve_GarbageCommitmentStillRefundsEveryone() (gas: 585402)
[PASS] testAbortOnExternalSolve_RejectsAfterCommit() (gas: 281384)
[PASS] testAbortOnExternalSolve_RejectsWrongScalar() (gas: 211581)
[PASS] testAbortOnExternalSolve_StrangerBeforeCommit() (gas: 585098)
[PASS] testAbortOnStall_StrangerAndLastRootResetsClock() (gas: 505104)
[PASS] testChallengeWindow_RejectsOldOrMismatchedRoot() (gas: 574315)
[PASS] testChallengeWindow_SettleDelayRestartsOnNewRoot() (gas: 672500)
[PASS] testClearCommitment_RejectsMissingOrClosedCommitment() (gas: 314139)
[PASS] testClearCommitment_RejectsSolvedRound() (gas: 285012)
[PASS] testClearCommitment_StrangerClearsAtExpiryAndOperatorRetries() (gas: 1326469)
[PASS] testCommitExpiry_MustExceedRevealDelay() (gas: 99558)
[PASS] testDenominatorDouble_RejectsAtSettleAndSweepRecoversExactResidue() (gas: 1411381)
[PASS] testDenominatorHalf_RejectsAtSettleAndAllLeavesReceiveExactShares() (gas: 1760356)
[PASS] testEcMath_VerifyDlogRejectsWrongAndOutOfRangeScalars() (gas: 952709)
[PASS] testExternalSolve_CommitmentIsSenderBoundAndReplacementRestartsDelay() (gas: 304701)
[PASS] testExternalSolve_MempoolRevealCannotBeFrontRun() (gas: 1352285)
[PASS] testFeeOnTransferToken_FundingRejectedWithoutAccountingChanges() (gas: 5522479)
[PASS] testFuzz_Conservation(uint256,uint256,uint256,uint8) (runs: 257, μ: 2950225, ~: 2939022)
[PASS] testFuzz_NoSweepWithdrawalRoundingBounds(uint256,uint256,uint8) (runs: 256, μ: 2597071, ~: 2295500)
[PASS] testFuzz_SingleWithdrawalAtEndIsExact(uint256,uint256) (runs: 256, μ: 1660222, ~: 1661702)
[PASS] testGasRevealSolution131Bit() (gas: 6545239)
[PASS] testH2_LatePrizesAccrueUnderSameRootForExistingAndLateClaimants() (gas: 1472698)
[PASS] testLatePrizeCannotBeSweptOnArrival() (gas: 1298714)
[PASS] testNoReturnToken_FundAndWithdraw() (gas: 6621301)
[PASS] testPythonRootVerifiesOnChain() (gas: 123665)
[PASS] testRootMonotonicity_RejectsEqualAndEarlierEpochs() (gas: 341324)
[PASS] testRootMonotonicity_ZeroEpochAndZeroRootAreConsumed() (gas: 227447)
[PASS] testRootTotals_RejectsFalseLeavesDuplicatesAndOverflow() (gas: 316758)
[PASS] testRootTotals_TwoEqualLeavesBothRegisterInEitherOrder() (gas: 1143669)
[PASS] testSolutionGate_CorrectScalarAfterDelay() (gas: 279265)
[PASS] testSolutionGate_MismatchedCommitment() (gas: 97568)
[PASS] testSolutionGate_RevealBeforeDelay() (gas: 91147)
[PASS] testSolutionGate_SettleWithoutReveal() (gas: 292014)
[PASS] testSolutionGate_WrongScalarWithMatchingCommitment() (gas: 234883)
[PASS] testSweepIsTrancheBased_LatePrizeStillClaimable() (gas: 2003154)
[PASS] testSweepLifetimeFloorDifference_Counterexample() (gas: 1655627)
[PASS] testSweep_LateTrancheOutstandingClaimsAreBounded() (gas: 1513024)
[PASS] testSweep_RejectsNothingToSweep() (gas: 860713)
[PASS] testT3_OperatorCannotTakeSponsorDepositAndStrangerEnablesRefund() (gas: 295428)
[PASS] testWithdrawBeforeRegisterPreservesPriorDeposits() (gas: 965549)
Suite result: ok. 41 passed; 0 failed; 0 skipped; finished in 964.72ms (2.00s CPU time)

Ran 1 test suite in 972.39ms (964.72ms CPU time): 41 tests passed, 0 failed, 0 skipped (41 total tests)
```

## 04-pre-fix-test.txt

```text
    function testWithdrawBeforeRegisterPreservesPriorDeposits() public {
        _fund(SPONSOR, POOL);
        _solveAndSettle(Fixture.TOTAL);
        (address who, uint256 steps, bytes32[] memory proof) = _fixture(0);
        vm.prank(who);
        vault.withdraw();
        assertEq(vault.accountedDeposits(who), POOL);
        vm.prank(who);
        vault.claim(steps, proof);
        assertEq(tok.balanceOf(who), 0);
        assertEq(vault.claimable(who), 0);
    }

```

## 04-pre-fix.txt

```text
Compiling 1 files with Solc 0.8.24
Solc 0.8.24 finished in 577.50ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 1 test for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testWithdrawBeforeRegisterPreservesPriorDeposits() (gas: 769494)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 5.06ms (1.06ms CPU time)

Ran 1 test suite in 121.15ms (5.06ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## 05-fixed.txt

```text
Compiling 2 files with Solc 0.8.24
Solc 0.8.24 finished in 571.67ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 43 tests for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testAbortOnDeadline_Stranger() (gas: 371141)
[PASS] testAbortOnExternalSolve_GarbageCommitmentStillRefundsEveryone() (gas: 585364)
[PASS] testAbortOnExternalSolve_RejectsAfterCommit() (gas: 281295)
[PASS] testAbortOnExternalSolve_RejectsWrongScalar() (gas: 211447)
[PASS] testAbortOnExternalSolve_StrangerBeforeCommit() (gas: 585027)
[PASS] testAbortOnStall_StrangerAndLastRootResetsClock() (gas: 505172)
[PASS] testChallengeWindow_RejectsOldOrMismatchedRoot() (gas: 574225)
[PASS] testChallengeWindow_SettleDelayRestartsOnNewRoot() (gas: 672410)
[PASS] testClearCommitment_RejectsMissingOrClosedCommitment() (gas: 314137)
[PASS] testClearCommitment_RejectsSolvedRound() (gas: 285100)
[PASS] testClearCommitment_StrangerClearsAtExpiryAndOperatorRetries() (gas: 1327261)
[PASS] testCommitExpiry_MustExceedRevealDelay() (gas: 99949)
[PASS] testDenominatorDouble_RejectsAtSettleAndSweepRecoversExactResidue() (gas: 1413195)
[PASS] testDenominatorHalf_RejectsAtSettleAndAllLeavesReceiveExactShares() (gas: 1764101)
[PASS] testDirectTransferExcessRecoverableAfterAbort() (gas: 600328)
[PASS] testDirectTransferRecoveryAndSweepPreserveTrackedClaims() (gas: 1522064)
[PASS] testEcMath_VerifyDlogRejectsWrongAndOutOfRangeScalars() (gas: 952732)
[PASS] testExternalSolve_CommitmentIsSenderBoundAndReplacementRestartsDelay() (gas: 304477)
[PASS] testExternalSolve_MempoolRevealCannotBeFrontRun() (gas: 1352371)
[PASS] testFeeOnTransferToken_FundingRejectedWithoutAccountingChanges() (gas: 5664195)
[PASS] testFuzz_Conservation(uint256,uint256,uint256,uint8) (runs: 257, μ: 2941509, ~: 2945121)
[PASS] testFuzz_NoSweepWithdrawalRoundingBounds(uint256,uint256,uint8) (runs: 256, μ: 2612836, ~: 2383984)
[PASS] testFuzz_SingleWithdrawalAtEndIsExact(uint256,uint256) (runs: 256, μ: 1662793, ~: 1664984)
[PASS] testGasRevealSolution131Bit() (gas: 6686846)
[PASS] testH2_LatePrizesAccrueUnderSameRootForExistingAndLateClaimants() (gas: 1474129)
[PASS] testLatePrizeCannotBeSweptOnArrival() (gas: 1298585)
[PASS] testNoReturnToken_FundAndWithdraw() (gas: 6763082)
[PASS] testPythonRootVerifiesOnChain() (gas: 124127)
[PASS] testRootMonotonicity_RejectsEqualAndEarlierEpochs() (gas: 341056)
[PASS] testRootMonotonicity_ZeroEpochAndZeroRootAreConsumed() (gas: 227246)
[PASS] testRootTotals_RejectsFalseLeavesDuplicatesAndOverflow() (gas: 316467)
[PASS] testRootTotals_TwoEqualLeavesBothRegisterInEitherOrder() (gas: 1143844)
[PASS] testSolutionGate_CorrectScalarAfterDelay() (gas: 279178)
[PASS] testSolutionGate_MismatchedCommitment() (gas: 97547)
[PASS] testSolutionGate_RevealBeforeDelay() (gas: 91125)
[PASS] testSolutionGate_SettleWithoutReveal() (gas: 291969)
[PASS] testSolutionGate_WrongScalarWithMatchingCommitment() (gas: 234905)
[PASS] testSweepIsTrancheBased_LatePrizeStillClaimable() (gas: 2005462)
[PASS] testSweepLifetimeFloorDifference_Counterexample() (gas: 1656458)
[PASS] testSweep_LateTrancheOutstandingClaimsAreBounded() (gas: 1514835)
[PASS] testSweep_RejectsNothingToSweep() (gas: 860920)
[PASS] testT3_OperatorCannotTakeSponsorDepositAndStrangerEnablesRefund() (gas: 295427)
[PASS] testWithdrawBeforeRegisterPreservesPriorDeposits() (gas: 966143)
Suite result: ok. 43 passed; 0 failed; 0 skipped; finished in 913.20ms (1.93s CPU time)

Ran 1 test suite in 918.10ms (913.20ms CPU time): 43 tests passed, 0 failed, 0 skipped (43 total tests)
```

## 05-pre-fix-test.txt

```text
    function testDirectTransferExcessRecoverableAfterAbort() public {
        _fundTwoDepositors();
        tok.mint(STRANGER, 123);
        vm.prank(STRANGER);
        tok.transfer(address(vault), 123);
        vm.warp(vault.deadline());
        vault.abortOnDeadline();
        vm.prank(SPONSOR);
        vault.refundClaim();
        vm.prank(SPONSOR2);
        vault.refundClaim();
        assertEq(tok.balanceOf(address(vault)), 123);
        vm.expectRevert("not settled");
        vault.sweep();
        (bool ok,) = address(vault).call(abi.encodeWithSignature("recoverExcess()"));
        assertFalse(ok);
        assertEq(tok.balanceOf(address(vault)), 123);
    }

```

## 05-pre-fix.txt

```text
Compiling 1 files with Solc 0.8.24
Solc 0.8.24 finished in 538.29ms
Compiler run successful with warnings:
Warning (2018): Function state mutability can be restricted to pure
  --> src/EcMath.sol:19:5:
   |
19 |     function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
   |     ^ (Relevant source part starts here and spans across multiple lines).


Ran 1 test for test/PrizeVault.t.sol:PrizeVaultTest
[PASS] testDirectTransferExcessRecoverableAfterAbort() (gas: 384968)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.09ms (1.08ms CPU time)

Ran 1 test suite in 112.07ms (4.09ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

