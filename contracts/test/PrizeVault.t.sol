// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/PrizeVault.sol";
import "./MockToken.sol";
import "./Fixture.sol";

contract PrizeVaultTest is Test {
    MockToken tok;
    PrizeVault v;
    uint256 constant POOL = 10_000e6; // 10,000 USDC

    function setUp() public {
        tok = new MockToken();
        v = new PrizeVault(IERC20(address(tok)), keccak256("ecc-p44-demo"));
        tok.mint(address(this), POOL);
        tok.approve(address(v), POOL);
        v.fund(POOL);
    }

    function testPythonRootVerifiesOnChain() public {
        v.postRoot(1, Fixture.ROOT, Fixture.TOTAL);
        for (uint256 i = 0; i < 5; i++) {
            (address a, uint256 s, bytes32[] memory p) = _leaf(i);
            assertTrue(v.verify(v.root(), v.leaf(a, s), p), "proof from python must verify");
        }
    }

    function testClaimProRataOnce() public {
        v.settle(9, Fixture.ROOT, Fixture.TOTAL);
        uint256 paid;
        for (uint256 i = 0; i < 5; i++) {
            (address a, uint256 s, bytes32[] memory p) = _leaf(i);
            vm.prank(a);
            v.claim(s, p);
            assertEq(tok.balanceOf(a), POOL * s / Fixture.TOTAL);
            paid += tok.balanceOf(a);
        }
        assertLe(POOL - paid, 5, "rounding dust only");
        (address a0, uint256 s0, bytes32[] memory p0) = _leaf(0);
        vm.prank(a0);
        vm.expectRevert(bytes("claimed"));
        v.claim(s0, p0);
    }

    function testWrongAmountRejected() public {
        v.settle(9, Fixture.ROOT, Fixture.TOTAL);
        (address a, uint256 s, bytes32[] memory p) = _leaf(2);
        vm.prank(a);
        vm.expectRevert(bytes("bad proof"));
        v.claim(s + 1, p);
    }

    function testAbortRefundsOperator() public {
        v.postRoot(1, Fixture.ROOT, Fixture.TOTAL);
        uint256 before = tok.balanceOf(address(this));
        v.abort();
        assertEq(tok.balanceOf(address(this)) - before, POOL);
        vm.expectRevert(bytes("closed"));
        v.settle(2, Fixture.ROOT, Fixture.TOTAL);
    }

    function testOnlyOperatorPostsRoots() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(bytes("not operator"));
        v.postRoot(1, Fixture.ROOT, 1);
    }

    function _leaf(uint256 i) internal pure returns (address, uint256, bytes32[] memory) {
        if (i == 0) return Fixture.leaf0();
        if (i == 1) return Fixture.leaf1();
        if (i == 2) return Fixture.leaf2();
        if (i == 3) return Fixture.leaf3();
        return Fixture.leaf4();
    }
}
