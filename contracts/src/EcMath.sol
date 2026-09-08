// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Short-Weierstrass arithmetic over a prime field. The caller supplies a prime p.
library EcMath {
    struct Point { uint256 x; uint256 y; uint256 z; }

    function isOnCurve(uint256 p, uint256 a, uint256 b, uint256 x, uint256 y)
        internal pure returns (bool)
    {
        require(p != 0, "zero p");
        if (x >= p || y >= p) return false;
        return mulmod(y, y, p) == addmod(addmod(mulmod(mulmod(x, x, p), x, p), mulmod(a, x, p), p), b, p);
    }

    /// @dev MSB-first double-and-add, with mixed Jacobian/affine additions.
    /// Fermat inversion uses Solidity square-and-multiply, without a precompile.
    /// Kept view consistently with the interface allowing a modexp implementation.
    function mulG(uint256 p, uint256 a, uint256 k, uint256 gx, uint256 gy)
        internal view returns (uint256 rx, uint256 ry, bool inf)
    {
        require(p != 0, "zero p");
        if (k == 0) return (0, 0, true);
        Point memory r;
        uint256 bit = uint256(1) << 255;
        while ((k & bit) == 0) bit >>= 1;
        while (bit != 0) {
            r = _double(p, a, r);
            if ((k & bit) != 0) r = _add(p, a, r, gx % p, gy % p);
            bit >>= 1;
        }
        if (r.z == 0) return (0, 0, true);
        uint256 zi = _pow(r.z, p - 2, p);
        uint256 zi2 = mulmod(zi, zi, p);
        return (mulmod(r.x, zi2, p), mulmod(r.y, mulmod(zi2, zi, p), p), false);
    }

    function verifyDlog(uint256 p, uint256 a, uint256 n, uint256 gx, uint256 gy,
        uint256 qx, uint256 qy, uint256 k) internal view returns (bool)
    {
        require(p != 0, "zero p");
        if (k == 0 || k >= n || qx >= p || qy >= p) return false;
        (uint256 x, uint256 y, bool inf) = mulG(p, a, k, gx, gy);
        return !inf && x == qx && y == qy;
    }

    function _sub(uint256 x, uint256 y, uint256 p) private pure returns (uint256) {
        return addmod(x, p - y, p); // All internal operands are reduced modulo p.
    }

    function _double(uint256 p, uint256 a, Point memory r) private pure returns (Point memory t) {
        if (r.z == 0 || r.y == 0) return Point(0, 0, 0);
        uint256 yy = mulmod(r.y, r.y, p);
        uint256 s = mulmod(4, mulmod(r.x, yy, p), p);
        uint256 zz = mulmod(r.z, r.z, p);
        uint256 m = addmod(mulmod(3, mulmod(r.x, r.x, p), p), mulmod(a, mulmod(zz, zz, p), p), p);
        t.x = _sub(mulmod(m, m, p), addmod(s, s, p), p);
        t.y = _sub(mulmod(m, _sub(s, t.x, p), p), mulmod(8, mulmod(yy, yy, p), p), p);
        t.z = mulmod(2, mulmod(r.y, r.z, p), p);
    }

    function _add(uint256 p, uint256 a, Point memory r, uint256 x, uint256 y)
        private pure returns (Point memory t)
    {
        if (r.z == 0) return Point(x, y, 1);
        uint256 h;
        uint256 d;
        {
            uint256 zz = mulmod(r.z, r.z, p);
            h = _sub(mulmod(x, zz, p), r.x, p);
            d = _sub(mulmod(y, mulmod(r.z, zz, p), p), r.y, p);
        }
        if (h == 0) {
            if (d == 0) return _double(p, a, r);
            return Point(0, 0, 0);
        }
        uint256 hhh;
        uint256 v;
        {
            uint256 hh = mulmod(h, h, p);
            hhh = mulmod(h, hh, p);
            v = mulmod(r.x, hh, p);
        }
        t.x = _sub(_sub(mulmod(d, d, p), hhh, p), addmod(v, v, p), p);
        t.y = _sub(mulmod(d, _sub(v, t.x, p), p), mulmod(r.y, hhh, p), p);
        t.z = mulmod(r.z, h, p);
    }

    function _pow(uint256 x, uint256 e, uint256 p) private pure returns (uint256 r) {
        r = 1;
        while (e != 0) {
            if ((e & 1) != 0) r = mulmod(r, x, p);
            x = mulmod(x, x, p);
            e >>= 1;
        }
    }
}
